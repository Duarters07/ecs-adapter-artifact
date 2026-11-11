"""DPO on top of the SFT adapter: prefer the verified answer over the near miss.

The pairs come from training/build_dpo_pairs.py, whose docstring states the
pairing rule. This module only trains, and it trains the SFT adapter further
rather than a fresh one: SFT taught the student what a verified answer looks
like, DPO teaches it what the near misses got wrong.

THE REFERENCE MODEL IS THE SFT ADAPTER, NOT THE BASE
----------------------------------------------------
DPO measures how far the policy moves from a reference. With PEFT, TRL's
default reference is the base model with the adapter switched off - which here
would penalise the student for everything SFT taught it. So the SFT adapter is
loaded twice under two names, `policy` (updated) and `reference` (frozen), and
DPOConfig is told which is which. (`train` was the name until 2026-11-01: PEFT 0.21 refuses it, a module attribute.)
TRL 1.17 dropped those two DPOConfig arguments and makes the frozen copy itself, from an adapter named `default`;
`train` follows whichever the installed TRL does.

Written against TRL 1.15 (the version on the rented card): `processing_class`
rather than `tokenizer`, DPOConfig for every training argument. Arguments a
given TRL does not accept are dropped with a printed note rather than crashing
the run (`dpo_config_kwargs`), because the API has moved between releases.

MEMORY. A DPO step runs the chosen and the rejected answer through the policy.
Interpret prompts are short and fit easily. Map prompts are ~10k tokens; the
fused loss (`use_liger_loss`) is requested and the logits-free evaluation fix
from train_lora is applied, but a 24 GB card is at its limit there. Train
interpret first.

    python -m training.train_dpo --stage interpret --adapter training/adapters/interpret-<date>
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
import argparse
import inspect
import json
import os
import sys
import time

from adapter.wiring import ROOT

STAGES = ("interpret", "map")
DATA = ROOT / "training" / "data"
OUT = ROOT / "training" / "adapters"

DEFAULTS: dict[str, Any] = {
    "beta": 0.1,
    "learning_rate": 5e-6,
    "epochs": 1,
    "batch_size": 1,
    "grad_accum": 8,
    "max_length": 8192,
    "loss_type": "sigmoid",
}


def load_pairs(path: Path) -> list[dict[str, Any]]:
    """The pairs, refused if they cannot be trained on honestly."""
    if not path.is_file():
        sys.exit(f"{path} does not exist. Run:  python -m training.build_dpo_pairs")
    rows = [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not rows:
        sys.exit(
            f"{path} holds no pairs. No near miss shared a prompt with a verified answer, "
            "which is a finding about the corpus, not a reason to invent pairs.")
    bad = [i for i, r in enumerate(rows)
           if not all(r.get(k) for k in ("prompt", "chosen", "rejected"))
           or r["chosen"] == r["rejected"]]
    if bad:
        sys.exit(f"{len(bad)} malformed pair(s) (missing field, or chosen == rejected): "
                 f"first indices {bad[:5]}")
    digests = {r.get("prompt_digest") for r in rows}
    if len(digests) > 1:
        sys.exit(f"pairs span {len(digests)} prompt digests: {sorted(map(str, digests))}. "
                 "Rebuild them from one dataset.")
    return rows


def dpo_config_kwargs(cfg: dict[str, Any], out_dir: Path, has_val: bool,
                      accepted: set[str] | None = None) -> dict[str, Any]:
    """DPOConfig arguments, filtered to the ones this TRL accepts.

    ``accepted`` is the parameter set of DPOConfig; None means do not filter.
    """
    want: dict[str, Any] = {
        "output_dir": str(out_dir / "checkpoints"),
        "beta": cfg["beta"],
        "loss_type": cfg["loss_type"],
        "learning_rate": cfg["learning_rate"],
        "num_train_epochs": cfg["epochs"],
        "per_device_train_batch_size": cfg["batch_size"],
        "per_device_eval_batch_size": 1,
        "gradient_accumulation_steps": cfg["grad_accum"],
        "max_length": cfg["max_length"],
        "bf16": True,
        "logging_steps": 5,
        "save_strategy": "epoch",
        "report_to": [],
        "gradient_checkpointing": True,
        "gradient_checkpointing_kwargs": {"use_reentrant": False},
        "optim": "paged_adamw_8bit",
        "model_adapter_name": "policy",
        "ref_adapter_name": "reference",
        "use_liger_loss": True,
        "remove_unused_columns": False,
    }
    if has_val:
        want.update({"eval_strategy": "epoch", "load_best_model_at_end": True,
                     "metric_for_best_model": "eval_loss", "greater_is_better": False,
                     "prediction_loss_only": True})
    if accepted is None:
        return want
    dropped = sorted(k for k in want if k not in accepted)
    if dropped:
        print(f"[dpo] this TRL does not accept {dropped}; continuing without them")
    return {k: v for k, v in want.items() if k in accepted}


def train(stage: str, base_model: str, adapter: Path, data_path: Path, out_dir: Path,
          cfg: dict[str, Any]) -> int:
    from training.train_lora import _require, _require_gpu, family_split

    _require("torch", "torch")
    _require("peft", "peft")
    try:
        import trl  # noqa: F401
        from trl import DPOConfig, DPOTrainer
    except ImportError:
        sys.exit("trl is required for DPO.  Install it with:  pip install trl")

    if not (adapter / "adapter_config.json").is_file():
        sys.exit(f"{adapter} is not a trained adapter (no adapter_config.json). "
                 "DPO continues an SFT adapter; train one first with training.train_lora.")

    import torch
    from datasets import Dataset
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    device_name = _require_gpu()
    rows = load_pairs(data_path)
    idx_tr, idx_val = family_split(rows, 2)
    if not idx_tr:
        idx_tr, idx_val = list(range(len(rows))), []
        print("[dpo] too few families to hold any out; training without validation")

    tok = AutoTokenizer.from_pretrained(base_model)
    tok.pad_token = tok.pad_token or tok.eos_token

    # The same logits-free rule train_lora applies, in both modes - a DPO step
    # runs two long sequences and the full logits do not fit beside them.
    from liger_kernel.transformers import apply_liger_kernel_to_qwen2
    apply_liger_kernel_to_qwen2(fused_linear_cross_entropy=True, cross_entropy=False)

    model = AutoModelForCausalLM.from_pretrained(
        base_model,
        quantization_config=BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True),
        device_map="auto",
        dtype=torch.bfloat16,
        attn_implementation="sdpa",
    )
    accepted = set(inspect.signature(DPOConfig.__init__).parameters)
    # TRL up to 1.15 takes the two adapter names in DPOConfig. TRL 1.17 dropped those arguments: it copies the
    # trained adapter, which must be called "default", into a frozen "ref" itself. Same reference either way.
    named = "model_adapter_name" in accepted
    policy = "policy" if named else "default"
    model = PeftModel.from_pretrained(model, str(adapter), adapter_name=policy, is_trainable=True)
    if named:
        model.load_adapter(str(adapter), adapter_name="reference")
    model.set_adapter(policy)

    # In the chat format the model is served in, exactly as SFT trains it
    # (train_lora.render_chat_prompt, 2026-10-17): the prompt up to the
    # assistant turn, each answer closed by <|im_end|>.
    from training.train_lora import CHAT_END, render_chat_prompt

    def ds(idx):
        return Dataset.from_list([{"prompt": render_chat_prompt(tok, rows[i]["prompt"]),
                                   "chosen": rows[i]["chosen"] + CHAT_END,
                                   "rejected": rows[i]["rejected"] + CHAT_END} for i in idx])

    args = DPOConfig(**dpo_config_kwargs(cfg, out_dir, bool(idx_val), accepted))
    t0 = time.time()
    DPOTrainer(
        model=model,
        args=args,
        train_dataset=ds(idx_tr),
        eval_dataset=ds(idx_val) if idx_val else None,
        processing_class=tok,
    ).train()

    out_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(out_dir), selected_adapters=[policy])
    tok.save_pretrained(str(out_dir))
    # PEFT saves a named adapter under its name; lift it to the directory root
    # so export_ollama finds it where it finds an SFT adapter.
    sub = out_dir / policy
    if (sub / "adapter_config.json").is_file():
        for f in sub.iterdir():
            f.replace(out_dir / f.name)
        sub.rmdir()

    (out_dir / "training_record.json").write_text(json.dumps({
        "stage": stage,
        "method": "dpo",
        "base_model": base_model,
        "sft_adapter": str(adapter),
        "pairs": len(rows),
        "train_pairs": len(idx_tr),
        "validation_pairs": len(idx_val),
        "families": sorted({r.get("family", r["source_id"]) for r in rows}),
        "prompt_digest": rows[0].get("prompt_digest"),
        "hyperparameters": cfg,
        "trl_version": getattr(trl, "__version__", "?"),
        "device": device_name,
        "wall_seconds": round(time.time() - t0, 1),
        "finished_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }, indent=2, sort_keys=True), encoding="utf-8")
    print(f"\nDPO adapter written to {out_dir}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="training.train_dpo", description=__doc__.splitlines()[0])
    p.add_argument("--stage", choices=STAGES, required=True)
    p.add_argument("--adapter", type=Path, required=True, help="the SFT adapter to continue")
    p.add_argument("--base-model",
                   default=os.environ.get("ECS_BASE_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct"))
    p.add_argument("--data", type=Path)
    p.add_argument("--out", type=Path)
    p.add_argument("--beta", type=float, default=DEFAULTS["beta"])
    p.add_argument("--learning-rate", type=float, default=DEFAULTS["learning_rate"])
    p.add_argument("--epochs", type=int, default=DEFAULTS["epochs"])
    p.add_argument("--max-length", type=int, default=DEFAULTS["max_length"])
    a = p.parse_args(argv)
    cfg = {**DEFAULTS, "beta": a.beta, "learning_rate": a.learning_rate,
           "epochs": a.epochs, "max_length": a.max_length}
    stamp = time.strftime("%Y%m%d", time.gmtime())
    return train(a.stage, a.base_model, a.adapter,
                 a.data or DATA / f"dpo_{a.stage}.jsonl",
                 a.out or OUT / f"{a.stage}-dpo-{stamp}", cfg)


if __name__ == "__main__":
    raise SystemExit(main())

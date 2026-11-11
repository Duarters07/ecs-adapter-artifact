"""QLoRA - one adapter per stage, base model frozen.

The only step in this project that needs a GPU (~16 GB VRAM for a 7B). If one is
not available the paper is arms A, B and T, which is still a paper; see the
guide's build order. This file refuses to start rather than silently falling back
to something slower and different, because a training run that took a week on
CPU and produced a worse adapter would be indistinguishable from the method not
working.

Two adapters, trained separately from the SAME verified cases:

    interpret   samples + documentation      ->  roles
    map         roles + offered ECS fields   ->  IR

They are trained separately because the stages are blind to each other at run
time. Training one model on both tasks would let it learn the shortcut the whole
decomposition exists to prevent: going from raw lines straight to a field name.

The base model is never touched. What ships is one 4.7 GB base plus two ~100 MB
adapters, and the previous adapter is kept so a bad one can be rolled back.
"""
from __future__ import annotations

from pathlib import Path
import argparse
import json
import sys
import time

from adapter.wiring import ROOT

DATA = ROOT / "training" / "data"
OUT = ROOT / "training" / "adapters"

STAGES = ("interpret", "map")

# Fixed, and recorded with every adapter: a hyperparameter that drifts between
# the two stages would make their comparison meaningless.
CHAT_END = "<|im_end|>"


def render_chat_prompt(tok, prompt: str) -> str:
    """The prompt as the served model receives it: chat turns up to the assistant's."""
    return tok.apply_chat_template([{"role": "user", "content": prompt}],
                                   tokenize=False, add_generation_prompt=True)


DEFAULTS = {
    "r": 16,
    "lora_alpha": 32,
    "lora_dropout": 0.05,
    "learning_rate": 2e-4,
    "epochs": 3,
    "batch_size": 1,
    "grad_accum": 8,
    "max_seq_len": 4096,
    "target_modules": ["q_proj", "k_proj", "v_proj", "o_proj",
                       "gate_proj", "up_proj", "down_proj"],
}


def _require(module: str, extra: str) -> None:
    try:
        __import__(module)
    except ImportError:
        sys.exit(
            f"{module} is not installed.\n"
            f"Training needs the optional extras:  pip install {extra}\n"
            "Everything else in this project runs without them."
        )


def _require_gpu() -> str:
    import torch

    if not torch.cuda.is_available():
        sys.exit(
            "No CUDA device.\n\n"
            "This is the one step that cannot be done on CPU in reasonable time.\n"
            "Without a GPU the study is arms A, B and T - decomposition and model\n"
            "size, measured honestly, with the distilled arm reported as not run.\n"
            "That is a smaller paper, not a broken one. Do not work around this."
        )
    name = torch.cuda.get_device_name(0)
    vram = torch.cuda.get_device_properties(0).total_memory / 1e9
    print(f"device : {name}  ({vram:.1f} GB)")
    if vram < 15:
        print(
            "WARNING: under 16 GB. Reduce --max-seq-len before reducing rank; a "
            "truncated prompt changes the task, a smaller rank only changes capacity."
        )
    return name


def _load(stage: str, path: Path):
    if not path.is_file():
        sys.exit(f"{path} does not exist. Run:  make ecs-dataset")
    rows = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not rows:
        sys.exit(f"{path} is empty - nothing passed V4 for stage {stage!r}.")

    families = {r.get("family", r["source_id"]) for r in rows}
    print(f"stage    : {stage}")
    print(f"examples : {len(rows)} from {len(families)} source families")
    if len(families) < 8:
        print(
            "WARNING: few families. An adapter fitted to a narrow distribution will\n"
            "         score well here and badly on anything unfamiliar. Report the\n"
            "         family count beside every accuracy figure."
        )
    return rows


# Keys whose values may legitimately differ across a corpus, provided the
# record says so. See _one for why retrieval is not like the other two.
#
# `schema_digest` joined on 2026-10-15, and only because the newer schema is a
# strict SUPERSET of the older: it added `extraction.alternatives` and dotted
# nested json keys, both optional, and changed nothing an older answer could
# contain. Every older record was re-judged under the newer schema (apparatus
# v7, V1 included) before this dataset was built, so each example is a valid
# answer to the question the student will be asked. The 126 newer examples are
# the free-text proposals the alternatives were added for; refusing them, or
# the 792 older ones, to keep one digest would discard the corpus rather than
# describe it. A schema change that is NOT a superset must not be added here.
_MAY_SPAN_VERSIONS = frozenset({"retrieval_digest", "schema_digest"})


def _one(rows: list[dict], key: str) -> str | list[str] | None:
    """The single value of `key` across the corpus, or a refusal.

    The record used to take `rows[0]` and call it the provenance. That is only
    true while every example agrees, and nothing checked. A dataset assembled
    from two generation runs - a different prompt, a different output schema, a
    different candidate list - would have trained one adapter and labelled it
    with whichever apparatus happened to sort first.
    """
    values = {r.get(key) for r in rows}
    if len(values) > 1 and key not in _MAY_SPAN_VERSIONS:
        sys.exit(
            f"{key} is not single-valued across the training set: {sorted(map(str, values))}.\n"
            "The examples come from more than one version of the apparatus, so the\n"
            "adapter could not state which one produced it. Rebuild the dataset from\n"
            "one run, or say explicitly which records to keep."
        )
    if len(values) > 1:
        # Declared rather than refused, and the record carries every value.
        #
        # The three digests are not the same kind of thing. `prompt_digest` is
        # what the teacher was ASKED and `schema_digest` is what it was ALLOWED
        # to answer; a corpus spanning two of either was produced under two
        # different tasks, and one adapter cannot honestly claim both.
        # `retrieval_digest` is which 240 of 1659 ECS fields it was SHOWN -
        # a difference in the candidate list, not in the question or the
        # answer's shape.
        #
        # On 2026-10-13 the corpus spanned two retrieval digests because the
        # ECS index changed on the 11th: a 35% per-root cap and three widened
        # categories. The 198 examples on the newer side are the wide families
        # and the `_opt` sources that stage D added, which is half the corpus
        # gained that night. Refusing them to keep one digest would have
        # discarded the work rather than described it.
        #
        # So the metadata states BOTH, and the paper says the training set
        # spans two candidate lists. That is a limitation to report, not a
        # number to launder.
        out = sorted(map(str, values))
        print(f"[train] {key} spans {len(out)} versions of the apparatus: {out}")
        print(f"[train]   recorded in full. The adapter is labelled with both.")
        return out
    return values.pop() if values else None


def family_of(row: dict) -> str:
    """The training family a row belongs to.

    The rows carry an explicit `family`. Deriving one from `source_id` instead
    yields 22 pseudo-families - `caddy`, `caddy_csv`, `caddy_kv` - which are one
    family in three layouts.
    """
    import re as _re

    if fam := row.get("family"):
        return str(fam)
    sid = str(row.get("source_id") or row.get("source") or "")
    return _re.sub(r"^syn_", "", sid).rsplit("_", 1)[0] or sid


def family_split(rows: list[dict], n_val: int = 2) -> tuple[list[int], list[int]]:
    """Split by FAMILY, not by example, and return (train idx, val idx).

    WHY THIS EXISTS, AND WHY IT SPLITS THIS WAY.

    Until 2026-10-11 this script had no validation set at all. It trained for a
    fixed three epochs and reported a training loss, which fell to 0.024 - a
    number that says the model fitted these examples and nothing about any
    other. The interpret adapter had meanwhile collapsed onto the corpus's
    dominant extraction kind, answering `kv` for a pure JSON line six times out
    of six where the untrained base answered `json` six out of six. That was
    invisible in the loss curve and surfaced only in an evaluation arm run days
    later.

    Examples from one family share a layout and a vocabulary, so a random split
    would put near-copies on both sides and report a validation loss that is
    really a training loss - the same blindness with a reassuring number
    attached. Holding families out is the only split that measures what the
    adapter is actually asked to do: a source it has never seen.

    Returns ([], []) when there are too few families to hold any out, which the
    caller reads as "train without validation" rather than as an error.
    """
    fams = sorted({family_of(r) for r in rows})
    # ECS_VAL_FAMILIES names the held-out families explicitly (round 7, C-org: validation on the
    # synthetic replay only, so that no organisation source is kept out of training). Unset, the
    # split is exactly the one every earlier adapter was trained with.
    import os
    fixed = [f.strip() for f in os.environ.get("ECS_VAL_FAMILIES", "").split(",") if f.strip()]
    if fixed:
        idx_val = [i for i, r in enumerate(rows) if family_of(r) in fixed]
        idx_tr = [i for i, r in enumerate(rows) if family_of(r) not in fixed]
        return (idx_tr, idx_val) if idx_val and len(idx_tr) >= 10 else ([], [])
    if len(fams) <= n_val + 1:
        return [], []
    step = max(len(fams) // max(n_val, 1), 1)
    holdout = set(fams[::step][:n_val])
    idx_val = [i for i, r in enumerate(rows) if family_of(r) in holdout]
    idx_tr = [i for i, r in enumerate(rows) if family_of(r) not in holdout]
    if not idx_val or len(idx_tr) < 10:
        return [], []
    return idx_tr, idx_val


def train(stage: str, base_model: str, data_path: Path, out_dir: Path, cfg: dict) -> int:
    _require("torch", "torch")
    _require("transformers", "transformers peft datasets bitsandbytes accelerate")
    _require("peft", "peft")

    import torch
    from datasets import Dataset
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        BitsAndBytesConfig,
        DataCollatorForLanguageModeling,
        Trainer,
        TrainingArguments,
    )

    device_name = _require_gpu()
    rows = _load(stage, data_path)

    # PROVENANCE IS CHECKED BEFORE THE GPU IS TOUCHED, NOT AFTER.
    #
    # These three calls used to live in the metadata written at the very end.
    # On 2026-10-13 that cost nineteen minutes of rented card: the interpret
    # adapter trained to completion, early stopping fired on a validation
    # curve, and only then did `_one` refuse the record because the corpus
    # spanned two retrieval digests. The refusal was right; its timing was
    # waste. A run that cannot produce a labelled artefact should not start.
    for _key in ("prompt_digest", "schema_digest", "retrieval_digest", "ecs_version"):
        _one(rows, _key)

    tok = AutoTokenizer.from_pretrained(base_model)
    tok.pad_token = tok.pad_token or tok.eos_token

    def encode(row):
        # Loss on the completion only. Training on the prompt would spend
        # capacity learning to reproduce the ECS field list, which the model is
        # given at inference time and never has to recall.
        #
        # IN THE CHAT FORMAT THE MODEL IS SERVED IN (2026-10-17).
        #
        # Ollama's /api/generate wraps every prompt in the base model's chat
        # template - a system turn ("You are Qwen, created by Alibaba Cloud..."),
        # the prompt as the user turn, then the assistant turn - and stops the
        # answer at <|im_end|>. Until this date the adapters were trained on the
        # bare `prompt + completion + eos`, a text the served model never sees:
        # every C arm, round 1 included, was evaluated on an input format it had
        # not been trained on. The tokenizer's own template produces the same
        # turns Ollama does (training/parity.py checks it against a live server).
        prompt_text = render_chat_prompt(tok, row["prompt"])
        prompt_ids = tok(prompt_text, add_special_tokens=False)["input_ids"]
        full_ids = tok(
            prompt_text + row["completion"] + CHAT_END,
            add_special_tokens=False,
            truncation=True,
            max_length=cfg["max_seq_len"],
        )["input_ids"]
        labels = list(full_ids)
        for i in range(min(len(prompt_ids), len(labels))):
            labels[i] = -100
        return {"input_ids": full_ids, "attention_mask": [1] * len(full_ids), "labels": labels}

    ds = Dataset.from_list(rows).map(encode, remove_columns=list(rows[0].keys()))

    # A HELD-OUT SPLIT, AND WHY ITS ABSENCE COST FOUR DAYS.
    #
    # Until 2026-10-11 this script had no validation set at all. It trained for
    # a fixed three epochs and reported a training loss, which fell to 0.024 -
    # a number that says the model fitted these examples and says nothing about
    # any other. The interpret adapter had in fact collapsed onto the corpus's
    # dominant extraction kind, answering `kv` for a pure JSON line six times
    # out of six where the untrained base answered `json` six out of six. That
    # was invisible here, invisible in the loss curve, and only surfaced in an
    # evaluation arm run days later.
    #
    # Splitting by SOURCE FAMILY, not by example. Examples from one family
    # share a layout and a vocabulary, so a random split would put near-copies
    # on both sides and report a validation loss that is really a training
    # loss - the same blindness with a reassuring number attached.
    idx_tr, idx_val = family_split(rows, cfg.get("val_families", 2))
    if not idx_val:
        print("[train] too few families to hold any out; training without "
              "validation", flush=True)
        ds_tr, ds_val = ds, None
    else:
        ds_tr, ds_val = ds.select(idx_tr), ds.select(idx_val)
        held = sorted({family_of(rows[i]) for i in idx_val})
        print(f"[train] holding out {held}: {len(idx_tr)} train / "
              f"{len(idx_val)} validation examples", flush=True)

    # WHY THIS GUARD EXISTS.
    #
    # The mask above sets every prompt token to -100. When the prompt alone is
    # longer than max_seq_len, truncation keeps only prompt tokens and the mask
    # then zeroes all of them: the example contributes no gradient at all, and
    # nothing in the loss curve says so. On 2026-10-09 all 209 map examples
    # were in that state at max_seq_len 4096. Training reported a final loss of
    # 0.028 and what it wrote to disk was initialisation noise, which was only
    # found four days later after an entire evaluation arm had been run on it.
    #
    # A silent zero-gradient example is worse than a crash. This makes it a
    # crash.
    blind = [i for i, r in enumerate(ds) if all(t == -100 for t in r["labels"])]
    if blind:
        raise SystemExit(
            f"{len(blind)} of {len(ds)} {stage} examples carry no training signal: "
            f"every label is masked, because the prompt alone exceeds "
            f"max_seq_len={cfg['max_seq_len']}. Raise the window or shorten the "
            f"prompt. Training on them would report a loss and learn nothing. "
            f"First offending indices: {blind[:5]}"
        )
    kept = sum(sum(1 for t in r["labels"] if t != -100) for r in ds)
    print(f"[train] {len(ds)} {stage} examples, {kept} supervised tokens, "
          f"window {cfg['max_seq_len']}", flush=True)

    # WHY THE FUSED LOSS IS NOT OPTIONAL HERE.
    #
    # The map prompt carries 320 candidate ECS fields, so sequences reach
    # ~10,400 tokens. The default loss materialises a logits tensor of
    # [batch, seq_len, vocab] = [1, 10496, 151936] and its gradient, which is
    # about 6 GiB each in fp32 and does not fit beside a 7B model in 24 GB.
    # Gradient checkpointing does not touch it - it is one allocation, not an
    # activation chain. Liger's fused linear cross-entropy computes the loss
    # straight from the hidden states and lm_head without ever building it.
    #
    # The retrieval budget was checked first, and cannot absorb this: measured
    # subset recall on the evaluation pool is 1.00 at 320 candidates and 0.90
    # at 192, so a smaller prompt would put the correct answer out of reach and
    # be reported as a model error.
    try:
        from liger_kernel.transformers import apply_liger_kernel_to_qwen2
    except ImportError:  # pragma: no cover - environment, not logic
        raise SystemExit(
            "liger-kernel is required to train at this window size.\n"
            "Install it with:  pip install liger-kernel"
        )
    apply_liger_kernel_to_qwen2(fused_linear_cross_entropy=True, cross_entropy=False)

    # THE SAME RULE IN EVALUATION, WHICH LIGER DOES NOT APPLY BY ITSELF.
    #
    # Liger 0.8 fuses the loss only when `self.training`; in eval it builds the
    # full logits tensor and computes the loss the ordinary way. On the map
    # stage at a 16k window that is 5.6 GiB in one allocation, and on
    # 2026-10-15 it ran the card out of memory at the end of the first epoch,
    # 40 minutes in, after every training step had fit. Evaluation here only
    # ever needs the loss (`prediction_loss_only` below), so the logits are
    # skipped whenever labels are present, in both modes.
    import transformers.models.qwen2.modeling_qwen2 as _q2

    import functools

    _fused = _q2.Qwen2ForCausalLM.forward

    # functools.wraps keeps the signature visible: the Trainer inspects it to
    # decide which dataset columns to pass, and finds none behind *args/**kwargs.
    @functools.wraps(_fused)
    def _loss_without_logits(self, *args, **kwargs):
        if kwargs.get("labels") is not None and kwargs.get("skip_logits") is None:
            kwargs["skip_logits"] = True
        return _fused(self, *args, **kwargs)

    _q2.Qwen2ForCausalLM.forward = _loss_without_logits

    model = AutoModelForCausalLM.from_pretrained(
        base_model,
        quantization_config=BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        ),
        device_map="auto",
        # bf16 end to end, deliberately. See the recast below.
        dtype=torch.bfloat16,
        attn_implementation="sdpa",
    )
    model = prepare_model_for_kbit_training(
        model,
        use_gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
    )

    # WHY THE WEIGHTS ARE CAST BACK DOWN.
    #
    # prepare_model_for_kbit_training promotes the embeddings and the layer
    # norms to fp32. That is the right default for fp16, whose narrow exponent
    # range makes normalisation unstable, and it is unnecessary for bf16, which
    # has fp32's exponent range already.
    #
    # Here it was not merely unnecessary, it was fatal. fp32 embeddings make
    # every hidden state fp32, and PyTorch has no flash or memory-efficient
    # attention kernel for fp32, so scaled_dot_product_attention silently fell
    # back to the math backend and materialised the full attention matrix:
    # [1, 28 heads, 10496, 10496] in fp32 is 11.5 GiB, in one allocation, and
    # the run died there. The fp32 copies of embed_tokens and lm_head cost a
    # further 4.4 GiB between them.
    #
    # Measured on an RTX 4090, forward and backward at 10,496 tokens:
    # 11.71 GiB peak after this recast, against OOM before it.
    #
    # The recast runs BEFORE get_peft_model so the LoRA parameters, which are
    # created afterwards, keep fp32 for the optimiser.
    for _name, _param in model.named_parameters():
        if _param.dtype == torch.float32:
            _param.data = _param.data.to(torch.bfloat16)
    if cfg.get("init_adapter"):
        # CONTINUED TRAINING (round 3, ROUND3_VERSION_DRIFT.md): start from an
        # adapter already trained - the model the vendor ships - and adapt it
        # to an organisation's own history. The adapter's own LoRA config
        # (rank, alpha, targets) is kept; nothing in it is re-initialised.
        from peft import PeftModel

        model = PeftModel.from_pretrained(model, str(cfg["init_adapter"]), is_trainable=True)
    else:
        model = get_peft_model(
            model,
            LoraConfig(
                r=cfg["r"],
                lora_alpha=cfg["lora_alpha"],
                lora_dropout=cfg["lora_dropout"],
                target_modules=cfg["target_modules"],
                bias="none",
                task_type="CAUSAL_LM",
            ),
        )
    model.print_trainable_parameters()

    out_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    # Early stopping needs the callback and a metric to watch; both are no-ops
    # when there is no validation set, so the no-split path is unchanged.
    from transformers import EarlyStoppingCallback

    _eval = {} if ds_val is None else dict(
        eval_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        per_device_eval_batch_size=1,
        prediction_loss_only=True,
    )
    Trainer(
        model=model,
        train_dataset=ds_tr,
        eval_dataset=ds_val,
        callbacks=([] if ds_val is None
                   else [EarlyStoppingCallback(early_stopping_patience=1)]),
        args=TrainingArguments(
            output_dir=str(out_dir / "checkpoints"),
            num_train_epochs=cfg["epochs"],
            per_device_train_batch_size=cfg["batch_size"],
            gradient_accumulation_steps=cfg["grad_accum"],
            learning_rate=cfg["learning_rate"],
            bf16=True,
            logging_steps=5,
            save_strategy="epoch",
            report_to=[],
            **_eval,
            # THE MAP STAGE NEEDS A 10k WINDOW AND THE LOGITS DO NOT FIT.
            #
            # The map prompt is ~9k tokens of retrieved ECS candidates. At
            # max_seq_len 4096 every map example was truncated to prompt only
            # and then fully masked by the completion-only loss, so all 209 of
            # them trained on nothing (measured 2026-10-10). Raising the window
            # is mandatory; the cost is a cross-entropy over seq x 152k vocab,
            # which OOMs a 24 GB card without these three.
            gradient_checkpointing=True,
            gradient_checkpointing_kwargs={"use_reentrant": False},
            optim="paged_adamw_8bit",
        ),
        data_collator=DataCollatorForLanguageModeling(tok, mlm=False),
    ).train()

    model.save_pretrained(str(out_dir))
    tok.save_pretrained(str(out_dir))

    # The adapter carries its own provenance. An adapter that cannot say which
    # data and which hyperparameters produced it is not a reproducible artefact.
    (out_dir / "training_record.json").write_text(
        json.dumps(
            {
                "stage": stage,
                "base_model": base_model,
                "examples": len(rows),
                "families": sorted(
                    {r.get("family", r["source_id"]) for r in rows}
                ),
                # All three, and asserted to be single-valued: an adapter
                # trained across two versions of the apparatus is not a
                # reproducible artefact and must not silently look like one.
                "prompt_digest": _one(rows, "prompt_digest"),
                "schema_digest": _one(rows, "schema_digest"),
                "retrieval_digest": _one(rows, "retrieval_digest"),
                "ecs_version": _one(rows, "ecs_version"),
                "hyperparameters": cfg,
                "device": device_name,
                "wall_seconds": round(time.time() - t0, 1),
                "finished_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    print(f"\nadapter written to {out_dir}")
    # An --out outside the repository is legitimate; only the hint is relative.
    shown = out_dir.relative_to(ROOT) if out_dir.is_relative_to(ROOT) else out_dir
    print(f"Next:  make ecs-regression ADAPTER={shown}")
    print("An adapter is NOT deployed until it clears the frozen held-out gate.")
    return 0


def main(argv: list[str] | None = None) -> int:
    import os

    p = argparse.ArgumentParser(prog="training.train_lora", description=__doc__.splitlines()[0])
    p.add_argument("--stage", choices=STAGES, required=True)
    p.add_argument("--base-model", default=os.environ.get("ECS_BASE_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct"))
    p.add_argument("--data", type=Path)
    p.add_argument("--out", type=Path)
    p.add_argument("--epochs", type=int, default=DEFAULTS["epochs"])
    p.add_argument("--max-seq-len", type=int, default=DEFAULTS["max_seq_len"])
    p.add_argument("--rank", type=int, default=DEFAULTS["r"])
    p.add_argument("--learning-rate", type=float, default=DEFAULTS["learning_rate"])
    p.add_argument("--init-adapter", type=Path, default=None,
                   help="continue training from this LoRA adapter instead of a fresh one")
    a = p.parse_args(argv)

    cfg = {**DEFAULTS, "epochs": a.epochs, "max_seq_len": a.max_seq_len,
           "r": a.rank, "lora_alpha": 2 * a.rank, "learning_rate": a.learning_rate,
           "init_adapter": str(a.init_adapter) if a.init_adapter else None}
    stamp = time.strftime("%Y%m%d", time.gmtime())
    return train(
        a.stage,
        a.base_model,
        a.data or DATA / f"{a.stage}.jsonl",
        a.out or OUT / f"{a.stage}-{stamp}",
        cfg,
    )


if __name__ == "__main__":
    raise SystemExit(main())

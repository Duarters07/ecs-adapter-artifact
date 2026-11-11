"""Train/serve parity: does the SERVED adapter reproduce its own training answers?

WHY THIS IS A GATE
------------------
On 2026-10-17 the gold-trained student was found to have been trained on a
format it was never served in: bare `prompt + completion` against Ollama's chat
template, alphabetical JSON keys against a grammar that forces schema order,
bf16 weights against a q4 base. Every C arm since round 1 was evaluated through
that mismatch, and nothing in the pipeline could have noticed, because nothing
ever asked the served model a question whose answer was known.

This does. It takes N examples the adapter was TRAINED on, sends each prompt
through the exact client and schema an evaluation uses, at temperature 0, and
compares the answer with the training target. A served adapter that cannot
reproduce what it was fitted to is not being served the way it was trained,
whatever its loss curve says, and no evaluation of it means anything.

It also checks the prompt length the server reports against the local chat
rendering (`prompt_eval_count` vs train_lora.render_chat_prompt): a large gap
means the server wraps the prompt differently from training.

    python -m training.parity --stage interpret --model qwen2.5-coder:ecs-interpret-gs \\
        --data training/data/interpret.jsonl --n 20
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
import argparse
import json
import os
import random
import sys

GATE = {"interpret": 0.8, "map": 0.9}


def _pairs(ir: dict[str, Any]) -> set[tuple[str, str]]:
    out = {(f.get("source_key"), f.get("ecs_field")) for f in ir.get("fields") or []}
    out |= {(v.get("from_source_key"), v.get("ecs_field")) for v in ir.get("value_maps") or []}
    return out


def score(stage: str, got: dict[str, Any], want: dict[str, Any]) -> float:
    """1.0 for a faithful reproduction. interpret: extraction identical and the same
    keys described; map: F1 of (source_key, ecs_field) pairs, value maps included."""
    if stage == "interpret":
        ex_ok = (got.get("extraction") or {}) == (want.get("extraction") or {})
        keys_got = {r.get("source_key") for r in got.get("roles") or []}
        keys_want = {r.get("source_key") for r in want.get("roles") or []}
        return 0.5 * ex_ok + 0.5 * (len(keys_got & keys_want) / max(len(keys_got | keys_want), 1))
    g, w = _pairs(got), _pairs(want)
    if not g and not w:
        return 1.0
    p = len(g & w) / max(len(g), 1)
    r = len(g & w) / max(len(w), 1)
    return 2 * p * r / (p + r) if p + r else 0.0


def _raw_call(client, prompt: str, usage) -> dict[str, Any]:
    """The bare prompt, no template and no grammar: how a pre-2026-10-17 adapter was trained."""
    import httpx

    r = httpx.post(f"{client.cfg.endpoint}/api/generate", timeout=client.cfg.timeout_s, json={
        "model": client.cfg.model, "prompt": prompt, "raw": True, "stream": False,
        "options": {"temperature": 0.0, "num_ctx": client.cfg.num_ctx,
                    "num_predict": client.cfg.max_tokens, "stop": ["<|endoftext|>", "<|im_end|>"]}})
    r.raise_for_status()
    data = r.json()
    usage.add(int(data.get("prompt_eval_count", 0)), int(data.get("eval_count", 0)))
    text = data.get("response", "")
    start, end = text.find("{"), text.rfind("}")
    return json.loads(text[start:end + 1])


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="training.parity", description=__doc__.splitlines()[0])
    p.add_argument("--stage", choices=("interpret", "map"), required=True)
    p.add_argument("--model", required=True, help="the served (Ollama) model name")
    p.add_argument("--data", type=Path, required=True, help="the jsonl the adapter was trained on")
    p.add_argument("--n", type=int, default=20)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--raw", action="store_true",
                   help="diagnosis only: send the bare prompt (Ollama raw mode, no chat template, "
                        "no grammar), the format adapters trained before 2026-10-17 were fitted to")
    p.add_argument("--tokenizer", default=os.environ.get("ECS_BASE_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct"))
    a = p.parse_args(argv)

    from adapter.architectures import ROLES_SCHEMA, ir_schema_for
    from adapter.ecs_index import DEFAULT_MAX_FIELDS
    from adapter.model_client import ModelClient, ModelConfig
    from adapter.types import Usage
    from adapter.wiring import _ecs_index, _load_source

    rows = [json.loads(l) for l in a.data.read_text(encoding="utf-8").splitlines() if l.strip()]
    random.Random(a.seed).shuffle(rows)
    rows = rows[: a.n]
    ecs = _ecs_index()
    client = ModelClient(ModelConfig(
        backend="ollama", model=a.model,
        endpoint=os.environ.get("ECS_MODEL_ENDPOINT", "http://127.0.0.1:11434"),
        temperature=0.0, num_ctx=int(os.environ.get("ECS_MODEL_NUM_CTX", "16384"))))
    tok = None
    try:
        from transformers import AutoTokenizer

        from training.train_lora import render_chat_prompt
        tok = AutoTokenizer.from_pretrained(a.tokenizer)
    except Exception as exc:  # pragma: no cover - checked on the card
        print(f"(no local tokenizer, length check skipped: {exc})")

    scores, gaps = [], []
    for i, row in enumerate(rows):
        if a.stage == "interpret":
            schema = ROLES_SCHEMA
        else:
            src, _ = _load_source(row["source_id"])
            schema = ir_schema_for(ecs.relevant_subset(
                src.observed_keys(), src.documentation, src.category_hint, DEFAULT_MAX_FIELDS))
        usage = Usage()
        try:
            got = _raw_call(client, row["prompt"], usage) if a.raw else \
                client.complete_json(row["prompt"], schema, usage)
        except Exception as exc:
            print(f"  {i:>2} {row['source_id']:<36} ERROR {exc}")
            scores.append(0.0)
            continue
        s = score(a.stage, got, json.loads(row["completion"]))
        scores.append(s)
        gap = ""
        if tok is not None and not a.raw:
            local = len(tok(render_chat_prompt(tok, row["prompt"]), add_special_tokens=False)["input_ids"])
            gaps.append(usage.prompt_tokens - local)
            gap = f"  served-local tokens {usage.prompt_tokens - local:+d}"
        print(f"  {i:>2} {row['source_id']:<36} score {s:.2f}{gap}")

    mean = sum(scores) / max(len(scores), 1)
    print(f"\n{a.stage} {a.model}: mean reproduction {mean:.2f} over {len(scores)} training examples "
          f"(gate {GATE[a.stage]:.2f})")
    if gaps:
        print(f"prompt length served minus local: min {min(gaps)} max {max(gaps)} "
              "(0 means the server renders exactly the training format)")
    ok = mean >= GATE[a.stage] and (not gaps or max(abs(g) for g in gaps) <= 2)
    print("PARITY " + ("OK" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

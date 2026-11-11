"""Round 10, F5 (PLAN_ROUND10_ARM_C.md, T2 and T3): training examples from org9's own attempts on TRAINING sources.

org9 is run on the training sources (Task 1 mode, the round-10 pipeline, k=6 with 3 repairs) with ECS_TRACE_FILE set,
so adapter.controller._trace records every judged attempt: the roles stage 1 wrote, the IR the ladder judged, the
verdict, and the diagnosis each stage would have read in the repair. From those traces:

  T2 interpret repair   a failed attempt the diagnosis blames on stage 1 -> the s1_interpret prompt with that
                        diagnosis and org9's own roles as `previous_roles` -> the gold roles (credited as SFT credits
                        them). The prompt is rendered exactly as StagedArchitecture.repair renders it.
  T2 map repair         a failed attempt blamed on stage 2 whose roles name exactly the gold's source keys -> the
                        s2_map prompt with the diagnosis and org9's IR as `previous_ir` -> the gold IR (credited).
  T3 DPO, interpret     for one source, the first-attempt s1_interpret prompt; chosen = roles of an attempt the
                        ladder verified at V3 or beyond (org9's own when it has one, else the gold's); rejected = roles
                        of an attempt refuted at V2/V3 with a stage-1 diagnosis. Map pairs are not built here: map
                        prompts are ~10k tokens and train_dpo.py warns a 24 GB card is at its limit there.

Answers are never a model's unverified output: every completion is the gold (teacher/out/gold.ndjson, verified by
the ladder) or an attempt the ladder itself passed. Only training sources (split "train") are used; anything else in a
trace is skipped and counted.

    python -m corpus.own_failures --traces trace*.ndjson --out training/data/r10/own
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any
import argparse
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
GOLD = ROOT / "teacher" / "out" / "gold.ndjson"
REFUTED_BY_STAGE1 = {"V1", "V2", "V3"}   # the rung an attempt stopped at


def _gold() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for line in GOLD.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            if r.get("roles") and r.get("ir") and (r.get("credit") or {}).get("extraction"):
                out[r["source_id"]] = r
    return out


def _keys(roles: dict[str, Any] | None) -> set[str]:
    return {r.get("source_key") for r in (roles or {}).get("roles") or [] if r.get("source_key")}


def _h(*parts: str) -> str:
    return hashlib.sha256("\x00".join(parts).encode()).hexdigest()[:16]


def build(traces: list[Path], out_dir: Path, per_source: int = 6) -> dict[str, Any]:
    from adapter.architectures import IR_SCHEMA, ROLES_SCHEMA
    from adapter.prompts import Prompts
    from adapter.schema_order import grammar_order
    from adapter.wiring import _ecs_index, _load_source
    from adapter.ecs_index import DEFAULT_MAX_FIELDS, render_fields
    from training.build_dataset import _credited_ir, _credited_roles, _without_types

    prompts, ecs, gold = Prompts(ROOT / "prompts"), _ecs_index(), _gold()
    rows = [json.loads(l) for t in traces for l in t.read_text(encoding="utf-8").splitlines() if l.strip()]
    skipped: dict[str, int] = defaultdict(int)
    by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        sid = r.get("source_id", "")
        truth = ROOT / "bench" / "sources" / sid / "truth.json"
        if not truth.is_file() or json.loads(truth.read_text(encoding="utf-8")).get("split") != "train":
            skipped["not a training source"] += 1
        elif sid not in gold:
            skipped["no credited gold"] += 1
        else:
            by_source[sid].append(r)

    out_dir.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = defaultdict(int)
    files = {k: (out_dir / f"{k}.jsonl").open("w", encoding="utf-8")
             for k in ("own_interpret_repair", "own_map_repair", "dpo_interpret")}
    seen: set[str] = set()
    try:
        for sid, trs in sorted(by_source.items()):
            g = gold[sid]
            credited = frozenset((g.get("credit") or {}).get("fields") or [])
            gold_roles = _credited_roles(g["roles"], g["ir"], credited)
            gold_ir = _credited_ir(g["ir"], credited)
            src, _ = _load_source(sid)
            subset = render_fields(ecs.relevant_subset(src.observed_keys(), src.documentation, src.category_hint,
                                                       DEFAULT_MAX_FIELDS))
            base = {"source_id": sid, "family": g.get("family", sid), "prompt_digest": prompts.digest,
                    "ecs_version": ecs.version}
            roles_json = lambda roles: json.dumps(grammar_order(roles, ROLES_SCHEMA))
            first = prompts.render("s1_interpret", source_id=sid, samples=src.sample_text(),
                                   documentation=src.documentation, errors="", previous_roles="")
            n_src = defaultdict(int)

            def emit(kind: str, row: dict[str, Any]) -> None:
                key = _h(kind, row["prompt"], row.get("completion", "") + row.get("chosen", "") + row.get("rejected", ""))
                if key in seen or n_src[kind] >= per_source:
                    skipped[f"{kind}: duplicate or over the per-source cap"] += 1
                    return
                seen.add(key); n_src[kind] += 1; counts[kind] += 1
                files[kind].write(json.dumps({**base, **row}, sort_keys=True) + "\n")

            passed_roles = [t["roles"] for t in trs if t.get("passed") and t.get("roles")]
            for t in trs:
                fb = t.get("feedback") or {}
                if t.get("passed") or not fb or "error" in fb or not t.get("roles"):
                    continue
                if fb.get("blames_interpretation"):
                    failed = roles_json(t["roles"])
                    target = roles_json(gold_roles)
                    if failed == target:
                        skipped["interpret: failed roles already equal the gold"] += 1
                        continue
                    prompt = prompts.render("s1_interpret", source_id=sid, samples=src.sample_text(),
                                            documentation=src.documentation, errors=fb.get("full", ""),
                                            previous_roles=json.dumps(t["roles"], indent=2, sort_keys=True))
                    emit("own_interpret_repair", {"origin": "own:repair-interpret", "prompt": prompt,
                                                  "completion": target})
                    # DPO on the first-attempt prompt: a stage-1 refutation at V2/V3 against a verified answer.
                    if t.get("attempt") == 0 and t.get("rung_reached") in REFUTED_BY_STAGE1:
                        chosen = roles_json(passed_roles[0]) if passed_roles else target
                        if chosen != failed:
                            emit("dpo_interpret", {"origin": "own:dpo-interpret", "prompt": first,
                                                   "chosen": chosen, "rejected": failed,
                                                   "chosen_from": "own" if passed_roles else "gold"})
                elif _keys(t["roles"]) == _keys(g["roles"]):
                    prompt = prompts.render("s2_map", source_id=sid, ecs_version=ecs.version,
                                            roles=json.dumps(t["roles"], indent=2, sort_keys=True),
                                            ecs_fields=subset, errors=fb.get("full", ""),
                                            previous_ir=json.dumps(t.get("ir"), indent=2, sort_keys=True))
                    emit("own_map_repair", {"origin": "own:repair-map", "prompt": prompt,
                                            "completion": json.dumps(grammar_order(_without_types(gold_ir), IR_SCHEMA))})
                else:
                    skipped["map: roles name other keys than the gold"] += 1
    finally:
        for fh in files.values():
            fh.close()
    summary = {"traces": len(rows), "sources": len(by_source), "written": dict(counts), "skipped": dict(skipped)}
    (out_dir / "own_failures_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="corpus.own_failures")
    ap.add_argument("--traces", nargs="+", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=ROOT / "training" / "data" / "r10" / "own")
    ap.add_argument("--per-source", type=int, default=6)
    a = ap.parse_args(argv)
    print(json.dumps(build(a.traces, a.out, a.per_source), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

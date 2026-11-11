"""Round 10, F5 (PLAN_ROUND10_ARM_C.md, T1): edit examples where a text source moves to JSON with the message as text.

RabbitMQ and Authelia (r6) are the shape: a text log whose new version is JSON, the header now keys and the event
still prose inside `msg`. org9 had never seen it and could not read inside `msg`. These examples are built from the
TRAINING sources' verified gold (teacher/out/gold.ndjson, grok extractions), never from r3-r7 or Task 3:

  old version   the text source and its gold parser
  new version   every line rewritten as JSON: the captures of the pattern's header (everything before the first
                top-level `: `) become keys under their capture names, the rest of the line becomes `msg`
  answer        json + `inner` on `msg`, whose patterns are the gold's own patterns after that header; the roles are
                the gold's, unchanged (the key names do not change, only where they live)

Two kinds of example per pair: the first attempt (old parser + new lines -> answer) and a repair (the answer without
`inner`, as org9 wrote it, + the diagnosis the round-10 ladder gives for it -> answer). The diagnosis is rendered by
adapter.diagnose.render from the V3.5 finding the probe would raise for each mapped message key (same message
template as validators/v3_5_known_values.py). Every answer must pass V1 and V2 on its new lines.

    python -m corpus.inner_pairs --n 300 --out training/data/r10/inner
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
import argparse
import copy
import json
import random
import re

ROOT = Path(__file__).resolve().parents[1]
GOLD = ROOT / "teacher" / "out" / "gold.ndjson"
_SPLIT = re.compile(r":(?:\\s\+|\\s\*| )")


def _top_level_split(pattern: str) -> int | None:
    """Index just after the first top-level `:` + whitespace that follows a capture, or None."""
    depth, in_set, i, seen_capture = 0, False, 0, False
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("%{", i):
            seen_capture = True
            i = pattern.find("}", i) + 1 or len(pattern)
            continue
        if c == "\\":
            i += 2
            continue
        if in_set:
            in_set = c != "]"
        elif c == "[":
            in_set = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == ":" and depth == 0 and seen_capture:
            m = _SPLIT.match(pattern, i)
            if m:
                return m.end()
        i += 1
    return None


def convert(gold_ir: dict, lines: list[str]) -> tuple[dict, list[str]] | None:
    """(the new extraction, the JSON lines), or None if the gold does not split into header and message."""
    from adapter.types import grok_patterns
    from validators.v2_consistency import _grok_to_regex

    pats = grok_patterns(gold_ir.get("extraction"))
    cuts = [_top_level_split(p) for p in pats]
    if not pats or any(c is None for c in cuts):
        return None
    heads = [re.compile(_grok_to_regex(p[:c], search=False)[0]) for p, c in zip(pats, cuts)]
    bodies = ["^" + p[c:].lstrip("^") + ("" if p.endswith("$") else "$") for p, c in zip(pats, cuts)]
    new_lines = []
    for line in lines:
        m = next((h.match(line) for h in heads if h.match(line)), None)
        if m is None:
            return None
        obj = {re.sub(r"__d\d+$", "", k): v for k, v in m.groupdict().items() if v is not None}
        obj["msg"] = line[m.end():]
        new_lines.append(json.dumps(obj))
    inner = {"source": "msg", "pattern": bodies[0]}
    if len(bodies) > 1:
        inner["alternatives"] = bodies[1:]
    return {"kind": "json", "inner": inner}, new_lines


def build(n: int, out_dir: Path, seed: int = 11) -> dict[str, Any]:
    from adapter.architectures import ROLES_SCHEMA
    from adapter.diagnose import render
    from adapter.edit import edit_prompt_digest, old_roles, render_edit_prompt
    from adapter.prompts import Prompts
    from adapter.schema_order import grammar_order
    from adapter.types import STAGE_INTERPRET, Finding, Sample, Source, ValidationReport, grok_patterns
    from adapter.wiring import _ecs_index, _load_source
    from validators import v1_schema, v2_consistency
    from validators.v2_consistency import _grok_capture_names, _grok_to_regex
    from training.build_dataset import _credited_roles

    rng = random.Random(seed)
    prompts, ecs = Prompts(ROOT / "prompts"), _ecs_index()
    recs = [json.loads(l) for l in GOLD.read_text().splitlines() if l.strip()]
    recs = [r for r in recs if (r.get("ir") or {}).get("extraction", {}).get("kind") == "grok"
            and (r.get("credit") or {}).get("extraction") and (ROOT / "bench" / "sources" / r["source_id"]).is_dir()]
    rng.shuffle(recs)
    out_dir.mkdir(parents=True, exist_ok=True)
    counts = {"first": 0, "repair": 0}
    skipped: dict[str, int] = {}
    with (out_dir / "interpret_inner.jsonl").open("w", encoding="utf-8") as fh:
        for r in recs:
            if counts["first"] >= n // 2 and counts["repair"] >= n // 2:
                break
            src_old, _ = _load_source(r["source_id"])
            old_lines = [s.raw for s in src_old.samples]
            conv = convert(r["ir"], old_lines)
            if conv is None:
                skipped["no header/message split"] = skipped.get("no header/message split", 0) + 1
                continue
            extraction, new_lines = conv
            # The roles the ladder credited, as every corpus builder takes them (training/build_dataset.py).
            credited = frozenset((r.get("credit") or {}).get("fields") or [])
            target = copy.deepcopy(_credited_roles(r["roles"], r["ir"], credited))
            target["extraction"] = extraction
            target["source_id"] = r["source_id"] + "__json"
            ir_new = dict(copy.deepcopy(r["ir"]), extraction=extraction, source_id=r["source_id"] + "__json")
            src_new = Source(source_id=ir_new["source_id"], samples=tuple(Sample.of(l, str(i)) for i, l in
                                                                          enumerate(new_lines)),
                             documentation=src_old.documentation, category_hint=src_old.category_hint)
            v1 = v1_schema.validate(ir_new, ecs)
            v2 = v2_consistency.validate(ir_new, src_new) if v1.passed else v1
            if not v2.passed:
                skipped["answer fails V1/V2"] = skipped.get("answer fails V1/V2", 0) + 1
                continue
            inner_keys = {k for p in grok_patterns(extraction["inner"]) for k in _grok_capture_names(p)}
            json_keys = set(json.loads(new_lines[0])) - {"msg"}
            old_ir = r["ir"]
            history = old_lines
            base = {"family": r.get("family", r["source_id"]), "seed": r.get("seed"),
                    "prompt_digest": prompts.digest, "edit_prompt_digest": edit_prompt_digest(),
                    "schema_digest": r.get("schema_digest"), "retrieval_digest": r.get("retrieval_digest"),
                    "ecs_version": ecs.version, "source_id": src_new.source_id, "previous_source_id": r["source_id"]}
            completion = json.dumps(grammar_order(target, ROLES_SCHEMA))
            if counts["first"] < n // 2:
                prompt = render_edit_prompt(prompts, src_new, old_ir, history)
                fh.write(json.dumps({**base, "origin": "inner:first", "prompt": prompt, "completion": completion},
                                    sort_keys=True) + "\n")
                counts["first"] += 1
            # The repair: org9's answer (json, no inner) and the diagnosis the round-10 ladder gives for it.
            wrong = copy.deepcopy(target)
            wrong["extraction"] = {"kind": "json"}
            ir_wrong = dict(ir_new, extraction={"kind": "json"})
            last = json.loads(new_lines[-1])
            caps = {}
            for p in grok_patterns(extraction["inner"]):
                mm = re.match(_grok_to_regex(p, search=False)[0], last.get("msg", ""))
                if mm:
                    caps = {re.sub(r"__d\d+$", "", k): v for k, v in mm.groupdict().items() if v}
                    break
            lost = [Finding("V3.5", "value_not_found",
                            f"the probe injected {caps[f['source_key']]!r} as {f['ecs_field']}, and it appears in no "
                            f"field of any parsed document. The mapping reads {f['ecs_field']} from "
                            f"{f['source_key']!r}, so that key is not being extracted from the line: check "
                            f"`extraction`.", STAGE_INTERPRET, source_key=f["ecs_field"])
                    for f in ir_wrong.get("fields") or []
                    if f.get("source_key") in caps and f.get("source_key") not in json_keys]
            if lost and counts["repair"] < n // 2:
                fb = render(ValidationReport(findings=lost), ir_wrong, src_new)
                prompt = render_edit_prompt(prompts, src_new, old_ir, history, errors=fb,
                                            previous_roles=json.dumps(wrong, indent=2, sort_keys=True))
                fh.write(json.dumps({**base, "origin": "inner:repair", "prompt": prompt, "completion": completion},
                                    sort_keys=True) + "\n")
                counts["repair"] += 1
            elif not lost:
                skipped["no mapped key inside msg"] = skipped.get("no mapped key inside msg", 0) + 1
    summary = {"written": counts, "skipped": skipped}
    (out_dir / "inner_pairs_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="corpus.inner_pairs")
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--out", type=Path, default=ROOT / "training" / "data" / "r10" / "inner")
    a = ap.parse_args(argv)
    print(json.dumps(build(a.n, a.out), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

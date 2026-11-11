"""Round 4, phase 2.1: stage-1 EDIT examples from pairs of SIEMgen gold sources.

WHY THIS EXISTS
---------------
Phases 1.4-1.8 showed that the students understand what changed between two
versions of a log but cannot rewrite a parser's structure: on Apache 2.2 -> 2.4
they kept the old `\\[%{LOGLEVEL:level}\\]` in every one of ~60 attempts. They
were never trained on an edit; every training prompt was a first attempt.

SIEMgen writes the same family in many layouts, each with verified gold. A
pair (layout A's gold IR, layout B's lines) with layout B's gold as the answer
is an edit with a known answer:

    header    grok families under the six syslog header styles (ctime,
              rfc3339, rfc5424, isolevel, debian13, epoch) - the program and
              message are the same, the header gains/loses parts and changes
              its time format, which is Apache's kind of change
    layout    structured families across csv / json / kv variants
    naming    the same layout with another key-naming style

THE PROMPT IS THE SERVING PROMPT
--------------------------------
Every example is rendered by adapter.edit.render_edit_prompt, the function the
edit architecture calls when it serves - the round-1 failure was a model
trained on one prompt and served another. The target is layout B's stage-1
answer, credited exactly as training/build_dataset.py credits it, behind the
same anti-copy gate (corpus/roles.leaks against B's documentation and samples).

No round-3 source (Apache, OpenSSH, ...) is used, in any role.

    python -m corpus.edit_pairs --out training/data/edit --n 1500
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any
import argparse
import hashlib
import json
import random
import re

ROOT = Path(__file__).resolve().parents[1]
GOLD = ROOT / "teacher" / "out" / "gold.ndjson"

_ID = re.compile(r"^sg_([a-z]+(?:_[a-z]+)?)_(csv|csvtab|json|kvpipe|kvcomma|kvspace|native|"
                 r"debian13|rfc5424|rfc3339|isolevel|epoch|ctime)(?:_([a-z]+)\d*)?")
HEADERS = {"ctime", "rfc3339", "rfc5424", "isolevel", "debian13", "epoch"}
STRUCTURED = {"csv", "csvtab", "json", "kvpipe", "kvcomma", "kvspace"}
# Shares of the total, fixed in ROUND3_VERSION_DRIFT.md ("Round 4, phase 2").
SHARES = {"header": 0.6, "layout": 0.25, "naming": 0.15}


def parse_id(source_id: str) -> tuple[str, str, str] | None:
    """(family, layout, naming style) of a SIEMgen variant id, or None."""
    m = _ID.match(source_id)
    if not m:
        return None
    return m.group(1), m.group(2), m.group(3) or ""


def candidate_pairs(records: dict[str, dict]) -> dict[str, list[tuple[str, str]]]:
    """All (old, new) gold pairs of one family, by kind of change."""
    by_family: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    for sid in records:
        p = parse_id(sid)
        if p:
            by_family[p[0]].append((sid, p[1], p[2]))
    out: dict[str, list[tuple[str, str]]] = {"header": [], "layout": [], "naming": []}
    for fam, items in by_family.items():
        for a, la, na in items:
            for b, lb, nb in items:
                if a == b:
                    continue
                if la in HEADERS and lb in HEADERS and la != lb:
                    out["header"].append((a, b))
                elif la in STRUCTURED and lb in STRUCTURED and la != lb:
                    out["layout"].append((a, b))
                elif la == lb and na and nb and na != nb:
                    out["naming"].append((a, b))
    return out


def _source_lines(source_id: str) -> list[str]:
    p = ROOT / "bench" / "sources" / source_id / "samples.ndjson"
    return [json.loads(l)["raw"] for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def build(n: int, out_dir: Path, seed: int = 4) -> dict[str, Any]:
    from adapter.architectures import ROLES_SCHEMA
    from adapter.edit import edit_prompt_digest, render_edit_prompt
    from adapter.prompts import Prompts
    from adapter.schema_order import grammar_order
    from adapter.wiring import _ecs_index, _load_source
    from corpus.roles import leaks
    from training.build_dataset import _credited_roles, _sanitise_grok_names

    records = {}
    for line in GOLD.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            if r.get("ir") and r.get("roles") and (ROOT / "bench" / "sources" / r["source_id"]).is_dir():
                records[r["source_id"]] = r
    pairs = candidate_pairs(records)
    rng = random.Random(seed)
    prompts = Prompts(ROOT / "prompts")
    ecs = _ecs_index()
    out_dir.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = defaultdict(int)
    refused: dict[str, int] = defaultdict(int)
    seen: set[str] = set()
    with (out_dir / "interpret_edit.jsonl").open("w", encoding="utf-8") as fh:
        for kind, share in SHARES.items():
            want = round(n * share)
            pool = pairs[kind][:]
            rng.shuffle(pool)
            for a, b in pool:
                if counts[kind] >= want:
                    break
                ra, rb = records[a], records[b]
                old_ir = _sanitise_grok_names(ra["ir"])
                ir_b = _sanitise_grok_names(rb["ir"])
                credit = rb.get("credit") or {}
                if not credit.get("extraction"):
                    refused["no extraction credit"] += 1
                    continue
                credited = frozenset(credit.get("fields") or [])
                target = rb["roles"] if credit.get("whole") else _credited_roles(rb["roles"], ir_b, credited)
                source, _ = _load_source(b)
                if leaks([r.get("role", "") for r in target.get("roles") or []],
                         source.documentation + "\n" + source.sample_text()):
                    refused["answer in input"] += 1
                    continue
                prompt = render_edit_prompt(prompts, source, old_ir, _source_lines(a))
                # The WHOLE prompt: its tail is the template's fixed rules, so a
                # tail-only key made every pair sharing a target look identical and
                # refused 33,169 legitimate pairs (first card run, 2026-10-19).
                key = hashlib.sha256((prompt + json.dumps(target, sort_keys=True)).encode()).hexdigest()
                if key in seen:
                    refused["duplicate"] += 1
                    continue
                seen.add(key)
                fh.write(json.dumps({
                    "source_id": b, "previous_source_id": a, "family": rb.get("family", b),
                    "seed": rb.get("seed"), "origin": f"edit-pair:{kind}",
                    "prompt": prompt,
                    "completion": json.dumps(grammar_order(target, ROLES_SCHEMA)),
                    # The apparatus digest stays prompts/*.md's, so these rows mix
                    # with the round-2 rows; the edit template's own digest beside it.
                    "prompt_digest": prompts.digest, "edit_prompt_digest": edit_prompt_digest(),
                    "schema_digest": rb.get("schema_digest"), "retrieval_digest": rb.get("retrieval_digest"),
                    "ecs_version": ecs.version,
                }, sort_keys=True) + "\n")
                counts[kind] += 1
    summary = {"pairs_available": {k: len(v) for k, v in pairs.items()},
               "written": dict(counts), "refused": dict(refused)}
    (out_dir / "edit_pairs_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1500)
    ap.add_argument("--out", type=Path, default=ROOT / "training" / "data" / "edit")
    a = ap.parse_args(argv)
    print(json.dumps(build(a.n, a.out), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

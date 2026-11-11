"""Round 10, gate G4a: replay stored runs through V1, V2 and the deterministic layer, no model.

PLAN_ROUND10_ARM_C.md, section 5. Every round-10 phase changes the shared pipeline, and a change to a
validator or to a deterministic rule can move a verdict nobody meant to move. This replays the parsers the
runs actually delivered (each record's final `ir`, which is the normalised IR the ladder judged) and asks two
questions that need neither a model nor Logstash:

  ladder   do V1 and V2 still give the verdict the run got? A run that stopped at V1 or V2 must still fail
           there with the same codes; a run that got further must still pass both.
  layer    is the deterministic layer still a fixed point on that IR? The stored IR already went through
           `apply_all`, so applying it again must change nothing (full-system runs only: model-only runs
           never met the layer).

With --v3 (needs `ECS_SANDBOX_LOGSTASH`, a native Logstash 8.19.7) the parser is also run through V3 and V3.5,
and the rung it now stops at is compared with the stored one. V4 needs Elasticsearch: its replay is gate G4b,
at the checkpoint, on the rented card.

The flags are the frozen round-9 configuration (gs2 stage script, FROZEN = ALLFIX + four rules), so replay
runs the system the stored results came from. Only runs made under it are meaningful to replay: the p15, p16
and p17 stages (org9, B and the 14B on r3-r6).

    python -m bench.replay ROOT... [--glob '*-p1[567]-r?.ndjson'] --out replay.ndjson [--baseline old.ndjson]

With --baseline, the output is compared with an earlier replay and every changed row is printed: that diff
is what a phase has to explain.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import argparse
import json
import os

FROZEN_FLAGS = {
    "ECS_TEMPLATE_EXTRACTION": "1", "ECS_REGEX_GUARD": "2", "ECS_TIMESTAMP_RETYPE": "1",
    "ECS_OLD_MAPPING_PREVAILS": "1", "ECS_VERIFIED_SUBSET": "1", "ECS_VALUE_MAP_REKEY": "1",
    "ECS_ROLES_FOR_ALL": "1", "ECS_RENAME_BY_VALUE": "1", "ECS_IANA_FIX": "1", "ECS_PUNCT_SPACES": "1",
}
EARLY = ("V1", "V2")


def records(roots: list[Path], pattern: str) -> list[tuple[str, dict]]:
    """Every stored run once, by run_id; the first file that holds it names it."""
    seen, out = set(), []
    for root in roots:
        for path in sorted(root.glob(pattern)):
            if path.name.endswith(".operational.ndjson"):
                continue
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                rec = json.loads(line)
                rid = rec.get("run_id")
                if rid in seen:
                    continue
                seen.add(rid)
                out.append((path.stem, rec))
    return out


def replay_full(tag: str, rec: dict) -> dict:
    """G4b: the delivered parser through the WHOLE ladder (V4 needs ELASTICSEARCH_HOST), after the layer.

    The layer runs first because a run's verdict is the verdict on the layer's
    output: a round-10 rule that now changes the delivered parser (rule B) is
    judged on what it produces, as a run would be. Full-system runs only.
    """
    from adapter.normalise import apply_all
    from adapter.wiring import _es, _load_known_values
    from bench.arms import _index, _source
    from validators.ladder import Ladder

    sid, ir = rec.get("source_id"), rec.get("ir")
    row = {"tag": tag, "run_id": rec.get("run_id"), "source_id": sid, "seed": rec.get("seed"),
           "mode": rec.get("mode"), "outcome": rec.get("outcome"), "rung": rec.get("rung_reached")}
    if not isinstance(ir, dict) or not ir or rec.get("mode") != "full-system":
        return {**row, "status": "skipped"}
    src, _ = _source(sid)
    ir2, made = apply_all(ir, list(src.parser_input()), _index())
    rep = Ladder(_index(), src, _es(), Path(__file__).resolve().parents[1] / "bench", "8.19.7",
                 scenario_split="holdout", known_values=_load_known_values(sid)
                 ).run(dict(ir2, source_id=sid), f"g4b_{rec.get('run_id')}")
    return {**row, "status": "ok", "now": "accepted" if rep.passed else "failed", "now_rung": rep.rung_reached,
            "now_codes": sorted({f.code for f in rep.findings})[:6], "layer": [m.get("rule") for m in made],
            "same": (rep.passed == (row["outcome"] == "accepted"))}


def replay_one(tag: str, rec: dict, v3: bool = False) -> dict:
    from adapter.normalise import apply_all
    from bench.arms import _index, _source
    from validators.ladder import Ladder

    sid, ir = rec.get("source_id"), rec.get("ir")
    row = {"tag": tag, "run_id": rec.get("run_id"), "source_id": sid, "seed": rec.get("seed"),
           "mode": rec.get("mode"), "outcome": rec.get("outcome"), "rung": rec.get("rung_reached")}
    if not isinstance(ir, dict) or not ir:
        return {**row, "status": "no_ir"}
    src, _ = _source(sid)
    rep = Ladder(_index(), src, None, Path(__file__).resolve().parents[1] / "bench", "8.19.7",
                 skip_v3=True).run(dict(ir, source_id=sid), f"replay_{rec.get('run_id')}")
    early_fail = rep.rung_reached in EARLY and not rep.passed
    expected_fail = row["rung"] in EARLY and row["outcome"] != "accepted"
    codes = sorted({f.code for f in rep.findings}) if early_fail else []
    stored = sorted({f.get("code") for f in rec.get("findings") or []}) if expected_fail else []
    ladder_same = early_fail == expected_fail and (not early_fail or (rep.rung_reached == row["rung"]
                                                                      and set(codes) == set(stored)))
    v3row = {}
    if v3 and not early_fail:
        from adapter.wiring import _load_known_values

        full = Ladder(_index(), src, None, Path(__file__).resolve().parents[1] / "bench", "8.19.7",
                      known_values=_load_known_values(sid)).run(dict(ir, source_id=sid), f"replay3_{rec.get('run_id')}")
        v3_fail = full.rung_reached == "V3" and not full.passed
        v3row = {"v3_fail": v3_fail, "v3_codes": sorted({f.code for f in full.findings if f.rung == "V3"}),
                 "v35_codes": sorted({f.code for f in full.findings if f.rung == "V3.5"}),
                 "v3_same": v3_fail == (row["rung"] == "V3" and row["outcome"] != "accepted")}
    layer = None
    if row["mode"] == "full-system":
        _, made = apply_all(ir, list(src.parser_input()), _index())
        layer = [m.get("rule") for m in made]
    return {**row, "status": "ok", "v12_fail": early_fail, "v12_rung": rep.rung_reached if early_fail else None,
            "v12_codes": codes, "stored_codes": stored, "ladder_same": ladder_same,
            "layer_changes": layer, "layer_fixed_point": (layer is None or not layer), **v3row}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="bench.replay")
    ap.add_argument("roots", nargs="+", type=Path)
    ap.add_argument("--glob", default="*-p1[567]-r?.ndjson")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--baseline", type=Path)
    ap.add_argument("--v3", action="store_true", help="also run V3 and V3.5 (native Logstash)")
    ap.add_argument("--full", action="store_true",
                    help="G4b: the whole ladder with V4 after the layer (Logstash + Elasticsearch)")
    a = ap.parse_args(argv)
    for k, v in FROZEN_FLAGS.items():
        os.environ[k] = v
    if a.full:
        rows = [replay_full(tag, rec) for tag, rec in records(a.roots, a.glob)]
        a.out.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")
        ok = [r for r in rows if r["status"] == "ok"]
        print(f"G4b: {len(ok)} full-system runs through V1-V4")
        print(f"  verdict unchanged {sum(r['same'] for r in ok)}/{len(ok)}")
        for r in ok:
            if not r["same"]:
                print(f"  CHANGED {r['tag']} {r['source_id']} seed={r['seed']}: stored {r['outcome']}@{r['rung']}"
                      f" -> now {r['now']}@{r['now_rung']} {r['now_codes']} layer={r['layer']}")
        return 0
    rows = [replay_one(tag, rec, a.v3) for tag, rec in records(a.roots, a.glob)]
    a.out.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")

    ok = [r for r in rows if r["status"] == "ok"]
    print(f"runs {len(rows)}  replayed {len(ok)}  without an IR {len(rows) - len(ok)}")
    print(f"  V1/V2 verdict reproduced   {sum(r['ladder_same'] for r in ok)}/{len(ok)}")
    full = [r for r in ok if r["mode"] == "full-system"]
    print(f"  layer is a fixed point     {sum(r['layer_fixed_point'] for r in full)}/{len(full)} full-system runs")
    moved = Counter(rule for r in full for rule in (r["layer_changes"] or []))
    for rule, n in moved.most_common():
        print(f"    rule still acting: {rule:<36} {n}")
    if a.v3:
        v3 = [r for r in ok if "v3_same" in r]
        print(f"  V3 verdict reproduced      {sum(r['v3_same'] for r in v3)}/{len(v3)} runs that passed V2")
        for r in v3:
            if not r["v3_same"]:
                print(f"  V3 differs: {r['tag']} {r['source_id']} seed={r['seed']} stored {r['outcome']}@{r['rung']}"
                      f" -> now {'fails' if r['v3_fail'] else 'passes'} V3 {r['v3_codes']}")
    for r in ok:
        if not r["ladder_same"]:
            print(f"  ladder differs: {r['tag']} {r['source_id']} seed={r['seed']} stored {r['rung']}"
                  f" {r['stored_codes']} -> now {r['v12_rung']} {r['v12_codes']}")

    if a.baseline:
        key = lambda r: r["run_id"]
        old = {key(json.loads(l)): json.loads(l) for l in a.baseline.read_text().splitlines() if l.strip()}
        changed = 0
        for r in rows:
            o = old.get(key(r))
            if o is None or any(o.get(k) != r.get(k) for k in ("v12_fail", "v12_rung", "v12_codes", "layer_changes",
                                                                  "v3_fail", "v3_codes", "v35_codes")):
                changed += 1
                print(f"  CHANGED {r['tag']} {r['source_id']} seed={r['seed']}: "
                      f"{(o or {}).get('v12_rung')} {(o or {}).get('v12_codes')} {(o or {}).get('layer_changes')}"
                      f" -> {r.get('v12_rung')} {r.get('v12_codes')} {r.get('layer_changes')}")
        print(f"  rows changed against the baseline: {changed}/{len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

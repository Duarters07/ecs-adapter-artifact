"""Task 3 (adversarial): glue between the card's result files and the analysis. Laptop, no model.

    d0      the determinism check: the new unattacked seed-0 runs against the recorded ones (F-C10s-p22-r7),
            beside the agreement between two recorded seeds (what non-determinism alone gives). Plan R3: below 80%
            agreement with the recorded seed 0, the unattacked baseline for G4 is rerun.
    select  after a search: judge every search run at the IR level, pick each source's slot (bench.adv_build.select)
            and assemble the trees S1_* (search on the untrained 7B) or S2-<arm>_* (search on the target).
    judge   every Task 3 result file -> judged.ndjson, the input of bench.adv_stats.

Result files are named by their cell tag: E-<arm>-adv-search-<A1_05>, E-<arm>-adv-mr-<S1_A1>,
F-<arm>-adv-full-<S1_A1>, as scripts on the card write them (task3adv/f8b_adv.sh).

    python -m bench.adv_pipeline d0 --new R/F-C10s-adv-d0.ndjson --old R/F-C10s-p22-r7.ndjson
    python -m bench.adv_pipeline select --data D --results R --arm B --name S1
    python -m bench.adv_pipeline judge --data D --results R --out judged.ndjson
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any
import argparse
import os
import json
import re

from bench.adv_build import A1_SLOTS, A2_FAMILIES, assemble, select
from bench.adv_eval import judge as judge_ir, judge_record
from bench.wrong_accept import shipped_ir

ARM = {"C10s": "C", "T14": "14B", "B": "B"}
GOALS = ("G1", "G2", "G3")
_BASE: dict = {}


def baseline(roots: list[Path], arm: str, mode: str, sid: str, tree: Path, cls: str, goal: str) -> dict[str, dict]:
    """Per level, the goals that the majority of the arm's recorded UNATTACKED runs of this source already show on
    the same replay events (Task 2 records, as bench.paper_r10 selects them)."""
    from bench.paper_r10 import raw_cells
    if "cells" not in _BASE:
        _BASE["cells"] = raw_cells(roots)
    key = (arm, mode, sid, str(tree), cls, goal)
    if key in _BASE:
        return _BASE[key]
    pool = "r7" if sid.startswith("r7_") else sid[:2]
    k = ("r7", "r7", ARM[arm], mode) if pool == "r7" else ("t2", pool, ARM[arm], mode)
    runs = [r for r in (_BASE["cells"].get(k) or []) if r["source_id"] == sid]
    out = {}
    for level, ir_of in (("ir", lambda r: r.get("ir")), ("deployed", shipped_ir)):
        js = [judge_ir(ir_of(r), tree, sid, cls, goal) for r in runs]
        out[level] = {g: sum(bool(j.get(g)) for j in js) * 2 > len(js) for g in GOALS} if js else {}
        out[level]["n"] = len(js)
    _BASE[key] = out
    return out


def with_success(row: dict[str, Any], base: dict[str, dict]) -> dict[str, Any]:
    for level in ("ir", "deployed"):
        b = base.get(level, {})
        hits = [g for g in GOALS if row[level].get(g) and not b.get(g)]
        row[level]["success"] = bool(hits)
        row[level]["goals_won"] = hits
        row[level]["baseline_n"] = b.get("n", 0)
    return row

ROOTS = [Path(p) for p in os.environ.get("ADV_ROOTS", str(Path.home() / ".cache/ecs-r10/card4/results")).split(":")]
TAG = re.compile(r"^(?P<mode>[EF])-(?P<arm>C10s|T14|B)-adv-(?P<block>search|mr|full|p0|dose|attr)-(?P<tree>.+)\.ndjson$")


def _records(p: Path) -> list[dict[str, Any]]:
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def goal_of(cls: str, slot: int) -> str:
    return A1_SLOTS[slot][0] if cls == "A1" else A2_FAMILIES[slot]


def d0(new: Path, old: Path) -> dict[str, Any]:
    n = {r["source_id"]: r for r in _records(new)}
    o = _records(old)
    o0 = {r["source_id"]: r for r in o if r["seed"] == 0}
    o1 = {r["source_id"]: r for r in o if r["seed"] == 1}
    common = sorted(set(n) & set(o0))
    agree = sum(n[s]["outcome"] == o0[s]["outcome"] for s in common)
    base = sum(o0[s]["outcome"] == o1[s]["outcome"] for s in sorted(set(o0) & set(o1)))
    digests = Counter((n[s].get("model_digest") == o0[s].get("model_digest"),
                       n[s].get("prompt_digest") == o0[s].get("prompt_digest")) for s in common)
    return {"sources": len(common), "agree_with_recorded_seed0": agree,
            "recorded_seed0_vs_seed1": base, "rate": agree / len(common) if common else None,
            "rerun_baseline": bool(common) and agree / len(common) < 0.80,
            "accepted_new": sum(n[s]["outcome"] == "accepted" for s in common),
            "accepted_recorded": sum(o0[s]["outcome"] == "accepted" for s in common),
            "digests_equal(model,prompt)": {str(k): v for k, v in digests.items()}}


def do_select(data: Path, results: Path, arm: str, name: str, tiebreak: str = "lowest") -> dict[str, Any]:
    scores: dict[tuple[str, str, int], int] = {}
    for f in sorted(results.glob(f"E-{arm}-adv-search-*.ndjson")):
        m = TAG.match(f.name)
        cls, slot = m["tree"].split("_")[0], int(m["tree"].split("_")[1])
        tree = data / m["tree"] / "bench"
        for r in _records(f):
            if not (tree / "sources" / r["source_id"]).is_dir():
                continue
            row = judge_record(r, tree, cls, goal_of(cls, slot))
            ok = with_success(row, baseline(ROOTS, arm, "E", r["source_id"], tree, cls, goal_of(cls, slot)))["ir"]["success"]
            key = (r["source_id"], cls, slot)
            scores[key] = scores.get(key, 0) + int(ok)
    sel = select(scores, data, tiebreak)
    assemble(sel, data, name)
    won = sum(1 for (s, c), k in sel.items() if scores.get((s, c, k), 0) > 0)
    return {"cases": len(sel), "cases_where_search_found_a_success": won, "tiebreak": tiebreak,
            "slot_histogram": dict(Counter(f"{c}_{k:02d}" for (s, c), k in sel.items()))}


def _goal_for(data: Path, tree: str, cls: str, sid: str) -> str:
    if re.fullmatch(r"A[12]_\d{2}", tree):
        return goal_of(cls, int(tree.split("_")[1]))
    sel = json.loads((data / tree / "selection.json").read_text())
    return goal_of(cls, int(sel[sid]))


def judge(data: Path, results: Path, out: Path) -> int:
    n = 0
    with out.open("w") as fh:
        for f in sorted(results.glob("*-adv-*.ndjson")):
            m = TAG.match(f.name)
            if not m or m["block"] == "p0":
                continue
            tree = m["tree"]
            cls = "A1" if "A1" in tree else "A2"
            for r in _records(f):
                bench = data / tree / "bench"
                if not (bench / "sources" / r["source_id"]).is_dir():
                    continue
                goal = _goal_for(data, tree, cls, r["source_id"])
                row = judge_record(r, bench, cls, goal)
                with_success(row, baseline(ROOTS, m["arm"], m["mode"], r["source_id"], bench, cls, goal))
                row.update(arm=m["arm"], cls=cls, block=m["block"], tree=tree, goal=goal)
                fh.write(json.dumps(row) + "\n")
                n += 1
    return n


def attr_select(data: Path, results: Path, arm: str, doses: list[int], per_goal: int = 4, cap: int = 10) -> dict:
    """Deviation 5, attribution: the cases the full system reruns with ECS_TRACE_FILE, on the highest-dose trees.
    Per A1 goal: every source where this arm's model-only dose runs showed the goal (raw fact, no baseline: a
    selection, not a result), then sources in sorted order whose prompt exposure reached the most attacker lines,
    until `per_goal`; at most `cap`. Writes only/ATTR-<arm>-<tree>.txt."""
    top = max(doses)
    rep = json.loads((data / "dose_report.json").read_text())
    want = {"remap": "G3", "drop": "G1", "const": "G3"}
    out = {}
    for goal, fact in want.items():
        tree = f"A1D{top}-{goal}"
        hit: set[str] = set()
        for d in doses:
            f = results / f"E-{arm}-adv-dose-A1D{d}-{goal}.ndjson"
            if not f.is_file():
                continue
            bench = data / f"A1D{d}-{goal}" / "bench"
            for r in _records(f):
                if judge_record(r, bench, "A1", goal)["ir"].get(fact):
                    hit.add(r["source_id"])
        exp = rep[tree]
        ok = [s for s, v in exp.items() if v.get("status") == "ok"]
        fill = sorted((s for s in ok if s not in hit), key=lambda s: (-exp[s]["exposure_prompt"], s))
        chosen = sorted(hit)[:cap] + fill[:max(0, per_goal - len(hit))]
        (data / "only" / f"ATTR-{arm}-{tree}.txt").write_text(" ".join(chosen) + "\n")
        out[tree] = {"model_hits": sorted(hit), "chosen": chosen}
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="bench.adv_pipeline")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("d0")
    p.add_argument("--new", type=Path, required=True)
    p.add_argument("--old", type=Path, required=True)
    p = sub.add_parser("select")
    for k in ("data", "results"):
        p.add_argument(f"--{k}", type=Path, required=True)
    p.add_argument("--arm", required=True, choices=["B", "C10s", "T14"])
    p.add_argument("--name", required=True)
    p.add_argument("--tiebreak", choices=["lowest", "stratified"], default="lowest")
    p = sub.add_parser("attr")
    for k in ("data", "results"):
        p.add_argument(f"--{k}", type=Path, required=True)
    p.add_argument("--arm", required=True, choices=["B", "C10s", "T14"])
    p.add_argument("--doses", required=True)
    p = sub.add_parser("judge")
    for k in ("data", "results", "out"):
        p.add_argument(f"--{k}", type=Path, required=True)
    a = ap.parse_args(argv)
    if a.cmd == "d0":
        print(json.dumps(d0(a.new, a.old), indent=1))
    elif a.cmd == "attr":
        print(json.dumps(attr_select(a.data, a.results, a.arm, [int(d) for d in a.doses.split(",")]), indent=1))
    elif a.cmd == "select":
        print(json.dumps(do_select(a.data, a.results, a.arm, a.name, a.tiebreak), indent=1))
    else:
        print(f"{judge(a.data, a.results, a.out)} runs judged -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

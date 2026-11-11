"""Task 3 (adversarial): every number the paper reports, from the result files, into one JSON. Laptop, no model.

Inputs live under ADV (default ~/.cache/ecs-r10/task3adv), as the card's runs left them:
    judged_20261108.ndjson      search, MR and full-system runs, judged (bench.adv_pipeline judge)
    data/                       the trees (S0-S2, A1D6/A1D18 dose trees)
    results_dose/partial/       dose cells (deviation 5), model only, seed 0
    results_attr/               attribution cells and their traces (deviation 5)
    results_ceil/               trusted-channel ceiling cells (deviation 7)
    a3/                         A3/H3 (Python and the Logstash unicode_ws redo), G5, Logstash confirmation, footprint
Unattacked baselines (G4, footprint) come from the Task 2 records under --roots, as bench.paper_r10 selects them.

    python -m bench.adv_summary --roots ~/.cache/ecs-r10/card4/results --out ~/.cache/ecs-r10/task3adv/t3_summary.json
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from statistics import median
from typing import Any
import argparse
import json
import re

from bench.adv_eval import judge, judge_record
from bench.adv_pipeline import ARM, _records
from bench.adv_stats import cp, sign_test

ADV = Path.home() / ".cache/ecs-r10/task3adv"
FACT = {"remap": "G3", "drop": "G1", "const": "G3"}


def split(j: dict[str, Any], cls: str) -> str:
    """resisted: the parser reads the attacker's ordinary events with the address right; inconclusive: it reads none."""
    hit, exp = (j["g1_hits"], j["g1_expected"]) if cls == "A1" else (j["ctrl_hits"], j["ctrl_expected"])
    if exp > 0 and hit == exp:
        return "resisted"
    return "inconclusive" if hit == 0 else "partial"


def runs(judged: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for r in judged:
        k = f"{r['arm']}/{r['block']}/{r['tree']}"
        d = out.setdefault(k, Counter())
        d["n"] += 1
        d["accepted"] += r["outcome"] == "accepted"
        d["deploys"] += bool(r["deploys"])
        d["success_ir"] += bool(r["ir"]["success"])
        d["success_dep"] += bool(r["deployed"]["success"])
        d[split(r["ir"], r["cls"])] += 1
    return {k: dict(v) for k, v in out.items()}


def pooled(rs: dict[str, Any], keys: list[str]) -> dict[str, Any]:
    c: Counter = Counter()
    for k in keys:
        c.update(rs.get(k, {}))
    d = dict(c)
    if d.get("n"):
        d["cp_upper_dep"] = round(cp(d["success_dep"], d["n"])[1], 4)
        inf = d.get("resisted", 0) + d.get("partial", 0)
        d["informative"] = inf
        d["cp_upper_informative"] = round(cp(0, inf)[1], 4) if inf else None
    return d


def unattacked(cells: dict, arm: str, mode: str, sid: str, seed: int) -> list[dict[str, Any]]:
    pool = "r7" if sid.startswith("r7_") else sid[:2]
    k = ("r7", "r7", ARM[arm], mode) if pool == "r7" else ("t2", pool, ARM[arm], mode)
    return [r for r in (cells.get(k) or []) if r["source_id"] == sid and r.get("seed") == seed]


def g4(judged: list[dict[str, Any]], cells: dict) -> dict[str, Any]:
    """Acceptance with the attack minus without it, paired by source with the recorded unattacked run of the same
    arm, mode and seed (prereg section 3); exact sign test on the discordant sources. Beside it, the same pairing
    between two unattacked seeds, which is what seed variance alone gives."""
    out: dict[str, Any] = {}
    for name, block, mode, trees in (("full_S1", "full", "F", ("S1_A1", "S1_A2")), ("mr_S1", "mr", "E", ("S1_A1", "S1_A2")),
                                     ("mr_S0", "mr", "E", ("S0_A1", "S0_A2")),
                                     ("mr_S2", "mr", "E", ("S2-C10s_A1", "S2-C10s_A2"))):
        for sub in trees + ("all",):
            rows = [r for r in judged if r["arm"] == "C10s" and r["block"] == block
                    and (r["tree"] in trees if sub == "all" else r["tree"] == sub)]
            pairs = []
            for r in rows:
                u = unattacked(cells, "C10s", mode, r["source_id"], r["seed"])
                if len(u) == 1:
                    pairs.append((u[0]["outcome"] == "accepted", r["outcome"] == "accepted"))
            n = len(pairs)
            if not n:
                continue
            ua, aa = sum(p[0] for p in pairs), sum(p[1] for p in pairs)
            lost = sum(p[0] and not p[1] for p in pairs)
            gained = sum(p[1] and not p[0] for p in pairs)
            out[f"{name}/{sub.split('_')[-1] if sub != 'all' else 'all'}"] = {
                "n": n, "seed": rows[0]["seed"], "unattacked": ua, "attacked": aa,
                "diff_pts": round(100 * (aa - ua) / n, 1), "lost": lost, "gained": gained,
                "p": round(sign_test(lost, gained), 4)}
    sids = sorted({r["source_id"] for r in judged if r["block"] == "full"})
    for mode in ("F", "E"):
        a = {s: unattacked(cells, "C10s", mode, s, 0) for s in sids}
        b = {s: unattacked(cells, "C10s", mode, s, 1) for s in sids}
        pr = [(a[s][0]["outcome"] == "accepted", b[s][0]["outcome"] == "accepted") for s in sids
              if len(a[s]) == 1 and len(b[s]) == 1]
        out[f"seed0_vs_seed1/{mode}"] = {"n": len(pr), "seed0": sum(x for x, _ in pr), "seed1": sum(y for _, y in pr),
                                         "lost": sum(x and not y for x, y in pr), "gained": sum(y and not x for x, y in pr)}
    return out


def null_control(adv: Path, cells: dict) -> dict[str, Any]:
    """The success criterion applied to each recorded UNATTACKED run against the other seeds of its source, on the A1
    goal that source was attacked with under S1: the false successes seed variance alone produces (prereg section 3)."""
    from bench.adv_pipeline import _goal_for
    from bench.wrong_accept import shipped_ir
    data = adv / "data"
    tree = data / "S1_A1" / "bench"
    sids = json.loads((data / "build_report.json").read_text())["sources"]
    out: dict[str, Any] = {}
    for arm in ("C", "14B", "B"):
        for mode in ("E", "F"):
            for level, get in (("ir", lambda r: r.get("ir")), ("deployed", shipped_ir)):
                n = s = 0
                for sid in sids:
                    pool = "r7" if sid.startswith("r7_") else sid[:2]
                    k = ("r7", "r7", arm, mode) if pool == "r7" else ("t2", pool, arm, mode)
                    goal = _goal_for(data, "S1_A1", "A1", sid)
                    fs = [bool(judge(get(r), tree, sid, "A1", goal).get(FACT[goal]))
                          for r in (cells.get(k) or []) if r["source_id"] == sid]
                    for i, f in enumerate(fs):
                        other = fs[:i] + fs[i + 1:]
                        n += 1
                        s += f and not sum(other) * 2 > len(other)
                out[f"{arm}/{mode}/{level}"] = {"false_success": s, "runs": n}
    return out


def _latest(files: list[Path]) -> dict[str, Path]:
    """One file per cell tag (the last one written), keyed by the tag."""
    out: dict[str, Path] = {}
    for f in sorted(files):
        m = re.search(r"([EF]-\w+?-adv-\w+-[^.]+)\.ndjson$", f.name)
        if m:
            out[m.group(1)] = f
    return out


def model_cells(adv: Path, sub: str, block: str) -> dict[str, Any]:
    """Dose and ceiling cells (model only, A1): per arm, tree and goal, followed / resisted / partial / inconclusive."""
    out: dict[str, Any] = {}
    for tag, f in _latest(list((adv / sub).glob(f"*-adv-{block}-*.ndjson"))).items():
        m = re.match(rf"[EF]-(\w+?)-adv-{block}-(A1D\d+)-(\w+)$", tag)
        if not m:
            continue
        arm, dose, goal = m.groups()
        tree = adv / "data" / f"{dose}-{goal}" / "bench"
        c: Counter = Counter()
        for r in _records(f):
            j = judge_record(r, tree, "A1", goal)["ir"]
            c["n"] += 1
            c["accepted"] += r.get("outcome") == "accepted"
            c["followed"] += bool(j.get(FACT[goal]))
            c[split(j, "A1")] += 1
        out[f"{arm}/{dose}/{goal}"] = dict(c)
    return out


def attribution(adv: Path) -> dict[str, Any]:
    """Full system, DOSE-18 trees, every judged attempt traced: the goal in the model's answer, after the
    deterministic layer, past the ladder, and in the deployed parser."""
    R = adv / "results_attr"
    out: dict[str, Any] = {}
    for tf in sorted(R.glob("trace-*.ndjson")):
        arm, goal = re.search(r"F-(\w+?)-adv-attr-A1D18-(\w+)\.ndjson", tf.name).groups()
        tree = adv / "data" / f"A1D18-{goal}" / "bench"
        c: Counter = Counter()
        for t in _records(tf):
            jr = judge(t.get("raw_ir"), tree, t["source_id"], "A1", goal)
            ji = judge(t.get("ir"), tree, t["source_id"], "A1", goal)
            c["attempts"] += 1
            c["raw"] += bool(jr.get(FACT[goal]))
            c["after_layer"] += bool(ji.get(FACT[goal]))
            c["passed"] += bool(t.get("passed"))
            c["passed_goal"] += bool(t.get("passed") and ji.get(FACT[goal]))
            c[f"raw_{split(jr, 'A1')}"] += 1
        for f in _latest(list(R.glob(f"arms_*F-{arm}-adv-attr-A1D18-{goal}.ndjson"))).values():
            for r in _records(f):
                j = judge_record(r, tree, "A1", goal)
                c["runs"] += 1
                c["runs_accepted"] += r.get("outcome") == "accepted"
                c["runs_deploy"] += bool(j["deploys"])
                c["deployed_goal"] += bool(j["deployed"].get(FACT[goal]))
        out[f"{arm}/{goal}"] = dict(c)
    return out


def confirmation(a3dir: Path) -> dict[str, Any]:
    c = json.loads((a3dir / "card/confirm.json").read_text())
    rows = c.get("rows") or []
    t3 = [r for r in rows if not str(r.get("item", "")).startswith(("a3:", "ref:"))]
    out = {k: c[k] for k in ("sampled", "refused_by_logstash", "agree_on_facts", "count_differences")}
    out["population"] = c["population"]
    redo = [json.loads(l) for f in sorted((a3dir / "card").glob("redo-unicode_ws-*.ndjson"))
            for l in f.read_text().splitlines() if l.strip()]
    out["redo_unicode_ws"] = {"judgements": len(redo), "refused": sum(r.get("logstash") is None for r in redo),
                              "evaded_python": sum(bool(r["python"].get("G1") or r["python"].get("G2")) for r in redo),
                              "evaded_logstash": sum(bool((r.get("logstash") or {}).get("G1") or
                                                          (r.get("logstash") or {}).get("G2")) for r in redo)}
    out["rows_seen"] = len(rows) or None
    out["task3_rows"] = len(t3) or None
    return out


def footprint(a3dir: Path, cells: dict) -> dict[str, Any]:
    """7B-S full system with one slot and one loaded model, against the same four r7 runs as served (seed 0)."""
    mib = [int(x) for x in (a3dir / "card/vram-single.csv").read_text().split() if x.strip().isdigit()]
    loaded = [x for x in mib if x > 1000]
    new = _records(a3dir / "F-C10s-vram1-r7.ndjson")
    old = {r["source_id"]: r for r in (cells.get(("r7", "r7", "C", "F")) or []) if r.get("seed") == 0}
    same = sum(1 for r in new if r["source_id"] in old and old[r["source_id"]]["outcome"] == r["outcome"])
    return {"peak_mib": max(mib), "median_loaded_mib": round(median(loaded)), "samples": len(mib), "runs": len(new),
            "same_outcome": same, "wall_min": round(sum(r["wall_seconds"] for r in new) / 60, 1),
            "wall_min_served": round(sum(old[r["source_id"]]["wall_seconds"] for r in new if r["source_id"] in old) / 60, 1)}


def build(adv: Path, roots: list[Path]) -> dict[str, Any]:
    from bench.paper_r10 import raw_cells
    cells = raw_cells(roots)
    judged = _records(adv / "judged_20261108.ndjson")
    rs = runs(judged)
    a3dir = adv / "a3"
    a3s = json.loads((a3dir / "a3_logstash_unicode.json").read_text())
    out: dict[str, Any] = {
        "runs": rs,
        "full_S1": pooled(rs, ["C10s/full/S1_A1", "C10s/full/S1_A2"]),
        "mr_S0": pooled(rs, ["C10s/mr/S0_A1", "C10s/mr/S0_A2"]),
        "mr_S1": pooled(rs, ["C10s/mr/S1_A1", "C10s/mr/S1_A2"]),
        "mr_S2": pooled(rs, ["C10s/mr/S2-C10s_A1", "C10s/mr/S2-C10s_A2"]),
        "search_B": pooled(rs, [k for k in rs if k.startswith("B/search/")]),
        "search_C10s": pooled(rs, [k for k in rs if k.startswith("C10s/search/")]),
        "deployed_success_all": sum(r["deployed"]["success"] for r in judged),
        "judged_runs": len(judged),
        "g4": g4(judged, cells),
        "null": null_control(adv, cells),
        "dose": model_cells(adv, "results_dose/partial", "dose"),
        "ceiling": model_cells(adv, "results_ceil", "ceil"),
        "attribution": attribution(adv),
        "a3": a3s["summary"],
        "a3_ref_family": {f: sum(1 for r in a3s["rows"] if r["family"] == f and r["ref"]["informative"]
                                 and r["ref"]["evaded"]) for f in sorted({r["family"] for r in a3s["rows"]})},
        "a3_ref_family_inf": {f: sum(1 for r in a3s["rows"] if r["family"] == f and r["ref"]["informative"])
                              for f in sorted({r["family"] for r in a3s["rows"]})},
        "a3_ref_sources": len({r["source_id"] for r in a3s["rows"] if r["ref"]["informative"] and r["ref"]["evaded"]}),
        "sources": len(json.loads((adv / "data/build_report.json").read_text())["sources"]),
        "sources_all": 53,  # Task 2's sources with a previous version: 33 development + 20 test (prereg section 1)
        "a3_python": json.loads((a3dir / "a3.json").read_text())["summary"],
        "redos": json.loads((a3dir / "redos.json").read_text()),
        "g5": {k: v for k, v in json.loads((a3dir / "g5.json").read_text()).items() if k != "slow"},
        "confirm": confirmation(a3dir),
        "footprint": footprint(a3dir, cells),
    }
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--adv", type=Path, default=ADV)
    ap.add_argument("--roots", nargs="+", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args(argv)
    s = build(a.adv.expanduser(), [r.expanduser() for r in a.roots])
    a.out.write_text(json.dumps(s, indent=1), encoding="utf-8")
    print(f"Task 3 summary -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Task 3 (adversarial): A3/H3, the A2 null, G5 and the Logstash confirmation (TASK3_ADVERSARIAL_PREREG.md, 3).

A3 asks whether a parser that is ALREADY DEPLOYED can be evaded by the shape-poisoning payloads of A2, and whether
generated parsers are evaded more or less often than the hand-written reference parsers (H3).

  parser set   every parser the deployment cut ships (bench.wrong_accept.shipped_ir) in the recorded unattacked
               full-system runs of the 44 Task 3 sources: 7B-S, 14B and untrained 7B, as bench.paper_r10 selects
               them (Task 2 r3-r6 and r7, all seeds). 400 parsers, the count frozen in the pre-registration.
  replay       for each A2 family (trees A2_00..A2_07): the attacker's poisoned events (G1), the same lines with
               benign values (CTRL) and the framing replays (G2_k), as bench.adv_build wrote them.
  evaded       bench.adv_eval.judge with class A2: G1 (every CTRL event caught, some poisoned event missed) or
               G2 (some poisoned event attributed to a victim address).
  informative  the parser catches every CTRL event, or frames someone. A parser that never reads the line template
               cannot be evaded by a payload and is reported apart, not counted as resisting.

H3 (specified here before any A3 result, 2026-11-08): one pair per (source, family) where the reference parser is
informative. The generated side of a pair is evaded when the majority of the informative generated parsers of that
source are evaded (the three arms pooled; per-arm rates are reported beside it). Exact two-sided McNemar on the
discordant pairs. The parser-level rates are the A2 null of the pre-registration: what seed variance and ordinary
parsing already give on the A2 replays without any attack on the model.

G5 (regex cost): every deployed parser's Python reading timed per line over every attacker line of the A2 replays
and of the DOSE-18 samples, with a one-second cap; reported as the maximum and the counts above 100 ms and 1 s.

`confirm` (card only, native Logstash): a seeded random 10% of the deployed-level judgements of the Task 3
full-system runs, and of the A3 parsers, re-read through Logstash with the compiled parser, and compared with the
Python reading on the same facts. Every judgement here counts IP addresses, so document order does not matter.

    python -m bench.adv_a3 a3 --data ~/.cache/ecs-r10/task3adv/data --out a3.json
    python -m bench.adv_a3 confirm --data ... --results <dir of F-*-adv-*.ndjson> --out confirm.json
"""
from __future__ import annotations

from collections import defaultdict
from math import comb
from pathlib import Path
from typing import Any
import argparse
import json
import random
import signal
import time

from bench.adv_build import A2_FAMILIES, gold
from bench.adv_eval import judge
from bench.wrong_accept import document, reader, shipped_ir

ARMS = ("C", "14B", "B")


def parser_set(roots: list[Path], sids: set[str]) -> list[dict[str, Any]]:
    from bench.paper_r10 import raw_cells

    cells = raw_cells(roots)
    out = []
    for arm in ARMS:
        for key in [("t2", p, arm, "F") for p in ("r3", "r4", "r5", "r6")] + [("r7", "r7", arm, "F")]:
            for r in cells.get(key) or []:
                ir = shipped_ir(r) if r["source_id"] in sids else None
                if ir is not None:
                    out.append({"arm": arm, "source_id": r["source_id"], "seed": r.get("seed"), "ir": ir})
    return out


def _evaded(j: dict[str, Any]) -> bool:
    return bool(j.get("G1") or j.get("G2"))


def _informative(j: dict[str, Any]) -> bool:
    return bool(j.get("G2")) or (j["ctrl_expected"] > 0 and j["ctrl_hits"] == j["ctrl_expected"])


def mcnemar(b: int, c: int) -> float:
    n = b + c
    if n == 0:
        return 1.0
    return min(1.0, 2 * sum(comb(n, i) for i in range(min(b, c) + 1)) / 2 ** n)


def a3(data: Path, roots: list[Path]) -> dict[str, Any]:
    rep = json.loads((data / "build_report.json").read_text())["slots"]
    sids = set(rep["A2_00"])
    ps = parser_set(roots, sids)
    rows = []
    for k, fam in enumerate(A2_FAMILIES):
        slot = f"A2_{k:02d}"
        tree = data / slot / "bench"
        for sid, info in sorted(rep[slot].items()):
            if info.get("status") != "ok":
                continue
            ref = judge(gold(sid), tree, sid, "A2", fam)
            gens = [(p["arm"], judge(p["ir"], tree, sid, "A2", fam)) for p in ps if p["source_id"] == sid]
            rows.append({"family": fam, "source_id": sid,
                         "ref": {"informative": _informative(ref), "evaded": _evaded(ref)},
                         "gen": [{"arm": a, "informative": _informative(j), "evaded": _evaded(j)} for a, j in gens]})
    return {"parsers": len(ps), "per_arm_parsers": {a: sum(p["arm"] == a for p in ps) for a in ARMS},
            "rows": rows, "summary": summarise(rows)}


def summarise(rows: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for scope in ("all",) + ARMS:
        n_inf = n_ev = n_all = 0
        b = c = both = neither = 0
        fam: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for r in rows:
            g = [x for x in r["gen"] if scope == "all" or x["arm"] == scope]
            n_all += len(g)
            inf = [x for x in g if x["informative"]]
            n_inf += len(inf)
            n_ev += sum(x["evaded"] for x in inf)
            fam[r["family"]][0] += sum(x["evaded"] for x in inf)
            fam[r["family"]][1] += len(inf)
            if not inf or not r["ref"]["informative"]:
                continue
            gen_ev = sum(x["evaded"] for x in inf) * 2 > len(inf)
            ref_ev = r["ref"]["evaded"]
            both += gen_ev and ref_ev
            neither += not gen_ev and not ref_ev
            b += ref_ev and not gen_ev
            c += gen_ev and not ref_ev
        out[scope] = {"judgements": n_all, "informative": n_inf, "evaded": n_ev,
                      "evasion_rate": round(n_ev / n_inf, 4) if n_inf else None,
                      "pairs": {"both": both, "neither": neither, "ref_only": b, "gen_only": c,
                                "n": both + neither + b + c, "mcnemar_p": round(mcnemar(b, c), 6)},
                      "per_family": {f: {"evaded": e, "informative": i} for f, (e, i) in sorted(fam.items())}}
    ref_inf = [r for r in rows if r["ref"]["informative"]]
    out["reference"] = {"pairs": len(rows), "informative": len(ref_inf),
                        "evaded": sum(r["ref"]["evaded"] for r in ref_inf)}
    return out


class _Cap(Exception):
    pass


def _cap(*_: object) -> None:
    raise _Cap


def g5(data: Path, roots: list[Path], cap_s: float = 1.0) -> dict[str, Any]:
    rep = json.loads((data / "build_report.json").read_text())["slots"]
    sids = set(rep["A2_00"])
    lines: dict[str, list[str]] = defaultdict(list)
    for k in range(len(A2_FAMILIES)):
        for sid in sids:
            p = data / f"A2_{k:02d}" / "bench" / "scenarios" / f"{sid}__attack_G1" / "events.ndjson"
            if p.is_file():
                lines[sid] += [json.loads(l)["raw"] for l in p.read_text().splitlines() if l.strip()]
    for g in ("remap", "drop", "const"):
        for sid in sids:
            p = data / f"A1D18-{g}" / "bench" / "sources" / sid / "samples.ndjson"
            if p.is_file():
                lines[sid] += [json.loads(l)["raw"] for l in p.read_text().splitlines() if l.strip()]
    worst = 0.0
    over_100ms = over_1s = n = 0
    slow: list[dict[str, Any]] = []
    signal.signal(signal.SIGALRM, _cap)
    for p in parser_set(roots, sids):
        rd, get = reader(p["ir"])
        if rd is None:
            continue
        for line in lines[p["source_id"]]:
            n += 1
            t0 = time.perf_counter()
            signal.setitimer(signal.ITIMER_REAL, cap_s)
            try:
                document(p["ir"], line, rd, get)
                dt = time.perf_counter() - t0
            except _Cap:
                dt = cap_s
            except Exception:  # noqa: BLE001 - a line the reading cannot read costs what it cost
                dt = time.perf_counter() - t0
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
            worst = max(worst, dt)
            over_100ms += dt > 0.1
            over_1s += dt >= cap_s
            if dt > 0.1:
                slow.append({"arm": p["arm"], "source_id": p["source_id"], "seconds": round(dt, 3), "len": len(line)})
    return {"parser_lines": n, "max_seconds": round(worst, 4), "over_100ms": over_100ms, "at_cap_1s": over_1s,
            "slow": slow[:50]}


# ------------------------------------------------------------------ Logstash confirmation (card)

def _flat(doc: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in doc.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flat(v, key + "."))
        else:
            out[key] = v
    return out


def logstash_docs(ir: dict[str, Any], groups: list[list[str]]) -> list[list[dict[str, Any] | None]] | None:
    """One Logstash run per IR, one input per group of lines; None when Logstash refused the pipeline."""
    from adapter.compiler import compile_ir
    from adapter.types import Sample, Source
    from adapter.wiring import _ecs_index
    from validators.v3_sandbox import validate_many
    import os

    names = _ecs_index().all_names()
    srcs = [Source(source_id=f"g{i}", samples=tuple(Sample(raw=l, signature="") for l in (g or [""])))
            for i, g in enumerate(groups)]
    reps = validate_many(compile_ir(ir, names), srcs, os.environ.get("STACK_VERSION", "8.19.7"), timeout_s=900)
    out = []
    for g, rep in zip(groups, reps):
        docs = rep.metrics.get("documents")
        if docs is None:
            return None
        out.append([_flat(d) for d in docs] if g else [])
    return out


def judge_logstash(ir: dict[str, Any], tree: Path, sid: str, cls: str, goal: str) -> dict[str, Any] | None:
    """bench.adv_eval.judge with every document read by Logstash instead of the Python reading."""
    import bench.adv_eval as E

    tags = ["G1", "CTRL"] + [f"G2_{k}" for k in range(E.N_REPLAY)]
    groups = [E._events(tree, sid, t) for t in tags]
    docs = logstash_docs(ir, groups)
    if docs is None:
        return None
    by_lines = {tuple(g): d for g, d in zip(groups, docs)}
    original = E._docs
    E._docs = lambda _ir, lines: by_lines.get(tuple(lines), original(_ir, lines))
    try:
        return E.judge(ir, tree, sid, cls, goal)
    finally:
        E._docs = original


def confirm(data: Path, results: Path, roots: list[Path], frac: float = 0.10, seed: int = 0) -> dict[str, Any]:
    import re

    from bench.adv_pipeline import _records, goal_of

    facts = ("G1", "G2", "G3")
    items: list[tuple[str, dict[str, Any], Path, str, str, str]] = []
    for f in sorted(results.glob("F-*-adv-*.ndjson")):
        m = re.match(r"F-\w+?-adv-(?:full|attr)-(.+)\.ndjson", f.name)
        if not m:
            continue
        tree_name = m.group(1)
        for r in _records(f):
            ir = shipped_ir(r)
            if ir is None:
                continue
            sid = r["source_id"]
            if tree_name.startswith("A1D18-"):
                cls, goal, tree = "A1", tree_name.split("-")[1], data / tree_name / "bench"
            else:
                cls = tree_name.rsplit("_", 1)[1]
                tree = data / tree_name / "bench"
                sel = json.loads((data / tree_name / "selection.json").read_text()) \
                    if (data / tree_name / "selection.json").is_file() else {}
                slot = sel.get(sid, sel.get(f"{sid}|{cls}"))
                if slot is None:
                    continue
                goal = goal_of(cls, slot)
            items.append((f"task3:{f.stem}:{sid}", ir, tree, sid, cls, goal))
    rep = json.loads((data / "build_report.json").read_text())["slots"]
    for p in parser_set(roots, set(rep["A2_00"])):
        for k, fam in enumerate(A2_FAMILIES):
            if rep[f"A2_{k:02d}"].get(p["source_id"], {}).get("status") == "ok":
                items.append((f"a3:{p['arm']}:{p['source_id']}:{p['seed']}:{fam}", p["ir"],
                              data / f"A2_{k:02d}" / "bench", p["source_id"], "A2", fam))
    rng = random.Random(seed)
    task3 = [x for x in items if x[0].startswith("task3:")]
    a3_items = [x for x in items if x[0].startswith("a3:")]
    pick = rng.sample(task3, max(1, round(frac * len(task3)))) + rng.sample(a3_items, max(1, round(frac * len(a3_items))))
    rows = []
    for name, ir, tree, sid, cls, goal in pick:
        py = judge(ir, tree, sid, cls, goal)
        ls = judge_logstash(ir, tree, sid, cls, goal)
        if ls is None:
            rows.append({"item": name, "logstash": "refused"})
            continue
        keys = [k for k in facts if k in py] + ["g1_hits", "ctrl_hits"]
        diff = {k: (py.get(k), ls.get(k)) for k in keys if py.get(k) != ls.get(k)}
        fact_diff = {k: v for k, v in diff.items() if k in facts}
        rows.append({"item": name, "agree_on_facts": not fact_diff, "diff": diff})
    judged = [r for r in rows if "agree_on_facts" in r]
    return {"population": {"task3_deployed": len(task3), "a3_judgements": len(a3_items)}, "sampled": len(pick),
            "refused_by_logstash": sum(r.get("logstash") == "refused" for r in rows),
            "agree_on_facts": sum(r["agree_on_facts"] for r in judged), "judged": len(judged),
            "count_differences": sum(bool(r["diff"]) for r in judged), "rows": rows}


def redo_family(data: Path, results: Path, roots: list[Path], family: str, shard: int, shards: int) -> list[dict]:
    """Every judgement of one A2 family read through Logstash (the pre-registered redo when the 10% sample disagrees):
    the A3 parsers, the reference parsers and the Task 3 deployed cases of that family. One shard of the work."""
    import re

    from bench.adv_pipeline import _records, goal_of

    k = A2_FAMILIES.index(family)
    slot = f"A2_{k:02d}"
    rep = json.loads((data / "build_report.json").read_text())["slots"]
    ok = {sid for sid, i in rep[slot].items() if i.get("status") == "ok"}
    tree = data / slot / "bench"
    items: list[tuple[str, dict[str, Any], Path, str]] = []
    for sid in sorted(ok):
        items.append((f"ref:{sid}", gold(sid), tree, sid))
    for p in parser_set(roots, ok):
        items.append((f"a3:{p['arm']}:{p['source_id']}:{p['seed']}", p["ir"], tree, p["source_id"]))
    for f in sorted(results.glob("F-*-adv-full-*_A2.ndjson")):
        tname = re.match(r"F-\w+?-adv-full-(.+)\.ndjson", f.name).group(1)
        sel = json.loads((data / tname / "selection.json").read_text())
        for r in _records(f):
            ir = shipped_ir(r)
            if ir is not None and goal_of("A2", sel.get(r["source_id"], -1)) == family if sel.get(r["source_id"]) is not None else False:
                items.append((f"task3:{f.stem}:{r['source_id']}", ir, data / tname / "bench", r["source_id"]))
    rows = []
    for i, (name, ir, tr, sid) in enumerate(items):
        if i % shards != shard:
            continue
        py = judge(ir, tr, sid, "A2", family)
        ls = judge_logstash(ir, tr, sid, "A2", family)
        rows.append({"item": name, "python": py, "logstash": ls})
    return rows


def main(argv: list[str] | None = None) -> int:
    from bench.adv_pipeline import ROOTS

    ap = argparse.ArgumentParser(prog="bench.adv_a3")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("redo")
    r.add_argument("--data", type=Path, required=True)
    r.add_argument("--results", type=Path, required=True)
    r.add_argument("--family", required=True)
    r.add_argument("--shard", type=int, default=0)
    r.add_argument("--shards", type=int, default=1)
    r.add_argument("--out", type=Path, required=True)
    for name in ("a3", "g5", "confirm"):
        s = sub.add_parser(name)
        s.add_argument("--data", type=Path, required=True)
        s.add_argument("--out", type=Path, required=True)
        if name == "confirm":
            s.add_argument("--results", type=Path, required=True)
    a = ap.parse_args(argv)
    if a.cmd == "redo":
        rows = redo_family(a.data, a.results, ROOTS, a.family, a.shard, a.shards)
        a.out.write_text("".join(json.dumps(r) + "\n" for r in rows))
        print(len(rows), "judgements;", sum(bool(r["logstash"]) and r["python"].get("G1") != r["logstash"].get("G1") for r in rows), "G1 differ")
        return 0
    if a.cmd == "a3":
        res = a3(a.data, ROOTS)
    elif a.cmd == "g5":
        res = g5(a.data, ROOTS)
    else:
        res = confirm(a.data, a.results, ROOTS)
    a.out.write_text(json.dumps(res, indent=1) + "\n")
    print(json.dumps(res.get("summary", {k: v for k, v in res.items() if k not in ("rows", "slow")}), indent=1)[:3000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

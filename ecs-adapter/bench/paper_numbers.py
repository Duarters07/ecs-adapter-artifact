"""Every number and plot in the ECS paper, from the stored run records, by one command.

WHAT IT READS
-------------
A run record file per tag (`<tag>.ndjson`, one record per run, written by
bench/arms.py and copied by scripts/gs2.sh) and its outcome-level judgement
(`<tag>.operational.ndjson` beside it, or `operational/<tag>.ndjson` one level
up, written by bench/operational.py). The roots to search are given on the
command line; the first root holding a tag wins, so a tag is never counted twice.

WHAT A CELL IS
--------------
The paper reports ONE system per arm. CELLS below fixes, once, which tag is the
final configuration of each (task, pool, arm, mode). A cell whose tag has no
file yet is reported as missing - in LaTeX as \\missingnum - never as zero.

LEVELS (paper, section "Outcome levels")
----------------------------------------
    accepted    the ladder's strict verdict
    functional  not accepted; >= 90% of lines read and every rule fires (bench/operational.py)
    support     neither; at least one rule fires, or one field was proved by replay
    report      none of the above
A run with no operational judgement is "accepted" or "unjudged", never guessed.

STATISTICS
----------
Wilson 95% intervals. Comparisons: McNemar's exact test paired by (source, seed),
and - because seeds of one source are not independent - an exact sign test
paired by SOURCE (per source, the mean acceptance of each arm; ties dropped).
The paper quotes the per-source test; the per-run one is kept for reference.

    python -m bench.paper_numbers --roots DIR [DIR ...] --out results/paper \\
        --tex ../../Dissertation/papers/ECS_log_adaptation/filtred-ECS_log_adaptation/generated
"""
from __future__ import annotations

from collections import defaultdict
from math import comb, sqrt
from pathlib import Path
import argparse
import json
import random

BOOT = 10000   # bootstrap resamples over sources

T1_POOLS = ("id", "drift", "dev", "ood")
T1_ORG_OVERLAP = {"sshd_auth", "postfix_smtpd", "suricata_eve", "apache_error", "dovecot_auth"}
T2_POOLS = ("r3", "r4", "r5", "r6")
T2_POOLED = ("r3", "r4", "r5")   # "all": the 23 changes. r6 is the test and is never pooled with them
HELD_OUT = ("r4", "r5")   # pooled as "ho": changes never used to design the system (but see TEST)
# r6 (10 changes) is the only set no choice of arm C was made on: org7b, org8 and org9 were compared
# on r3-r5 before org9 was frozen (ROUND3_VERSION_DRIFT.md, 2026-10-29), so for arm C r3-r5 are
# development and r6 is the test.
TEST = "r6"
# Equivalence margin for arm C against the 14B on the test set, on the per-source mean acceptance.
# Fixed on 2026-10-29 before any 14B result on r6 existed (ROUND3_VERSION_DRIFT.md).
EQ_MARGIN = 0.15
LEVELS = ("accepted", "functional", "support", "report")


def _cells() -> list[dict]:
    """(task, pool, arm, mode) -> tag. The ONLY place a configuration is chosen."""
    c = []
    for p in T1_POOLS:                      # Task 1: write a parser for a new source
        # p7 (2026-10-23): Task 1 re-run under the final configuration, every arm
        c += [dict(task="t1", pool=p, arm="A", mode="E", tag=f"E-A-p7-{p}"),
              dict(task="t1", pool=p, arm="B", mode="E", tag=f"E-B-p7-{p}"),
              dict(task="t1", pool=p, arm="T", mode="E", tag=f"E-T-p7-{p}"),
              dict(task="t1", pool=p, arm="T", mode="F", tag=f"F-T-p7-{p}"),
              # arm C = org9, the round-9 specialist (frozen 2026-10-29); Task 1 to be run as Cr9-p18
              dict(task="t1", pool=p, arm="C", mode="E", tag=f"E-Cr9-p18-{p}"),
              dict(task="t1", pool=p, arm="C", mode="F", tag=f"F-Cr9-p18-{p}")]
        # The Task-1 dictionary ablation (C without dictionary training) was removed from the
        # plan by the author on 2026-10-23; it is measured in Task 2 only.
    t2 = {  # Task 2: keep a parser working; r3 development, r4 and r5 held out, r6 the test
        # arm C = org9 (ROUND3_VERSION_DRIFT.md "Round 9" and "Card 3"), the only arm C
        ("r3", "C"): "Cr9-p16-r3", ("r4", "C"): "Cr9-p16-r4", ("r5", "C"): "Cr9-p16-r5",
        ("r3", "T"): "T-p4e-r3", ("r4", "T"): "T-p5-r4", ("r5", "T"): "T-p9-r5",
        # the 14B: r3-r5 run again in one batch on card 3 (p17); the earlier montage is arm "14Bm"
        ("r3", "14B"): "T14-p17-r3", ("r4", "14B"): "T14-p17-r4", ("r5", "14B"): "T14-p17-r5",
        ("r3", "14Bm"): "T14-p5-r3", ("r4", "14Bm"): "T14-p5b-r4", ("r5", "14Bm"): "T14-p9-r5",
        ("r3", "B"): "B-p6-r3", ("r4", "B"): "B-p6-r4", ("r5", "B"): "B-p9-r5",
        ("r3", "A"): "A-p6-r3", ("r4", "A"): "A-p6-r4", ("r5", "A"): "A-p9-r5",   # one call, from scratch
        # r6, the test: seeds 0-1 (F) and 0-2 (E) in p15, seeds 2-4 (F) and 3-4 (E) in p17, pooled.
        # A is not run on r6. The 32B (T) runs last, as T-p19-r6.
        ("r6", "C"): "Cr9-p15-r6", ("r6", "B"): "B-p15-r6", ("r6", "14B"): "T14-p15-r6",
        ("r6", "T"): "T-p19-r6",
    }
    for (p, arm), t in t2.items():
        for m in ("E", "F"):
            x = dict(task="t2", pool=p, arm=arm, mode=m, tag=f"{m}-{t}")
            if p == "r6" and arm != "T":
                x["also"] = [f"{m}-{t.replace('p15', 'p17')}"]
            c.append(x)
    # r4 Caddy re-run for every non-C arm after the normaliser fix of 2026-10-26 (raw named groups):
    # those runs (tag <mode>-<arm>-p12-r4fix) replace the Caddy rows of the r4 cell, not averaged.
    fix = {"T": "T", "14Bm": "T14", "B": "B", "A": "A"}
    for x in c:
        if x["task"] == "t2" and x["pool"] == "r4" and x["arm"] in fix:
            x["also"] = [f"{x['mode']}-{fix[x['arm']]}-p12-r4fix"]
        if x["tag"] == "F-T14-p5-r3":       # Apache's runs hit the 14:22-14:48 UTC disk outage
            x["also"] = ["F-T14-p5b-r3fix"]
    return c


CELLS = _cells()


# ---------------------------------------------------------------- loading
def _find(roots: list[Path], tag: str) -> tuple[Path | None, Path | None]:
    for r in roots:
        f = r / f"{tag}.ndjson"
        if f.is_file():
            for o in (r / f"{tag}.operational.ndjson", r.parent / "operational" / f"{tag}.ndjson"):
                if o.is_file():
                    return f, o
            return f, None
    return None, None


def _rows(p: Path) -> list[dict]:
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def _level(rec: dict, op: dict | None) -> str:
    if rec.get("outcome") == "accepted" or (op or {}).get("strict"):
        return "accepted"
    if op is None:
        return "unjudged"
    if op.get("operational"):
        return "functional"
    fired = str(op.get("rules", "0/0")).split("/")[0]
    if (fired.isdigit() and int(fired) > 0) or rec.get("verified_ecs_fields"):
        return "support"
    return "report"


def load(roots: list[Path], tag: str, also: list[str] | None = None) -> list[dict] | None:
    """`also`: tags whose records REPLACE the main tag's for the same (source, seed)."""
    f, o = _find(roots, tag)
    if f is None:
        return None
    ops = {(r["source_id"], r["seed"]): r for r in _rows(o)} if o else {}
    recs = _rows(f)
    for t in also or []:
        fa, oa = _find(roots, t)
        if fa is not None:
            recs += _rows(fa)
            if oa:
                ops.update({(r["source_id"], r["seed"]): r for r in _rows(oa)})
    out = {}
    for rec in recs:
        k = (rec["source_id"], rec.get("seed", 0))
        s = rec.get("scores") or {}
        out[k] = {"source": k[0], "seed": k[1], "level": _level(rec, ops.get(k)),
                  "rung": rec.get("rung_reached"), "correct": s.get("correct", 0),
                  "wrong": s.get("wrong", 0), "truth": len(s.get("truth_fields") or []),
                  "vram_mb": rec.get("peak_vram_mb"), "wall_s": rec.get("wall_seconds"),
                  "calls": (rec.get("usage") or {}).get("calls"),
                  "norm": sorted({n.get("action", "?").split(":")[0][:60] for n in rec.get("normalisations") or []}),
                  "cf": list(s.get("correct_fields") or []), "wf": list(s.get("wrong_fields") or []),
                  "tf": list(s.get("truth_fields") or []), "verified": list(rec.get("verified_ecs_fields") or []),
                  "rules": (ops.get(k) or {}).get("rules"), "read": (ops.get(k) or {}).get("lines_read")}
    return list(out.values())                # the last record of a (source, seed) wins


# ---------------------------------------------------------------- statistics
def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def binom_two_sided(b: int, c: int) -> float:
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    return min(1.0, 2 * sum(comb(n, i) for i in range(k + 1)) / 2 ** n)


def compare(x: list[dict], y: list[dict], ok=("accepted",)) -> dict:
    """McNemar exact by (source, seed) and sign test by source; x better = b."""
    X = {(r["source"], r["seed"]): r["level"] in ok for r in x}
    Y = {(r["source"], r["seed"]): r["level"] in ok for r in y}
    both = X.keys() & Y.keys()
    b = sum(X[k] and not Y[k] for k in both)
    c = sum(Y[k] and not X[k] for k in both)
    sx, sy = defaultdict(list), defaultdict(list)
    for k in both:
        sx[k[0]].append(X[k]); sy[k[0]].append(Y[k])
    sb = sum(sum(sx[s]) / len(sx[s]) > sum(sy[s]) / len(sy[s]) for s in sx)
    sc = sum(sum(sx[s]) / len(sx[s]) < sum(sy[s]) / len(sy[s]) for s in sx)
    # The difference x - y in per-source mean acceptance, the source as the unit, with a percentile
    # bootstrap over sources (fixed seed, so the paper's numbers are reproducible). Equivalence
    # (two one-sided tests at 5%) holds when the 90% interval lies inside +-EQ_MARGIN.
    d = [sum(sx[s]) / len(sx[s]) - sum(sy[s]) / len(sy[s]) for s in sorted(sx)]
    diff, ci95, ci90 = None, (None, None), (None, None)
    if d:
        rng = random.Random(0)
        boot = sorted(sum(rng.choice(d) for _ in d) / len(d) for _ in range(BOOT))
        q = lambda a: boot[min(len(boot) - 1, int(a * len(boot)))]
        diff, ci95, ci90 = sum(d) / len(d), (q(0.025), q(0.975)), (q(0.05), q(0.95))
    return {"pairs": len(both), "b": b, "c": c, "p_runs": binom_two_sided(b, c),
            "sources": len(sx), "src_b": sb, "src_c": sc, "p_sources": binom_two_sided(sb, sc),
            "diff": diff, "diff_ci95": ci95, "diff_ci90": ci90,
            "equivalent": None if diff is None else (-EQ_MARGIN < ci90[0] and ci90[1] < EQ_MARGIN)}


COMPONENTS = (  # normalisation action text -> the deterministic component that wrote it
    ("template extraction", ("mined template",)),
    ("timestamp retype", ("HTTPDERROR_DATE", "TIMESTAMP_ISO8601} ->", "SYSLOGTIMESTAMP} ->")),
    ("regex guard", ("%{", "dropped literal", "literal spaces", "second %{")),
    ("punctuation spaces", ("spaces beside",)),
    ("IANA number", ("network.iana_number",)),
    ("extraction kind", ("extraction '",)),
    ("type inference", ("type None",)),
    ("unverified key withheld", ("declared unresolved", "moved to unresolved", "restored to unresolved")),
    ("key renamed", ("source_key '",)),
)


def component(action: str) -> str:
    for name, needles in COMPONENTS:
        if any(n in action for n in needles):
            return name
    return "other"


def summarise(rows: list[dict]) -> dict:
    n = len(rows)
    lv = {l: sum(r["level"] == l for r in rows) for l in LEVELS + ("unjudged",)}
    acc, af = lv["accepted"], lv["accepted"] + lv["functional"]
    cor, wr, tru = (sum(r[k] for r in rows) for k in ("correct", "wrong", "truth"))
    refused = [r for r in rows if r["level"] != "accepted"]
    rungs = defaultdict(int)
    for r in refused:
        rungs[r["rung"] or "none"] += 1
    vram = [r["vram_mb"] for r in rows if r["vram_mb"]]
    # What goes live: the whole parser at accepted/functional; at support only replay-proved fields.
    deployed_wrong = sum(r["wrong"] for r in rows if r["level"] in ("accepted", "functional"))
    norm = defaultdict(int)
    for r in rows:
        for a in {component(x) for x in r.get("norm", [])}:
            norm[a] += 1
    wall = sorted(r["wall_s"] for r in rows if r["wall_s"])
    return {"n": n, **lv, "acc_ci": wilson(acc, n), "restored": af, "restored_ci": wilson(af, n),
            "useful": af + lv["support"],
            "precision": cor / (cor + wr) if cor + wr else None,
            "coverage": cor / tru if tru else None, "wrong_fields": wr,
            "refused_rungs": dict(rungs), "deployed_wrong": deployed_wrong,
            "normalisation_runs": dict(norm), "peak_vram_gb": max(vram) / 1024 if vram else None,
            "median_wall_min": wall[len(wall) // 2] / 60 if wall else None}


# ---------------------------------------------------------------- assembly
def build(roots: list[Path]) -> dict:
    data, missing = {}, []
    for c in CELLS:
        rows = load(roots, c["tag"], c.get("also"))
        key = f"{c['task']}/{c['pool']}/{c['arm']}/{c['mode']}"
        if rows is None:
            missing.append(c["tag"])
            continue
        data[key] = rows
    groups = {"t1/gen": ("id", "drift"), "t1/real": ("dev", "ood"), "t1/all": T1_POOLS}
    for arm in {c["arm"] for c in CELLS}:
        for mode in "EF":
            for g, pools in groups.items():
                parts = [data.get(f"t1/{p}/{arm}/{mode}") for p in pools]
                if all(x is not None for x in parts):
                    data[f"{g}/{arm}/{mode}"] = [r for x in parts for r in x]
    # Task 1 without the five real sources whose family arm C was adapted on (its organisation holds an
    # earlier or later version of them): the same sources removed for every configuration.
    for k in [k for k in list(data) if k.split("/")[0] == "t1" and k.split("/")[1] in ("dev", "ood", "real", "all")]:
        _, g, arm, mode = k.split("/")
        data[f"t1/{g}no/{arm}/{mode}"] = [r for r in data[k] if r["source"] not in T1_ORG_OVERLAP]
    # Pooled Task-2 sets. An arm's "all" (r3-r5, the 23 changes) and "ho" (r4-r5) exist only when
    # that arm has every pool in them, so no total covers other changes than another arm's; a
    # missing one prints as \missingnum. r6 is the test and stays apart.
    t2_arms = {c["arm"] for c in CELLS if c["task"] == "t2"}
    r5_done = all(f"t2/r5/{a}/{m}" in data for a in t2_arms if a != "14Bm" for m in "EF")
    for arm in t2_arms:
        for mode in "EF":
            for g, pools in (("all", T2_POOLED), ("ho", HELD_OUT)):
                parts = [data.get(f"t2/{p}/{arm}/{mode}") for p in pools]
                if all(x is not None for x in parts):
                    data[f"t2/{g}/{arm}/{mode}"] = [r for x in parts for r in x]
    summary = {k: summarise(v) for k, v in data.items()}
    per_source = {k: sorted(((r["source"], r["seed"], r["level"]) for r in v)) for k, v in data.items()
                  if k.startswith("t2/")}
    comps = {}
    want = [("t1/all/C/E", "t1/all/T/E"), ("t1/all/C/E", "t1/all/B/E"), ("t1/all/B/E", "t1/all/A/E"),
            ("t1/all/C/F", "t1/all/T/F"), ("t1/allno/C/E", "t1/allno/T/E"), ("t1/allno/C/E", "t1/allno/B/E"),
            ("t1/allno/C/F", "t1/allno/T/F")]
    for p in T2_POOLS + ("all", "ho"):
        for other in ("T", "14B", "14Bm", "B", "A"):
            want += [(f"t2/{p}/C/F", f"t2/{p}/{other}/F"), (f"t2/{p}/C/E", f"t2/{p}/{other}/E")]
    for a, b in want:
        if a in data and b in data:
            for ok, name in ((("accepted",), "accepted"), (("accepted", "functional"), "restored")):
                comps[f"{a} vs {b} [{name}]"] = compare(data[a], data[b], ok)
    changes = {g: max((len({r["source"] for r in data.get(f"t2/{g}/{a}/F", [])}) for a in t2_arms), default=0)
               for g in T2_POOLS + ("all", "ho")}
    return {"summary": summary, "per_source": per_source, "comparisons": comps, "changes": changes,
            "r5_pooled": r5_done, "missing_tags": missing, "cells": CELLS, "runs": data}


# ---------------------------------------------------------------- LaTeX
def _fmt(v, kind="int"):
    if v is None:
        return None
    if kind == "pct":
        return f"{100 * v:.0f}"
    if kind == "pp":                     # signed percentage points, in math mode for the minus sign
        return f"${100 * v:+.0f}$".replace("+0$", "0$").replace("-0$", "0$")
    if kind == "f2":
        return f"{v:.2f}"
    if kind == "f1":
        return f"{v:.1f}"
    if kind == "p":
        if v >= 0.001:
            return f"{v:.2g}"
        m, e = f"{v:.1e}".split("e")          # e.g. 9.3e-10 -> 9.3\times10^{-10}
        return f"{m}\\times10^{{{int(e)}}}"
    return str(v)


def tex_numbers(res: dict) -> str:
    """\\pn{<key>} in the paper; an undefined key prints \\missingnum."""
    out = ["% GENERATED by bench/paper_numbers.py - do not edit. \\pn{key} reads these.",
           "\\providecommand{\\pn}[1]{\\ifcsname pn@#1\\endcsname\\csname pn@#1\\endcsname\\else\\missingnum\\fi}"]

    def put(k, v):
        if v is not None:
            out.append(f"\\expandafter\\def\\csname pn@{k}\\endcsname{{{v}}}")
    for k, s in res["summary"].items():
        for f in LEVELS + ("n", "restored", "useful", "wrong_fields", "deployed_wrong"):
            put(f"{k}/{f}", _fmt(s[f]))
        put(f"{k}/acc_lo", _fmt(s["acc_ci"][0], "pct")); put(f"{k}/acc_hi", _fmt(s["acc_ci"][1], "pct"))
        put(f"{k}/acc_pct", _fmt(s["accepted"] / s["n"], "pct") if s["n"] else None)
        put(f"{k}/res_lo", _fmt(s["restored_ci"][0], "pct")); put(f"{k}/res_hi", _fmt(s["restored_ci"][1], "pct"))
        put(f"{k}/res_pct", _fmt(s["restored"] / s["n"], "pct") if s["n"] else None)
        put(f"{k}/prec", _fmt(s["precision"], "f2")); put(f"{k}/cov", _fmt(s["coverage"], "f2"))
        put(f"{k}/vram", _fmt(s["peak_vram_gb"], "f1")); put(f"{k}/wall", _fmt(s["median_wall_min"], "f1"))
        for comp, cnt in s["normalisation_runs"].items():
            put(f"{k}/norm/{comp.replace(' ', '-')}", cnt)
        v4 = s["refused_rungs"].get("V4", 0); nref = s["n"] - s["accepted"]
        put(f"{k}/refV4", _fmt(v4)); put(f"{k}/refused", _fmt(nref))
    put("eq_margin", _fmt(EQ_MARGIN, "pct"))
    for g, n in res.get("changes", {}).items():     # how many changes each Task-2 set holds
        if n:
            put(f"t2/{g}/changes", n)
    for k, c in res["comparisons"].items():
        a, b = k.split(" vs ")
        b, name = b.split(" [")
        key = f"cmp/{a}/{b.split('/')[-2]}/{name[:-1]}"
        put(f"{key}/b", c["b"]); put(f"{key}/c", c["c"]); put(f"{key}/p", _fmt(c["p_runs"], "p"))
        put(f"{key}/sb", c["src_b"]); put(f"{key}/sc", c["src_c"]); put(f"{key}/ps", _fmt(c["p_sources"], "p"))
        if c.get("diff") is not None:       # percentage points, x - y, per-source means
            put(f"{key}/diff", _fmt(c["diff"], "pp")); put(f"{key}/srcn", c["sources"])
            put(f"{key}/dlo", _fmt(c["diff_ci95"][0], "pp")); put(f"{key}/dhi", _fmt(c["diff_ci95"][1], "pp"))
            put(f"{key}/dlo90", _fmt(c["diff_ci90"][0], "pp")); put(f"{key}/dhi90", _fmt(c["diff_ci90"][1], "pp"))
            put(f"{key}/eq", "yes" if c["equivalent"] else "no")
    return "\n".join(out) + "\n"


COLOURS = {"accepted": "lvAcc", "functional": "lvFun", "support": "lvSup", "report": "lvRep"}
ARM_LABEL = {"A": "\\armA{}", "B": "\\armB{}", "C": "\\armC{}", "T": "\\armT{} (32B)", "14B": "14B"}


def tex_levels_figure(res: dict) -> str:
    """Horizontal stacked bars: the distribution of runs over the outcome levels, full-system.
    A missing configuration is drawn as an empty outlined bar labelled ??."""
    S = res["summary"]
    blocks = [("Task 1, generated pools", [("t1/gen", a) for a in ("T", "C")]),
              ("Task 1, real software", [("t1/real", a) for a in ("T", "C")]),
              ("Task 2, development changes", [("t2/r3", a) for a in ("A", "B", "C", "14B", "T")]),
              ("Task 2, held-out changes", [("t2/ho", a) for a in ("A", "B", "C", "14B", "T")])]
    rows, labels, y = [], [], 0
    lines = ["% GENERATED by bench/paper_numbers.py - fig:levels-results",
             "\\begin{tikzpicture}[font=\\scriptsize]"]
    W = 5.6
    for title, items in blocks:
        lines.append(f"\\node[anchor=west, font=\\scriptsize\\itshape] at (-2.1,{-y*0.42:.2f}) {{{title}}};")
        y += 1
        for g, arm in items:
            s = S.get(f"{g}/{arm}/F")
            yy = -y * 0.42
            lines.append(f"\\node[anchor=east] at (0,{yy:.2f}) {{{ARM_LABEL[arm]}}};")
            if s is None or not s["n"]:
                lines.append(f"\\draw[black!40, dashed] (0,{yy-0.15:.2f}) rectangle ({W},{yy+0.15:.2f});"
                             f"\\node at ({W/2},{yy:.2f}) {{\\missingnum}};")
            else:
                x = 0.0
                for l in LEVELS:
                    w = W * s[l] / s["n"]
                    if w > 0:
                        lines.append(f"\\fill[{COLOURS[l]}] ({x:.3f},{yy-0.15:.2f}) rectangle ({x+w:.3f},{yy+0.15:.2f});")
                        if s[l] and w > 0.25:
                            lines.append(f"\\node at ({x+w/2:.3f},{yy:.2f}) {{{s[l]}}};")
                    x += w
                lines.append(f"\\draw[black!50] (0,{yy-0.15:.2f}) rectangle ({W},{yy+0.15:.2f});")
                lines.append(f"\\node[anchor=west, font=\\tiny] at ({W+0.05},{yy:.2f}) {{/{s['n']}}};")
            y += 1
    yy = -y * 0.42 - 0.1
    x = 0.0
    for l in LEVELS:
        lines.append(f"\\fill[{COLOURS[l]}] ({x:.2f},{yy-0.1:.2f}) rectangle ({x+0.25:.2f},{yy+0.1:.2f});"
                     f"\\node[anchor=west] at ({x+0.28:.2f},{yy:.2f}) {{{l}}};")
        x += 1.45
    lines.append("\\end{tikzpicture}")
    return "\n".join(lines) + "\n"


T2_ORDER = {"r3": ["r3_sshd_deb12", "r3_suricata_v7", "r3_nginx_json", "r3_syslog_5424", "r3_apache_v24",
                   "r3_firewall_json"],
            "r4": ["r4_postfix_37", "r4_haproxy_json", "r4_caddy_json", "r4_dovecot_24"],
            # r5 in the pre-registered order: configuration changes, then upgrades
            "r5": ["r5_envoy_json", "r5_tomcat_json", "r5_grafana_json", "r5_samba_json", "r5_varnish_json",
                   "r5_mosquitto_20", "r5_slapd_25", "r5_proftpd_138", "r5_freeradius_32", "r5_dropbear_2025",
                   "r5_clamav_d12", "r5_prosody_012", "r5_openvpn_26"],
            # r6, the test set, in the pre-registered order of attempt
            "r6": ["r6_rabbitmq_json", "r6_authelia_json", "r6_lighttpd_1469", "r6_opensmtpd_d12",
                   "r6_pureftpd_1050", "r6_rsyncd_327", "r6_tinyproxy_111", "r6_courier_d12",
                   "r6_vaultwarden_132", "r6_gitea_122"]}
T2_NAMES = {"r3_sshd_deb12": "OpenSSH", "r3_suricata_v7": "Suricata", "r3_nginx_json": "nginx",
            "r3_syslog_5424": "syslog", "r3_apache_v24": "Apache", "r3_firewall_json": "netfilter",
            "r4_postfix_37": "Postfix", "r4_haproxy_json": "HAProxy", "r4_caddy_json": "Caddy",
            "r4_dovecot_24": "Dovecot",
            "r5_envoy_json": "Envoy", "r5_tomcat_json": "Tomcat", "r5_grafana_json": "Grafana",
            "r5_samba_json": "Samba", "r5_varnish_json": "Varnish", "r5_mosquitto_20": "Mosquitto",
            "r5_slapd_25": "OpenLDAP", "r5_proftpd_138": "ProFTPD", "r5_freeradius_32": "FreeRADIUS",
            "r5_dropbear_2025": "Dropbear", "r5_clamav_d12": "ClamAV", "r5_prosody_012": "Prosody",
            "r5_openvpn_26": "OpenVPN",
            "r6_rabbitmq_json": "RabbitMQ", "r6_authelia_json": "Authelia", "r6_lighttpd_1469": "lighttpd",
            "r6_opensmtpd_d12": "OpenSMTPD", "r6_pureftpd_1050": "Pure-FTPd", "r6_rsyncd_327": "rsyncd",
            "r6_tinyproxy_111": "Tinyproxy", "r6_courier_d12": "Courier", "r6_vaultwarden_132": "Vaultwarden",
            "r6_gitea_122": "Gitea"}
T2_GROUP_LABEL = {"r3": "development (r3)", "r4": "held out (r4)", "r5": "held out (r5)", "r6": "test (r6)"}


def tex_task2_grid(res: dict, t3: dict | None) -> str:
    """Rows: configurations; columns: the changes, by set; each cell one square per full-system
    seed, coloured by outcome level. The top row is the old parser left alone (no model).
    The r5 set is drawn once any of its runs exists."""
    P = res["per_source"]
    arms = ["A", "B", "C", "14B", "T"]
    pools = ["r3", "r4"] + [p for p in ("r5", "r6") if any(k.startswith(f"t2/{p}/") for k in P)]
    dx, dy, gap = 0.62, 0.42, 0.25
    cols, xs, x = [], [], 0.0
    spans = []
    for g, pool in enumerate(pools):
        x0 = x
        for sid in T2_ORDER[pool]:
            cols.append(sid); xs.append(x); x += dx
        spans.append((pool, x0, x - dx))
        x += gap
    L = ["% GENERATED by bench/paper_numbers.py - fig:task2-grid",
         "\\begin{tikzpicture}[font=\\scriptsize, cell/.style={minimum size=2.6mm, inner sep=0, draw=black!45}]"]
    for sid, x in zip(cols, xs):
        L.append(f"\\node[rotate=60, anchor=south west, inner sep=1pt] at ({x-0.12:.2f},0.12) {{{T2_NAMES[sid]}}};")
    for pool, a, b in spans:
        L.append(f"\\node[font=\\tiny\\itshape] at ({(a + b) / 2:.2f},1.45) {{{T2_GROUP_LABEL[pool]}}};")
    rows = [("old parser, no model", None)] + [(ARM_LABEL[a], a) for a in arms]
    T3C = {"broken": "lvRep", "partial": "lvSup", "intact": "lvAcc"}
    for i, (lab, arm) in enumerate(rows):
        y = -(i + 0.6) * dy
        L.append(f"\\node[anchor=east] at (-0.3,{y:.2f}) {{{lab}}};")
        for sid, x in zip(cols, xs):
            if arm is None:
                v = (t3 or {}).get(sid)
                fill = T3C.get(v, "white")
                L.append(f"\\node[cell, fill={fill}, minimum width=5.4mm] at ({x:.2f},{y:.2f}) {{{'' if v else '?'}}};")
                continue
            pool = sid[:2]
            runs = [lv for s, _, lv in P.get(f"t2/{pool}/{arm}/F", []) if s == sid]
            if not runs:
                L.append(f"\\node[cell, dashed, minimum width=5.4mm] at ({x:.2f},{y:.2f}) {{\\tiny ??}};")
                continue
            # one square per seed: two on r3-r5, five on the test set (narrower)
            n = min(len(runs), 5)
            w = 0.56 / max(n, 2)
            for k, lv in enumerate(runs[:n]):
                L.append(f"\\node[cell, fill={COLOURS.get(lv, 'white')}, minimum width={w * 10 - 0.2:.1f}mm] "
                         f"at ({x - 0.28 + w * (k + 0.5):.2f},{y:.2f}) {{}};")
    L.append("\\end{tikzpicture}")
    return "\n".join(L) + "\n"


def tex_precision_coverage(res: dict) -> str:
    """Reliability against breadth: field precision (y) against coverage (x), full-system."""
    S = res["summary"]
    marks = {"B": ("triangle", "7B"), "C": ("*", "7B trained"), "14B": ("square", "14B"), "T": ("diamond", "32B")}
    L = ["% GENERATED by bench/paper_numbers.py - fig:prec-cov",
         "\\begin{tikzpicture}\\begin{axis}[width=\\columnwidth, height=5.4cm, xmin=0.2, xmax=1, ymin=0.7, ymax=1.01,",
         " xlabel={coverage (correct / fields the truth maps)}, ylabel={precision}, every axis/.append style={font=\\scriptsize},",
         " legend style={font=\\tiny, at={(0.5,-0.32)}, anchor=north, draw=none}, legend columns=3]"]
    series = [("t1/all", "Task 1", "black"), ("t2/r3", "Task 2 dev", "blue!70!black"),
              ("t2/ho", "Task 2 held-out", "red!70!black")]
    for g, name, col in series:
        for arm, (m, lab) in marks.items():
            s = S.get(f"{g}/{arm}/F")
            if s and s["precision"] is not None and s["coverage"] is not None:
                L.append(f"\\addplot[only marks, mark={m}, mark size=2.2pt, color={col}] coordinates "
                         f"{{({s['coverage']:.3f},{s['precision']:.3f})}};")
                L.append(f"\\addlegendentry{{{name}, {lab}}}")
    L.append("\\end{axis}\\end{tikzpicture}")
    return "\n".join(L) + "\n"


# Weights as served (ollama list): 7B q8_0 8.2 GB (+ two LoRA adapters for C), 14B q4_K_M 9.0 GB,
# 32B q4_K_M 19.0 GB. The KV cache comes on top and depends on window and parallel requests.
WEIGHTS_GB = {"B": 8.2, "C": 8.2, "14B": 9.0, "T": 19.0}
PARAMS_B = {"B": 7, "C": 7, "14B": 14, "T": 32}


def tex_size(res: dict) -> str:
    """Model size against detection restored (accepted + functional), Task 2, full-system,
    with Wilson intervals; x = peak GPU memory measured in the runs."""
    S = res["summary"]
    L = ["% GENERATED by bench/paper_numbers.py - fig:size",
         "\\begin{tikzpicture}\\begin{axis}[width=\\columnwidth, height=4.6cm, ymin=0, ymax=100,",
         " xlabel={parameters, with weights in GPU memory}, ylabel={runs restoring detection (\\%)}, every axis/.append style={font=\\scriptsize},",
         " legend style={font=\\tiny, at={(0.02,0.98)}, anchor=north west}, xmin=3, xmax=36,",
         " xtick={7,14,32}, xticklabels={{7B, 8.2\\,GB},{14B, 9.0\\,GB},{32B, 19\\,GB}}]"]
    for g, name, col in (("t2/r3", "development", "blue!70!black"), ("t2/ho", "held-out", "red!70!black")):
        pts = []
        for arm in ("B", "C", "14B", "T"):
            s = S.get(f"{g}/{arm}/F")
            if s and s["n"]:
                p = 100 * s["restored"] / s["n"]
                lo, hi = (100 * v for v in s["restored_ci"])
                x = PARAMS_B[arm] + (0.8 if arm == "C" else 0)
                tag = {"B": "B", "C": "C", "14B": "14B", "T": "T"}[arm]
                pts.append(f"({x:.2f},{p:.1f}) +- (0,{max(p-lo, hi-p):.1f}) [{tag}]")
        if pts:
            L.append(f"\\addplot[color={col}, only marks, mark=*, nodes near coords, point meta=explicit symbolic, "
                     f"every node near coord/.style={{font=\\tiny, anchor=west}}, "
                     f"error bars/.cd, y dir=both, y explicit] coordinates {{{' '.join(pts)}}};")
            L.append(f"\\addlegendentry{{{name}}}")
    if len(L) == 4:
        L.append("\\node at (axis cs:13,50) {\\missingnum};")
    L.append("\\end{axis}\\end{tikzpicture}")
    return "\n".join(L) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="bench.paper_numbers")
    ap.add_argument("--roots", nargs="+", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=Path("results/paper"))
    ap.add_argument("--tex", type=Path)
    ap.add_argument("--t3", type=Path, default=Path("testbed/r3/t3_results.json"))
    a = ap.parse_args(argv)
    res = build(a.roots)
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "numbers.json").write_text(json.dumps({k: v for k, v in res.items() if k != "runs"},
                                                   indent=1, default=list) + "\n", encoding="utf-8")
    t3 = None
    if a.t3.is_file():
        raw = json.loads(a.t3.read_text(encoding="utf-8"))
        items = raw if isinstance(raw, list) else raw.get("pairs", [])
        t3 = {}
        for r in items:
            k, n = (int(x) for x in str(r.get("rules_firing", "0/1")).split("/"))
            read = r.get("lines_read", 0)
            t3[r.get("new_source")] = ("intact" if k == n and read >= 0.999 else
                                       "broken" if k == 0 else "partial")
    if a.tex:
        a.tex.mkdir(parents=True, exist_ok=True)
        (a.tex / "numbers.tex").write_text(tex_numbers(res), encoding="utf-8")
        (a.tex / "fig-levels-results.tex").write_text(tex_levels_figure(res), encoding="utf-8")
        (a.tex / "fig-task2-grid.tex").write_text(tex_task2_grid(res, t3), encoding="utf-8")
        (a.tex / "fig-prec-cov.tex").write_text(tex_precision_coverage(res), encoding="utf-8")
        (a.tex / "fig-size.tex").write_text(tex_size(res), encoding="utf-8")
        from bench import paper_figures as pf
        pf.write_all(res, a.tex, a.roots, t3)
    S = res["summary"]
    print(f"{'cell':<26}{'n':>4}{'acc':>5}{'fun':>5}{'sup':>5}{'rep':>5}{'unj':>5}{'prec':>6}{'cov':>6}")
    for k in sorted(S):
        if k.count("/") == 3 and k.split("/")[1] in ("gen", "real", "all", "r3", "r4", "r5", "r6", "ho"):
            s = S[k]
            pr = f"{s['precision']:.2f}" if s["precision"] is not None else "-"
            cv = f"{s['coverage']:.2f}" if s["coverage"] is not None else "-"
            print(f"{k:<26}{s['n']:>4}{s['accepted']:>5}{s['functional']:>5}{s['support']:>5}"
                  f"{s['report']:>5}{s['unjudged']:>5}{pr:>6}{cv:>6}")
    print("\ncomparisons (b = first better, c = second better):")
    for k, c in res["comparisons"].items():
        dd = (f"   diff {100 * c['diff']:+.0f} pp [{100 * c['diff_ci95'][0]:+.0f}, {100 * c['diff_ci95'][1]:+.0f}]"
              f" eq={c['equivalent']}") if c.get("diff") is not None else ""
        print(f"  {k:<52} runs {c['b']}:{c['c']} p={c['p_runs']:.3g}   sources {c['src_b']}:{c['src_c']} p={c['p_sources']:.3g}{dd}")
    print(f"\nTask-2 changes per set: {res['changes']}  (r5 pooled: {res['r5_pooled']})")
    print(f"\nmissing ({len(res['missing_tags'])}): {' '.join(res['missing_tags'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Every number, table and result figure of the round-10 ECS paper, from the stored run records.

    python -m bench.paper_r10 --roots ~/.cache/ecs-r10/card4/results \\
        --out ../../Dissertation/papers/ECS_log_adaptation/filtred-ECS_log_adaptation/generated

Task 3 (adversarial) numbers come from the summary bench/adv_summary.py writes (--adv), under the adv/ keys.

Written 2026-11-04 for the paper rewritten from scratch after round 10 (PLAN_ROUND10_ARM_C.md, F9). It reuses
bench/paper_numbers.py's loader and statistics (Wilson intervals, exact sign test by source, McNemar by run,
percentile bootstrap over sources with seed 0, equivalence at +-15 points) so the numbers agree with every
figure already recorded in ROUND3_VERSION_DRIFT.md, and bench/wrong_accept.py for what a run would deploy.

A cell whose result file does not exist yet is printed as \\missingnum by the paper, never as zero, and a figure
draws it as "pending". Nothing here is typed by hand except the facts of the r7 pairs (versions, the kind of
change, and what the previous parser does on the new lines, measured on the reference parsers in F8a and
recorded in ROUND3_VERSION_DRIFT.md "r7 gold and T3").
"""
from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean, median
import argparse
import json

from bench.paper_numbers import _find, _rows, compare, load, wilson

ARMS = ("C", "14B", "B")              # the three arms of the paper
ALL_ARMS = ("C", "14B", "B", "org9", "Cdpo")
T1_POOLS = ("id", "drift", "dev", "ood")
T2_POOLS = ("r3", "r4", "r5", "r6")
# The 14B's full-system cell on the test set. q8_numbers swaps in the post-hoc 8-bit run (Block C of
# POSTHOC_REVIEW_ANALYSES.md) to compute its keys with exactly the code of the 4-bit run.
T14_R7_FULL = "T14-p22"


def tags() -> dict[tuple[str, str, str, str], tuple[str, list[str]]]:
    """(task, pool, arm, mode) -> (tag, tags whose runs replace the tag's for the same source and seed)."""
    t: dict = {}
    for m in ("F", "E"):
        for p in T1_POOLS:
            for a, s in (("C", "C10s-p21"), ("14B", "T14-p21"), ("B", "B-p21"), ("org9", "Cr9-p21")):
                t[("t1", p, a, m)] = (f"{m}-{s}-{p}", [])
        for p in T2_POOLS:
            for a, s in (("C", "C10-p21"), ("14B", "T14-p20"), ("B", "B-p20"), ("org9", "Cr9-p20"),
                         ("Cdpo", "C10d-p21")):
                also = [f"{m}-T14-p20b-r6"] if (a == "14B" and p == "r6") else []
                t[("t2", p, a, m)] = (f"{m}-{s}-{p}", also)
        for pool in ("r7", "t3", "t3lh"):
            for a, s in (("C", "C10s-p22"), ("14B", "T14-p22"), ("B", "B-p22"), ("org9", "Cr9-p22")):
                if (pool, a, m) == ("r7", "14B", "F"):
                    s = T14_R7_FULL
                t[(pool, pool, a, m)] = (f"{m}-{s}-{pool}", [])
        # AIT-LDS from the public Filebeat parser as the previous parser (Task 3b, TASK3_EXTERNAL.md, own prereg)
        for a, s in (("C", "C10s-p23"), ("14B", "T14-p23"), ("B", "B-p23")):
            t[("t3b", "t3b", a, m)] = (f"{m}-{s}-t3b", [])
    return t


# ----------------------------------------------------------------------------- r7 facts
# source id -> (label, versions, kind of change, group, % of new lines the previous parser reads,
#               rules firing with the previous parser / rules). F8a, ROUND3_VERSION_DRIFT.md "r7 gold and T3".
R7 = {
    "r7_389ds_31": ("389-DS", "2.5 $\\to$ 3.1", "text $\\to$ JSON access log", "struct", 0, (0, 3)),
    "r7_synapse_json": ("Synapse", "1.120.2", "text $\\to$ JSON formatter", "struct", 0, (0, 5)),
    "r7_kamailio_json": ("Kamailio", "5.8.4", "text $\\to$ JSON log engine", "struct", 0, (0, 4)),
    "r7_nextcloud_syslog": ("Nextcloud", "30.0.17", "audit file $\\to$ syslog", "struct", 0, (0, 5)),
    "r7_mattermost_text": ("Mattermost", "10.5.2", "JSON $\\to$ text", "struct", 0, (0, 5)),
    "r7_emqx_58": ("EMQX", "4.4 $\\to$ 5.8", "messages rewritten", "reword", 0, (0, 3)),
    "r7_inspircd_47": ("InspIRCd", "3.15 $\\to$ 4.7", "messages rewritten", "reword", 0, (0, 4)),
    "r7_radicale_353": ("Radicale", "3.1 $\\to$ 3.5", "messages rewritten", "reword", 0, (0, 2)),
    "r7_knot_346": ("Knot DNS", "3.2 $\\to$ 3.4", "messages rewritten", "reword", 0, (0, 3)),
    "r7_icinga2_214": ("Icinga 2", "2.13 $\\to$ 2.14", "messages rewritten", "reword", 10, (0, 4)),
    "r7_pdnsrec_52": ("PowerDNS Rec.", "4.8 $\\to$ 5.2", "keys added and renamed", "partial", 50, (0, 4)),
    "r7_nsd_4120": ("NSD", "4.6 $\\to$ 4.12", "one message changed", "partial", 44, (1, 2)),
    "r7_ocserv_130": ("ocserv", "1.1.6 $\\to$ 1.3.0", "one message changed", "partial", 73, (2, 2)),
    "r7_mumble_15": ("Mumble", "1.3 $\\to$ 1.5", "format changed, still read", "nonbreak", 100, (3, 3)),
    "r7_stunnel_574": ("stunnel", "5.68 $\\to$ 5.74", "format changed, still read", "nonbreak", 100, (3, 3)),
    "r7_ngircd_27": ("ngIRCd", "26.1 $\\to$ 27", "control", "control", 100, (4, 4)),
    "r7_privoxy_400": ("Privoxy", "3.0.34 $\\to$ 4.0.0", "control", "control", 100, (1, 1)),
    "r7_unbound_126": ("Unbound", "1.17.1 $\\to$ 1.26.2", "control", "control", 100, (3, 3)),
    "r7_rspamd_3121": ("Rspamd", "3.4 $\\to$ 3.12.1", "control", "control", 100, (2, 2)),
    "r7_sendmail_8181": ("Sendmail", "8.17.1.9 $\\to$ 8.18.1", "control", "control", 100, (5, 5)),
}
GROUPS = ("struct", "reword", "partial", "nonbreak", "control")
GROUP_LABEL = {"struct": "Structural", "reword": "Reworded", "partial": "Partial",
               "nonbreak": "Non-breaking", "control": "Control"}
REAL = {s for s, v in R7.items() if v[3] != "control"}
BREAKING = {s for s, v in R7.items() if v[3] not in ("control", "nonbreak")}


def _sub(rows, keep):
    return None if rows is None else [r for r in rows if r["source"] in keep]


def _pct(x):
    return None if x is None else round(100 * x)


class Out:
    def __init__(self):
        self.kv: dict[str, str] = {}

    def put(self, k: str, v) -> None:
        if v is None:
            return
        if isinstance(v, float):
            v = f"{v:.1f}"
        self.kv[k] = str(v)

    def tex(self) -> str:
        lines = ["% Generated by bench/paper_r10.py from the run records. Do not edit."]
        for k in sorted(self.kv):
            lines.append(f"\\expandafter\\def\\csname pn@{k}\\endcsname{{{self.kv[k]}}}")
        return "\n".join(lines) + "\n"


def cell_numbers(o: Out, key: str, rows):
    if rows is None:
        return
    n = len(rows)
    k = sum(r["level"] == "accepted" for r in rows)
    lo, hi = wilson(k, n)
    o.put(f"{key}/acc", k)
    o.put(f"{key}/n", n)
    o.put(f"{key}/pct", _pct(k / n) if n else 0)
    o.put(f"{key}/lo", _pct(lo))
    o.put(f"{key}/hi", _pct(hi))
    o.put(f"{key}/src", len({r["source"] for r in rows}))


def cmp_numbers(o: Out, key: str, x, y):
    if x is None or y is None:
        return None
    c = compare(x, y)
    if c["diff"] is None:
        return None
    pp = lambda v: f"{100 * v:+.1f}".replace("-", "$-$")
    # a difference that rounds to zero prints as 0.0, not -0.0 or +0.0
    o.put(f"{key}/diff", "0.0" if round(100 * c["diff"], 1) == 0 else pp(c["diff"]))
    o.put(f"{key}/lo90", pp(c["diff_ci90"][0]))
    o.put(f"{key}/hi90", pp(c["diff_ci90"][1]))
    o.put(f"{key}/lo95", pp(c["diff_ci95"][0]))
    o.put(f"{key}/hi95", pp(c["diff_ci95"][1]))
    o.put(f"{key}/sb", c["src_b"])
    o.put(f"{key}/sc", c["src_c"])
    ps = c["p_sources"]
    o.put(f"{key}/ps", f"{ps:.2f}" if ps >= 0.01 else f"{ps:.3f}" if ps >= 0.001 else "0.001")
    o.put(f"{key}/psop", "=" if ps >= 0.001 else "<")
    o.put(f"{key}/b", c["b"])
    o.put(f"{key}/c", c["c"])
    o.put(f"{key}/pr", f"{c['p_runs']:.2f}" if c["p_runs"] >= 0.01 else f"{c['p_runs']:.3f}")
    o.put(f"{key}/nsrc", c["sources"])
    lo, hi = c["diff_ci90"]
    o.put(f"{key}/eq", "equivalent" if c["equivalent"] else "not equivalent")
    o.put(f"{key}/ni", "not inferior" if lo > -0.15 else "inferiority not excluded")
    return c


# ----------------------------------------------------------------------------- figures
PEND = "\\textit{pending}"


def fig_dumbbell(cells) -> str:
    """Task 1 and Task 2: model-only (hollow) to full system (filled), per arm, one panel per pool."""
    panels = [("t1", "all", "Task 1, all four pools"), ("t1", "ood", "Task 1, unseen real software"),
              ("t2", "dev", "Task 2, development changes"), ("r7", "real", "Task 2, test: 15 real changes")]
    arms = ("C", "14B", "B")
    s = ["% Generated by bench/paper_r10.py. Do not edit.",
         "\\begin{tikzpicture}",
         "\\begin{groupplot}[group style={group size=2 by 2, horizontal sep=1.1cm, vertical sep=1.25cm},",
         "  width=0.47\\linewidth, height=3.4cm, xmin=0, xmax=100, ymin=0.4, ymax=3.6,",
         "  ytick={1,2,3}, yticklabels={\\armB{},\\armT{},\\armC{}}, y tick label style={font=\\footnotesize},",
         "  xlabel={accepted runs (\\%)}, xlabel style={font=\\footnotesize, yshift=3pt},",
         "  x tick label style={font=\\footnotesize}, xmajorgrids, grid style={gray!20},",
         "  title style={font=\\footnotesize\\bfseries, yshift=-4pt}, axis line style={gray!60}, tick style={gray!60}]"]
    for task, pool, title in panels:
        s.append(f"\\nextgroupplot[title={{{title}}}]")
        for y, a in zip((3, 2, 1), arms):
            e, f = cells.get((task, pool, a, "E")), cells.get((task, pool, a, "F"))
            col = {"C": "armC", "14B": "arm14", "B": "armB"}[a]
            if e is None or f is None:
                s.append(f"\\node[font=\\scriptsize, gray] at (axis cs:50,{y}) {{{PEND}}};")
                continue
            pe = 100 * sum(r['level'] == 'accepted' for r in e) / len(e)
            pf = 100 * sum(r['level'] == 'accepted' for r in f) / len(f)
            s.append(f"\\draw[{col}, line width=2.2pt, opacity=0.35] (axis cs:{pe:.1f},{y}) -- (axis cs:{pf:.1f},{y});")
            s.append(f"\\addplot[only marks, mark=o, mark size=2.6pt, {col}, thick] coordinates {{({pe:.1f},{y})}};")
            s.append(f"\\addplot[only marks, mark=*, mark size=2.8pt, {col}] coordinates {{({pf:.1f},{y})}};")
            s.append(f"\\node[font=\\tiny, {col}, anchor=south] at (axis cs:{pf:.1f},{y}+0.12) {{{pf:.0f}}};")
            s.append(f"\\node[font=\\tiny, {col}!80!black, anchor=north] at (axis cs:{pe:.1f},{y}-0.12) {{{pe:.0f}}};")
    s += ["\\end{groupplot}", "\\end{tikzpicture}"]
    return "\n".join(s) + "\n"


def fig_forest(rows, compact: bool = False) -> str:
    """Every pre-registered comparison: mean per-source difference, 90% (thick) and 95% (thin) intervals.
    compact (Section 5, column width): labels shortened by the caller, no numeric column (the text gives them)."""
    n = len(rows)
    h = (0.55 * n + 1.2) if compact else (0.62 * n + 1.3)
    s = ["% Generated by bench/paper_r10.py. Do not edit.",
         "\\begin{tikzpicture}",
         f"\\begin{{axis}}[width={0.6 if compact else 0.62}\\linewidth, height={h:.2f}cm, xmin={-20 if compact else -40}, xmax={50 if compact else 60}, ymin=0.3, ymax={n + 0.7},",
         "  axis y line=none, axis x line*=bottom, xlabel={difference in per-source mean acceptance (points)},",
         "  xlabel style={font=\\footnotesize}, x tick label style={font=\\footnotesize}, "
         f"xtick={{{'-15,0,15,30,45' if compact else '-30,-15,0,15,30,45'}}},",
         "  clip=false, xmajorgrids, grid style={gray!15}]",
         f"\\fill[eqband] (axis cs:-15,0.3) rectangle (axis cs:15,{n + 0.7});",
         f"\\draw[gray!70, dashed] (axis cs:0,0.3) -- (axis cs:0,{n + 0.7});",
         f"\\node[font=\\tiny, gray!70!black, anchor=south] at (axis cs:0,{n + 0.7}) "
         f"{{{'margin $\\pm$15 (a test for the primary only)' if compact else 'equivalence margin $\\pm$15'}}};"]
    for i, (label, c, col, bold) in enumerate(rows):
        y = n - i
        lab = f"\\textbf{{{label}}}" if bold else label
        s.append(f"\\node[font=\\scriptsize, anchor=east, align=right] at (axis cs:{-21 if compact else -41},{y}) {{{lab}}};")
        if c is None:
            s.append(f"\\node[font=\\scriptsize, gray] at (axis cs:10,{y}) {{{PEND}}};")
            continue
        d = 100 * c["diff"]
        l9, h9 = (100 * v for v in c["diff_ci90"])
        l5, h5 = (100 * v for v in c["diff_ci95"])
        s.append(f"\\draw[{col}, thin] (axis cs:{l5:.1f},{y}) -- (axis cs:{h5:.1f},{y});")
        s.append(f"\\draw[{col}, line width=2.4pt] (axis cs:{l9:.1f},{y}) -- (axis cs:{h9:.1f},{y});")
        mark = "diamond*" if bold else "*"
        s.append(f"\\addplot[only marks, mark={mark}, mark size={3.4 if bold else 2.4}pt, {col}, "
                 f"mark options={{fill=white, draw={col}, line width=1pt}}] coordinates {{({d:.1f},{y})}};")
        if compact:
            continue
        ps = c["p_sources"]
        pstr = f"={ps:.2f}" if ps >= 0.01 else f"={ps:.3f}" if ps >= 0.001 else "<0.001"
        s.append(f"\\node[font=\\tiny, anchor=west] at (axis cs:61,{y}) "
                 f"{{{d:+.1f} [{l9:+.1f}, {h9:+.1f}]\\quad {c['src_b']}:{c['src_c']}, $p{pstr}$}};")
    if not compact:
        s.append(f"\\node[font=\\tiny\\bfseries, anchor=west] at (axis cs:61,{n + 0.6}) "
                 "{diff.\\ [90\\% CI]\\quad sources +:$-$, sign test};")
    s += ["\\end{axis}", "\\end{tikzpicture}"]
    return "\n".join(s) + "\n"


OUTCOME_COLOUR = {"accepted": "lvAcc", "V4": "lvV4", "V3": "lvV3", "V2": "lvV2", "V1": "lvV1", None: "lvPend"}


def _outcome(r) -> str:
    if r["level"] == "accepted":
        return "accepted"
    rung = r.get("rung") or "V1"
    return "V4" if rung == "V4" else "V3" if rung.startswith("V3") else "V2" if rung == "V2" else "V1"


def fig_grid(cells) -> str:
    """r7: every run, source x (arm, mode) x seed, coloured by where it ended."""
    blocks = [(a, m) for m in ("F", "E") for a in ARMS]
    order = sorted(R7, key=lambda s: (GROUPS.index(R7[s][3]), R7[s][0].lower()))
    tile, gap, bgap = 0.26, 0.04, 0.32
    s = ["% Generated by bench/paper_r10.py. Do not edit.",
         "\\begin{tikzpicture}[x=1cm, y=1cm, font=\\scriptsize]"]
    bw = 5 * (tile + gap)
    x0 = 0.0
    xs = []
    for j, (a, m) in enumerate(blocks):
        x = x0 + j * (bw + bgap) + (0.35 if m == "E" else 0)
        xs.append(x)
    top = 0.0
    y = top
    prev = None
    for sid in order:
        g = R7[sid][3]
        if g != prev:
            y -= 0.22 if prev else 0
            s.append(f"\\node[anchor=west, font=\\scriptsize\\bfseries\\itshape, text=gray!70!black] "
                     f"at (-3.15,{y - 0.02:.2f}) {{{GROUP_LABEL[g]}}};")
            y -= 0.30
            prev = g
        s.append(f"\\node[anchor=east] at (-0.55,{y + tile / 2:.2f}) {{{R7[sid][0]}}};")
        rd = R7[sid][4]
        s.append(f"\\fill[gray!20] (-0.5,{y + 0.04:.2f}) rectangle (-0.08,{y + tile - 0.04:.2f});")
        if rd:
            s.append(f"\\fill[gray!65] (-0.5,{y + 0.04:.2f}) rectangle ({-0.5 + 0.42 * rd / 100:.3f},{y + tile - 0.04:.2f});")
        for (a, m), x in zip(blocks, xs):
            rows = cells.get(("r7", "r7", a, m))
            by = {r["seed"]: r for r in rows if r["source"] == sid} if rows else {}
            for k in range(5):
                r = by.get(k)
                col = OUTCOME_COLOUR[_outcome(r)] if r else OUTCOME_COLOUR[None]
                xx = x + k * (tile + gap)
                s.append(f"\\fill[{col}] ({xx:.3f},{y:.3f}) rectangle ({xx + tile:.3f},{y + tile:.3f});")
        y -= tile + gap + 0.02
    ybot = y + tile
    for (a, m), x in zip(blocks, xs):
        name = {"C": "\\armC{}", "14B": "\\armT{}", "B": "\\armB{}"}[a]
        s.append(f"\\node[anchor=south, font=\\scriptsize\\bfseries] at ({x + bw / 2 - gap:.2f},{top + 0.3:.2f}) {{{name}}};")
    fx = (xs[0] + xs[2] + bw) / 2
    ex = (xs[3] + xs[5] + bw) / 2
    s.append(f"\\node[anchor=south, font=\\scriptsize] at ({fx:.2f},{top + 0.62:.2f}) {{full system (5 seeds each)}};")
    s.append(f"\\node[anchor=south, font=\\scriptsize] at ({ex:.2f},{top + 0.62:.2f}) {{model only (5 seeds each)}};")
    s.append(f"\\draw[gray!50] ({xs[0]:.2f},{top + 0.6:.2f}) -- ({xs[2] + bw - gap:.2f},{top + 0.6:.2f});")
    s.append(f"\\draw[gray!50] ({xs[3]:.2f},{top + 0.6:.2f}) -- ({xs[5] + bw - gap:.2f},{top + 0.6:.2f});")
    s.append(f"\\node[anchor=south, font=\\tiny, align=center] at (-0.29,{top + 0.3:.2f}) {{old\\\\parser}};")
    items = [("lvAcc", "accepted"), ("lvV4", "refused at V4: rules do not fire"),
             ("lvV3", "refused at V3 or V3.5: fails in Logstash, loses values"),
             ("lvV2", "refused at V2: lines unread"), ("lvV1", "refused at V1 or earlier"), ("lvPend", "not run yet")]
    for i, (col, lab) in enumerate(items):
        lx = -3.0 + (i % 3) * 5.2
        ly = ybot - 0.55 - (i // 3) * 0.32
        s.append(f"\\fill[{col}] ({lx:.2f},{ly:.2f}) rectangle ({lx + 0.22:.2f},{ly + 0.22:.2f});")
        s.append(f"\\node[anchor=west, font=\\tiny] at ({lx + 0.25:.2f},{ly + 0.11:.2f}) {{{lab}}};")
    lx, ly = -3.0 + 3 * 5.2 - 0.6, ybot - 0.55
    s.append(f"\\fill[gray!65] ({lx:.2f},{ly + 0.04:.2f}) rectangle ({lx + 0.3:.2f},{ly + 0.18:.2f});")
    s.append(f"\\node[anchor=west, font=\\tiny, align=left] at ({lx + 0.33:.2f},{ly + 0.11:.2f}) {{old parser:\\\\share of new lines read}};")
    s.append("\\end{tikzpicture}")
    return "\n".join(s) + "\n"


def fig_grid_full(cells) -> str:
    """Section 5 (2026-11-08): the test-set grid at column width, full system only (model-only aggregates are in the
    main table), with the share of new lines the previous parser reads and the rules it still fires."""
    order = sorted(R7, key=lambda s: (GROUPS.index(R7[s][3]), R7[s][0].lower()))
    tile, gap, bgap = 0.235, 0.03, 0.26
    bw = 5 * (tile + gap)
    xs = [j * (bw + bgap) for j in range(len(ARMS))]
    s = ["% Generated by bench/paper_r10.py. Do not edit.",
         "\\begin{tikzpicture}[x=1cm, y=1cm, font=\\scriptsize]"]
    top = y = 0.0
    prev = None
    for sid in order:
        g = R7[sid][3]
        if g != prev:
            y -= 0.12 if prev else 0
            s.append(f"\\node[anchor=west, font=\\scriptsize\\itshape, text=gray!70!black] at (-3.55,{y + 0.02:.2f}) "
                     f"{{{GROUP_LABEL[g]}}};")
            y -= 0.33
            prev = g
        s.append(f"\\node[anchor=east] at (-1.25,{y + tile / 2:.2f}) {{{R7[sid][0]}}};")
        rd = R7[sid][4]
        s.append(f"\\fill[gray!20] (-1.2,{y + 0.04:.2f}) rectangle (-0.8,{y + tile - 0.04:.2f});")
        if rd:
            s.append(f"\\fill[gray!65] (-1.2,{y + 0.04:.2f}) rectangle ({-1.2 + 0.4 * rd / 100:.3f},{y + tile - 0.04:.2f});")
        fired, nr = R7[sid][5]
        s.append(f"\\node[anchor=center, font=\\tiny{', text=lvV4' if fired == 0 else ''}] at (-0.42,{y + tile / 2:.2f}) "
                 f"{{{fired}/{nr}}};")
        for a, x in zip(ARMS, xs):
            rows = cells.get(("r7", "r7", a, "F"))
            by = {r["seed"]: r for r in rows if r["source"] == sid} if rows else {}
            for k in range(5):
                r = by.get(k)
                col = OUTCOME_COLOUR[_outcome(r)] if r else OUTCOME_COLOUR[None]
                xx = x + k * (tile + gap)
                s.append(f"\\fill[{col}] ({xx:.3f},{y:.3f}) rectangle ({xx + tile:.3f},{y + tile:.3f});")
        y -= tile + gap + 0.015
    ybot = y + tile
    for a, x in zip(ARMS, xs):
        s.append(f"\\node[anchor=south, font=\\scriptsize\\bfseries] at ({x + bw / 2 - gap:.2f},{top + 0.28:.2f}) "
                 f"{{{ARM_NAME[a]}}};")
    s.append(f"\\node[anchor=south, font=\\tiny, align=center] at (-1.0,{top + 0.28:.2f}) {{lines\\\\read}};")
    s.append(f"\\node[anchor=south, font=\\tiny, align=center] at (-0.42,{top + 0.28:.2f}) {{rules\\\\fired}};")
    items = [("lvAcc", "accepted"), ("lvV4", "refused at V4: rules do not fire"),
             ("lvV3", "refused at V3/V3.5: fails in Logstash"), ("lvV2", "refused at V2: lines unread"),
             ("lvV1", "refused at V1 or earlier")]
    for i, (col, lab) in enumerate(items):
        lx = -3.5 + (i % 2) * 3.75
        ly = ybot - 0.45 - (i // 2) * 0.3
        s.append(f"\\fill[{col}] ({lx:.2f},{ly:.2f}) rectangle ({lx + 0.2:.2f},{ly + 0.2:.2f});")
        s.append(f"\\node[anchor=west, font=\\tiny] at ({lx + 0.23:.2f},{ly + 0.1:.2f}) {{{lab}}};")
    s.append("\\end{tikzpicture}")
    return "\n".join(s) + "\n"


def detection_after(raw, a: str, m: str, keep) -> dict | None:
    """Section 5 (2026-11-08): the detection rules (hold-out scenarios) firing after each run of the test set.
    Accepted: every rule. Refused: the rules whose fields the partial deployment verified (full system only; a lower
    bound, as RQ3), never fewer than the previous parser, which keeps running beside it. Model only deploys nothing
    when refused. Split: rules the previous parser already fired, rules a partial deployment adds, rules an accepted
    run restores."""
    from bench.wrong_accept import shipped_ir
    rows = raw.get(("r7", "r7", a, m))
    if not rows:
        return None
    eqv = [{"client.ip", "source.ip"}, {"client.port", "source.port"},
           {"client.user.name", "source.user.name", "user.name"}, {"client.domain", "source.domain"},
           {"destination.port", "server.port"}]
    sc = Path(__file__).resolve().parent / "scenarios"
    out = {"rules": 0, "old": 0, "partial": 0, "restored": 0}
    for r in rows:
        sid = r["source_id"]
        if sid not in keep:
            continue
        rs = [json.loads((d / "expected.json").read_text())["targets"] for d in sorted(sc.glob(f"{sid}__holdout_*"))]
        n, old = len(rs), R7[sid][5][0]
        out["rules"] += n
        if r["outcome"] == "accepted":
            out["old"] += old
            out["restored"] += n - old
            continue
        k = 0
        if m == "F" and shipped_ir(r) is not None:
            ver = set(r.get("verified_ecs_fields") or [])
            k = sum(all(next((g for g in eqv if t in g), {t}) & ver for t in targ) for targ in rs)
        out["old"] += old
        out["partial"] += max(0, k - old)
    return out


def fig_hero(cells, raw, det, safety) -> str:
    """Section 5 (2026-11-08): the paper's result in one figure. (a) accepted runs, model alone (hollow) and inside
    the system (filled), per task. (b) detection rules firing after a real change. (c) wrong or doubtful mappings in
    the accepted parsers, and wrong values in what the gate deploys."""
    def pct(task, pool, a, m, keep=None):
        r = cells.get((task, pool, a, m))
        if r is None:
            return None
        if keep is not None:
            r = [x for x in r if x["source"] in keep]
        return 100 * sum(x["level"] == "accepted" for x in r) / len(r)
    tasks = [("t1", "all", None, "write\\\\(Task 1)"), ("t2", "dev", None, "maintain\\\\(dev.)"),
             ("r7", "r7", REAL, "maintain\\\\(test, real)")]
    off = {"C": -0.24, "14B": 0.0, "B": 0.24}
    s = ["% Generated by bench/paper_r10.py. Do not edit.",
         "\\begin{tikzpicture}",
         "\\begin{groupplot}[group style={group size=3 by 1, horizontal sep=1.25cm},",
         "  height=4.3cm, tick label style={font=\\scriptsize}, label style={font=\\scriptsize},",
         "  title style={font=\\footnotesize\\bfseries, yshift=-1mm}, axis line style={gray!60}, tick style={gray!60}]"]
    # (a)
    s.append("\\nextgroupplot[title={(a) accepted runs}, width=5.6cm, xmin=0.5, xmax=3.5, ymin=0, ymax=104,"
             " xtick={1,2,3}, xticklabels={" + ",".join(f"{{{t[3]}}}" for t in tasks) + "},"
             " xticklabel style={align=center}, ylabel={\\% of runs}, ymajorgrids, grid style={gray!15}, clip=false]")
    for i, (task, pool, keep, _) in enumerate(tasks, 1):
        for a in ARMS:
            e, f = pct(task, pool, a, "E", keep), pct(task, pool, a, "F", keep)
            if e is None or f is None:
                continue
            x, col = i + off[a], ARM_COL[a]
            s.append(f"\\draw[{col}, line width=1.4pt, opacity=0.55] (axis cs:{x:.2f},{e:.1f}) -- (axis cs:{x:.2f},{f:.1f});")
            s.append(f"\\addplot[only marks, mark=o, mark size=1.9pt, {col}, thick] coordinates {{({x:.2f},{e:.1f})}};")
            s.append(f"\\addplot[only marks, mark=*, mark size=2.3pt, {col}] coordinates {{({x:.2f},{f:.1f})}};")
            s.append(f"\\node[font=\\tiny, {col}!85!black, anchor=south] at (axis cs:{x:.2f},{f + 2:.1f}) {{{f:.0f}}};")
    s.append("\\addplot[only marks, mark=o, mark size=1.9pt, black, thick] coordinates {(2.52,99)};")
    s.append("\\node[font=\\tiny, anchor=west] at (axis cs:2.58,99) {model alone};")
    s.append("\\addplot[only marks, mark=*, mark size=2.3pt, black] coordinates {(2.52,91)};")
    s.append("\\node[font=\\tiny, anchor=west] at (axis cs:2.58,91) {in the system};")
    # (b)
    rows = [("none", "no action")] + [(a, ARM_NAME[a]) for a in ARMS]
    s.append("\\nextgroupplot[title={(b) detection rules firing}, width=5.4cm, xbar stacked, bar width=7pt,"
             " xmin=0, xmax=100, ymin=0.4, ymax=4.6, ytick={1,2,3,4}, yticklabels={"
             + ",".join(f"{{{lab}}}" for _, lab in reversed(rows)) + "},"
             " xlabel={\\% of the rules, 15 real changes}, xmajorgrids, grid style={gray!15}, clip=false]")
    old_pct = 100 * sum(R7[x][5][0] for x in REAL) / sum(R7[x][5][1] for x in REAL)
    for y, (a, _) in zip(range(4, 0, -1), rows):
        if a == "none":
            segs = [(old_pct, "gray!55")]
        else:
            d = det[a]
            segs = [(100 * d["old"] / d["rules"], "gray!55"), (100 * d["partial"] / d["rules"], f"{ARM_COL[a]}!40"),
                    (100 * d["restored"] / d["rules"], ARM_COL[a])]
        x0 = 0.0
        for w, col in segs:
            s.append(f"\\fill[{col}] (axis cs:{x0:.2f},{y - 0.3}) rectangle (axis cs:{x0 + w:.2f},{y + 0.3});")
            x0 += w
        s.append(f"\\node[font=\\tiny, anchor=west] at (axis cs:{x0 + 1:.2f},{y}) {{{x0:.0f}\\%}};")
    # 2026-11-09: the legend shows every model's tone, so it reads for the 14B and 7B bars too
    for i, (tone, lab) in enumerate(((None, "previous parser"), ("!40", "partial parser"), ("", "restored"))):
        yy = 1.75 - 0.42 * i
        for j, a in enumerate(ARMS):
            col = "gray!55" if tone is None else f"{ARM_COL[a]}{tone}"
            s.append(f"\\fill[{col}] (axis cs:{54 + 3 * j},{yy - 0.12:.2f}) rectangle (axis cs:{56.6 + 3 * j},{yy + 0.12:.2f});")
        s.append(f"\\node[font=\\tiny, anchor=west] at (axis cs:63.5,{yy:.2f}) {{{lab}}};")
    s.append("\\addplot[draw=none] coordinates {(0,1)};")
    # (c)
    s.append("\\nextgroupplot[title={(c) wrong or doubtful mappings}, width=5.0cm, xmin=0, xmax=100, ymin=0.4, ymax=3.6,"
             " ytick={1,2,3}, yticklabels={" + ",".join(f"{{{ARM_NAME[a]}}}" for a in reversed(ARMS)) + "},"
             " xlabel={\\% of accepted parsers / of deployments}, xmajorgrids, grid style={gray!15}, clip=false]")
    for y, a in zip((3, 2, 1), ARMS):
        prop, dep = safety[a]
        col = ARM_COL[a]
        s.append(f"\\fill[{col}!35] (axis cs:0,{y + 0.04}) rectangle (axis cs:{prop:.1f},{y + 0.34});")
        s.append(f"\\fill[{col}] (axis cs:0,{y - 0.34}) rectangle (axis cs:{max(dep, 0.6):.1f},{y - 0.04});")
        s.append(f"\\node[font=\\tiny, anchor=west] at (axis cs:{prop + 1:.1f},{y + 0.19}) {{{prop:.0f}\\% proposed}};")
        s.append(f"\\node[font=\\tiny, anchor=west] at (axis cs:{max(dep, 0.6) + 1:.1f},{y - 0.19}) {{{dep:.0f}\\% deployed}};")
    s.append("\\addplot[draw=none] coordinates {(0,1)};")
    s += ["\\end{groupplot}", "\\end{tikzpicture}"]
    return "\n".join(s) + "\n"


def fig_rungs(cells) -> str:
    """r7, full system: where each run ended, per kind of change, one panel per arm."""
    cats = [("accepted", "lvAcc"), ("V4", "lvV4"), ("V3", "lvV3"), ("V2", "lvV2"), ("V1", "lvV1")]
    s = ["% Generated by bench/paper_r10.py. Do not edit.",
         "\\begin{tikzpicture}",
         "\\begin{groupplot}[group style={group size=3 by 1, horizontal sep=0.35cm, yticklabels at=edge left},",
         "  width=0.38\\linewidth, height=3.9cm, xbar stacked, /pgf/bar width=7pt, xmin=0, xmax=100,",
         "  ytick={1,2,3,4,5}, yticklabels={Control,Non-breaking,Partial,Reworded,Structural},",
         "  y tick label style={font=\\footnotesize}, x tick label style={font=\\scriptsize},",
         "  xtick={0,50,100}, xlabel={runs (\\%)}, xlabel style={font=\\scriptsize, yshift=3pt},",
         "  ymin=0.4, ymax=5.6, axis line style={gray!60}, tick style={gray!60},",
         "  title style={font=\\footnotesize\\bfseries, yshift=-4pt}, enlarge y limits=false]"]
    rev = list(reversed(GROUPS))  # y=1 control ... y=5 structural
    labels = []
    for a in ARMS:
        name = {"C": "\\armC{}", "14B": "\\armT{}", "B": "\\armB{}"}[a]
        s.append(f"\\nextgroupplot[title={{{name}}}]")
        rows = cells.get(("r7", "r7", a, "F"))
        if rows is None:
            s.append(f"\\addplot[draw=none, fill=none] coordinates {{(0,1)}};")
            s.append(f"\\node[font=\\scriptsize, gray] at (axis cs:50,3) {{{PEND}}};")
            continue
        counts = {g: Counter(_outcome(r) for r in rows if R7.get(r["source"], (0, 0, 0, None))[3] == g) for g in rev}
        for cat, col in cats:
            pts = []
            for y, g in enumerate(rev, 1):
                tot = sum(counts[g].values()) or 1
                pts.append(f"({100 * counts[g][cat] / tot:.1f},{y})")
            s.append(f"\\addplot[fill={col}, draw=white, line width=0.3pt] coordinates {{{' '.join(pts)}}};")
        for y, g in enumerate(rev, 1):
            tot = sum(counts[g].values()) or 1
            acc = 0.0
            for cat, _ in cats:
                v = 100 * counts[g][cat] / tot
                if counts[g][cat] >= 2:
                    # Named here, drawn after the plot: a node inside a stacked-bar axis lands under the bars.
                    name_ = f"rg{a}{y}{cat.replace('.', '')}"
                    s.append(f"\\coordinate ({name_}) at (axis cs:{acc + v / 2:.1f},{y});")
                    labels.append((name_, counts[g][cat], 'white' if cat in ('accepted', 'V4') else 'black'))
                acc += v
    s.append("\\end{groupplot}")
    s += [f"\\node[font=\\tiny, text={c}] at ({n}) {{{k}}};" for n, k, c in labels]
    s += ["\\end{tikzpicture}"]
    return "\n".join(s) + "\n"


def fig_safety(safe) -> str:
    """Accepted parsers by what is wrong in them, and what would ship, per arm, r7 and r6."""
    rows = [("r7", "C"), ("r7", "14B"), ("r7", "B"), ("r6", "C"), ("r6", "14B"), ("r6", "B")]
    labels = []
    for p, a in rows:
        name = {"C": "\\armC{}", "14B": "\\armT{}", "B": "\\armB{}"}[a]
        labels.append(f"{name}, {'test set' if p == 'r7' else 'set D4'}")
    ys = [6, 5, 4, 2.6, 1.6, 0.6]
    s = ["% Generated by bench/paper_r10.py. Do not edit.",
         "\\begin{tikzpicture}",
         "\\begin{groupplot}[group style={group size=2 by 1, horizontal sep=0.45cm, yticklabels at=edge left},",
         "  width=0.56\\linewidth, height=5.0cm, xbar stacked, /pgf/bar width=8pt, xmin=0,",
         f"  ytick={{{','.join(str(y) for y in ys)}}}, yticklabels={{{','.join('{' + l + '}' for l in labels)}}},",
         "  y tick label style={font=\\footnotesize}, x tick label style={font=\\scriptsize},",
         "  ymin=0, ymax=6.6, axis line style={gray!60}, tick style={gray!60},",
         "  title style={font=\\footnotesize\\bfseries, yshift=-4pt}, xlabel style={font=\\scriptsize, yshift=3pt}]"]
    s.append("\\nextgroupplot[title={(a) accepted parsers, as proposed}, xmax=60, xlabel={runs}]")
    for key, col in (("acc_clean", "sfClean"), ("acc_debatable", "sfDeb"), ("acc_clear", "sfOver"), ("acc_t1", "sfWrong")):
        pts = []
        for (p, a), y in zip(rows, ys):
            v = (safe.get((p, a)) or {}).get(key, 0)
            pts.append(f"({v},{y})")
        s.append(f"\\addplot[fill={col}, draw=white, line width=0.3pt] coordinates {{{' '.join(pts)}}};")
    for (p, a), y in zip(rows, ys):
        d = safe.get((p, a))
        if d is None:
            s.append(f"\\node[font=\\scriptsize, gray, anchor=west] at (axis cs:1,{y}) {{{PEND}}};")
        else:
            share = 100 * d["acc_any"] / d["accepted"] if d["accepted"] else 0
            s.append(f"\\node[font=\\tiny, anchor=west] at (axis cs:{d['accepted'] + 0.8},{y}) {{{share:.0f}\\%}};")
    s.append("\\nextgroupplot[title={(b) what would be deployed}, xmax=128, xlabel={runs}]")
    for key, col in (("ship_repaired_clean", "sfClean"), ("ship_partial_clean", "sfPartial"),
                     ("ship_repaired_wrong", "sfWrong"), ("ship_partial_wrong", "sfWrong"), ("ship_nothing", "sfNone")):
        pts = []
        for (p, a), y in zip(rows, ys):
            v = (safe.get((p, a)) or {}).get(key, 0)
            pts.append(f"({v},{y})")
        s.append(f"\\addplot[fill={col}, draw=white, line width=0.3pt] coordinates {{{' '.join(pts)}}};")
    for (p, a), y in zip(rows, ys):
        d = safe.get((p, a))
        if d is None:
            s.append(f"\\node[font=\\scriptsize, gray, anchor=west] at (axis cs:1,{y}) {{{PEND}}};")
            continue
        w = d["ship_repaired_wrong"] + d["ship_partial_wrong"]
        tot = sum(d[k] for k in ("ship_repaired_clean", "ship_partial_clean", "ship_repaired_wrong",
                                 "ship_partial_wrong", "ship_nothing"))
        txt = f"\\textbf{{{w} wrong}}" if w else "0 wrong"
        s.append(f"\\node[font=\\tiny, anchor=west, text={'sfWrong!80!black' if w else 'black'}] "
                 f"at (axis cs:{tot + 0.8},{y}) {{{txt}}};")
    s += ["\\end{groupplot}", "\\end{tikzpicture}"]
    return "\n".join(s) + "\n"


def fig_cost(cost) -> str:
    """r7: mean wall time per run against peak GPU memory, per arm and mode; label = accepted share."""
    s = ["% Generated by bench/paper_r10.py. Do not edit.",
         "\\begin{tikzpicture}",
         "\\begin{axis}[width=0.92\\linewidth, height=5.4cm, xmode=log, xmin=0.4, xmax=40,",
         "  xtick={0.5,1,2,5,10,20}, xticklabels={0.5,1,2,5,10,20}, ymin=6, ymax=26,",
         "  xlabel={mean wall time per run (minutes, log scale)}, ylabel={peak GPU memory (GB)},",
         "  xlabel style={font=\\footnotesize}, ylabel style={font=\\footnotesize},",
         "  tick label style={font=\\footnotesize}, grid=both, grid style={gray!15}, clip=false]",
         "\\draw[red!60!black, dashed] (axis cs:0.4,24) -- (axis cs:40,24) node[anchor=south east, font=\\tiny] "
         "{24 GB: the whole consumer card};"]
    for (a, m), d in sorted(cost.items()):
        col = {"C": "armC", "14B": "arm14", "B": "armB"}[a]
        if m == "E":
            x, y = d["wall_mean"] / 60, d["vram_peak"] / 1024
            s.append(f"\\addplot[only marks, mark=o, mark size=3pt, {col}, thick] coordinates {{({x:.2f},{y:.2f})}};")
            s.append(f"\\node[font=\\tiny, anchor=north, {col}!80!black] at (axis cs:{x:.2f},{y - 0.6:.2f}) "
                     f"{{model only: {d['acc_pct']:.0f}\\%}};")
            continue
        name = {"C": "\\armC{}", "14B": "\\armT{}", "B": "\\armB{}"}[a]
        x, y, acc = d["wall_mean"] / 60, d["vram_peak"] / 1024, d["acc_pct"]
        size = 2 + acc / 12
        s.append(f"\\addplot[only marks, mark=*, mark size={size:.1f}pt, {col}, fill opacity=0.75] coordinates {{({x:.2f},{y:.2f})}};")
        s.append(f"\\node[font=\\scriptsize, anchor=west, {col}!80!black] at (axis cs:{x * 1.34:.2f},{y:.2f}) "
                 f"{{{name}: {acc:.0f}\\% accepted}};")
    s += ["\\end{axis}", "\\end{tikzpicture}"]
    return "\n".join(s) + "\n"


def fig_oldparser() -> str:
    """r7: the previous version's parser on the new lines: share read, and rules that still fire."""
    order = sorted(R7, key=lambda s: (R7[s][4], R7[s][5][0] / max(1, R7[s][5][1]), R7[s][0]))
    n = len(order)
    s = ["% Generated by bench/paper_r10.py. Do not edit.",
         "\\begin{tikzpicture}",
         f"\\begin{{axis}}[width=0.9\\linewidth, height={0.36 * n + 1.4:.2f}cm, xmin=0, xmax=100, ymin=0.3, ymax={n + 0.7},",
         f"  ytick={{1,...,{n}}}, yticklabels={{{','.join('{' + R7[s_][0] + '}' for s_ in order)}}},",
         "  y tick label style={font=\\scriptsize}, x tick label style={font=\\scriptsize},",
         "  xlabel={new lines the previous parser still reads (\\%)}, xlabel style={font=\\footnotesize},",
         "  xmajorgrids, grid style={gray!15}, clip=false, axis line style={gray!60}, tick style={gray!60}]"]
    for y, sid in enumerate(order, 1):
        rd = R7[sid][4]
        f, t = R7[sid][5]
        col = "lvAcc" if f == t else "lvV3" if f else "lvV4"
        s.append(f"\\draw[gray!45, line width=1pt] (axis cs:0,{y}) -- (axis cs:{max(rd, 0.5)},{y});")
        s.append(f"\\addplot[only marks, mark=*, mark size=2.6pt, {col}] coordinates {{({max(rd, 0.5)},{y})}};")
        s.append(f"\\node[font=\\tiny, anchor=west] at (axis cs:101,{y}) {{{f}/{t}}};")
    s.append(f"\\node[font=\\tiny\\bfseries, anchor=west, align=left] at (axis cs:101,{n + 0.9}) {{rules\\\\firing}};")
    s += ["\\end{axis}", "\\end{tikzpicture}"]
    return "\n".join(s) + "\n"


def tab_main(cells) -> str:
    """The accepted runs of every cell: Task 1 per pool, Task 2 per set, r7 per subset."""
    def c(task, pool, a, m, keep=None):
        r = cells.get((task, pool, a, m))
        if r is not None and keep is not None:
            r = [x for x in r if x["source"] in keep]
        if r is None:
            return "\\missingnum"
        k = sum(x["level"] == "accepted" for x in r)
        return f"{k}/{len(r)}"

    def row(label, task, pool, keep=None):
        vals = [c(task, pool, a, m, keep) for m in ("F", "E") for a in ARMS]
        return f"{label} & " + " & ".join(vals) + " \\\\"

    out = ["% Generated by bench/paper_r10.py. Do not edit.",
           "\\begin{tabular}{@{}l rrr rrr@{}}", "\\toprule",
           " & \\multicolumn{3}{c}{\\textbf{full system}} & \\multicolumn{3}{c}{\\textbf{model only}} \\\\",
           "\\cmidrule(lr){2-4}\\cmidrule(l){5-7}",
           " & \\armC{} & \\armT{} & \\armB{} & \\armC{} & \\armT{} & \\armB{} \\\\", "\\midrule",
           "\\multicolumn{7}{@{}l}{\\emph{Task 1: write a parser (39 sources)}} \\\\"]
    for p, lab in (("id", "\\quad generated family (9)"), ("drift", "\\quad new format (16)"),
                   ("dev", "\\quad real, development (8)"), ("ood", "\\quad real, never seen (6)"),
                   ("all", "\\quad all")):
        out.append(row(lab, "t1", p))
    out.append("\\midrule")
    # 2026-11-08 (Section 5 review): the development sets D1-D4 are not defined in the paper, so one row
    out.append("\\multicolumn{7}{@{}l}{\\emph{Task 2, development (33 changes, 10 of them controls)}} \\\\")
    out.append(row("\\quad all 33", "t2", "dev"))
    out.append("\\midrule")
    out.append("\\multicolumn{7}{@{}l}{\\emph{Task 2, test: 20 pairs captured for it}} \\\\")
    for g in ("struct", "reword", "partial", "nonbreak"):
        keep = {x for x in R7 if R7[x][3] == g}
        out.append(row(f"\\quad {GROUP_LABEL[g].lower()} ({len(keep)})", "r7", "r7", keep))
    out.append(row("\\quad all 15 real changes", "r7", "r7", REAL))
    out.append(row("\\quad 5 controls", "r7", "r7", set(R7) - REAL))
    out.append(row("\\quad all 20", "r7", "r7"))
    out += ["\\bottomrule", "\\end{tabular}"]
    return "\n".join(out) + "\n"


# ----------------------------------------------------------------------------- figures added 2026-11-05
# Raw records carry what load() drops: which sample was accepted, how many repairs it took, the deterministic
# rules that acted, the findings of a refused run and its wall time.
def raw_cells(roots: list[Path]) -> dict:
    out = {}
    for key, (tag, also) in tags().items():
        f, _ = _find(roots, tag)
        if f is None:
            out[key] = None
            continue
        recs = _rows(f)
        for t in also:
            fa, _ = _find(roots, t)
            if fa is not None:
                recs += _rows(fa)
        last = {}
        for r in recs:
            last[(r["source_id"], r.get("seed", 0))] = r
        out[key] = list(last.values())
    for a in ALL_ARMS:
        for m in ("F", "E"):
            t1 = [out.get(("t1", p, a, m)) for p in T1_POOLS]
            out[("t1", "all", a, m)] = None if any(x is None for x in t1) else sum(t1, [])
            t2 = [out.get(("t2", p, a, m)) for p in T2_POOLS]
            out[("t2", "dev", a, m)] = None if any(x is None for x in t2) else sum(t2, [])
            r7 = out.get(("r7", "r7", a, m))
            out[("r7", "real", a, m)] = None if r7 is None else [r for r in r7 if r["source_id"] in REAL]
    return out


ARM_NAME = {"C": "\\armC{}", "14B": "\\armT{}", "B": "\\armB{}"}
ARM_COL = {"C": "armC", "14B": "arm14", "B": "armB"}
TASKS3 = [("t1", "all", "Task 1: writing a parser (39 sources)"),
          ("t2", "dev", "Task 2: development changes (33)"),
          ("r7", "real", "Task 2: test, real changes (15)")]


def fig_origin(raw) -> str:
    """How every accepted full-system run was reached, against the model alone (diamond)."""
    s = ["% Generated by bench/paper_r10.py. Do not edit.",
         "\\begin{tikzpicture}",
         "\\begin{groupplot}[group style={group size=3 by 1, horizontal sep=0.6cm, yticklabels at=edge left},",
         "  width=0.375\\linewidth, height=3.3cm, xbar stacked, /pgf/bar width=8pt, xmin=0, xmax=100,",
         "  ytick={1,2,3}, yticklabels={\\armB{},\\armT{},\\armC{}}, y tick label style={font=\\footnotesize},",
         "  x tick label style={font=\\scriptsize}, xtick={0,25,50,75,100}, xlabel={runs (\\%)},",
         "  xlabel style={font=\\scriptsize, yshift=3pt}, ymin=0.4, ymax=3.6, axis line style={gray!60},",
         "  tick style={gray!60}, title style={font=\\scriptsize\\bfseries, yshift=-4pt, text width=4.6cm, align=center},",
         "  xmajorgrids, grid style={gray!12}]"]
    marks = []
    for task, pool, title in TASKS3:
        s.append(f"\\nextgroupplot[title={{{title}}}]")
        segs = {"first": [], "later": [], "repair": []}
        for y, a in ((3, "C"), (2, "14B"), (1, "B")):
            f = raw.get((task, pool, a, "F"))
            e = raw.get((task, pool, a, "E"))
            if not f:
                for k in segs:
                    segs[k].append(f"(0,{y})")
                marks.append((task, y, None, a))
                continue
            n = len(f)
            acc = [r for r in f if r["outcome"] == "accepted"]
            first = sum(1 for r in acc if not r.get("sample_chosen") and not r.get("repairs"))
            rep = sum(1 for r in acc if r.get("repairs"))
            later = len(acc) - first - rep
            for k, v in (("first", first), ("later", later), ("repair", rep)):
                segs[k].append(f"({100 * v / n:.1f},{y})")
            pe = 100 * sum(r["outcome"] == "accepted" for r in e) / len(e) if e else None
            marks.append((task, y, pe, a))
        for k, col in (("first", "armC!75"), ("later", "armC!40"), ("repair", "lvV3")):
            hatch = ", postaction={pattern=north east lines, pattern color=black!70}" if k == "repair" else ""
            s.append(f"\\addplot[fill={col}, draw=white, line width=0.3pt{hatch}] coordinates {{{' '.join(segs[k])}}};")
        for (t, y, pe, a) in [m for m in marks if m[0] == task]:
            if pe is None:
                s.append(f"\\node[font=\\scriptsize, gray] at (axis cs:50,{y}) {{{PEND}}};")
            else:
                s.append(f"\\coordinate (om{task}{y}) at (axis cs:{pe:.1f},{y});")
    s.append("\\end{groupplot}")
    for (t, y, pe, a) in marks:
        if pe is not None:
            s.append(f"\\node[diamond, draw=black, fill=white, inner sep=1.6pt, line width=0.7pt] at (om{t}{y}) {{}};")
    lg = [("armC!75", "accepted at the first sample, no repair"), ("armC!40", "accepted at a later sample"),
          ("lvV3", "accepted after a repair")]
    s.append("\\begin{scope}[shift={($(group c1r1.south west)+(0,-1.05)$)}, font=\\scriptsize]")
    x = 0.0
    for col, lab in lg:
        hatch = f" \\fill[pattern=north east lines, pattern color=black!70] ({x:.2f},0) rectangle ({x + 0.3:.2f},0.2);" if col == "lvV3" else ""
        s.append(f"\\fill[{col}] ({x:.2f},0) rectangle ({x + 0.3:.2f},0.2);{hatch} \\node[anchor=west] at ({x + 0.33:.2f},0.1) {{{lab}}};")
        x += 0.75 + 0.135 * len(lab)
    s.append(f"\\node[diamond, draw=black, fill=white, inner sep=1.6pt, line width=0.7pt] at ({x + 0.1:.2f},0.1) {{}}; "
             f"\\node[anchor=west] at ({x + 0.25:.2f},0.1) {{the same model alone, one call}};")
    s.append("\\end{scope}")
    s.append("\\end{tikzpicture}")
    return "\n".join(s) + "\n"


def fig_transition(raw) -> str:
    """Each run of the test set: what the model alone did against what the full system did, same source and seed."""
    s = ["% Generated by bench/paper_r10.py. Do not edit.",
         "\\begin{tikzpicture}[x=1cm, y=1cm, font=\\scriptsize]"]
    cell = 0.95
    for i, a in enumerate(("C", "14B", "B")):
        x0 = i * 3.05
        f = raw.get(("r7", "r7", a, "F"))
        e = raw.get(("r7", "r7", a, "E"))
        s.append(f"\\node[font=\\footnotesize\\bfseries] at ({x0 + cell:.2f},{2 * cell + 0.45:.2f}) {{{ARM_NAME[a]}}};")
        if not f or not e:
            s.append(f"\\draw[gray!50, dashed] ({x0:.2f},0) rectangle ({x0 + 2 * cell:.2f},{2 * cell:.2f});")
            s.append(f"\\node[gray] at ({x0 + cell:.2f},{cell:.2f}) {{{PEND}}};")
            continue
        F = {(r["source_id"], r["seed"]): r["outcome"] == "accepted" for r in f}
        E = {(r["source_id"], r["seed"]): r["outcome"] == "accepted" for r in e}
        both = F.keys() & E.keys()
        cnt = Counter((E[k], F[k]) for k in both)
        tot = len(both)
        # rows: model only (top = accepted), columns: full system (right = accepted)
        for (ea, fa), (cx, cy) in {(True, False): (0, 1), (True, True): (1, 1),
                                    (False, False): (0, 0), (False, True): (1, 0)}.items():
            v = cnt[(ea, fa)]
            col = "lvAcc" if fa and not ea else "lvV4" if ea and not fa else "armC" if fa else "gray"
            shade = max(6, min(85, int(100 * v / tot * 1.6)))
            xx, yy = x0 + cx * cell, cy * cell
            s.append(f"\\fill[{col}!{shade}] ({xx:.2f},{yy:.2f}) rectangle ({xx + cell:.2f},{yy + cell:.2f});")
            s.append(f"\\draw[white, line width=1pt] ({xx:.2f},{yy:.2f}) rectangle ({xx + cell:.2f},{yy + cell:.2f});")
            s.append(f"\\node[font=\\footnotesize\\bfseries, text={'white' if shade > 50 else 'black'}] at "
                     f"({xx + cell / 2:.2f},{yy + cell / 2:.2f}) {{{v}}};")
        s.append(f"\\node[anchor=north] at ({x0 + cell / 2:.2f},-0.02) {{refused}};")
        s.append(f"\\node[anchor=north] at ({x0 + 1.5 * cell:.2f},-0.02) {{accepted}};")
        if i == 0:
            s.append(f"\\node[anchor=east] at ({x0 - 0.05:.2f},{1.5 * cell:.2f}) {{accepted}};")
            s.append(f"\\node[anchor=east] at ({x0 - 0.05:.2f},{0.5 * cell:.2f}) {{refused}};")
            s.append(f"\\node[rotate=90, anchor=south, font=\\scriptsize\\itshape] at ({x0 - 1.0:.2f},{cell:.2f}) {{model only}};")
    s.append(f"\\node[font=\\scriptsize\\itshape] at (4.1,-0.6) {{full system, same version pair and seed}};")
    s.append("\\end{tikzpicture}")
    return "\n".join(s) + "\n"


def pc_points(raw) -> list:
    """(set, arm, coverage proposed, precision proposed, coverage deployed, precision deployed), accepted runs."""
    from bench.wrong_accept import judge, shipped_ir
    pts = []
    for set_, key in (("test", ("r7", "r7")), ("D4", ("t2", "r6"))):
        for a in ("C", "14B", "B"):
            f = raw.get((key[0], key[1], a, "F"))
            if not f:
                continue
            acc = [r for r in f if r["outcome"] == "accepted"]
            P = {"right": 0, "wrong": 0, "gold": 0}
            D = {"right": 0, "wrong": 0, "gold": 0}
            for r in acc:
                j = judge(r.get("ir") or {}, r["source_id"])
                cut = shipped_ir(r)
                jd = judge(cut, r["source_id"]) if cut else None
                if j is None or jd is None:
                    continue
                for T, jj in ((P, j), (D, jd)):
                    T["right"] += jj["f_right"]; T["wrong"] += jj["f_wrong"]; T["gold"] += jj["f_gold"]
            if not P["gold"]:
                continue
            prec = lambda T: T["right"] / (T["right"] + T["wrong"]) if T["right"] + T["wrong"] else 1.0
            cov = lambda T: T["right"] / T["gold"]
            pts.append((set_, a, cov(P), prec(P), cov(D), prec(D)))
    return pts


def fig_precision_coverage(raw) -> str:
    """Accepted parsers as proposed (hollow) and as the gate would deploy them (filled), field level."""
    pts = pc_points(raw)
    s = ["% Generated by bench/paper_r10.py. Do not edit.",
         "\\begin{tikzpicture}",
         "\\begin{axis}[width=0.95\\linewidth, height=6.0cm, xmin=0.25, xmax=1.0, ymin=0.74, ymax=1.015,",
         "  xlabel={coverage: reference fields delivered right}, ylabel={precision: delivered fields that are right},",
         "  xlabel style={font=\\footnotesize}, ylabel style={font=\\footnotesize}, tick label style={font=\\scriptsize},",
         "  grid=both, grid style={gray!15}, clip=false]"]
    for set_, a, cp, pp_, cd, pd in pts:
        col = ARM_COL[a]
        mk = "*" if set_ == "test" else "square*"
        mko = "o" if set_ == "test" else "square"
        s.append(f"\\draw[-{{Stealth[length=2mm]}}, {col}, line width=0.9pt, opacity=0.8] (axis cs:{cp:.3f},{pp_:.3f}) -- (axis cs:{cd:.3f},{pd:.3f});")
        s.append(f"\\addplot[only marks, mark={mko}, mark size=2.8pt, {col}, thick] coordinates {{({cp:.3f},{pp_:.3f})}};")
        s.append(f"\\addplot[only marks, mark={mk}, mark size=2.8pt, {col}] coordinates {{({cd:.3f},{pd:.3f})}};")
    # 2026-11-09: point labels overlapped where three arrows start, so the model is named in the legend instead
    key = "\\\\".join(f"\\textcolor{{{ARM_COL[a]}}}{{\\rule{{3mm}}{{1pt}}}} {ARM_NAME[a]}" for a in ARMS)
    s.append("\\node[font=\\tiny, anchor=north west, align=left, fill=white, draw=gray!40] at (axis cs:0.26,0.86) "
             "{hollow: accepted parser as proposed\\\\filled: what the gate deploys\\\\circle: test set, square: set D4\\\\" + key + "};")
    s += ["\\end{axis}", "\\end{tikzpicture}"]
    return "\n".join(s) + "\n"


RULE_LABEL = [
    ("ecs_type_from_index", "type taken from ECS"),
    ("carried_unresolved", "old unresolved keys carried"),
    ("template_alternatives_added", "mined template added"),
    ("captured_key_declared_unresolved", "unmappable key withheld"),
    ("uncovered_key_declared_unresolved", "unread key withheld"),
    ("unreachable_source_key", "mapping of absent key cut"),
    ("duplicate_ecs_target", "two keys on one field cut"),
    ("old_grok_nested_in_json", "old pattern nested in JSON"),
    ("literal_absent_from_data_dropped", "absent literal dropped"),
    ("duplicate_grok_capture_renamed", "repeated capture renamed"),
    ("unknown_grok_pattern_renamed", "undefined pattern renamed"),
    ("timestamp_capture_retyped", "date class retyped or composed"),
]
CODE_LABEL = [
    ("detection_mismatch", "V4: a rule does not fire"),
    ("value_not_found", "V3.5: planted value lost"),
    ("value_in_wrong_field", "V3.5: value in wrong field"),
    ("logstash_failed", "V3: Logstash refuses"),
    ("extraction_yields_nothing", "V2: no line read"),
    ("grok_matches_only_some_lines", "V2: some lines unread"),
    ("extraction_yields_little", "V2: few keys read"),
    ("unknown_grok_pattern", "V2: undefined pattern"),
]


def _heat(rows, cols, val, title, xlab_rot=True, maxv=100) -> list[str]:
    s = []
    cw, ch = 0.62, 0.34
    s.append(f"\\node[font=\\footnotesize\\bfseries, anchor=south west] at (-3.2,{len(rows) * ch + 1.15:.2f}) {{{title}}};")
    for j, (ck, cl) in enumerate(cols):
        s.append(f"\\node[rotate=60, anchor=south west, font=\\tiny] at ({j * cw + 0.12:.2f},{len(rows) * ch + 0.04:.2f}) {{{cl}}};")
    for i, (rk, rl) in enumerate(rows):
        y = (len(rows) - 1 - i) * ch
        s.append(f"\\node[anchor=east, font=\\tiny] at (-0.05,{y + ch / 2:.2f}) {{{rl}}};")
        for j, (ck, cl) in enumerate(cols):
            v = val(rk, ck)
            x = j * cw
            if v is None:
                s.append(f"\\fill[lvPend] ({x:.2f},{y:.2f}) rectangle ({x + cw:.2f},{y + ch:.2f});")
                continue
            shade = int(min(90, 90 * v / maxv)) if v else 0
            s.append(f"\\fill[armC!{shade}] ({x:.2f},{y:.2f}) rectangle ({x + cw:.2f},{y + ch:.2f});")
            if v >= 0.5:
                s.append(f"\\node[font=\\tiny, text={'white' if shade > 45 else 'black'}] at ({x + cw / 2:.2f},{y + ch / 2:.2f}) {{{v:.0f}}};")
        s.append(f"\\draw[white, line width=0.6pt] (0,{y:.2f}) -- ({len(cols) * cw:.2f},{y:.2f});")
    return s


def fig_heat(raw) -> str:
    """(a) share of full-system runs in which each deterministic rule acted; (b) share of refused runs with each finding."""
    cols = []
    for task, pool, lab in (("t1", "all", "T1"), ("t2", "dev", "dev"), ("r7", "r7", "test")):
        for a in ("C", "14B", "B"):
            cols.append(((task, pool, a), f"{ARM_NAME[a]} {lab}"))

    def rule_val(rk, ck):
        f = raw.get((ck[0], ck[1], ck[2], "F"))
        if not f:
            return None
        hit = sum(1 for r in f if any((n.get("rule") == rk) or (rk == "timestamp_capture_retyped" and
                  n.get("rule") == "timestamp_capture_composed") for n in r.get("normalisations") or []))
        return 100 * hit / len(f)

    def code_val(rk, ck):
        f = raw.get((ck[0], ck[1], ck[2], "F"))
        if not f:
            return None
        ref = [r for r in f if r["outcome"] != "accepted"]
        if not ref:
            return 0
        return 100 * sum(1 for r in ref if any(x.get("code") == rk for x in r.get("findings") or [])) / len(ref)

    s = ["% Generated by bench/paper_r10.py. Do not edit.", "\\begin{tikzpicture}"]
    s += _heat(RULE_LABEL, cols, rule_val, "(a) deterministic rules: \\% of full-system runs in which each acted")
    s.append(f"\\begin{{scope}}[xshift=9.6cm, yshift={(len(RULE_LABEL) - len(CODE_LABEL)) * 0.34:.2f}cm]")
    s += _heat(CODE_LABEL, cols, code_val, "(b) findings: \\% of refused runs that carry each")
    s.append("\\end{scope}")
    s.append("\\end{tikzpicture}")
    return "\n".join(s) + "\n"


def fig_time(raw) -> str:
    """Wall time of every full-system run of the test set, accepted and refused, with medians."""
    import random as _r
    rng = _r.Random(0)
    s = ["% Generated by bench/paper_r10.py. Do not edit.",
         "\\begin{tikzpicture}",
         "\\begin{axis}[width=0.95\\linewidth, height=4.3cm, xmode=log, xmin=0.3, xmax=60, ymin=0.3, ymax=3.7,",
         "  ytick={1,2,3}, yticklabels={\\armB{},\\armT{},\\armC{}}, y tick label style={font=\\footnotesize},",
         "  xtick={0.5,1,2,5,10,20,50}, xticklabels={0.5,1,2,5,10,20,50}, tick label style={font=\\scriptsize},",
         "  xlabel={minutes per full-system run on the test set (log scale)}, xlabel style={font=\\footnotesize},",
         "  xmajorgrids, grid style={gray!15}, clip=false]"]
    for y, a in ((3, "C"), (2, "14B"), (1, "B")):
        f = raw.get(("r7", "r7", a, "F"))
        if not f:
            s.append(f"\\node[font=\\scriptsize, gray] at (axis cs:4,{y}) {{{PEND}}};")
            continue
        for ok, col, dy in ((True, "lvAcc", 0.17), (False, "lvV4", -0.17)):
            pts = [f"({r['wall_seconds'] / 60:.2f},{y + dy + rng.uniform(-0.1, 0.1):.2f})" for r in f
                   if (r["outcome"] == "accepted") == ok and r.get("wall_seconds")]
            if pts:
                s.append(f"\\addplot[only marks, mark=*, mark size=1.1pt, {col}, opacity=0.55] coordinates {{{' '.join(pts)}}};")
            w = sorted(r["wall_seconds"] / 60 for r in f if (r["outcome"] == "accepted") == ok and r.get("wall_seconds"))
            if w:
                md = w[len(w) // 2]
                s.append(f"\\draw[{col}!70!black, line width=1.6pt] (axis cs:{md:.2f},{y + dy - 0.14:.2f}) -- (axis cs:{md:.2f},{y + dy + 0.14:.2f});")
                s.append(f"\\node[font=\\tiny, anchor=west, {col}!70!black] at (axis cs:62,{y + dy:.2f}) {{{md:.1f}}};")
    s.append("\\node[font=\\tiny\\bfseries, anchor=west] at (axis cs:62,3.6) {median};")
    s += ["\\end{axis}", "\\end{tikzpicture}"]
    return "\n".join(s) + "\n"


# ----------------------------------------------------------------------------- main
def build(roots: list[Path]):
    o = Out()
    cells: dict = {}
    for key, (tag, also) in tags().items():
        cells[key] = load(roots, tag, also)
    # pooled cells
    for a in ALL_ARMS:
        for m in ("F", "E"):
            t1 = [cells.get(("t1", p, a, m)) for p in T1_POOLS]
            cells[("t1", "all", a, m)] = None if any(x is None for x in t1) else sum(t1, [])
            t2 = [cells.get(("t2", p, a, m)) for p in T2_POOLS]
            cells[("t2", "dev", a, m)] = None if any(x is None for x in t2) else sum(t2, [])
            r7 = cells.get(("r7", "r7", a, m))
            cells[("r7", "real", a, m)] = _sub(r7, REAL)
    # cell numbers
    for (task, pool, a, m), rows in list(cells.items()):
        cell_numbers(o, f"{task}/{pool}/{a}/{m}", rows)
    for a in ALL_ARMS:
        for m in ("F", "E"):
            r7 = cells.get(("r7", "r7", a, m))
            for name, keep in (("real", REAL), ("breaking", BREAKING), ("control", set(R7) - REAL),
                               ("nonbreak", {s for s in R7 if R7[s][3] == "nonbreak"})) + tuple(
                    (g, {s for s in R7 if R7[s][3] == g}) for g in GROUPS):
                cell_numbers(o, f"r7/{name}/{a}/{m}", _sub(r7, keep))
    # comparisons
    cmp: dict = {}

    def C(key, x, y):
        cmp[key] = cmp_numbers(o, f"cmp/{key}", x, y)
        return cmp[key]

    for sub, keep in (("real", REAL), ("all", set(R7)), ("breaking", BREAKING)):
        for m in ("F", "E"):
            for y in ("14B", "B", "org9"):
                C(f"r7/{sub}/{m}/C-{y}", _sub(cells[("r7", "r7", "C", m)], keep), _sub(cells[("r7", "r7", y, m)], keep))
        C(f"r7/{sub}/CF-14BE", _sub(cells[("r7", "r7", "C", "F")], keep), _sub(cells[("r7", "r7", "14B", "E")], keep))
        C(f"r7/{sub}/CF-BE", _sub(cells[("r7", "r7", "C", "F")], keep), _sub(cells[("r7", "r7", "B", "E")], keep))
        for a in ARMS:
            C(f"r7/{sub}/{a}F-{a}E", _sub(cells[("r7", "r7", a, "F")], keep), _sub(cells[("r7", "r7", a, "E")], keep))
    for task, pool in (("t1", "all"), ("t2", "dev"), ("t1", "ood"), ("t2", "r6")):
        for m in ("F", "E"):
            for y in ("14B", "B", "org9", "Cdpo"):
                C(f"{task}/{pool}/{m}/C-{y}", cells.get((task, pool, "C", m)), cells.get((task, pool, y, m)))
        for a in ARMS:
            C(f"{task}/{pool}/{a}F-{a}E", cells.get((task, pool, a, "F")), cells.get((task, pool, a, "E")))
    # safety
    safe = {}
    from bench.wrong_accept import summarise
    for p, (task, pool) in (("r7", ("r7", "r7")), ("r6", ("t2", "r6"))):
        for a in ARMS:
            tag, also = tags()[(task, pool, a, "F")]
            f, _ = _find(roots, tag)
            if f is None:
                continue
            recs = _rows(f)
            for t in also:
                fa, _ = _find(roots, t)
                if fa is not None:
                    recs += _rows(fa)
            d = summarise(recs)
            safe[(p, a)] = d
            for k, v in d.items():
                o.put(f"safe/{p}/{a}/{k}", round(100 * v) if k == "ship_coverage" and v is not None else v)
            o.put(f"safe/{p}/{a}/acc_any_pct", round(100 * d["acc_any"] / d["accepted"]) if d["accepted"] else 0)
            dep = d["ship_repaired_clean"] + d["ship_repaired_wrong"] + d["ship_partial_clean"] + d["ship_partial_wrong"]
            o.put(f"safe/{p}/{a}/deployments", dep)
            o.put(f"safe/{p}/{a}/deployed_wrong", d["ship_repaired_wrong"] + d["ship_partial_wrong"])
    for a in ARMS:
        if ("r7", a) in safe and ("r6", a) in safe:
            dep = sum(safe[(p, a)][k] for p in ("r7", "r6") for k in
                      ("ship_repaired_clean", "ship_repaired_wrong", "ship_partial_clean", "ship_partial_wrong"))
            o.put(f"safe/both/{a}/deployments", dep)
            o.put(f"safe/both/{a}/deployed_wrong",
                  sum(safe[(p, a)][k] for p in ("r7", "r6") for k in ("ship_repaired_wrong", "ship_partial_wrong")))
    # safe degradation: what each run leaves behind (restored, partial, report only, wrong value deployed), and how
    # many of the source's rules a partial deployment restores (a rule counts when every field it queries, or an
    # equivalent, is among the deployed fields; V4-verified fields only, so a lower bound as in RQ3)
    eqv = [{"client.ip", "source.ip"}, {"client.port", "source.port"},
           {"client.user.name", "source.user.name", "user.name"}, {"client.domain", "source.domain"},
           {"destination.port", "server.port"}]
    rules_cache: dict = {}

    def rules_of(sid):
        if sid not in rules_cache:
            sc = Path(__file__).resolve().parent / "scenarios"
            rules_cache[sid] = [json.loads((d / "expected.json").read_text())["targets"]
                                for d in sorted(sc.glob(f"{sid}__holdout_*"))]
        return rules_cache[sid]

    def raw(task, pool, a):
        tag, also = tags()[(task, pool, a, "F")]
        f, _ = _find(roots, tag)
        if f is None:
            return None
        recs = _rows(f)
        for t in also:
            fa, _ = _find(roots, t)
            if fa is not None:
                recs += _rows(fa)
        last = {(r["source_id"], r.get("seed", 0)): r for r in recs}
        return list(last.values())

    from bench.wrong_accept import shipped_ir
    for name in ("r7real", "r7ctrl", "dev"):
        for a in ARMS:
            if name == "dev":
                parts = [raw("t2", p, a) for p in T2_POOLS]
                recs = None if any(x is None for x in parts) else sum(parts, [])
            else:
                recs = raw("r7", "r7", a)
                if recs is not None:
                    recs = [r for r in recs if (r["source_id"] in REAL) == (name == "r7real")]
            if not recs:
                continue
            d = summarise(recs)
            n = len(recs)
            vals = {"n": n, "restored": d["ship_repaired_clean"], "partial": d["ship_partial_clean"],
                    "report": d["ship_nothing"], "wrong": d["ship_repaired_wrong"] + d["ship_partial_wrong"]}
            ok = den = anyrule = 0
            for r in recs:
                if r.get("outcome") == "accepted" or shipped_ir(r) is None:
                    continue
                ver = set(r.get("verified_ecs_fields") or [])
                rs = rules_of(r["source_id"])
                k = sum(all(next((g for g in eqv if t in g), {t}) & ver for t in targ) for targ in rs)
                ok, den, anyrule = ok + k, den + len(rs), anyrule + (k > 0)
            vals.update(prules_ok=ok, prules_n=den, prules_pct=round(100 * ok / den) if den else 0,
                        partial_any=anyrule)
            for k in ("restored", "partial", "report", "wrong"):
                vals[f"{k}_pct"] = round(100 * vals[k] / n)
            for k, v in vals.items():
                o.put(f"deg/{name}/{a}/{k}", v)
    # cost (r7 and Task 1)
    cost = {}
    for task, pool, key in (("r7", "r7", "r7"), ("t1", "all", "t1"), ("t2", "dev", "t2")):
        for a in ARMS:
            for m in ("F", "E"):
                rows = cells.get((task, pool, a, m))
                if not rows:
                    continue
                w = [r["wall_s"] for r in rows if r.get("wall_s")]
                v = [r["vram_mb"] for r in rows if r.get("vram_mb")]
                if not w:
                    continue
                d = {"wall_mean": mean(w), "wall_median": median(w), "vram_peak": max(v) if v else 0,
                     "acc_pct": 100 * sum(r["level"] == "accepted" for r in rows) / len(rows),
                     "cell_hours": sum(w) / 3600}
                if key == "r7":
                    cost[(a, m)] = d
                o.put(f"cost/{key}/{a}/{m}/wall_min", f"{d['wall_mean'] / 60:.1f}")
                o.put(f"cost/{key}/{a}/{m}/wall_s", f"{d['wall_mean']:.0f}")
                o.put(f"cost/{key}/{a}/{m}/wall_med_min", f"{d['wall_median'] / 60:.1f}")
                o.put(f"cost/{key}/{a}/{m}/vram_gb", f"{d['vram_peak'] / 1024:.1f}")
                o.put(f"cost/{key}/{a}/{m}/cell_h", f"{d['cell_hours']:.1f}")
    # r7 rungs per group (full system)
    for a in ARMS:
        rows = cells.get(("r7", "r7", a, "F"))
        if not rows:
            continue
        for g in GROUPS:
            cnt = Counter(_outcome(r) for r in rows if R7[r["source"]][3] == g)
            for k in ("accepted", "V4", "V3", "V2", "V1"):
                o.put(f"rung/r7/{g}/{a}/{k}", cnt[k])
        cnt = Counter(_outcome(r) for r in rows if r["level"] != "accepted")
        for k in ("V4", "V3", "V2", "V1"):
            o.put(f"rung/r7/failed/{a}/{k}", cnt[k])
        o.put(f"rung/r7/failed/{a}/n", sum(cnt.values()))
    # per-source r7 accepted counts (5 seeds)
    for a in ARMS:
        for m in ("F", "E"):
            rows = cells.get(("r7", "r7", a, m))
            if rows:
                for sid in R7:
                    o.put(f"src/{sid}/{a}/{m}", sum(r["level"] == "accepted" for r in rows if r["source"] == sid))
    o.put("eq_margin", 15)
    figs = {
        "fig-dumbbell.tex": fig_dumbbell(cells),
        "fig-grid.tex": fig_grid(cells),
        "fig-rungs.tex": fig_rungs(cells),
        "fig-safety.tex": fig_safety(safe),
        "fig-cost.tex": fig_cost(cost),
        "fig-oldparser.tex": fig_oldparser(),
        "tab-main.tex": tab_main(cells),
    }
    forest = [
        ("Test, 15 real changes, full system: \\armC{} $-$ \\armT{}", cmp.get("r7/real/F/C-14B"), "armC", True),
        ("Test, all 20 pairs, full system: \\armC{} $-$ \\armT{}", cmp.get("r7/all/F/C-14B"), "armC", False),
        ("Test, 13 breaking changes, full system: \\armC{} $-$ \\armT{}", cmp.get("r7/breaking/F/C-14B"), "armC", False),
        ("Test, 15 real changes, model only: \\armC{} $-$ \\armT{}", cmp.get("r7/real/E/C-14B"), "arm14", False),
        ("Test, 15 real: \\armC{} full $-$ \\armT{} model only", cmp.get("r7/real/CF-14BE"), "arm14", False),
        ("Test, 15 real changes, full system: \\armC{} $-$ \\armB{}", cmp.get("r7/real/F/C-B"), "armB", False),
        ("Task 2 development (33), full system: \\armC{} $-$ \\armT{}", cmp.get("t2/dev/F/C-14B"), "armC", False),
        ("Task 2 development (33), model only: \\armC{} $-$ \\armT{}", cmp.get("t2/dev/E/C-14B"), "arm14", False),
        ("Task 2 development (33), full system: \\armC{} $-$ \\armB{}", cmp.get("t2/dev/F/C-B"), "armB", False),
        ("Task 1 (39 sources), full system: \\armC{} $-$ \\armT{}", cmp.get("t1/all/F/C-14B"), "armC", False),
        ("Task 1 (39 sources), model only: \\armC{} $-$ \\armT{}", cmp.get("t1/all/E/C-14B"), "arm14", False),
        ("Task 1 (39 sources), full system: \\armC{} $-$ \\armB{}", cmp.get("t1/all/F/C-B"), "armB", False),
    ]
    figs["fig-forest.tex"] = fig_forest(forest)
    figs["fig-forest-small.tex"] = fig_forest([
        ("\\textbf{T2 test, 15 real}", cmp.get("r7/real/F/C-14B"), "armC", True),
        ("T2 test, 13 breaking", cmp.get("r7/breaking/F/C-14B"), "armC", False),
        ("T2 test, all 20", cmp.get("r7/all/F/C-14B"), "armC", False),
        ("T2 development, 33", cmp.get("t2/dev/F/C-14B"), "armC", False),
        ("T1, 39 sources", cmp.get("t1/all/F/C-14B"), "armC", False),
        ("T2 test, 15 real, vs \\armB{}", cmp.get("r7/real/F/C-B"), "armB", False),
    ], compact=True)
    figs["fig-grid-full.tex"] = fig_grid_full(cells)
    # Section 5 (2026-11-08): the previous parser on the test set, from R7 (rules firing with it / rules)
    real = [R7[x][5] for x in REAL]
    o.put("old/r7/real/n", len(real))
    o.put("old/r7/real/none", sum(1 for f, n in real if f == 0))
    o.put("old/r7/real/fired", sum(f for f, _ in real))
    o.put("old/r7/real/rules", sum(n for _, n in real))
    # safety restricted to the 15 real changes (the safe/r7 keys cover all 20 pairs)
    from bench.wrong_accept import summarise as _summ
    for a in ARMS:
        tag, also = tags()[("r7", "r7", a, "F")]
        f, _ = _find(roots, tag)
        if f is None:
            continue
        recs = [r for r in _rows(f) if r["source_id"] in REAL]
        d = _summ(recs)
        o.put(f"safe/r7real/{a}/accepted", d["accepted"])
        o.put(f"safe/r7real/{a}/acc_any", d["acc_any"])
        o.put(f"safe/r7real/{a}/acc_t1", d["acc_t1"])
        o.put(f"safe/r7real/{a}/acc_any_pct", round(100 * d["acc_any"] / d["accepted"]) if d["accepted"] else 0)
        o.put(f"safe/r7real/{a}/ship_coverage", round(100 * d["ship_coverage"]) if d.get("ship_coverage") is not None else None)
    raw = raw_cells(roots)
    figs["fig-origin.tex"] = fig_origin(raw)
    figs["fig-transition.tex"] = fig_transition(raw)
    figs["fig-pc.tex"] = fig_precision_coverage(raw)
    figs["fig-heat.tex"] = fig_heat(raw)
    figs["fig-time.tex"] = fig_time(raw)
    det = {a: detection_after(raw, a, "F", REAL) for a in ARMS}
    for a in ARMS:
        d = det[a]
        if d:
            for k, v in d.items():
                o.put(f"det/r7real/{a}/{k}", v)
            o.put(f"det/r7real/{a}/pct", round(100 * (d["old"] + d["partial"] + d["restored"]) / d["rules"]))
    o.put("det/r7real/none/pct", round(100 * sum(R7[x][5][0] for x in REAL) / sum(R7[x][5][1] for x in REAL)))
    safety = {}
    for a in ARMS:
        acc = int(o.kv.get(f"safe/r7real/{a}/acc_any_pct", 0))
        wrong = int(o.kv.get(f"deg/r7real/{a}/wrong", 0))
        # deployments with a wrong value are counted apart in deg/, so add them back
        dep_n = int(o.kv.get(f"deg/r7real/{a}/restored", 0)) + int(o.kv.get(f"deg/r7real/{a}/partial", 0)) + wrong
        safety[a] = (acc, 100 * wrong / dep_n if dep_n else 0.0)
        o.put(f"det/r7real/{a}/deployments", dep_n)
    if all(det.values()):
        figs["fig-hero.tex"] = fig_hero(cells, raw, det, safety)
    # field precision and coverage, proposed and deployed (accepted runs; test = all 20 pairs, D4 = set r6)
    for set_, a, cp, pp_, cd, pd in pc_points(raw):
        k = "r7" if set_ == "test" else "r6"
        o.put(f"pc/{k}/{a}/prec_prop", round(100 * pp_))
        o.put(f"pc/{k}/{a}/prec_dep", round(100 * pd))
        o.put(f"pc/{k}/{a}/cov_prop", round(100 * cp))
        o.put(f"pc/{k}/{a}/cov_dep", round(100 * cd))
    # wall time of accepted and refused full-system runs (median minutes), per task
    for task, pool, key in (("r7", "r7", "r7"), ("t1", "all", "t1"), ("t2", "dev", "t2")):
        for a in ARMS:
            f = raw.get((task, pool, a, "F")) if task == "r7" else None
            if task != "r7":
                parts = [raw.get((task, p, a, "F")) for p in (T1_POOLS if task == "t1" else T2_POOLS)]
                f = None if any(x is None for x in parts) else sum(parts, [])
            if not f:
                continue
            for ok, nm in ((True, "acc"), (False, "ref")):
                w = sorted(r["wall_seconds"] / 60 for r in f if (r["outcome"] == "accepted") == ok and r.get("wall_seconds"))
                if w:
                    o.put(f"time/{key}/{a}/{nm}_med_min", f"{w[len(w) // 2]:.1f}")
    # numbers behind the new figures
    for task, pool, _ in TASKS3:
        for a in ARMS:
            f = raw.get((task, pool, a, "F"))
            if not f:
                continue
            acc = [r for r in f if r["outcome"] == "accepted"]
            first = sum(1 for r in acc if not r.get("sample_chosen") and not r.get("repairs"))
            rep = sum(1 for r in acc if r.get("repairs"))
            o.put(f"origin/{task}/{pool}/{a}/first", first)
            o.put(f"origin/{task}/{pool}/{a}/later", len(acc) - first - rep)
            o.put(f"origin/{task}/{pool}/{a}/repair", rep)
            o.put(f"origin/{task}/{pool}/{a}/acc", len(acc))
    for a in ARMS:
        f, e = raw.get(("r7", "r7", a, "F")), raw.get(("r7", "r7", a, "E"))
        if f and e:
            F = {(r["source_id"], r["seed"]): r["outcome"] == "accepted" for r in f}
            E = {(r["source_id"], r["seed"]): r["outcome"] == "accepted" for r in e}
            k = F.keys() & E.keys()
            o.put(f"trans/r7/{a}/rescued", sum(1 for x in k if F[x] and not E[x]))
            o.put(f"trans/r7/{a}/lost", sum(1 for x in k if E[x] and not F[x]))
            o.put(f"trans/r7/{a}/both", sum(1 for x in k if E[x] and F[x]))
            o.put(f"trans/r7/{a}/neither", sum(1 for x in k if not E[x] and not F[x]))
    return o, figs


def adv_numbers(o: Out, s: dict) -> None:
    """Task 3 (adversarial, 7B-S unless the key names another arm) and the single-slot footprint, from the summary
    bench/adv_summary.py writes. Keys under adv/ so they never collide with the earlier t3/ cells."""
    for name in ("full_S1", "mr_S0", "mr_S1", "mr_S2", "search_B", "search_C10s"):
        d = s[name]
        for k in ("n", "accepted", "deploys", "success_ir", "success_dep", "resisted", "partial", "inconclusive",
                  "informative"):
            o.put(f"adv/{name}/{k}", d.get(k, 0))
        o.put(f"adv/{name}/cp_dep_pct", f"{100 * d['cp_upper_dep']:.1f}")
        if d.get("cp_upper_informative") is not None:
            o.put(f"adv/{name}/cp_inf_pct", f"{100 * d['cp_upper_informative']:.1f}")
    for k, d in s["runs"].items():
        if "/full/S1_" in k:
            cls = k.rsplit("_", 1)[1]
            for f in ("n", "accepted", "deploys", "resisted", "partial", "inconclusive"):
                o.put(f"adv/full_S1/{cls}/{f}", d.get(f, 0))
    o.put("adv/judged_runs", s["judged_runs"])
    o.put("adv/deployed_success_all", s["deployed_success_all"])
    for k, d in s.get("null", {}).items():
        o.put(f"adv/null/{k}/fs", d["false_success"])
        o.put(f"adv/null/{k}/runs", d["runs"])
    o.put("adv/sources", s.get("sources"))
    # 2026-11-09 (review): the 88 primary cases come from 44 sources and are not independent, so also give the exact
    # bound with the source as the unit (a source counts as a success if any of its cases is one)
    from bench.adv_stats import cp
    if s.get("sources") and s["full_S1"]["success_dep"] == 0:
        o.put("adv/full_S1/cp_dep_src_pct", f"{100 * cp(0, s['sources'])[1]:.1f}")
    o.put("adv/sources_all", s.get("sources_all"))
    for k, d in s["g4"].items():
        for f, v in d.items():
            o.put(f"adv/g4/{k}/{f}", f"{v:.2f}" if f == "p" else v)
    for block in ("dose", "ceiling"):
        tot = Counter()
        for k, d in s[block].items():
            for f, v in d.items():
                o.put(f"adv/{block}/{k}/{f}", v)
            tot.update({f: v for f, v in d.items()})
        for f, v in tot.items():
            o.put(f"adv/{block}/total/{f}", v)
        o.put(f"adv/{block}/total/informative", tot["resisted"] + tot["partial"])
    for arm in ("C10s", "B"):
        tot = Counter()
        for k, d in s["attribution"].items():
            if k.startswith(arm + "/"):
                for f, v in d.items():
                    o.put(f"adv/attr/{k}/{f}", v)
                tot.update(d)
        for f, v in tot.items():
            o.put(f"adv/attr/{arm}/total/{f}", v)
    for scope in ("all", "C", "14B", "B"):
        d = s["a3"][scope]
        for f in ("judgements", "informative", "evaded"):
            o.put(f"adv/a3/{scope}/{f}", d[f])
        o.put(f"adv/a3/{scope}/rate_pct", f"{100 * d['evasion_rate']:.1f}")
        for f, v in d["pairs"].items():
            o.put(f"adv/a3/{scope}/pairs/{f}", v)
        for fam, v in d["per_family"].items():
            o.put(f"adv/a3/{scope}/fam/{fam}/evaded", v["evaded"])
            o.put(f"adv/a3/{scope}/fam/{fam}/informative", v["informative"])
    for fam, v in s.get("a3_ref_family", {}).items():
        o.put(f"adv/a3/ref/fam/{fam}/evaded", v)
    o.put("adv/a3/ref/sources_evaded", s.get("a3_ref_sources"))
    for scope in ("all", "C", "14B", "B"):
        o.put(f"adv/a3/{scope}/parsers", s["a3"][scope]["judgements"] // len(s["a3"][scope]["per_family"]))
    o.put("adv/a3/families", len(s["a3"]["all"]["per_family"]))
    rd = s.get("redos")
    if rd:
        for d in ("A1D6", "A1D18"):
            o.put(f"adv/redos/{d}/max", max(rd[d].values()))
            o.put(f"adv/redos/{d}/min", min(rd[d].values()))
        o.put("adv/redos/S1", rd["S1_A1"] + rd["S1_A2"])
        o.put("adv/redos/train/stall", rd["train_sg"]["stall"])
        o.put("adv/redos/train/sources", f"{rd['train_sg']['sources']:,}".replace(",", "\\,"))
    ref = s["a3"]["reference"]
    o.put("adv/a3/ref/informative", ref["informative"])
    o.put("adv/a3/ref/evaded", ref["evaded"])
    o.put("adv/a3/ref/rate_pct", f"{100 * ref['evaded'] / ref['informative']:.1f}")
    py = s["a3_python"]["all"]
    o.put("adv/a3py/all/evaded", py["evaded"])
    o.put("adv/a3py/all/rate_pct", f"{100 * py['evasion_rate']:.1f}")
    o.put("adv/a3py/all/fam/unicode_ws/evaded", py["per_family"]["unicode_ws"]["evaded"])
    g5 = s["g5"]
    o.put("adv/g5/parser_lines", f"{g5['parser_lines']:,}".replace(",", "\\,"))
    o.put("adv/g5/max_ms", round(1000 * g5["max_seconds"]))
    o.put("adv/g5/over_100ms", g5["over_100ms"])
    o.put("adv/g5/at_cap_1s", g5["at_cap_1s"])
    c = s["confirm"]
    for f in ("sampled", "refused_by_logstash", "agree_on_facts", "count_differences", "task3_rows"):
        o.put(f"adv/confirm/{f}", c[f])
    for f, v in c["population"].items():
        o.put(f"adv/confirm/pop/{f}", v)
    for f, v in c["redo_unicode_ws"].items():
        o.put(f"adv/confirm/redo/{f}", v)
    fp = s["footprint"]
    o.put("cost/single/C/F/peak_gb", f"{fp['peak_mib'] / 1024:.1f}")
    o.put("cost/single/C/F/peak_mib", f"{fp['peak_mib']:,}".replace(",", "\\,"))
    o.put("cost/single/C/F/median_gb", f"{fp['median_loaded_mib'] / 1024:.1f}")
    for f in ("runs", "same_outcome", "wall_min", "wall_min_served"):
        o.put(f"cost/single/C/F/{f}", fp[f])


ADV_FAMILY = {"context_echo": "text after the field", "quote_break": "quotes", "brackets": "brackets",
              "spaces": "spaces", "kv_fragment": "key and value fragment", "unicode_ws": "Unicode whitespace",
              "victim_ip": "victim's address", "long": "overlong value"}


def fig_evasion(s: dict) -> str:
    """Task 3, A2 without a model: the share of informative cases each payload family evades, for the hand-written
    reference parsers and the parsers each model deployed in Task 2. Rows sorted by the reference rate. Markers differ
    by shape as well as colour, and the three models sit on small vertical offsets so that equal rates stay visible."""
    ref_ev, ref_inf = s["a3_ref_family"], s["a3_ref_family_inf"]
    fams = sorted(ADV_FAMILY, key=lambda f: (-ref_ev[f] / ref_inf[f], ADV_FAMILY[f]))
    n = len(fams)
    ys = {f: n - i for i, f in enumerate(fams)}
    out = ["% Generated by bench/paper_r10.py. Do not edit.",
           "\\begin{tikzpicture}",
           "\\begin{axis}[scale only axis, width=\\linewidth-2.9cm, height=3.7cm, xmin=-2, xmax=52, ymin=0.4, ymax=%.1f," % (n + 0.6),
           "  xtick={0,10,20,30,40,50}, xlabel={informative cases evaded (\\%)}, xlabel style={font=\\scriptsize, yshift=3pt},",
           "  ytick={%s}, yticklabels={%s}," % (",".join(str(ys[f]) for f in fams), ",".join("{" + ADV_FAMILY[f] + "}" for f in fams)),
           "  y tick label style={font=\\scriptsize}, x tick label style={font=\\scriptsize},",
           "  xmajorgrids, grid style={gray!20}, axis line style={gray!60}, tick style={gray!60}, axis x line*=bottom, axis y line*=left,",
           "  legend columns=4, legend style={font=\\scriptsize, draw=none, at={(0.5,1.02)}, anchor=south, /tikz/every even column/.append style={column sep=4pt}}]"]
    pts = " ".join(f"({100 * ref_ev[f] / ref_inf[f]:.1f},{ys[f]})" for f in fams)
    out.append(f"\\addplot[only marks, mark=diamond, mark size=4pt, draw=black, line width=0.8pt] coordinates {{{pts}}};")
    out.append("\\addlegendentry{hand-written}")
    for scope, col, mark, dy in (("C", "armC", "*", 0.24), ("14B", "arm14", "square*", 0.0), ("B", "armB", "triangle*", -0.24)):
        fam = s["a3"][scope]["per_family"]
        pts = " ".join(f"({100 * fam[f]['evaded'] / fam[f]['informative']:.1f},{ys[f] + dy:.2f})" for f in fams)
        name = {"C": "\\armC{}", "14B": "\\armT{}", "B": "\\armB{}"}[scope]
        out.append(f"\\addplot[only marks, mark={mark}, mark size=2.5pt, color={col}, mark options={{draw=white, line width=0.3pt}}] coordinates {{{pts}}};")
        out.append(f"\\addlegendentry{{{name}}}")
    out += ["\\end{axis}", "\\end{tikzpicture}"]
    return "\n".join(out) + "\n"


def posthoc_numbers(o: Out, d: Path) -> None:
    """The post-hoc analyses of POSTHOC_REVIEW_ANALYSES.md (declared 2026-11-09, not pre-registered), under ph/.
    B1 bench/posthoc_vc.py, B2 bench/posthoc_gate.py, B4 bench/posthoc_nomodel.py, D bench/posthoc_vc.py --tag. A missing file leaves its keys
    out."""
    f = d / "b1_vc.json"
    if f.is_file():
        s = json.loads(f.read_text())["summary"]
        for a in ARMS:
            x = s[a]
            o.put(f"ph/vc/{a}/runs", x["runs"])
            o.put(f"ph/vc/{a}/deploys", x["vc_deploys"])
            o.put(f"ph/vc/{a}/wrong", x["vc_wrong"])
            o.put(f"ph/vc/{a}/prec_pct", round(100 * x["vc_precision"]) if x["vc_precision"] is not None else None)
            o.put(f"ph/vc/{a}/cov_pct", round(100 * x["vc_coverage"]) if x["vc_coverage"] is not None else None)
            o.put(f"ph/vc/{a}/det_pct", round(x["vc_det_pct"]))
            # B3: of the deployments the paper counts (V4 cut), how many carry a categorisation constant the
            # previous parser did not write with that value
            o.put(f"ph/b3/{a}/deployments", x["v4_deploys"])
            o.put(f"ph/b3/{a}/category_changed", x.get("v4_refused_key:event.category", 0))
            o.put(f"ph/b3/{a}/dataset_changed", x.get("v4_refused_key:event.dataset", 0))
    f = d / "d_noreplay.json"           # D: the 7B-S run end to end with no replay scenario, gated by VC alone
    if f.is_file():
        rows = json.loads(f.read_text())["rows"]["C"]
        x = json.loads(f.read_text())["summary"]["C"]
        o.put("ph/nr/C/runs", x["runs"])
        o.put("ph/nr/C/accepted", sum(r["outcome"] == "accepted" for r in rows))
        o.put("ph/nr/C/deploys", x["vc_deploys"])
        o.put("ph/nr/C/wrong", x["vc_wrong"])
        o.put("ph/nr/C/f_right", x["vc_f_right"])
        o.put("ph/nr/C/prec_pct", round(100 * x["vc_precision"]) if x["vc_precision"] is not None else None)
        o.put("ph/nr/C/cov_pct", round(100 * x["vc_coverage"]) if x["vc_coverage"] is not None else None)
        o.put("ph/nr/C/det_pct", round(x["vc_det_pct"]))
    f = d / "b4_nomodel.json"
    if f.is_file():
        rows = [r for r in json.loads(f.read_text())["rows"] if r.get("candidate") == "layer" and r.get("real")]
        tot = sum(r["rules_total"] for r in rows)
        det = sum(max(R7[r["source"]][5][0], r.get("rules_fire", 0)) for r in rows)
        o.put("ph/nomodel/n", len(rows))
        o.put("ph/nomodel/accepted", sum(bool(r.get("accepted")) for r in rows))
        o.put("ph/nomodel/deploys", sum(bool(r.get("gate_deploys")) for r in rows))
        o.put("ph/nomodel/wrong", sum(bool(r.get("gate_wrong")) for r in rows))
        o.put("ph/nomodel/det_pct", round(100 * det / tot) if tot else None)
    f = d / "b2_gate.json"
    if f.is_file():
        rows = [r for r in json.loads(f.read_text())["rows"] if r.get("applies") and "error" not in r]
        # A candidate whose unmutated original already deploys a wrong value (the 14B on PowerDNS, Fig. 7) would
        # count that value under every mutation: it is reported apart, and the mutation counts leave it out.
        base_wrong = {(r["arm"], r["source"]) for r in rows if r["mutation"] == "M0_original" and r.get("gate_wrong")}
        o.put("ph/gate/base_wrong", len(base_wrong))
        rows = [r for r in rows if (r["arm"], r["source"]) not in base_wrong]
        o.put("ph/gate/candidates", len({(r["arm"], r["source"]) for r in rows}))
        for m in sorted({r["mutation"] for r in rows}):
            rs = [r for r in rows if r["mutation"] == m]
            k = m.split("_")[0]
            o.put(f"ph/gate/{k}/n", len(rs))
            o.put(f"ph/gate/{k}/accepted", sum(bool(r.get("accepted")) for r in rs))
            o.put(f"ph/gate/{k}/refused", sum(not r.get("accepted") for r in rs))
            o.put(f"ph/gate/{k}/deploys", sum(bool(r.get("gate_deploys")) for r in rs))
            o.put(f"ph/gate/{k}/wrong", sum(bool(r.get("gate_wrong")) for r in rs))
            o.put(f"ph/gate/{k}/wrong_b3", sum(bool(r.get("gate_b3_wrong")) for r in rs))


def q8_numbers(o: Out, roots: list[Path]) -> None:
    """Block C (post hoc): the 14B served at 8 bits, run as F-T14-p22-r7 was, under ph/q8/.

    The whole build runs again with the 8-bit cell in the 14B's place, and its keys for that cell are copied:
    acceptance, what the gate deployed, the rules that fire, cost, and the comparison with the specialised model.
    The 8-bit cell is also compared with the 4-bit one.
    """
    global T14_R7_FULL
    if _find(roots, "F-T14q8-p22-r7")[0] is None:
        return
    T14_R7_FULL = "T14q8-p22"
    try:
        q, _ = build(roots)
    finally:
        T14_R7_FULL = "T14-p22"
    keep = ("r7/real/14B/F/", "r7/control/14B/F/", "deg/r7real/14B/", "det/r7real/14B/", "cost/r7/14B/F/",
            "safe/r7real/14B/", "cmp/r7/real/F/C-14B/")
    for k, v in q.kv.items():
        for pre in keep:
            if k.startswith(pre):
                o.put("ph/q8/" + pre.replace("14B/", "").replace("C-", "C-q8/").strip("/") + "/" + k[len(pre):], v)
    real = lambda rows: [r for r in rows if r["source"] in REAL]
    x, y = load(roots, "F-T14q8-p22-r7"), load(roots, "F-T14-p22-r7")
    cmp_numbers(o, "ph/q8/cmp/q8-q4", real(x), real(y))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--roots", nargs="+", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--adv", type=Path, default=Path.home() / ".cache/ecs-r10/task3adv/t3_summary.json",
                    help="Task 3 summary from bench/adv_summary.py; its keys are left out if the file is absent")
    ap.add_argument("--posthoc", type=Path, default=Path.home() / ".cache/ecs-r10/posthoc",
                    help="directory of the post-hoc analyses (POSTHOC_REVIEW_ANALYSES.md); absent files are skipped")
    a = ap.parse_args(argv)
    o, figs = build([r.expanduser() for r in a.roots])
    if a.adv.expanduser().is_file():
        adv = json.loads(a.adv.expanduser().read_text())
        adv_numbers(o, adv)
        figs["fig-evasion.tex"] = fig_evasion(adv)
    posthoc_numbers(o, a.posthoc.expanduser())
    q8_numbers(o, [r.expanduser() for r in a.roots])
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "r10-numbers.tex").write_text(o.tex(), encoding="utf-8")
    for name, body in figs.items():
        (a.out / f"r10-{name}").write_text(body, encoding="utf-8")
    print(f"{len(o.kv)} numbers, {len(figs)} figures/tables -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

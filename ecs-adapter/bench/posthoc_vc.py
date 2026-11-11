"""B1 and the constant count of B3 (POSTHOC_REVIEW_ANALYSES.md): what the gate deploys with VC alone.

The paper's deployment figures cut each recorded candidate to the fields V4 verified. An organisation that records no
replay scenario of the new version has only VC, continuity with what the previous parser produced. This recomputes,
for every full-system run of the 15 real test changes, the VC-verified field set with the system's own code
(adapter/anchors.py, validators/continuity.py, adapter/deploy.decide), from the stored final candidate, the frozen
previous parser and the frozen lines, and judges the cut with the paper's judge (bench/wrong_accept.judge).

No model and no Logstash: parsers are read with the Python reading of bench/wrong_accept (no date parsing or type
conversion), the same reading the paper's judge uses. Declared post hoc, see the plan file.

    python -m bench.posthoc_vc --roots ~/.cache/ecs-r10/card4/results --out ~/.cache/ecs-r10/posthoc/b1_vc.json

D (declared 2026-11-11): the same cut on the runs made with no replay scenario at all (V4 and V3.5 skipped),
    python -m bench.posthoc_vc --roots ../runs/posthoc/d_noreplay --tag C=F-C10sNR-p22-r7 --out ../runs/posthoc/d_noreplay.json
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any
import argparse
import json

from adapter import anchors as anchors_mod
from adapter.deploy import DeployPolicy, _canon, decide
from adapter.drift_loop import _v35_objections
from adapter.edit import load_previous_ir, old_lines_for
from bench.paper_numbers import _find, _rows
from bench.paper_r10 import ARMS, R7, REAL, tags
from bench.wrong_accept import document, judge, lines, reader, shipped_ir
from validators import continuity

EQV = [{"client.ip", "source.ip"}, {"client.port", "source.port"},
       {"client.user.name", "source.user.name", "user.name"}, {"client.domain", "source.domain"},
       {"destination.port", "server.port"}]
SCEN = Path(__file__).resolve().parent / "scenarios"


def rules_of(sid: str) -> list[list[str]]:
    return [json.loads((d / "expected.json").read_text())["targets"] for d in sorted(SCEN.glob(f"{sid}__holdout_*"))]


def rules_covered(sid: str, fields: set[str]) -> tuple[int, int]:
    rs = rules_of(sid)
    ok = sum(all(next((g for g in EQV if t in g), {t}) & fields for t in targ) for targ in rs)
    return ok, len(rs)


def parse(ir: dict[str, Any], ls: list[str]) -> list[dict[str, Any]]:
    """The documents a parser yields, with `message` kept so computed fields can be joined to their line."""
    rd, get = reader(ir)
    if rd is None:
        return []
    out = []
    for line in ls:
        d = document(ir, line, rd, get)
        if d is not None:
            out.append({**d, "message": line})
    return out


def cut_ir(ir: dict[str, Any], deliver: list[str], constants: dict[str, Any] | None) -> dict[str, Any]:
    cut = dict(ir)
    cut["fields"] = [f for f in ir.get("fields") or [] if f.get("ecs_field") in deliver]
    cut["value_maps"] = [v for v in ir.get("value_maps") or [] if v.get("ecs_field") in deliver]
    if constants is not None:
        cut["constants"] = dict(constants)
    return cut


def context(sid: str) -> dict[str, Any]:
    """Everything VC knows about a source before any candidate exists."""
    prev = load_previous_ir(sid)
    old_docs = parse(prev, old_lines_for(sid)) if prev else []
    new = lines(sid)
    hist = anchors_mod.history_from_documents(old_docs)
    anc = anchors_mod.anchor(hist, new)
    expected = anchors_mod.expectations(anchors_mod.token_rules(old_docs), new)
    fills = anchors_mod.fill_rates(old_docs)
    rare = {f for f, r in fills.items() if r < 0.05}
    old_fields = [f for f in anchors_mod.detection_fields(old_docs) if f not in rare]
    return {"prev": prev, "old_docs": old_docs, "new": new, "anchors": anc.values, "expected": expected,
            "old_fields": old_fields}


def one(rec: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    sid = rec["source_id"]
    ir = rec.get("ir") or {}
    row: dict[str, Any] = {"source": sid, "seed": rec.get("seed", 0), "outcome": rec.get("outcome"),
                           "rung": rec.get("rung_reached")}
    # the paper's setting, recomputed: V4-verified fields only
    v4cut = shipped_ir(rec)
    row["v4_deploys"] = v4cut is not None
    if v4cut is not None:
        j = judge(v4cut, sid)
        row["v4_wrong"] = bool(j and j["verdict"] in ("T1", "T2-clear"))
        row["v4_rules"] = rules_covered(sid, set(rec.get("verified_ecs_fields") or []))[0]
    if not ir or rec.get("rung_reached") in (None, "", "pre", "V1"):
        row["vc_deploys"] = False
        return row
    docs = parse(ir, ctx["new"])
    vc = continuity.validate(docs, ctx["anchors"], ctx["expected"]).metrics
    novc = dict(rec, verified_ecs_fields=[])                      # VC alone: V4 is not used at all
    # Offline the previous parser's IR is on disk, so its constants are read from it exactly: the Python reading
    # turns lists into text and drops event.dataset, which would make every constant look changed.
    prev_const = dict((ctx["prev"] or {}).get("constants") or {})
    d = decide(novc, vc, ctx["old_fields"], DeployPolicy(), v35_objections=_v35_objections(rec),
               previous_constants=prev_const)
    row.update(vc_verified=sorted(vc.get("verified_fields") or []),
               vc_contradicted=sorted(vc.get("contradicted_fields") or []),
               vc_kind=d.kind, vc_deliver=d.deliver, refused_constants=d.refused_constants)
    row["vc_deploys"] = d.kind != "escalated"
    if row["vc_deploys"]:
        for tag, consts in (("vc", None), ("vc_b3", d.constants)):
            j = judge(cut_ir(ir, d.deliver, consts), sid)
            row[f"{tag}_wrong"] = bool(j and j["verdict"] in ("T1", "T2-clear"))
            if j:
                row[f"{tag}_f_right"], row[f"{tag}_f_wrong"], row[f"{tag}_f_gold"] = j["f_right"], j["f_wrong"], j["f_gold"]
        row["vc_rules"] = rules_covered(sid, set(d.deliver))[0]
    # Rules firing after the run, as the paper's detection_after counts them (the previous parser keeps running
    # beside a partial deployment). With VC alone no run is accepted by detection, so none restores every rule.
    old = R7[sid][5][0]
    row["vc_det"] = max(old, row.get("vc_rules", 0)) if row["vc_deploys"] else old
    # B3: would the constant rule have changed what the paper's (V4) cut deploys?
    if v4cut is not None:
        row["v4_refused_constants"] = sorted(
            k for k, v in (ir.get("constants") or {}).items()
            if k not in prev_const or _canon(prev_const[k]) != _canon(v))
    return row


def summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    c: Counter = Counter()
    for r in rows:
        c["runs"] += 1
        c["v4_deploys"] += r["v4_deploys"]
        c["v4_wrong"] += bool(r.get("v4_wrong"))
        c["vc_deploys"] += r["vc_deploys"]
        c["vc_wrong"] += bool(r.get("vc_wrong"))
        c["vc_b3_wrong"] += bool(r.get("vc_b3_wrong"))
        c["vc_any_contradicted"] += bool(r.get("vc_contradicted"))
        c["v4_with_refused_constant"] += bool(r.get("v4_refused_constants"))
        for k in r.get("v4_refused_constants") or []:
            c[f"v4_refused_key:{k}"] += 1
        c["vc_with_refused_constant"] += bool(r.get("refused_constants")) and r["vc_deploys"]
        for k in ("f_right", "f_wrong", "f_gold"):
            c[f"vc_{k}"] += r.get(f"vc_{k}", 0) if r["vc_deploys"] else 0
        c["vc_rules"] += r.get("vc_rules", 0)
        c["v4_rules"] += r.get("v4_rules", 0)
        c["rules_total"] += len(rules_of(r["source"]))
        c["vc_det"] += r["vc_det"]
    d = dict(c)
    d["vc_precision"] = c["vc_f_right"] / (c["vc_f_right"] + c["vc_f_wrong"]) if c["vc_f_right"] + c["vc_f_wrong"] else None
    d["vc_coverage"] = c["vc_f_right"] / c["vc_f_gold"] if c["vc_f_gold"] else None
    d["vc_rules_pct"] = 100 * c["vc_rules"] / c["rules_total"] if c["rules_total"] else None
    d["vc_det_pct"] = 100 * c["vc_det"] / c["rules_total"] if c["rules_total"] else None
    d["v4_rules_pct"] = 100 * c["v4_rules"] / c["rules_total"] if c["rules_total"] else None
    return d


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--roots", type=Path, nargs="+", required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--tag", action="append", default=[], metavar="ARM=TAG",
                    help="read only these arms, from these run tags (the no-replay runs of D)")
    a = ap.parse_args()
    override = dict(t.split("=", 1) for t in a.tag)
    ctxs: dict[str, dict[str, Any]] = {}
    out: dict[str, Any] = {"rows": {}, "summary": {}}
    for arm in ARMS:
        if override and arm not in override:
            continue
        tag, also = (override[arm], ()) if override else tags()[("r7", "r7", arm, "F")]
        recs = []
        for t in (tag, *also):
            f, _ = _find(a.roots, t)
            if f is not None:
                recs += _rows(f)
        last = {(r["source_id"], r.get("seed", 0)): r for r in recs}
        recs = [r for r in last.values() if r["source_id"] in REAL]
        rows = []
        for r in recs:
            sid = r["source_id"]
            if sid not in ctxs:
                ctxs[sid] = context(sid)
            rows.append(one(r, ctxs[sid]))
        out["rows"][arm] = rows
        out["summary"][arm] = summary(rows)
        print(arm, json.dumps(out["summary"][arm], default=str))
    out["sources"] = {s: {"old_docs": len(c["old_docs"]), "new_lines": len(c["new"]),
                          "anchored_fields": sorted(c["anchors"]), "computed": sorted(c["expected"]),
                          "old_fields": c["old_fields"]} for s, c in ctxs.items()}
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(out, indent=1, default=str))


if __name__ == "__main__":
    main()

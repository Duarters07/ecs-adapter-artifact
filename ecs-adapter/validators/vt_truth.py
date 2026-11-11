"""VT - the truth oracle, for training data generated with per-line truth.

A SIEMgen source knows, for every line it emits, the ECS document that line
means (`render_ecs` of the same event). So a candidate parser can be checked
field by field against it: parse the lines, join each document to its line by
`message`, compare. No scenario and no detection rule is needed, and nothing is
approximate.

WHAT IT IS FOR, AND WHAT IT MUST NEVER BE USED FOR
--------------------------------------------------
It verifies TRAINING material: a proposal VT verifies may become an example.
It is never an evaluation oracle on a source the student was trained on, and
it is not V4: the truth here is SIEMgen's own ECS rendering, one generator's
opinion, which is fine for teaching and would be circular for grading. The
held-out evaluation stays on real sources (PLAN_R2.md).

PER FIELD
---------
    verified      agrees on >= MIN_AGREE of the lines whose truth carries it,
                  over at least MIN_LINES lines
    contradicted  disagrees on more than 1 - MIN_AGREE of them
    unchecked     too few lines carry it, or the parser never produced it
    extra         produced by the parser, absent from every truth row - not
                  wrong, not verifiable, never credited
"""
from __future__ import annotations

from typing import Any

from adapter.types import STAGE_MAP, Finding, ValidationReport

MIN_AGREE = 0.95
MIN_LINES = 3
_ABSENT = ("", "-")
# Present in every parsed document for reasons that have nothing to do with the
# mapping: the input plugin, the pipeline, the timestamp the date filter sets.
_IGNORE = ("@timestamp", "@version", "tags", "message", "event.original", "host.name",
           "log.file.path", "ecs.version", "data_stream.", "labels.", "related.")


def _flatten(doc: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in doc.items():
        if isinstance(v, dict):
            out.update(_flatten(v, f"{prefix}{k}."))
        else:
            out[f"{prefix}{k}"] = v
    return out


def _vals(v: Any) -> frozenset[str]:
    if v is None:
        return frozenset()
    items = v if isinstance(v, list) else [v]
    return frozenset(str(x) for x in items if str(x) not in _ABSENT)


def _ignored(name: str) -> bool:
    return any(name == p or (p.endswith(".") and name.startswith(p)) for p in _IGNORE)


def compare(documents: list[dict[str, Any]],
            line_truth: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """{field: {agree, disagree, absent, lines}} over the lines truth covers."""
    by_msg = {str(d.get("message")): _flatten(d) for d in documents
              if d.get("message") is not None}
    out: dict[str, dict[str, int]] = {}
    for row in line_truth:
        got_doc = by_msg.get(row["raw"])
        truth = _flatten(row.get("ecs") or {})
        for name, want_v in truth.items():
            if _ignored(name):
                continue
            want = _vals(want_v)
            if not want:
                continue
            c = out.setdefault(name, {"agree": 0, "disagree": 0, "absent": 0, "lines": 0})
            c["lines"] += 1
            got = _vals(got_doc.get(name)) if got_doc is not None else frozenset()
            if not got:
                c["absent"] += 1
            elif got == want:
                c["agree"] += 1
            else:
                c["disagree"] += 1
    return out


def validate(documents: list[dict[str, Any]],
             line_truth: list[dict[str, Any]]) -> ValidationReport:
    rep = ValidationReport(rung_reached="VT")
    if not line_truth:
        rep.passed = True
        rep.metrics.update({"verified": False, "verified_fields": [],
                            "contradicted_fields": [], "skipped": "no line truth"})
        return rep

    per = compare(documents, line_truth)
    truth_fields = set(per)
    produced = {k for d in documents for k in _flatten(d) if not _ignored(k)}

    verified, contradicted, unchecked = [], [], []
    for name, c in sorted(per.items()):
        seen = c["agree"] + c["disagree"]
        if seen and c["disagree"] / seen > 1 - MIN_AGREE:
            contradicted.append(name)
            rep.findings.append(Finding(
                "VT", "truth_mismatch",
                f"{name} disagrees with the truth on {c['disagree']} of {seen} lines",
                STAGE_MAP, source_key=name))
        elif seen >= MIN_LINES and c["agree"] / c["lines"] >= MIN_AGREE:
            verified.append(name)
        else:
            unchecked.append(name)

    rep.metrics.update({
        "verified": True,
        "verified_fields": verified,
        "contradicted_fields": contradicted,
        "unchecked_fields": unchecked,
        "extra_fields": sorted(produced - truth_fields),
        "per_field": per,
        "documents": len(documents),
        "truth_lines": len(line_truth),
    })
    rep.passed = not contradicted and bool(verified)
    return rep

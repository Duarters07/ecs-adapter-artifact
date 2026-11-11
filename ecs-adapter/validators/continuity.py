"""VC - continuity with the parser that drifted. Field by field.

V3.5 asks, for ONE injected value per field, which field is holding it, and it
is advisory inside the ladder for a reason recorded there: placement against a
probe is an opinion about the right field, and V4 decides. This rung asks the
same question with the values `adapter/anchors.py` harvested from the OLD
parser's output, and its answer is not an opinion: it is what the detection
rules in production already read.

It is not a gate inside the ladder - the arms are compared on the ladder alone,
and nothing here may change their numbers. It is the deployment gate: a field
reaches production unattended only if this rung or V4 verified it, and never if
either contradicted it. See `adapter/deploy.py`.

PER FIELD, THREE STATES
-----------------------
    verified      most of the field's anchors were found in that field, and
                  none of them in another
    contradicted  an anchor was found in a DIFFERENT field and not in its own.
                  This is the swapped mapping, the defect the project exists to
                  catch, and it blocks the field whatever V4 said
    untested      the field has no anchor in these lines, or none of its
                  anchors turned up in any parsed document
"""
from __future__ import annotations

from typing import Any

from adapter.types import STAGE_MAP, Finding, ValidationReport

# A field is verified when this share of its anchors landed in place. Not 1.0:
# an anchor value can legitimately be absent from a document the new parser
# produced from a line variant that does not carry that key.
MIN_PLACED = 0.8


def _flatten(doc: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in doc.items():
        path = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, f"{path}."))
        else:
            out[path] = v
    return out


def _values(v: Any) -> set[str]:
    if isinstance(v, list):
        return {str(x) for x in v if x is not None}
    return set() if v is None else {str(v)}


# A computed field is checked line by line against the value history's marker
# words predict (adapter/anchors.token_rules). It is verified when it agrees on
# this share of the lines a rule decides, and contradicted past this share of
# disagreements - a marker word can occasionally appear for another reason.
MIN_AGREEMENT = 0.9
MIN_DECIDED = 3


def _computed(flat_by_msg: dict[str, dict[str, Any]],
              expected: dict[str, dict[str, str]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for name, per_line in sorted(expected.items()):
        agree = disagree = absent = 0
        example = None
        for line, want in per_line.items():
            d = flat_by_msg.get(line)
            if d is None:
                continue
            got = _values(d.get(name))
            if not got:
                absent += 1
            elif want in got:
                agree += 1
            else:
                disagree += 1
                example = example or (line, want, sorted(got))
        out[name] = {"agree": agree, "disagree": disagree, "absent": absent,
                     "example": example}
    return out


def validate(
    documents: list[dict[str, Any]],
    anchors: dict[str, list[str]],
    expected: dict[str, dict[str, str]] | None = None,
) -> ValidationReport:
    """``expected``: per-line values of computed fields, {field: {line: value}}.
    Documents are joined to lines through `message`, which every compiled
    parser keeps."""
    rep = ValidationReport(rung_reached="VC")
    if not anchors and not expected:
        rep.passed = True
        rep.metrics.update({"verified": False, "verified_fields": [],
                            "contradicted_fields": [], "untested_fields": [],
                            "skipped": "no history anchors for this source"})
        return rep
    if not documents:
        rep.findings.append(Finding(
            "VC", "no_documents", "the parser produced no documents to inspect.",
            STAGE_MAP))
        rep.metrics.update({"verified": False, "verified_fields": [],
                            "contradicted_fields": [],
                            "untested_fields": sorted(anchors)})
        return rep

    flat = [_flatten(d) for d in documents]
    # value -> the fields any document holds it in
    where: dict[str, set[str]] = {}
    for d in flat:
        for path, v in d.items():
            for s in _values(v):
                where.setdefault(s, set()).add(path)

    verified: list[str] = []
    contradicted: list[str] = []
    untested: list[str] = []
    per_field: list[dict[str, Any]] = []

    for name, values in sorted(anchors.items()):
        placed = [v for v in values if name in where.get(v, set())]
        astray = {v: sorted(where[v] - {name}) for v in values
                  if v in where and name not in where[v]}
        seen = len(placed) + len(astray)
        per_field.append({"field": name, "anchors": len(values), "placed": len(placed),
                          "elsewhere": {v: f for v, f in astray.items()}})
        if astray:
            contradicted.append(name)
            v, fs = next(iter(sorted(astray.items())))
            rep.findings.append(Finding(
                "VC", "continuity_broken",
                f"before the format changed, {v!r} was {name}. The new parser puts "
                f"it in {', '.join(fs)}. Detection rules written against {name} "
                "would stop matching.",
                STAGE_MAP, source_key=name))
        elif seen and len(placed) / seen >= MIN_PLACED:
            verified.append(name)
        else:
            untested.append(name)

    if expected:
        by_msg = {str(d.get("message")): d for d in flat if d.get("message") is not None}
        for name, c in _computed(by_msg, expected).items():
            decided = c["agree"] + c["disagree"]
            per_field.append({"field": name, "computed": True, **c})
            if decided and c["disagree"] / decided > 1 - MIN_AGREEMENT:
                if name not in contradicted:
                    contradicted.append(name)
                line, want, got = c["example"]
                rep.findings.append(Finding(
                    "VC", "computed_field_broken",
                    f"before the format changed, a line like this one had {name} = "
                    f"{want!r}; the new parser gives {got} for {line[:120]!r}.",
                    STAGE_MAP, source_key=name))
            elif decided >= MIN_DECIDED and name not in contradicted:
                if name not in verified:
                    verified.append(name)
                if name in untested:
                    untested.remove(name)
            elif name not in verified and name not in contradicted and name not in untested:
                untested.append(name)
        verified = [f for f in verified if f not in contradicted]

    rep.metrics.update({
        "verified": True,
        "verified_fields": verified,
        "contradicted_fields": contradicted,
        "untested_fields": untested,
        "results": per_field,
    })
    rep.passed = not contradicted
    return rep

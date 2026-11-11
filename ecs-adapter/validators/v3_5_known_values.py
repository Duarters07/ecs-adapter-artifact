"""V3.5 - the known-value probe. Placement, checked directly.

A probe puts values we chose into the source: the address it connected from, a
unique username, a unique path. Afterwards we ask one question of the parsed
documents:

    the value I injected - which ECS field is actually holding it?

That is a different question from the one V4 asks, and it is answerable without
Elasticsearch, without a detection rule and without a staged scenario beyond the
values themselves.

WHY THIS IS NOT GROUND TRUTH, AND WHY THE LADDER MAY READ IT
------------------------------------------------------------
The ladder never reads `truth.json`, by design: ground truth is a human's
semantic judgement about what a field *means*, and validating against it would
make the oracle depend on the labelling work this project exists to avoid.

`known_values.json` is a different kind of statement:

    truth.json         "client_ip should map to source.ip"       a judgement
    known_values.json  "203.0.113.200 is where the probe
                        connected from"                          an observation

The second requires no understanding of the log format at all - only knowledge
of what we did. That asymmetry is what makes this rung cheap, and it is why
reading it does not compromise the ladder.

WHAT THIS RUNG DOES AND DOES NOT CATCH
--------------------------------------
It catches PLACEMENT: a value that landed in the wrong field, or was dropped.
It is blind to TYPE - "401" as a keyword looks identical to 401 as a long here,
and that is V1's job to declare and V4's job to feel. It also says nothing about
fields the probe did not control.

It earns its place on attribution. "The value you put in destination.ip is the
address the probe connected from" is a far better repair message than "a rule
expected 4 and found 0".
"""
from __future__ import annotations

from typing import Any

from adapter.types import STAGE_INTERPRET, STAGE_MAP, Finding, ValidationReport, round9_pipeline


def _flatten(doc: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Logstash emits nested ECS; known_values are written dotted."""
    out: dict[str, Any] = {}
    for k, v in doc.items():
        path = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, f"{path}."))
        else:
            out[path] = v
    return out


def _same(a: Any, b: Any) -> bool:
    """Compare by string form.

    Placement is the question here, not type: if the probe injected 401 and the
    parser produced the string "401", the value is in the right place and the
    type problem belongs to V1 and V4. Coercing avoids reporting a type error
    as a placement error, which would send the repair loop to the wrong stage.
    """
    return str(a) == str(b)


def validate(
    documents: list[dict[str, Any]],
    known_values: dict[str, Any],
    ir: dict[str, Any] | None = None,
) -> ValidationReport:
    """Check that each injected value is in the field it belongs to.

    Args:
        documents: parsed documents from the V3 sandbox, nested as Logstash
            emits them.
        known_values: dotted ECS field -> the value the probe injected.
    """
    rep = ValidationReport(rung_reached="V3.5")

    if not known_values:
        # Nothing was declared, so nothing is claimed. Distinguished from a
        # pass, exactly as V4 distinguishes "not contradicted" from "verified".
        rep.passed = True
        rep.metrics["verified"] = False
        rep.metrics["values_checked"] = 0
        rep.metrics["skipped"] = "no known values declared for this source"
        return rep

    if not documents:
        rep.findings.append(
            Finding("V3.5", "no_documents",
                    "the sandbox produced no documents to inspect.", STAGE_MAP)
        )
        return rep

    flat = [_flatten(d) for d in documents]
    correct: list[str] = []
    results: list[dict[str, Any]] = []

    for field, value in sorted(known_values.items()):
        in_place = sum(1 for d in flat if _same(d.get(field), value))

        # Where else did the value end up? This is the attribution.
        elsewhere = sorted({
            path
            for d in flat
            for path, v in d.items()
            if path != field and _same(v, value)
        })

        results.append({
            "field": field, "value": value,
            "documents_with_value_in_place": in_place,
            "also_found_in": elsewhere,
        })

        if in_place:
            correct.append(field)
            continue

        if elsewhere:
            rep.findings.append(
                Finding(
                    "V3.5", "value_in_wrong_field",
                    f"the probe injected {value!r} as {field}, but the parser put "
                    f"it in {', '.join(elsewhere)}. Whatever the source calls that "
                    f"key, its value is {field} - that is what the probe did.",
                    STAGE_MAP, source_key=field,
                )
            )
        else:
            # Round 10 (A1): when the mapping DOES name a key for this field,
            # the value is missing because that key was never extracted, which
            # is stage 1's; when nothing is mapped to it, it is stage 2's.
            keys = sorted({f.get("source_key") for f in (ir or {}).get("fields") or []
                           if isinstance(f, dict) and f.get("ecs_field") == field and f.get("source_key")})
            if keys and not round9_pipeline():
                rep.findings.append(
                    Finding(
                        "V3.5", "value_not_found",
                        f"the probe injected {value!r} as {field}, and it appears in no "
                        f"field of any parsed document. The mapping reads {field} from "
                        f"{', '.join(repr(k) for k in keys)}, so that key is not being "
                        f"extracted from the line: check `extraction`.",
                        STAGE_INTERPRET, source_key=field,
                    )
                )
            else:
                rep.findings.append(
                    Finding(
                        "V3.5", "value_not_found",
                        f"the probe injected {value!r} as {field}, and it appears in no "
                        f"field of any parsed document. The parser dropped it.",
                        STAGE_MAP, source_key=field,
                    )
                )

    rep.metrics.update({
        "verified": True,
        "values_checked": len(known_values),
        "values_correct": len(correct),
        "placement_accuracy": len(correct) / len(known_values),
        "results": results,
    })
    rep.passed = not rep.findings
    return rep

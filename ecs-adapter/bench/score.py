"""Field-level semantic scoring against reviewed ground truth.

Abstention on a field ground truth marks as genuinely ambiguous is CORRECT and
is scored as such. With no analyst reviewing the output, a confident wrong
answer is worse than "I do not know", and the scoring has to reflect that or it
rewards the wrong behaviour.

TWO ACCURACIES ARE REPORTED, AND NEITHER REPLACES THE OTHER
-----------------------------------------------------------
    semantic_accuracy             the field named in truth, and only that one
    semantic_accuracy_equivalent  that field or any ECS field adapter.ecs_index
                                  declares the same answer

ECS carries the same information under two names in a few places: the network
view (source, destination) and the role view (client, server) of one endpoint,
and `user.name` and `source.user.name`, which share one sentence of
documentation. A parser that picks either has read the log correctly, and the
IR can write only one field per key, so it must pick.

The strict figure is the one a deployment cares about: if the detection rules
in place name `source.ip`, a parser writing `client.ip` breaks them. The
equivalent figure is the one a reader needs in order to tell a mapping error
from a convention mismatch. Reporting only the first understates the model;
reporting only the second understates the operational risk.
"""
from __future__ import annotations

from typing import Any


def score(ir: dict[str, Any], truth: dict[str, Any]) -> dict[str, Any]:
    from adapter.ecs_index import EQUIVALENT_TO

    t_by_key = {f["source_key"]: f for f in truth.get("fields", [])}
    ir_by_key = {f["source_key"]: f for f in ir.get("fields", [])}
    unresolved = {u["source_key"] for u in ir.get("unresolved", [])}

    correct = wrong = missing = 0
    equivalent = 0          # right entity, the other ECS name for it
    # Which ECS fields, by name. The counts say how good a mapping is; the
    # names say what a deployment of it would SHIP right and wrong, which is
    # what bench/report_r2.py measures (PLAN_R2.md: delivered fields).
    correct_fields: list[str] = []
    wrong_fields: list[str] = []
    good_abstain = bad_abstain = missed_abstain = 0

    # A truth field may name other keys a correct parser can use for the same value
    # (round 6: a JSON key such as `requestHeaders.User-Agent` cannot be a grok capture
    # name, so a grok parser of the same line names it differently). No truth before
    # round 6 carries aliases, so no earlier number changes.
    for key, t in t_by_key.items():
        for alias in t.get("source_key_aliases", ()):
            if key not in ir_by_key and key not in unresolved:
                if alias in ir_by_key:
                    ir_by_key[key] = ir_by_key.pop(alias)
                elif alias in unresolved:
                    unresolved = (unresolved - {alias}) | {key}

    for key, t in t_by_key.items():
        acceptable = bool(t.get("acceptable_abstention", False))

        if key in unresolved:
            if acceptable:
                good_abstain += 1
            else:
                bad_abstain += 1
            continue

        if key not in ir_by_key:
            missing += 1
            continue

        if t.get("ecs_field") is None:
            # Ground truth says there is no correct ECS field; assigning one is an error.
            missed_abstain += 1
            continue

        answered = ir_by_key[key]["ecs_field"]
        if answered == t["ecs_field"]:
            correct += 1
            correct_fields.append(answered)
        elif answered in EQUIVALENT_TO.get(t["ecs_field"], frozenset()):
            equivalent += 1
            wrong_fields.append(answered)    # equivalent, but not what the rules read
        else:
            wrong += 1
            wrong_fields.append(answered)

    decided = correct + equivalent + wrong
    return {
        "correct": correct,
        "equivalent": equivalent,
        "wrong": wrong,
        "missing": missing,
        "semantic_accuracy": (correct / decided) if decided else None,
        "semantic_accuracy_equivalent":
            ((correct + equivalent) / decided) if decided else None,
        "abstention": {
            "correct": good_abstain,
            "incorrect": bad_abstain,
            "should_have_abstained": missed_abstain,
        },
        "hallucinated_keys": sorted(set(ir_by_key) - set(t_by_key)),
        "correct_fields": sorted(set(correct_fields)),
        "wrong_fields": sorted(set(wrong_fields)),
        "truth_fields": sorted({t["ecs_field"] for t in t_by_key.values() if t.get("ecs_field")}),
    }


def score_lines(per_field: dict[str, dict[str, int]], min_agree: float = 0.95) -> dict[str, Any]:
    """The same summary from per-line truth (validators.vt_truth.compare).

    A field is correct when it agrees on `min_agree` of the lines whose truth
    carries it, wrong when it disagrees on more than the rest, and missing when
    the parser never produced it on those lines.
    """
    correct_fields, wrong_fields, missing_fields = [], [], []
    agree = seen = 0
    for name, c in sorted(per_field.items()):
        decided = c["agree"] + c["disagree"]
        agree += c["agree"]
        seen += decided
        if decided and c["disagree"] / decided > 1 - min_agree:
            wrong_fields.append(name)
        elif decided and c["agree"] / c["lines"] >= min_agree:
            correct_fields.append(name)
        else:
            missing_fields.append(name)
    return {
        "correct": len(correct_fields),
        "wrong": len(wrong_fields),
        "missing": len(missing_fields),
        "semantic_accuracy": (len(correct_fields) / (len(correct_fields) + len(wrong_fields)))
        if (correct_fields or wrong_fields) else None,
        "line_agreement": (agree / seen) if seen else None,
        "correct_fields": correct_fields,
        "wrong_fields": wrong_fields,
        "truth_fields": sorted(per_field),
        "per_field": per_field,
        "scored_by": "line_truth",
    }

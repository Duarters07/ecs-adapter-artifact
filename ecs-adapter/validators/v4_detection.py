"""V4 - detection replay. THE CONTRIBUTION.

Runs real detection rules over events normalised by the candidate parser. This
is the only rung that can catch a schema-valid, semantically wrong mapping - the
swapped source.ip / destination.ip case that V1, V2 and V3 all pass.

Two rules that make the numbers mean anything:

1. Scenario events are DISJOINT from the samples shown to the model. Replaying
   the samples the parser was built from would only prove the parser fits its
   own input.
2. Replay used for REPAIR and replay used for EVALUATION use disjoint scenario
   sets, fixed before any model runs. Otherwise the method fits its own tests.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
import json

from adapter.types import STAGE_INTERPRET, STAGE_MAP, Finding, ValidationReport, round9_pipeline

# The replay index needs an explicit mapping. Under Elasticsearch's dynamic
# mapping a string becomes `text` with a `.keyword` subfield, and a `term` query
# on "source.ip" would silently match nothing - which would make every scenario
# fail for the wrong reason and destroy the V4 signal.
REPLAY_MAPPINGS: dict[str, Any] = {
    "dynamic_templates": [
        {
            "strings_as_keyword": {
                "match_mapping_type": "string",
                "mapping": {"type": "keyword"},
            }
        }
    ],
    "properties": {
        "@timestamp": {"type": "date"},
        "source": {"properties": {"ip": {"type": "ip"}}},
        "destination": {"properties": {"ip": {"type": "ip"}}},
        "observer": {"properties": {"ip": {"type": "ip"}}},
        "client": {"properties": {"ip": {"type": "ip"}}},
        "server": {"properties": {"ip": {"type": "ip"}}},
    },
}


def _clause_values(clause: dict[str, Any]) -> frozenset[Any]:
    """Every literal a clause filters on, whatever shape it was written in."""
    out: set[Any] = set()
    if "term" in clause:
        out.update(clause["term"].values())
    for sub in (clause.get("bool") or {}).get("should") or []:
        out |= _clause_values(sub)
    for sub in (clause.get("bool") or {}).get("filter") or []:
        out |= _clause_values(sub)
    return frozenset(out)


def indistinguishable_targets(scenarios: list[dict[str, Any]]) -> frozenset[str]:
    """Fields a scenario cannot tell apart, and must therefore never credit.

    A rule filtering on two fields that carry the SAME marker value answers the
    same count whichever way those two are mapped, so it proves nothing about
    either. The corpus generator does this deliberately for related pairs -
    `network.protocol` and `network.transport` share `gre`, `sctp` and `dccp`
    across the three namespaces - and the key names are shared on purpose too,
    `proto` and `l4proto` belonging to both.

    It was found when a proposal mapped `proto -> network.protocol` and
    `l4proto -> network.transport`, the exact inverse of the ground truth, and
    V4 credited both. Crediting a mapping the truth calls wrong is the one
    thing no rule in this project may do; refusing to credit a mapping it
    cannot adjudicate is merely conservative, and matches the project's own
    sentence that not contradicted is not verified.

    Computed from the scenarios on disk rather than recorded in the report, so
    that it applies to every record ever written and not only to new ones.
    """
    out: set[str] = set()
    for sc in scenarios:
        targets = list(sc.get("targets") or [])
        clauses = ((sc.get("query") or {}).get("bool") or {}).get("filter") or []
        if len(clauses) != len(targets):
            continue
        vals = [_clause_values(c) for c in clauses]
        for i, field in enumerate(targets):
            if any(vals[i] & vals[j] for j in range(len(targets)) if j != i):
                out.add(field)
    return frozenset(out)


def verified_fields(report: dict[str, Any]) -> frozenset[str]:
    """Which ECS fields did detection actually confirm in this report?

    `is_detection_verified` answers whether the proposal survived AS A WHOLE.
    This answers a different and usually larger question: which parts of it a
    rule fired on. A scenario's query filters on its `targets` and its expected
    hit count is known by construction, so a scenario that comes back with the
    right count is positive evidence that the parser put the right values in
    exactly those fields - whatever it did with the rest of the line.

    Why this exists. V4 is all-or-nothing by design: `passed` is
    `scenarios_passed == len(scenarios)`. On a wide source one misplaced value
    discards the whole proposal, taking every correct mapping with it. Measured
    over the 383 revalidated proposals, 104 die at V4 and 40 of those fail a
    single scenario out of four; over the 21 twelve-field families added in
    October, the first 34 runs produced zero accepted proposals. Credit at
    field granularity keeps the oracle exactly as it is - a detection rule,
    replayed - and changes only what a passing rule is taken to prove.

    Returns the empty set when replay did not run, so an absence of evidence is
    never read as evidence. Fields no scenario targets are never credited: they
    were not tested, which is not the same as being wrong.
    """
    metrics = report.get("metrics") or {}
    if metrics.get("verified") is not True:
        return frozenset()
    if int(metrics.get("scenarios_total", 0)) <= 0:
        return frozenset()
    out: set[str] = set()
    for result in metrics.get("results") or []:
        per_target = result.get("per_target") or {}
        if per_target:
            # The finer answer when the apparatus recorded it: a field is
            # credited when a rule filtering on IT ALONE would have fired
            # correctly, whether or not the field beside it in the same rule
            # did. See validate(), where those counts are taken.
            out.update(f for f, ok in per_target.items() if ok)
        elif result.get("passed"):
            # Records written before per-target counts existed. A rule that
            # fired on a conjunction proves every field in it; a rule that did
            # not fire proves nothing about any of them, and that is the loss
            # the counts above exist to stop.
            out.update(result.get("targets") or [])
    return frozenset(out)


def is_detection_verified(report: dict[str, Any]) -> bool:
    """Did detection replay actually run, and did the candidate survive it?

    The distinction this draws is the one the whole method rests on. A report
    can carry ``passed: True`` and ``rung_reached: "V4"`` in two very different
    situations:

        the candidate was replayed against real rules and they all fired
        the candidate was never replayed, because no scenario exists

    Only the first is evidence. Treating the second as evidence would feed
    unverified mappings into the training set - importing exactly the errors
    the filter exists to exclude, and doing it silently, because nothing about
    the record looks wrong.

    This is the single definition. teacher/filter.py and
    training/build_dataset.py both call it rather than re-deriving it, because
    the first version of this project derived it twice and got it wrong once.
    """
    if not report.get("passed"):
        return False
    if report.get("rung_reached") != "V4":
        return False
    metrics = report.get("metrics") or {}
    if metrics.get("verified") is not True:
        return False
    return int(metrics.get("scenarios_total", 0)) > 0


def load_scenarios(bench_root: Path, source_id: str, split: str) -> list[dict[str, Any]]:
    """split: 'repair' during the loop, 'holdout' for evaluation. Never the same set."""
    out: list[dict[str, Any]] = []
    base = bench_root / "scenarios"
    if not base.is_dir():
        return out

    for d in sorted(base.glob(f"{source_id}__*")):
        expected_path = d / "expected.json"
        query_path = d / "query.json"
        events_path = d / "events.ndjson"
        if not (expected_path.is_file() and query_path.is_file() and events_path.is_file()):
            continue

        meta = json.loads(expected_path.read_text(encoding="utf-8"))
        if meta.get("split") != split:
            continue

        meta["id"] = d.name
        meta["query"] = json.loads(query_path.read_text(encoding="utf-8"))
        meta["events"] = [
            json.loads(line)["raw"]
            for line in events_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        out.append(meta)
    return out


def _flatten(doc: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Logstash emits nested objects; ECS field names are dotted paths."""
    out: dict[str, Any] = {}
    for k, v in doc.items():
        path = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, f"{path}."))
        else:
            out[path] = v
    return out


def _term_of(clause: dict[str, Any]) -> tuple[str, str] | None:
    """(field, value) of a plain term clause, or of a should-list of them."""
    term = clause.get("term") or clause.get("match")
    if isinstance(term, dict) and len(term) == 1:
        (field, value), = term.items()
        value = value.get("value", value.get("query")) if isinstance(value, dict) else value
        return field, str(value)
    should = (clause.get("bool") or {}).get("should") or []
    for c in should:
        t = _term_of(c)
        if t:
            return t
    return None


def _value_hint(docs: list[dict[str, Any]], clauses: list[Any],
                per_target: dict[str, bool]) -> str:
    """What the rule looks for beside what the parser wrote, for each clause that misses.

    "every field the rule needs is present ... the VALUES are landing somewhere
    unexpected" was all a repair got when the field was right and its WORDS were
    not: sshd's `outcome` holding `Failed` where the rule asks `event.outcome:
    failure`. The fix is a value map, and nothing said so (2026-10-17). The
    expected value is the organisation's own rule, so showing it reveals nothing
    a deployment does not already hold.
    """
    def values(field: str) -> list[str]:
        out: list[str] = []
        for d in docs:
            cur: Any = d
            for part in field.split("."):
                cur = cur.get(part) if isinstance(cur, dict) else None
            if cur is None:
                cur = d.get(field)
            for v in (cur if isinstance(cur, list) else [cur]):
                if v is not None and str(v) not in out:
                    out.append(str(v))
        return out[:5]

    notes = []
    for clause in clauses:
        t = _term_of(clause) if isinstance(clause, dict) else None
        if not t or per_target.get(t[0], False):
            continue
        field, want = t
        got = values(field)
        if got and want not in got:
            notes.append(f"the rule looks for {field} = {want!r}; the parsed documents carry "
                         f"{', '.join(repr(g) for g in got)} - if those are the source's words "
                         "for the same thing, translate them with a value map")
    return (" " + "; ".join(notes) + ".") if notes else ""


def _diagnose(docs: list[dict[str, Any]], targets: list[str]) -> tuple[str, list[str]]:
    """Why did the rule find nothing? Name the thing that is actually wrong.

    The message this replaces said "a field is probably assigned to the wrong
    ECS role" whatever had happened, and sent the repair loop to re-check
    source.* against destination.* every time. Measured on arm C: sshd_auth had
    every role correct - field-level accuracy 1.00 - and proposed a key=value
    extraction for a line that contains no '=' at all. Nineteen documents
    indexed, none carrying a single ECS field, and three repair rounds spent
    looking at the one part of the mapping that was right.

    The three cases are distinguishable from what is already in hand, so they
    are distinguished.
    """
    if not docs:
        return (
            "the parser produced no documents at all, so nothing could match. "
            "This is an extraction failure, not a mapping one: check `extraction` "
            "- the kind, the delimiters, the pattern - before changing any field.",
            [],
        )
    flat = [_flatten(d) for d in docs]
    present = [t for t in targets if any(t in d for d in flat)]
    missing = [t for t in targets if t not in present]
    if targets and not present:
        return (
            f"{len(docs)} document(s) were produced and NOT ONE of them carries any "
            f"of the fields the rule needs ({', '.join(targets)}). The mapping may "
            "well be right; the parser is not producing these fields. Check "
            "`extraction` first - if the layout is wrong, every field is empty and "
            "every rule fails regardless of where it is mapped.",
            missing,
        )
    if missing:
        return (
            f"the documents carry {', '.join(present)} but never "
            f"{', '.join(missing)}. Those fields are declared in the mapping and "
            "absent from the output, so either the source key does not exist or "
            "the extraction is not reaching it.",
            missing,
        )
    return (
        "every field the rule needs is present in the documents, so the fields are "
        "being produced and the VALUES are landing somewhere unexpected. This is "
        "the case where a role is likely wrong: re-check source.* against "
        "destination.* against observer.*.",
        [],
    )


def validate(
    es,
    index_prefix: str,
    parsed_by_scenario: dict[str, list[dict[str, Any]]],
    scenarios: list[dict[str, Any]],
    declared: set[str] | None = None,
) -> ValidationReport:
    """Index each scenario's normalised events separately and run its rule.

    `declared` is the set of ECS fields the mapping names (round 10, A1): a
    field the rule needs, declared and absent from every document, is an
    extraction fault; one the mapping never names is a mapping fault.
    """
    rep = ValidationReport(rung_reached="V4")

    if not scenarios:
        # A source with no scenarios for this split cannot be contradicted, so
        # the ladder lets it through: refusing every such candidate would make
        # the system unusable on sources nobody has written a scenario for yet.
        #
        # But "not contradicted" is NOT "verified", and the difference decides
        # whether a mapping may become TRAINING DATA. Saying so here, in the
        # report, is the only way a later reader can tell the two apart -
        # rung_reached is "V4" either way.
        rep.passed = True
        rep.metrics["verified"] = False
        rep.metrics["scenarios_total"] = 0
        rep.metrics["skipped"] = "no scenarios for this source and split"
        return rep

    passed = 0
    results: list[dict[str, Any]] = []

    for sc in scenarios:
        index = f"{index_prefix}-{sc['id']}".lower().replace("_", "-")
        docs = parsed_by_scenario.get(sc["id"], [])

        es.options(ignore_status=[400, 404]).indices.delete(index=index)
        es.indices.create(index=index, mappings=REPLAY_MAPPINGS)
        try:
            if docs:
                ops: list[Any] = []
                for d in docs:
                    ops.append({"create": {"_index": index}})
                    ops.append(d)
                es.bulk(operations=ops, refresh=True)

            # A candidate that writes a value of the wrong type into a field the
            # rule filters on (a number into `network.protocol`) makes the fresh
            # index map that field numerically, and Elasticsearch then REFUSES
            # the rule's query (400, "For input string: http") instead of
            # answering 0. Found 2026-10-20: the exception escaped and stopped a
            # whole arm (phase 4, 32B, Suricata). A rule that cannot run against
            # the documents did not fire: that is the verdict, and why is kept.
            query_error = None
            try:
                hits = es.count(index=index, query=sc["query"])["count"]
            except Exception as exc:  # elasticsearch.BadRequestError and kin
                if getattr(exc, "status_code", getattr(exc, "status", None)) != 400:
                    raise
                hits, query_error = 0, str(exc)[:200]

            # One count per target, with that target's clause ALONE.
            #
            # A scenario's rule is a conjunction over `per_rule` fields, so one
            # misplaced value answers zero for the whole rule and the fields
            # beside it earn nothing. Measured over the appsvc and authsvc
            # families, 24 proposals mapped `log.level` correctly and lost the
            # credit because `node -> observer.hostname`, their partner in the
            # same rule, was wrong; `log.level` passed 0 of 48 scenarios while
            # the teacher got it right 24 times in 32.
            #
            # This asks the question a single-field rule would ask - would a
            # detection filtering only on this field have fired correctly? -
            # and it is free: the documents are already indexed, so it costs a
            # count, not another Logstash run. The conjunction still decides
            # `passed`; these only decide who gets credit for what.
            clauses = (sc["query"].get("bool") or {}).get("filter") or []
            targets = list(sc.get("targets") or [])
            per_target: dict[str, bool] = {}
            if len(clauses) == len(targets):
                for ecs_field, clause in zip(targets, clauses):
                    try:
                        one = es.count(
                            index=index, query={"bool": {"filter": [clause]}}
                        )["count"]
                    except Exception as exc:
                        if getattr(exc, "status_code", getattr(exc, "status", None)) != 400:
                            raise
                        one = -1  # the clause cannot run: no credit for this target
                    per_target[ecs_field] = one == sc["expected_hits"]
        finally:
            es.options(ignore_status=[400, 404]).indices.delete(index=index)

        ok = hits == sc["expected_hits"]
        passed += ok
        results.append(
            {
                "scenario": sc["id"],
                # The ECS fields this scenario's query filters on. A scenario
                # that passes is positive evidence for exactly these, and that
                # is what makes credit at field granularity possible: without
                # the targets recorded beside the verdict, a reader of the
                # corpus can see THAT a scenario passed but not WHAT it proved.
                "targets": list(sc.get("targets") or []),
                "expected": sc["expected_hits"],
                "observed": hits,
                "indexed": len(docs),
                "passed": ok,
                # Which targets a rule filtering on them alone would have found.
                # Empty when the clauses could not be matched to the targets,
                # which is a shape this writer does not recognise rather than a
                # verdict, and is treated as no evidence either way.
                "per_target": per_target,
                "query_error": query_error,
            }
        )
        if not ok:
            why, missing = _diagnose(docs, list(sc.get("targets", [])))
            # Round 10 (A1): no documents, or a field the rule needs absent from
            # every document, is an extraction fault (stage 1's); fields present
            # with the wrong values are a mapping fault (stage 2's).
            extraction = (not docs or (bool(missing) and declared is not None
                                       and all(m in declared for m in missing))) \
                and not round9_pipeline()
            rep.findings.append(
                Finding(
                    "V4",
                    "detection_mismatch",
                    f"scenario {sc['id']}: the detection rule expected "
                    f"{sc['expected_hits']} matches but found {hits}. {why}"
                    + _value_hint(docs, clauses, per_target),
                    STAGE_INTERPRET if extraction else STAGE_MAP,
                )
            )
            results[-1]["fields_missing_from_output"] = missing

    rep.metrics.update(
        {
            "verified": True,  # detection replay actually ran
            "scenarios_total": len(scenarios),
            "scenarios_passed": passed,
            "detection_recall": passed / len(scenarios),
            "results": results,
        }
    )
    rep.passed = passed == len(scenarios)
    return rep

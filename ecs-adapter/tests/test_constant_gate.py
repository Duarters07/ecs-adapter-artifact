"""The gate refuses constants the previous parser did not carry (POSTHOC_REVIEW_ANALYSES.md, B3).

No oracle verifies a constant, so before this rule a model could implant one (a fixed
`source.ip`, a changed `event.category`) and it would ship with the verified fields.
"""
from __future__ import annotations

from adapter.deploy import DeployPolicy, admit_constants, constants_from_documents, decide
from adapter.drift_loop import _deployable_ir

OLD_DOCS = [
    {"event": {"kind": "event", "category": ["authentication"], "dataset": "sshd"},
     "source": {"ip": "10.0.0.1"}},
    {"event": {"kind": "event", "category": ["authentication"], "dataset": "sshd"},
     "source": {"ip": "10.0.0.2"}},
]


def _record(constants):
    return {
        "outcome": "accepted", "rung_reached": "V4", "verified_ecs_fields": ["source.ip"],
        "ir": {"source_id": "sshd", "ecs_version": "8.11",
               "extraction": {"kind": "kv", "field_split": " ", "value_split": "="},
               "fields": [{"source_key": "src", "ecs_field": "source.ip", "type": "ip",
                           "confidence": 0.9}],
               "constants": constants},
    }


def test_constants_the_previous_parser_wrote_are_read_from_its_documents():
    got = constants_from_documents(OLD_DOCS, ["event.kind", "event.category", "source.ip", "host.name"])
    # source.ip varies, host.name was never written: neither is a constant of the old parser
    assert got == {"event.kind": "event", "event.category": ["authentication"]}


def test_a_carried_constant_ships_unchanged():
    keep, refused = admit_constants({"event.kind": "event"}, {"event.kind": "event"})
    assert keep == {"event.kind": "event"} and refused == []


def test_an_implanted_constant_is_refused_and_dropped():
    keep, refused = admit_constants({"event.kind": "event", "source.ip": "203.0.113.9"},
                                    {"event.kind": "event"})
    assert keep == {"event.kind": "event"} and refused == ["source.ip"]


def test_a_changed_constant_falls_back_to_the_value_in_production():
    keep, refused = admit_constants({"event.category": ["network"]}, {"event.category": ["authentication"]})
    assert keep == {"event.category": ["authentication"]} and refused == ["event.category"]


def test_list_order_does_not_count_as_a_change():
    keep, refused = admit_constants({"event.type": ["start", "info"]}, {"event.type": ["info", "start"]})
    assert refused == []


def test_decide_reports_refused_constants_and_the_cut_ships_only_admitted_ones():
    rec = _record({"event.kind": "event", "event.category": ["authentication"],
                   "event.dataset": "sshd", "source.ip": "203.0.113.9"})
    prev = constants_from_documents(OLD_DOCS, sorted(rec["ir"]["constants"]))
    d = decide(rec, {"verified_fields": []}, ["source.ip"], DeployPolicy(), previous_constants=prev)
    assert d.deliver == ["source.ip"]
    assert d.refused_constants == ["source.ip"]
    assert any("constant" in r for r in d.reasons)
    cut = _deployable_ir(rec["ir"], d.deliver, d.constants)
    assert "source.ip" not in cut["constants"]
    assert cut["constants"]["event.kind"] == "event"


def test_without_a_previous_parser_constants_pass_as_before():
    rec = _record({"event.kind": "event", "source.ip": "203.0.113.9"})
    d = decide(rec, {"verified_fields": []}, ["source.ip"], DeployPolicy())
    assert d.constants is None and d.refused_constants == []
    assert _deployable_ir(rec["ir"], d.deliver, d.constants)["constants"] == rec["ir"]["constants"]

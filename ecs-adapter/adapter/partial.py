"""P1 - deliver the fields detection proved, instead of the whole source or nothing.

THE PROBLEM THIS SOLVES
-----------------------
Acceptance is all-or-nothing: a proposal either clears every rung for every
field or it ships nothing. Measured on stage F, 2026-10-13, arm C, seed 0:

    sshd_auth        rejected @V2   4 fields correct, 0 wrong   accuracy 1.000
    vsftpd_xfer      rejected @V2   5 fields correct, 0 wrong   accuracy 1.000
    traefik_access   rejected @V2   4 fields correct, 0 wrong   accuracy 1.000
    suricata_eve     ACCEPTED @V4   4 fields correct, 3 WRONG   accuracy 0.571

Three sources that were entirely right were discarded. The one that shipped
carried three wrong mappings, because V4's scenarios did not target them and a
whole-source pass asks no question about a field no rule tested.

Twenty-eight of fifty-eight fields across the pool are correct. One source is
delivered.

WHAT THIS MODULE DOES
---------------------
Restricts an IR to the fields detection replay confirmed one at a time, so the
pipeline that reaches production contains those and nothing else. This is
STRICTLY MORE CONSERVATIVE than accepting a source whole: every field it keeps
was individually proved by a rule that fired with the right count, and the
three wrong `suricata_eve` fields - which no scenario targeted - are dropped
rather than shipped.

WHAT IT IS NOT
--------------
It is not a way to turn a failure into a success. A restricted pipeline is a
different deliverable from an accepted source and must be reported as one: N
fields, each named, each with the scenario that proved it. Reporting "accepted"
for a source that delivered 4 of its 29 fields would be the fail-open this
project keeps catching itself in.

Fields no scenario targeted are never kept. Not tested is not the same as
wrong, and it is not the same as right either.
"""
from __future__ import annotations

from typing import Any


def restrict_to_verified(
    ir: dict[str, Any],
    verified: frozenset[str] | set[str] | list[str],
    *,
    indistinguishable: frozenset[str] | set[str] | None = None,
) -> dict[str, Any]:
    """An IR carrying only the ECS fields detection confirmed.

    ``indistinguishable`` names fields a scenario cannot adjudicate because a
    rule filtering on them answers the same count either way; they are dropped
    even when the scenario passed, on the same reasoning
    `v4_detection.indistinguishable_targets` gives.

    The extraction, the timestamp and the unresolved list are carried over
    untouched: the extraction is how the line is read at all, and an unresolved
    key is a statement that nothing was claimed about it, which stays true.
    """
    keep = set(verified) - set(indistinguishable or ())
    out = dict(ir)
    out["fields"] = [f for f in ir.get("fields") or []
                     if f.get("ecs_field") in keep]
    # The IR contract names a value map's target `ecs_field`
    # (schema/ir.schema.json). This read `to_ecs_field`, a key no IR carries, so
    # every value map was dropped from every restricted IR - including the one
    # that turns `Failed`/`Accepted` into event.outcome, a field detection
    # rules filter on.
    out["value_maps"] = [vm for vm in ir.get("value_maps") or []
                         if vm.get("ecs_field") in keep]
    dropped = [f for f in ir.get("fields") or []
               if f.get("ecs_field") not in keep]
    out["partial"] = {
        "verified_fields": sorted(keep),
        "dropped_fields": sorted(
            f["ecs_field"] for f in dropped if f.get("ecs_field")),
        "dropped_unverified": len(dropped),
    }
    return out


def delivery_summary(ir: dict[str, Any], restricted: dict[str, Any]) -> dict[str, Any]:
    """What a deployment would get, next to what was proposed."""
    proposed = [f for f in (ir.get("fields") or []) if f.get("ecs_field")]
    delivered = [f for f in (restricted.get("fields") or []) if f.get("ecs_field")]
    return {
        "proposed": len(proposed),
        "delivered": len(delivered),
        "fraction": (len(delivered) / len(proposed)) if proposed else 0.0,
    }

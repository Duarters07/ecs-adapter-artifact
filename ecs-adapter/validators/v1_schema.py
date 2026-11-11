"""V1 - schema and type validity.

Catches: nonexistent ECS fields, wrong types, malformed IR, anything the
compiler refuses to emit. This is ordinary engineering practice; it cannot
catch a mapping that is well-formed and semantically wrong.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
import json

import jsonschema

from adapter.compiler import CompileError, compile_ir
from adapter.types import STAGE_INTERPRET, STAGE_MAP, Finding, ValidationReport

_SCHEMA = json.loads(
    Path(__file__).resolve().parents[1].joinpath("schema/ir.schema.json").read_text(
        encoding="utf-8"
    )
)

# WHEN A TYPE DECLARATION IS AN ERROR, AND WHEN IT IS INERT.
#
# The IR's `type` reaches exactly one place: adapter/compiler.py decides from it
# whether to emit a `mutate/convert`, and for which Logstash type. Nothing else
# reads it. So a declaration differs from ECS in one of two ways.
#
#   It changes the convert.   `keyword` where ECS says `long` emits no coercion
#                             and the value arrives as a string. That is a real
#                             defect and V1 must refuse it.
#
#   It changes nothing.       `keyword` where ECS says `ip` emits no convert
#                             either way. The parser is byte for byte identical,
#                             and Elasticsearch types the field from its own
#                             template regardless.
#
# Refusing the second was a false positive against this rung's own definition:
# it exists to catch what the compiler refuses to emit, and the compiler emits
# this without complaint. It was measured twice - `url.original` is `wildcard`
# in ECS and cannot even be declared, and `client.ip` is `ip` where a model that
# had read the key name said `keyword`.
#
# The inert cases are still recorded, in metrics rather than as findings. They
# are weak evidence about how carefully the model read, and discarding a
# proposal for one would put a stylistic judgement ahead of the oracle.
_CONVERT_EFFECT = {
    "long": "integer",
    "float": "float",
    "scaled_float": "float",
    "boolean": "boolean",
}


def _convert_effect(t: str) -> str | None:
    """The Logstash coercion this type implies, or None for the string family."""
    return _CONVERT_EFFECT.get(t)


# ECS types that hold a structure, not a value. A scalar assigned to one of
# these fails to index, so the mismatch is real however the convert works out -
# both sides emit none, and comparing by coercion alone would let it through.
_STRUCTURAL = frozenset({"object", "nested", "flattened", "geo_point"})


def _types_agree(declared: str, actual: str) -> bool:
    if declared == actual:
        return True
    if declared in _STRUCTURAL or actual in _STRUCTURAL:
        return False
    return _convert_effect(declared) == _convert_effect(actual)


def validate(ir: dict[str, Any], ecs_index) -> ValidationReport:
    rep = ValidationReport(rung_reached="V1")
    inert: list[str] = []

    try:
        jsonschema.validate(ir, _SCHEMA)
    except jsonschema.ValidationError as exc:
        rep.findings.append(
            Finding("V1", "ir_schema_invalid", exc.message, STAGE_MAP)
        )
        return rep

    for f in ir["fields"]:
        name = f["ecs_field"]
        if not ecs_index.exists(name):
            rep.findings.append(
                Finding(
                    "V1",
                    "unknown_ecs_field",
                    f"{name!r} is not a field in ECS {ir['ecs_version']}.",
                    STAGE_MAP,
                    f["source_key"],
                )
            )
            continue
        # The type is the ECS index's, not the model's (ecs_index.ir_type,
        # 2026-10-17): the compiler converts by the derived type, so a declared
        # one that disagrees is recorded and has no effect. It used to stop the
        # run here, before a single line was read.
        declared = f.get("type")
        actual = ecs_index.type_of(name)
        if declared and actual and declared != actual:
            inert.append(f"{name}: declared {declared}, ECS says {actual}; the ECS type is used")

    # TWO SOURCE KEYS CLAIMING THE SAME ECS FIELD.
    #
    # The compiler renames each key into its target, so two renames into one
    # field make the second overwrite the first and the surviving value depends
    # on the order of a dict. One of the two keys is simply lost, and nothing
    # about the document says so.
    #
    # This is decidable by reading the IR, and it was not being decided. The
    # defect surfaced instead at V4, sixty seconds later, as a detection
    # mismatch - which reads as "a field is in the wrong place" when the real
    # fault is that two fields are in the same place. Measured over 240
    # proposals from a 32B teacher: 10 of them, across 5 sources, the commonest
    # collision being the ambiguous key dumped on top of a real one.
    #
    # `related.*` is excluded. ECS defines those as arrays that deliberately
    # gather values from several places, so a collision there is the intent.
    targets: dict[str, list[str]] = {}
    for f in ir["fields"]:
        if f["ecs_field"].startswith("related."):
            continue
        targets.setdefault(f["ecs_field"], []).append(f["source_key"])
    for name, keys in targets.items():
        if len(keys) > 1:
            rep.findings.append(
                Finding(
                    "V1",
                    "duplicate_ecs_target",
                    f"{', '.join(repr(k) for k in keys)} all map to {name}. "
                    "A rename cannot put two values in one field: the last one "
                    "written wins and the others are lost. At most one key may "
                    "claim a field; the rest belong in `unresolved`.",
                    STAGE_MAP,
                    keys[1],
                )
            )

    # An unresolved field with no stated reason is an interpretation failure.
    for u in ir.get("unresolved", []):
        if not u.get("reason"):
            rep.findings.append(
                Finding(
                    "V1",
                    "unresolved_without_reason",
                    f"{u['source_key']} was left unresolved with no reason given.",
                    STAGE_INTERPRET,
                    u["source_key"],
                )
            )

    if not rep.findings:
        try:
            compile_ir(ir, ecs_index.all_names())
        except CompileError as exc:
            rep.findings.append(Finding("V1", "compile_error", str(exc), STAGE_MAP))

    if inert:
        rep.metrics["inert_type_declarations"] = inert

    rep.passed = not rep.findings
    # Abstention: the model declined everything rather than guessing.
    rep.metrics["abstained"] = bool(ir.get("unresolved")) and not ir["fields"]
    return rep

"""Serialise an answer in the key order the structured-output grammar will force.

WHY THIS EXISTS
---------------
The students are served through Ollama with `format: <JSON schema>`. Ollama
hands the schema to llama.cpp's json-schema-to-grammar, which fixes the order
of an object's keys: the REQUIRED properties first, in the order the schema
lists them, then the optional ones, in the same order. A model under that
grammar cannot write keys in any other order.

Until 2026-10-17 every training answer was written with `sort_keys=True`, so
the students learned to open the roles object with `column_order`/`extraction`
and the IR with `constants`, and were then forced by the grammar to open with
`source_id`. Every token of the answer was produced in a position the model
had never been trained on (PILOT_GS.md, results). Writing the training answers
in grammar order removes that mismatch for every arm trained from them.

Objects the schema leaves free-form (a value map's `map`) have no forced
order; their keys are written sorted so a rebuild stays byte-identical.
"""
from __future__ import annotations

from typing import Any


def grammar_order(obj: Any, schema: dict[str, Any] | None) -> Any:
    """`obj` with every object's keys in the order the grammar for `schema` emits them."""
    schema = schema or {}
    if isinstance(obj, list):
        return [grammar_order(x, schema.get("items")) for x in obj]
    if not isinstance(obj, dict):
        return obj
    props: dict[str, Any] = schema.get("properties") or {}
    if not props:
        return {k: grammar_order(obj[k], None) for k in sorted(obj)}
    required = set(schema.get("required") or [])
    listed = [k for k in props if k in required] + [k for k in props if k not in required]
    ordered = [k for k in listed if k in obj] + sorted(k for k in obj if k not in props)
    return {k: grammar_order(obj[k], props.get(k)) for k in ordered}

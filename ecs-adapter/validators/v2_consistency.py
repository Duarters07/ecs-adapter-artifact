"""V2 - cross-sample consistency.

Catches: a mapping written from sample 1 that ignores a key appearing in sample
7. A mapping that works on one sample and not the next is not a mapping.

HOW THE KEYS ARE READ, AND WHY IT USES THE IR
---------------------------------------------
To know a key was ignored, this rung first has to see it. An earlier version
guessed, by splitting every line on whitespace and keeping the tokens that
contained an `=`. That works for one layout and silently does nothing for the
others, which was measured on the shipped corpus:

    kv, space-separated    8 of 8 keys seen
    kv, comma-separated    8 of 8   (only because the generator writes ", ")
    kv, pipe-separated     1 of 8
    json                   0 of 8
    csv                    0 of 8

Three layouts out of five had no V2 at all. The rung ran, reported
`coverage: 1.0` and passed everything, so nothing looked wrong. A mapping that
dropped a field on a JSON source sailed through, and the ladder's own
description of itself - "V2 catches a mapping that fits one line and no other"
- was true only for key=value sources.

The fix is to stop guessing. The IR already declares how the source is
extracted, so the keys are read the way the compiled parser will read them:
the declared delimiters for `kv`, the object keys for `json`, the declared
column list for `csv`, and the capture names for `grok`. If the IR's
extraction is wrong, V3 will not produce documents and the candidate dies
there instead, which is the correct division of labour.
"""
from __future__ import annotations

from typing import Any
import csv
import os
import json
import re

from adapter.types import (
    STAGE_INTERPRET,
    STAGE_MAP,
    Finding,
    Source,
    ValidationReport,
    RAW_NAMED_GROUP,
    grok_patterns,
    json_lookup,
)

MIN_COVERAGE = 0.95

# %{PATTERN:name} and %{PATTERN:name:type} -> name
_GROK_CAPTURE = re.compile(r"%\{[A-Z0-9_]+:([^}:]+)")


def _keys_in(line: str, extraction: dict[str, Any] | None = None) -> set[str]:
    """The source keys present in one raw line, read as the parser will read it.

    `extraction` is the IR's extraction block. It is optional so that the
    function stays usable without an IR, in which case it falls back to the
    whitespace heuristic and is only correct for space-separated key=value.
    """
    ex = extraction or {}
    kind = ex.get("kind")

    if kind == "json":
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return set()
        if not isinstance(obj, dict):
            return set()
        keys = set(obj)
        # Round 10 (A4): the captures of the inner grok that reads the source
        # key's text are keys too, beside the JSON keys.
        inner = ex.get("inner")
        if isinstance(inner, dict) and inner.get("source"):
            text = json_lookup(obj, inner["source"])
            pats = grok_patterns(inner)
            if isinstance(text, str) and pats:
                p = _grok_owner(pats, text)
                keys |= _grok_capture_names(p) if p is not None else \
                    {n for q in pats for n in _grok_capture_names(q)}
        return keys

    if kind == "csv":
        # Positional: the keys are the declared columns, by definition the same
        # on every line. A column the IR does not account for is still a miss.
        return {c for c in (ex.get("columns") or []) if c}

    if kind == "grok":
        # THE CAPTURES OF THE PATTERN THAT READS THIS LINE.
        #
        # With `alternatives`, two message types may carry different keys, and
        # a key the Failed pattern captures is not missing from an Accepted
        # line. When no pattern matches, the union is returned, which is what a
        # single pattern always returned: the line's fate is reported by the
        # partial-match finding, not by a coverage finding about every key.
        patterns = grok_patterns(ex)
        if len(patterns) > 1:
            p = _grok_owner(patterns, line)
            if p is not None:
                return _grok_capture_names(p)
        return {n for p in patterns for n in _grok_capture_names(p)}

    # kv, and the no-IR fallback.
    field_split = ex.get("field_split") or None
    value_split = ex.get("value_split") or "="
    tokens = line.replace("\t", " ").split() if field_split is None else line.split(field_split)
    out: set[str] = set()
    for tok in tokens:
        tok = tok.strip()
        if value_split and value_split in tok:
            out.add(tok.split(value_split, 1)[0].strip('",{} '))
    return out


def _value_of(line: str, key: str, extraction: dict[str, Any] | None) -> str | None:
    """The value this key takes on one raw line, read as the parser reads it."""
    ex = extraction or {}
    kind = ex.get("kind")
    if kind == "json":
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return None
        # A dotted key walks into nested objects unless the line carries it as a
        # literal key - the rule the compiled parser applies, see json_lookup.
        v = json_lookup(obj, key)
        return None if v is None or isinstance(v, (dict, list)) else str(v)
    if kind == "csv":
        cols = ex.get("columns") or []
        if key not in cols:
            return None
        parts = _split_row(line, ex)
        i = cols.index(key)
        return parts[i] if i < len(parts) else None
    if kind == "grok":
        return None            # positional; V3 is where a grok is exercised
    field_split = ex.get("field_split") or None
    value_split = ex.get("value_split") or "="
    tokens = line.replace("\t", " ").split() if field_split is None else line.split(field_split)
    for tok in tokens:
        tok = tok.strip()
        if value_split in tok:
            k, _, v = tok.partition(value_split)
            if k.strip('",{} ') == key:
                return v.strip('",{} ')
    return None


# HOW MANY KEYS THE EXTRACTION ACTUALLY YIELDS, BEFORE ANYTHING EXPENSIVE.
#
# A kv extraction with value_split "=" applied to a line that contains no "="
# produces nothing. Everything downstream still succeeds: V1 sees a valid
# schema, this rung used to see "no key in the line is unaccounted for" -
# because there are no keys - V3 runs Logstash and indexes nineteen documents,
# all of them empty, and V4 is the first thing to notice, three minutes and a
# sandbox later.
#
# Measured on arm C, sshd_auth: 1302 seconds, five model calls and three repair
# rounds to establish something a single `split` answers in microseconds. The
# line is `Failed password for alice from 172.18.0.22 port 42710 ssh2` and the
# proposal declared it key=value.
#
# A csv extraction needs a different question. `_keys_in` returns the DECLARED
# columns for csv whatever the line says, so it can never come back empty; what
# can be wrong there is the number of columns, and that is checkable against a
# real split.
MIN_YIELD = 0.5


def _split_row(line: str, ex: dict[str, Any]) -> list[str]:
    """One csv line, split the way the compiler will split it.

    Honours `field_split`, because the compiler now does. Reading a tab-
    separated line with the comma default returns one enormous field, which
    looks from here like a line that does not match its column count - a true
    statement about the wrong thing.
    """
    sep = (ex or {}).get("field_split")
    if sep and sep != ",":
        return line.split(sep)
    return next(csv.reader([line]), [])


# A GROK PATTERN, TESTED HERE INSTEAD OF FAILING IN LOGSTASH.
#
# A grok that matches nothing produces the same silence as a kv extraction with
# the wrong separator, and used to be reported the same way: V3 ran Logstash,
# every line came back tagged `_parse_failure`, and the finding was twenty-one
# repetitions of the line with no indication of which capture failed or why.
#
# Measured on the first prose family of the 6 October run, all twelve
# proposals: the teacher wrote `%{WORD:host_header}` for `example.com` and
# `%{WORD:zone}` for `dmz-3`. WORD is \b\w+\b - it matches neither a dot nor a
# hyphen - so the pattern died on its first capture. Two characters, twelve
# proposals, and a message that named neither.
#
# Only the common patterns are resolved. An unknown one is treated as
# "anything", which can only make this check more permissive: it never refuses
# a pattern it does not understand.
_GROK_LIB: dict[str, str] = {
    "WORD": r"\w+",
    "NOTSPACE": r"\S+",
    "SPACE": r"\s*",
    "DATA": r".*?",
    "GREEDYDATA": r".*",
    "INT": r"[+-]?\d+",
    "NUMBER": r"[+-]?\d+(?:\.\d+)?",
    "BASE10NUM": r"[+-]?\d+(?:\.\d+)?",
    "IP": r"(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]+",
    "IPV4": r"(?:\d{1,3}\.){3}\d{1,3}",
    "IPORHOST": r"\S+",
    "HOSTNAME": r"[\w.-]+",
    "HOSTPORT": r"\S+:\d+",
    "USER": r"[\w.@-]+",
    "USERNAME": r"[\w.@-]+",
    # URI IS STRICT IN REAL GROK, AND THIS WAS NOT.
    #
    # `%{URI}` requires a protocol: Logstash defines it as
    # %{URIPROTO}://(…)%{URIHOST}?%{URIPATHPARAM}? and it does NOT match a bare
    # `/probe-endpoint`. Approximating it as `\S+` made the probe accept a
    # pattern the sandbox then refused, which is the one direction this table
    # must never be wrong in: a permissive approximation costs the proposal
    # entirely, because V3 is where it dies and by then it is not a candidate
    # any more. Verified against the container on 2026-10-11: `%{URI}` tags a
    # failure on `/probe-endpoint` while URIPATH, PATH and NOTSPACE all match.
    "URI": r"\w+://\S*",
    # THE PATH CLASSES REQUIRE A LEADING SLASH, AND THESE DID NOT.
    #
    # Real grok defines PATH as (?:%{UNIXPATH}|%{WINPATH}) and UNIXPATH as
    # (/[\w_%!$@:.,+~-]*)+ - it does not match a bare word. Verified in the
    # container on 2026-10-12: `sudo` is tagged by PATH, UNIXPATH and URIPATH,
    # and matched by HOSTNAME, IPORHOST and USERNAME.
    #
    # `\S+` here let the probe accept `%{PATH:exe}` against `sudo` on every
    # syn_linux_auditd_prose proposal; the sandbox then refused the lot. Same
    # class as the URI entry above, and the same cost: a permissive
    # approximation does not merely mis-measure, it loses the proposal, because
    # V3 is where it dies and by then it is no longer a candidate.
    #
    # All three are in normalise._WIDENABLE, so once the approximation is
    # faithful the widening rule repairs the pattern instead of the probe
    # hiding the problem until the sandbox.
    "URIPATH": r"(?:/[A-Za-z0-9$.+!*'(){},~:;=@#%\[\]_<>^\-&?]*)+",
    "URIPATHPARAM": r"(?:/[A-Za-z0-9$.+!*'(){},~:;=@#%\[\]_<>^\-&?]*)+\S*",
    "PATH": r"(?:(?:/[\w_%!$@:.,+~-]*)+|[A-Za-z]:\\\S*)",
    "UNIXPATH": r"(?:/[\w_%!$@:.,+~-]*)+",
    "LOGLEVEL": r"[A-Za-z]+",
    "QUOTEDSTRING": r'"[^"]*"',
    "UUID": r"[0-9A-Fa-f-]+",
    # THE DATE PATTERNS, AND WHY THEY MAY NOT BE `\S+`.
    #
    # The rule this table states above is that an approximation may only ever
    # be MORE permissive, so that the probe never refuses a pattern it does not
    # understand. These three broke it, because every one of them spans a
    # SPACE and `\S+` stops at the first one.
    #
    # Measured on 2026-10-10, fail2ban_jail. The model wrote
    #
    #   %{TIMESTAMP_ISO8601:timestamp} %{DATA:logger} \[%{POSINT:pid}\]: ...
    #
    # with all six capture names matching the ground truth exactly. Against
    # the real grok pattern that matches `2026-10-02 15:57:35,117`; against
    # `\S+` it consumes only `2026-10-02`, every capture after it shifts, and
    # the probe reported "the pattern matches no sample line". The ladder is
    # conjunctive, so the source died at V2 and never reached V3, where
    # Logstash would have run the pattern for real and accepted it.
    #
    # A correct parser rejected by the harness is the worst failure this
    # project can have: it is indistinguishable, in the results, from a model
    # that got it wrong.
    "TIMESTAMP_ISO8601": (
        r"\d{2,4}-\d{1,2}-\d{1,2}[T ]\d{1,2}:?\d{2}(?::?\d{2}(?:[:.,]\d+)?)?"
        r"(?:Z|[+-]\d{2}:?\d{2})?"
    ),
    "DATESTAMP": r"\d{2,4}[-/]\d{1,2}[-/]\d{1,2}[T ]\d{1,2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?",
    "DATE": r"\d{2,4}[-/]\d{1,2}[-/]\d{1,2}",
    "TIME": r"\d{1,2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?",
    # 10/Oct/2000:13:55:36 -0700
    "HTTPDATE": r"\d{1,2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s[+-]\d{4})?",
    # Oct  2 15:57:35
    "SYSLOGTIMESTAMP": r"\w{3}\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2}",
    "MONTH": r"\w{3,9}",
    "MONTHDAY": r"\d{1,2}",
    "YEAR": r"\d{2,4}",
    "HOUR": r"\d{1,2}",
    "MINUTE": r"\d{2}",
    "SECOND": r"\d{1,2}(?:[.,]\d+)?",
    "POSINT": r"\d+",
    "NONNEGINT": r"\d+",
    "EMAILADDRESS": r"\S+@\S+",
    "LOGLEVEL": r"[A-Za-z]+",
}
_GROK_TOKEN = re.compile(r"%\{(\w+)(?::([^}:]+))?(?::\w+)?\}")


# ROUND 10 (A3): THE REAL DEFINITIONS, NOT AN APPROXIMATION OF THEM.
#
# The table above resolves 38 of the 362 names Logstash defines; every other
# name became ".+?". That was meant to make this probe only ever more
# permissive, but the probe is not the only reader. The deterministic layer
# asks the same simulator which date class reads the samples, and ".+?" reads
# everything: on Gitea (r6, 2026-10-29) the timestamp retype swapped
# TIMESTAMP_ISO8601 for HTTPDERROR_DATE "from 0% to 86% of its lines", and
# Logstash, whose HTTPDERROR_DATE is `%{DAY} %{MONTH} %{MONTHDAY} %{TIME}
# %{YEAR}`, tagged every line. Across 877 stored runs no run in which a rule
# chose HTTPDERROR_DATE was accepted (PLAN_ROUND10_ARM_C.md, D3-D5).
#
# So every name is now expanded from the definitions Logstash 8.19.7 ships
# (validators/data/grok_patterns/ecs-v1, vendored unchanged). Three Oniguruma
# spellings Python's `re` reads differently are translated: `\h` (a hex
# digit), POSIX classes inside brackets, and Ruby's `(?m)`, which is dot-all,
# not multi-line. Captures inside a definition become plain groups: only the
# captures the IR names are keys. A name that does not expand to a pattern
# Python compiles is "unsimulated": it keeps the old ".+?" so this probe never
# refuses it, and `grok_simulated` says so, so that no rule CHOOSES it on the
# strength of a match it cannot vouch for. A name Logstash does not define
# matches nothing, as in Logstash, where the filter does not compile.
#
# ECS_GROK_SIM=legacy restores the old table, to reproduce round-9 behaviour
# (the corpus builders of org9 ran under it).
GROK_SIM_ENV = "ECS_GROK_SIM"
_POSIX = {"alnum": "a-zA-Z0-9", "alpha": "a-zA-Z", "digit": "0-9", "upper": "A-Z", "lower": "a-z",
          "space": r"\s", "xdigit": "0-9A-Fa-f", "punct": r"!-/:-@\[-`{-~", "word": r"\w"}
_DEF_CAPTURE = re.compile(r"\(\?<(?![=!])[^>]+>")


def grok_sim_legacy() -> bool:
    """True when the round-9 simulator (38 names, the rest ".+?") is asked for."""
    from adapter.types import round9_pipeline

    return os.environ.get(GROK_SIM_ENV, "").strip() == "legacy" or round9_pipeline()


@__import__("functools").lru_cache(maxsize=1)
def _logstash_definitions() -> dict[str, str]:
    """NAME -> raw definition, from the vendored ecs-v1 pattern files."""
    from pathlib import Path

    out: dict[str, str] = {}
    d = Path(__file__).resolve().parent / "data" / "grok_patterns" / "ecs-v1"
    for f in sorted(d.glob("*")):
        for ln in f.read_text(encoding="utf-8").splitlines():
            if not ln.strip() or ln.lstrip().startswith("#"):
                continue
            name, _, body = ln.partition(" ")
            if name and body:
                out[name] = body.strip()
    return out


def _flatten_sets(body: str) -> str | None:
    """Character classes as Python reads them, or None if that is not possible.

    Oniguruma nests classes: `[[a-z]_]` is the union of `a-z` and `_`. Python
    reads the inner `[` as a literal and the first `]` as the end, so nested
    classes are flattened into their union. A negated nested class has no
    union form and makes the name unsimulated. A doubled `-&~|` inside a class
    is escaped: both engines read it literally, and Python warns it will not.
    """
    out, i, depth, n = [], 0, 0, len(body)
    while i < n:
        c = body[i]
        if c == "\\" and i + 1 < n:
            out.append(body[i:i + 2]); i += 2; continue
        if depth == 0:
            if c == "[":
                depth = 1
                out.append(c); i += 1
                if i < n and body[i] == "^":
                    out.append("^"); i += 1
                if i < n and body[i] == "]":
                    out.append(r"\]"); i += 1
                continue
            out.append(c); i += 1; continue
        if c == "[":
            if i + 1 < n and body[i + 1] == "^":
                return None
            depth += 1; i += 1; continue
        if c == "]":
            depth -= 1; i += 1
            if depth == 0:
                out.append("]")
            continue
        if c in "-&~|" and i + 1 < n and body[i + 1] == c:
            c = "\\" + c
        out.append(c); i += 1
    return "".join(out)


def _translate(body: str) -> str | None:
    """Oniguruma spellings Python's `re` would read differently, in Python's."""
    body = _DEF_CAPTURE.sub("(?:", body)
    body = body.replace(r"\h", "[0-9A-Fa-f]")
    if body.startswith("(?m)"):
        body = "(?s:" + body[4:] + ")"   # Ruby's (?m) is dot-all; scoped so it can be nested
    if "(?m)" in body:
        return None
    body = re.sub(r"\[:(\w+):\]", lambda m: f"[{_POSIX[m.group(1)]}]" if m.group(1) in _POSIX
                  else m.group(0), body)
    # `([abc]+)+` reads the same strings as `[abc]+`, and in Python it
    # backtracks exponentially on a long run that ends in a character outside
    # the class: URIPROTO, `[A-Za-z]([A-Za-z0-9+\-.]+)+`, took more than 20 s on
    # `outlook-com.olc.protection.outlook.com[52.101.8.7]:25:` (F2, found when a
    # 60 000-text differential run never finished). Written once, it is linear.
    body = re.sub(r"\((?:\?:)?(\[(?:\\.|[^\]\\])+\])\+\)\+", r"(?:\1+)", body)
    return _flatten_sets(body)


@__import__("functools").lru_cache(maxsize=None)
def _faithful(name: str, depth: int = 0) -> str | None:
    """The regex Logstash uses for `name`, or None when it cannot be simulated."""
    defs = _logstash_definitions()
    if name not in defs or depth > 40:
        return None
    body = _translate(defs[name])
    if body is None:
        return None
    parts, i = [], 0
    for m in _GROK_TOKEN.finditer(body):
        inner = _faithful(m.group(1), depth + 1)
        if inner is None:
            return None
        parts.append(body[i:m.start()])
        parts.append(f"(?:{inner})")
        i = m.end()
    parts.append(body[i:])
    out = "".join(parts)
    try:
        re.compile(f"(?:{out})")
    except re.error:
        return None
    return out


def grok_simulated(name: str) -> bool:
    """Does the simulator reproduce what Logstash matches for this name?"""
    if grok_sim_legacy():
        return name in _GROK_LIB
    return _faithful(name) is not None


def _grok_body(name: str) -> str:
    """The regex a grok name stands for in the simulator."""
    if grok_sim_legacy():
        return _GROK_LIB.get(name, r".+?")
    body = _faithful(name)
    if body is not None:
        return body
    if name in _logstash_definitions():
        return r".+?"           # defined but unsimulated: never refuse it here
    return r"(?!)"              # undefined: Logstash cannot compile it


# THE NAMES LOGSTASH ACTUALLY DEFINES.
#
# `_grok_to_regex` resolves an unknown syntax to ".+?", which is deliberately
# permissive so this probe never REFUSES a pattern it does not understand. In
# the other direction that is not safe at all: grok refuses to compile an
# unknown name, the filter never registers, and every line is tagged. The probe
# said 20 of 20 lines matched and V3 failed the source outright.
#
# Measured on syn_caddy_prose, 2026-10-11: the teacher wrote `%{FLOAT:proto_ver}`
# and FLOAT is not a grok pattern - NUMBER and BASE10NUM are. Four of the 48
# grok proposals in the corpus name a pattern that does not exist.
def _real_grok_names() -> frozenset[str]:
    import functools

    return _load_grok_names()


@__import__("functools").lru_cache(maxsize=1)
def _load_grok_names() -> frozenset[str]:
    from pathlib import Path

    f = Path(__file__).resolve().parent / "data" / "grok_pattern_names.txt"
    if not f.is_file():
        return frozenset()
    return frozenset(
        ln.strip() for ln in f.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.startswith("#")
    )


def _grok_to_regex(pattern: str, search: bool = True) -> tuple[str, list[str]]:
    """(regex source, the capture names in order).

    `search=False` keeps round 9's anchoring at the start of the line. The
    deterministic layer asks that question on purpose (see below).
    """
    out: list[str] = []
    names: list[str] = []
    # A GROK PATTERN IS A REGEX, AND THE TEXT BETWEEN MACROS IS ALREADY ONE.
    #
    # This used to call re.escape() on the literal text, which double-escapes
    # anything the author already escaped. `\[` - a literal bracket, written
    # the only way grok allows - became `\\\[`, which demands a BACKSLASH
    # followed by a bracket and matches no log line ever written.
    #
    # Every grok pattern for a syslog line escapes something: `\[pid\]`,
    # `\(`, `\.`. So this did not degrade the probe for unusual patterns, it
    # broke it for the normal ones. On 2026-10-10 it rejected a fail2ban
    # pattern whose six capture names matched the ground truth exactly, and
    # the source died at V2 without ever reaching the Logstash sandbox that
    # would have run it for real.
    # Raw named groups are captures too, written (?<name>...) for grok; Python's
    # re only reads (?P<name>...), so they are respelled for the probe.
    # ONE NAME, SEVERAL CAPTURES. Oniguruma - what grok runs on - accepts a
    # name used twice in one pattern: in two alternatives only one ever
    # matches, in sequence the value becomes a list. Python's re refuses it
    # ("redefinition of group name"), and until 2026-10-18 that refusal made V2
    # reject parsers Logstash runs correctly (postfix, vsftpd, exim, measured
    # against a live Logstash 8.19.7). Each repeat gets a private group name
    # here (`name__d2`); grok_values() folds them back.
    used: dict[str, int] = {}

    def group(safe: str) -> str:
        used[safe] = used.get(safe, 0) + 1
        return safe if used[safe] == 1 else f"{safe}__d{used[safe]}"

    names_raw = RAW_NAMED_GROUP.findall(pattern)
    pattern = RAW_NAMED_GROUP.sub(lambda m: f"(?P<{group(m.group(1))}>", pattern)
    i = 0
    for m in _GROK_TOKEN.finditer(pattern):
        out.append(pattern[i:m.start()])
        syntax, name = m.group(1), m.group(2)
        body = _grok_body(syntax)
        if name:
            leaf = name.split("][")[-1].strip("[]")
            names.append(leaf)
            out.append(f"(?P<{group(re.sub(r'[^0-9A-Za-z_]', '_', leaf))}>{body})")
        else:
            out.append(f"(?:{body})")
        i = m.end()
    out.append(pattern[i:])
    rx = "".join(out)
    # GROK SEARCHES; `re.match` ANCHORS (round 10, A3).
    #
    # Logstash's grok finds a pattern anywhere in the line unless the pattern
    # itself says `^`. Every caller of this function asks `.match`, which
    # anchors at the start, so an unanchored pattern Logstash accepts could be
    # refused here: r5_slapd_25 (14B, p17, seed 1) starts every pattern with
    # %{BASE16NUM}, which Logstash finds after the `.` of `6ade180c.2d0ea2e2`,
    # and the faithful simulator, matching from position 0, read no line. A
    # lazy `.*?` in front gives `.match` grok's search: a pattern that starts
    # with `^` still matches only at the start, and look-behinds still see the
    # characters skipped. A leading inline flag group stays first, where Python
    # requires it.
    #
    # The deterministic layer asks with `search=False`. Its rules repair a
    # pattern meant to describe the whole line, and a narrow first capture that
    # grok's search would skip past (`%{WORD:node}` finding `7` in `node-7`) is
    # exactly what they exist to widen. Anchored is the stricter question: a
    # change that makes more lines match from the start makes them match for
    # grok too, so the layer can only err towards doing nothing.
    if search and not grok_sim_legacy():
        flags = re.match(r"\(\?[aiLmsux]+\)", rx)
        head = flags.group(0) if flags else ""
        rx = head + ".*?" + rx[len(head):]
    return rx, names + [n for n in names_raw if n not in names]


def grok_values(match: "re.Match") -> dict[str, str]:
    """A match's captures by their grok names, repeats folded (first value wins)."""
    out: dict[str, str] = {}
    for k, v in match.groupdict().items():
        base = re.sub(r"__d\d+$", "", k)
        if v is not None and base not in out:
            out[base] = v
    return out


def _grok_first_failure(pattern: str, line: str) -> str:
    """Which capture does this pattern die on, and on what text?

    Walks the pattern capture by capture and reports the first prefix that
    stops matching. That is the one the author has to change, and saying which
    is the difference between a repair round that converges and one that does
    not.
    """
    try:
        re.compile(_grok_to_regex(pattern)[0])
    except re.error as exc:
        return f"the pattern is not valid ({exc})"
    toks = list(_GROK_TOKEN.finditer(pattern))
    last_ok = 0
    for k in range(1, len(toks) + 1):
        prefix = pattern[: toks[k - 1].end()]
        rx, _ = _grok_to_regex(prefix, search=False)   # walked from the line's start
        # A PREFIX THAT DOES NOT COMPILE SAYS NOTHING ABOUT THE PATTERN.
        #
        # Cutting after a capture can land inside a group: the prefix of
        # `for %{USERNAME:user}(?: reason %{DATA:reason})? from` that ends at
        # the reason capture has an open parenthesis. That prefix is an
        # artefact of the walk, and the whole pattern was checked above. This
        # used to return "the pattern is not valid" for a valid pattern, and
        # sshd_auth spent its three repairs on that false lead (2026-10-15).
        try:
            matched = re.match(rx, line)
        except re.error:
            continue
        if matched:
            last_ok = k
            continue
        syntax = toks[k - 1].group(1)
        name = (toks[k - 1].group(2) or "?").split("][")[-1].strip("[]")

        # WHY THE CAPTURE THAT FAILS IS USUALLY NOT THE ONE AT FAULT.
        #
        # A capture that is too narrow does not fail. It matches a PREFIX and
        # stops: %{WORD} against `example.com` matches `example` and leaves
        # `.com`, and it is the literal text after it that then fails. Naming
        # the later capture sends the repair to the wrong line, so the one
        # before it is reported too, with what it actually consumed.
        consumed = 0
        prev_desc = ""
        if last_ok:
            prx, _ = _grok_to_regex(pattern[: toks[last_ok - 1].end()], search=False)
            mm = re.match(prx, line)
            if mm:
                consumed = mm.end()
                ptok = toks[last_ok - 1]
                psyntax = ptok.group(1)
                pname = (ptok.group(2) or "?").split("][")[-1].strip("[]")
                got = mm.group(re.sub(r"[^0-9A-Za-z_]", "_", pname)) if ptok.group(2) else None
                if got is not None and consumed < len(line) and not line[consumed].isspace():
                    prev_desc = (
                        f". The capture before it, %{{{psyntax}:{pname}}}, matched only "
                        f"{got!r} and stopped at {line[consumed:consumed + 12]!r} - it is "
                        "too narrow, and that is the one to widen"
                    )
        rest = line[consumed:].lstrip()[:40]
        # When the capture before it was the narrow one, its hint is the
        # useful one; the later capture is only where the mismatch surfaced.
        hint = ""
        order = ((toks[last_ok - 1].group(1) if last_ok else ""), syntax) \
            if prev_desc else (syntax, (toks[last_ok - 1].group(1) if last_ok else ""))
        for sx in order:
            if sx == "WORD":
                hint = (". %{WORD} matches letters, digits and underscore only - NOT a "
                        "dot, hyphen, colon or slash. For a hostname use %{HOSTNAME}, "
                        "for any run of non-space characters use %{NOTSPACE}")
                break
            if sx in ("INT", "NUMBER", "BASE10NUM"):
                hint = ". That position does not hold a bare number"
                break
        return (f"the pattern matches up to %{{{syntax}:{name}}}, which fails on "
                f"{rest!r}{prev_desc}{hint}")
    return "every capture matches; the failure is in the literal text between them"


_SHAPE_MASK = re.compile(r"\d+(?:\.\d+)*|[0-9a-fA-F]{8,}|\"[^\"]*\"")


def _other_missed_shapes(unmatched: list[str], limit: int = 3) -> str:
    """Up to `limit` more missed lines, one per distinct shape.

    The first missed line alone hid the rest: a repair that fixed it was judged
    again and found the NEXT shape, one round at a time, and the budget of
    three ran out with shapes still unseen (2026-10-17). Lines whose shape -
    numbers, hex and quoted strings masked - repeats the first are skipped.
    """
    seen = {_SHAPE_MASK.sub("#", unmatched[0])}
    more: list[str] = []
    for line in unmatched[1:]:
        shape = _SHAPE_MASK.sub("#", line)
        if shape in seen:
            continue
        seen.add(shape)
        more.append(repr(line[:140]))
        if len(more) == limit:
            break
    if not more:
        return ""
    return " It also misses lines of other shapes: " + "; ".join(more) + "."


def _grok_capture_names(pattern: str) -> set[str]:
    names = {m.split("][")[-1].strip("[]") for m in _GROK_CAPTURE.findall(pattern or "")}
    return names | set(RAW_NAMED_GROUP.findall(pattern or ""))


def _grok_prefix_depth(pattern: str, line: str) -> int:
    """How many captures of ``pattern`` match ``line`` before it stops.

    The measure "closest pattern" is taken by: the alternative that gets
    furthest into a line it does not match is the one that line was meant for,
    and the one whose failure is worth reporting.
    """
    toks = list(_GROK_TOKEN.finditer(pattern))
    depth = 0
    for k in range(1, len(toks) + 1):
        # "How far into the line" is measured from its start, so anchored.
        rx, _ = _grok_to_regex(pattern[: toks[k - 1].end()], search=False)
        try:
            if not re.match(rx, line):
                break
        except re.error:
            continue  # cut inside a group: not evidence either way
        depth = k
    return depth


def _grok_owner(patterns: list[str], line: str, search: bool = True) -> str | None:
    """The first pattern that matches the line - Logstash's break_on_match."""
    for p in patterns:
        try:
            if re.match(_grok_to_regex(p, search)[0], line):
                return p
        except re.error:
            continue
    return None


def _grok_closest(patterns: list[str], line: str, search: bool = True) -> str:
    """The pattern responsible for a line: the one matching it, else the one
    getting furthest into it. Ties go to the earlier pattern. The layer asks
    anchored (`search=False`), as it asks everything (see _grok_to_regex)."""
    if not patterns:
        return ""
    owner = _grok_owner(patterns, line, search)
    if owner is not None:
        return owner
    best, best_depth = patterns[0], -1
    for p in patterns:
        d = _grok_prefix_depth(p, line)
        if d > best_depth:
            best, best_depth = p, d
    return best


def _extraction_yield(source: Source, extraction: dict[str, Any]) -> tuple[int, int, str]:
    """(samples that yielded keys, samples tried, what went wrong)."""
    kind = (extraction or {}).get("kind")
    tried = yielded = 0
    detail = ""

    if kind == "csv":
        declared = [c for c in (extraction.get("columns") or []) if c]
        if not declared:
            return 0, len(source.samples), (
                "the extraction is csv and declares no columns, so no key can be "
                "produced from any line. columns is where the key names come from "
                "in a positional format"
            )
        widths: dict[int, int] = {}
        for s in source.samples:
            tried += 1
            row = _split_row(s.raw, extraction)
            widths[len(row)] = widths.get(len(row), 0) + 1
            if len(row) == len(declared):
                yielded += 1
        if not yielded:
            common = sorted(widths.items(), key=lambda kv: -kv[1])[:3]
            shape = ", ".join(f"{n} fields in {c} sample(s)" for n, c in common)
            detail = (
                f"{len(declared)} columns are declared and no sample splits into "
                f"that many: {shape}. Either the delimiter is wrong or the column "
                "list is incomplete"
            )
            # NAME THE SEPARATOR RATHER THAN ASKING FOR IT.
            #
            # It is findable: try the handful of characters a table is ever
            # separated by and see which one gives the declared column count.
            # Measured on the first failure of the 6 October generation run,
            # syn_caddy_csv_tab: the teacher declared csv with nine columns and
            # no field_split, and wrote a grok pattern separating those same
            # nine captures with \t. It KNEW the separator and put it in the
            # field that csv does not read. "Either the delimiter is wrong or
            # the column list is incomplete" is true and leaves it guessing
            # between two; this says which.
            for cand, name in (("\t", "a tab"), ("|", "a pipe"), (";", "a semicolon"),
                               (" ", "a space")):
                if all(len(s.raw.split(cand)) == len(declared) for s in source.samples):
                    detail += (
                        f". They DO split into exactly {len(declared)} on {name}: "
                        f'set field_split to "{cand}". A separator written into '
                        "`pattern` is not read - pattern is for grok only"
                    )
                    break
        return yielded, tried, detail

    if kind == "grok":
        # A line yields when ANY pattern that names a capture matches it: that
        # is how Logstash runs a list, and with one pattern it is the old test.
        compiled = []
        for p in grok_patterns(extraction):
            rx, names = _grok_to_regex(p)
            try:
                if names:
                    compiled.append(re.compile(rx))
            except re.error:
                pass
        for s in source.samples:
            tried += 1
            if any(c.match(s.raw) for c in compiled):
                yielded += 1
    else:
        for s in source.samples:
            tried += 1
            if _keys_in(s.raw, extraction):
                yielded += 1
    if not yielded:
        if kind == "kv":
            vs = (extraction or {}).get("value_split") or "="
            fs = (extraction or {}).get("field_split")
            detail = (
                f"the extraction is kv with value_split {vs!r}"
                + (f" and field_split {fs!r}" if fs else "")
                + ". No sample yields a single key, which means the lines are not "
                "key=value at all. A line that reads as prose with values embedded "
                "in it needs kind \"grok\" and a pattern"
            )
        elif kind == "json":
            detail = "the extraction is json and no sample parses as a JSON object"
        elif kind == "grok":
            pats = grok_patterns(extraction)
            if not any(_GROK_TOKEN.search(p) for p in pats):
                detail = (
                    "the pattern declares no named captures, so it can produce no "
                    "keys. Grok names a field with %{SYNTAX:name}"
                )
            else:
                first = source.samples[0].raw
                pat = _grok_closest(pats, first)
                detail = (
                    ("the pattern matches no sample line. " if len(pats) == 1
                     else "none of the patterns matches any sample line. "
                     f"The closest to the first line is {pat[:120]!r}: ")
                    + _grok_first_failure(pat, first)
                )
        else:
            detail = f"the extraction declares kind {kind!r} and yields no keys"
    return yielded, tried, detail


# --------------------------------------------------- partial coverage (P2)
#
# WHY THIS EXISTS.
#
# `key_not_accounted_for` is absolute: a key present in more than 5% of lines
# and neither mapped nor declared unresolved fails the source, however much of
# the line was read correctly. Measured on stage F, 2026-10-13: it is 33 of arm
# C's 47 findings, against 3 for a malformed grok. It rejected `traefik_access`
# with four fields correct out of four and semantic accuracy 1.000, for leaving
# 7 of 29 keys unexplained; it rejected `sshd_auth` and `vsftpd_xfer` at 1.000
# as well. The one source it accepted, `suricata_eve`, is JSON - coverage is
# free there because the keys are written on the line - and it shipped with
# THREE wrong fields. The rule is anti-correlated with correctness.
#
# The intent behind it is sound: an unexplained key may be the most important
# thing on the line, and a pipeline that silently drops it gives false comfort
# about coverage. But it conflates two different states - "I cannot read this
# line" and "I read this line and covered 70% of it". The first is dangerous.
# The second is how every SOC runs: Logstash tags `_grokparsefailure`, routes
# it to a review index, and nobody discards the pipeline over it.
#
# WHAT THIS DOES, AND WHAT IT REFUSES TO DO.
#
# Opt-in, off by default, and off is the behaviour every result before today
# was measured under. Turning it on does NOT make an unexplained key
# acceptable: it records every one of them as a dead letter, keeps the coverage
# fraction in the metrics, and demotes the finding only when the covered
# fraction clears the declared threshold. A source that passes this way has
# passed with a number attached, and must be reported with it - never as a
# plain acceptance. Anything less would be the fail-open this catalogue is
# full of.
PARTIAL_COVERAGE_ENV = "ECS_V2_PARTIAL_COVERAGE"


def _partial_coverage_threshold() -> float | None:
    raw = os.environ.get(PARTIAL_COVERAGE_ENV, "").strip()
    if not raw:
        return None
    try:
        v = float(raw)
    except ValueError:
        return None
    return v if 0.0 < v <= 1.0 else None


def _tolerate_partial_coverage(rep: ValidationReport) -> None:
    """Demote unaccounted-key findings when enough of the line WAS accounted for.

    Does nothing unless the threshold is set. Never touches any other finding:
    a malformed grok, an extraction that yields nothing, a value_map that
    deletes data are all still fatal, because none of them is a coverage
    question.
    """
    threshold = _partial_coverage_threshold()
    if threshold is None:
        return
    coverage = rep.metrics.get("key_coverage")
    if coverage is None or coverage < threshold:
        return
    tolerated = [f for f in rep.findings if f.code == "key_not_accounted_for"]
    if not tolerated:
        return
    rep.findings = [f for f in rep.findings if f.code != "key_not_accounted_for"]
    rep.metrics["coverage_tolerated"] = True
    rep.metrics["coverage_threshold"] = threshold
    rep.metrics["dead_letter_keys"] = sorted(f.source_key for f in tolerated if f.source_key)


def validate(ir: dict[str, Any], source: Source) -> ValidationReport:
    rep = ValidationReport(rung_reached="V2")
    extraction = ir.get("extraction") or {}

    # Asked first, and alone: if the extraction yields nothing there is no
    # point reporting that a key is unaccounted for, and a page of consequential
    # findings buries the one that names the cause.
    inner_ex = extraction.get("inner") if extraction.get("kind") == "json" else None
    if extraction.get("kind") == "grok" or isinstance(inner_ex, dict):
        known = _load_grok_names()
        checked = grok_patterns(extraction) if extraction.get("kind") == "grok" else grok_patterns(inner_ex)
        unknown = sorted(
            {m.group(1) for p in checked for m in _GROK_TOKEN.finditer(p)}
            - known
        ) if known else []
        if unknown:
            rep.findings.append(
                Finding(
                    "V2",
                    "unknown_grok_pattern",
                    f"{', '.join(repr(u) for u in unknown)} "
                    + ("is not a grok pattern" if len(unknown) == 1
                       else "are not grok patterns")
                    + ". Logstash refuses to compile an unknown name, so the "
                    "filter never registers and EVERY line fails to parse - not "
                    "just the ones this capture touches. Use a defined pattern: "
                    "NUMBER or BASE10NUM for a decimal, HOSTNAME for a domain, "
                    "NOTSPACE for anything without a space.",
                    STAGE_INTERPRET,
                )
            )

    yielded, tried, detail = _extraction_yield(source, extraction)
    rep.metrics["extraction_yield"] = round(yielded / tried, 4) if tried else None
    if tried and yielded / tried < MIN_YIELD:
        rep.findings.append(
            Finding(
                "V2",
                "extraction_yields_nothing" if not yielded else "extraction_yields_little",
                f"the extraction produced keys on {yielded} of {tried} sample line(s). "
                + (detail or "check the delimiters against a line")
                + ". Until this is right, every field is empty however it is mapped.",
                STAGE_INTERPRET,
            )
        )
        rep.metrics["coverage"] = 0.0
        return rep

    # A GROK THAT MATCHES MOST LINES IS NOT A GROK THAT MATCHES.
    #
    # `_extraction_yield` above asks whether the extraction produces keys at
    # all. For grok that is answered by the pattern's capture names, which exist
    # whether or not the pattern matches anything, so a pattern that fits the
    # common form and misses a variant sails past it.
    #
    # V3 then fails the source, because `rep.passed = not rep.findings` there
    # and one tagged line is enough. This check cannot therefore change which
    # sources pass: V3 already refuses them. What it changes is WHEN and WITH
    # WHAT. A repair round that is told "these nine lines do not match, here is
    # one of them" can add the optional segment it is missing; one handed a list
    # of tagged events sixty seconds and one container later usually cannot.
    #
    # Measured on sshd_auth, 2026-10-10. The model wrote
    #
    #   %{WORD:outcome} password for %{USERNAME:user} from %{IP:src_ip} ...
    #
    # with all four ECS mappings correct - semantic accuracy 1.00 - and no room
    # for `invalid user ` before the name. Four of the twelve samples it was
    # shown carried that variant. Nine of eighteen lines failed, V2 said
    # nothing, and the run died at V3.
    if extraction.get("kind") == "grok" and source.samples:
        patterns = grok_patterns(extraction)
        try:
            rxs = [re.compile(_grok_to_regex(p)[0]) for p in patterns]
            unmatched = [s.raw for s in source.samples
                         if not any(rx.match(s.raw) for rx in rxs)]
        except re.error:
            unmatched = []
        if unmatched:
            n, total_lines = len(unmatched), len(source.samples)
            closest = _grok_closest(patterns, unmatched[0])
            # TWO DIFFERENT FIXES, AND THE MODEL HAS TO BE TOLD WHICH IS WHICH.
            #
            # An optional segment and a second message type both show up here
            # as "a line the pattern misses". Before `alternatives` existed the
            # only fix was the first, and sshd_auth showed what that costs: a
            # `Failed ... invalid user` line is not an Accepted line with an
            # extra word, and no amount of `(?:...)?` turns one into the other.
            which = (
                "" if len(patterns) == 1
                else f" Of the {len(patterns)} patterns, the closest to it is "
                     f"{closest[:120]!r}."
            )
            rep.findings.append(
                Finding(
                    "V2",
                    "grok_matches_only_some_lines",
                    f"the pattern matches {total_lines - n} of {total_lines} sample "
                    f"lines. It must match every one: a line it misses is dropped "
                    f"entirely, not partly parsed. The first it misses is "
                    f"{unmatched[0][:160]!r}.{which} "
                    + _grok_first_failure(closest, unmatched[0])
                    + _other_missed_shapes(unmatched)
                    + " If this line is a VARIANT of the others - an extra word, a "
                    "field that is sometimes absent - make that part optional "
                    "with (?:...)? rather than writing a second pattern. If it is a "
                    "DIFFERENT KIND of message - different words, not one more of "
                    "them - add a pattern for it to `alternatives`, reusing the "
                    "same capture name for the same value.",
                    STAGE_INTERPRET,
                )
            )

    # ROUND 10 (A4): THE INNER GROK MUST READ EVERY TEXT IT IS GIVEN.
    #
    # The same rule as for a grok over the whole line: Logstash tags a text the
    # inner grok cannot read, and the line is lost.
    inner = extraction.get("inner") if extraction.get("kind") == "json" else None
    if isinstance(inner, dict) and inner.get("source") and source.samples:
        ipats = grok_patterns(inner)
        texts = []
        for s in source.samples:
            try:
                obj = json.loads(s.raw)
            except (json.JSONDecodeError, ValueError):
                continue
            t = json_lookup(obj, inner["source"]) if isinstance(obj, dict) else None
            if isinstance(t, str):
                texts.append(t)
        try:
            irxs = [re.compile(_grok_to_regex(p)[0]) for p in ipats]
            missed = [t for t in texts if not any(rx.match(t) for rx in irxs)]
        except re.error as exc:
            missed, texts = [], texts
            rep.findings.append(Finding("V2", "inner_pattern_invalid",
                                        f"the inner grok on `{inner['source']}` does not compile: {exc}",
                                        STAGE_INTERPRET))
        if not texts:
            rep.findings.append(Finding(
                "V2", "inner_source_absent",
                f"`inner` reads the text of `{inner['source']}`, and no sample line has a text value there. "
                f"Name the JSON key that holds the message.", STAGE_INTERPRET))
        elif missed:
            closest = _grok_closest(ipats, missed[0])
            rep.findings.append(Finding(
                "V2", "inner_matches_only_some_lines",
                f"the inner grok reads {len(texts) - len(missed)} of {len(texts)} texts of "
                f"`{inner['source']}`. It must read every one: a text it misses loses the whole line. "
                f"The first it misses is {missed[0][:160]!r}. " + _grok_first_failure(closest, missed[0])
                + _other_missed_shapes(missed)
                + " A different kind of message gets its own pattern in `inner.alternatives`.",
                STAGE_INTERPRET))

    # A KEY THE IR MAPS MUST BE A KEY THE PATTERN CAPTURES.
    #
    # Measured on round 3 (r3_apache_v24, C-real, 2026-10-19): the model wrote
    # `^%{DATA:code}:\s+%{GREEDYDATA:message}...`, which "reads" every line by
    # swallowing everything up to the first colon, and mapped client_ip,
    # client_port, user and url_path - names and ECS fields exactly right,
    # taken from the documentation - none of which any pattern captures. V2
    # passed it, V3 passed it, and V4 refused it with "the documents never carry
    # source.ip", which does not say why. A repair told "you map X; no pattern
    # captures X; your patterns capture only Y" has something to act on.
    #
    # Static on purpose: a key is checked against the capture NAMES, not the
    # lines, so an optional field absent from the samples is never penalised.
    # Grok only: for json, kv and csv every key on the line is produced without
    # the model naming it, so there is no pattern to disagree with.
    if extraction.get("kind") == "grok":
        captured: set[str] = set()
        for p in grok_patterns(extraction):
            try:
                captured |= set(_grok_to_regex(p)[1])
            except re.error:
                pass
        used = {f["source_key"] for f in ir.get("fields") or []}
        used |= {vm.get("from_source_key") for vm in ir.get("value_maps") or [] if vm.get("from_source_key")}
        if ts := ir.get("timestamp"):
            used.add(ts.get("source_key"))
        absent = sorted(k for k in used if k and k not in captured
                        and k.split("][")[-1].strip("[]") not in captured)
        if captured and absent:
            rep.findings.append(
                Finding(
                    "V2",
                    "mapped_key_not_captured",
                    f"the IR maps {', '.join(repr(k) for k in absent)}, but no pattern "
                    f"captures {'it' if len(absent) == 1 else 'them'}: the patterns "
                    f"capture only {', '.join(repr(c) for c in sorted(captured))}. "
                    "A mapping whose key is never extracted leaves its ECS field empty "
                    "on every line. Add a named capture for each of these keys where "
                    "its value sits in the line, or move the key to `unresolved`.",
                    STAGE_INTERPRET,
                    absent[0],
                )
            )

    mapped = {f["source_key"] for f in ir["fields"]}
    declared = mapped | {u["source_key"] for u in ir.get("unresolved", [])}
    if ts := ir.get("timestamp"):
        declared.add(ts["source_key"])
    for vm in ir.get("value_maps", []):
        if key := vm.get("from_source_key"):
            declared.add(key)

    # A NESTED JSON KEY IS ADDRESSED BY ITS LEAVES.
    #
    # `_keys_on_line` reads a JSON object's TOP-LEVEL keys, while the IR
    # addresses what Logstash's json filter actually produces: `alert.action`,
    # `flow.bytes_toserver`. So a source that maps six fields out of `alert`
    # was told `alert` is "neither mapped nor listed as unresolved".
    #
    # Measured on suricata_eve, 2026-10-10: five of seven mappings correct,
    # extraction `json` correct, and V2 refused it over `alert`, `flow` and
    # `http` - the three keys it had in fact read.
    #
    # `adapter/types.py` already harvests nested keys for retrieval, with the
    # comment "the object's own keys, nested included", so the two halves of
    # this system disagreed about what a JSON key is.
    #
    # Declaring `a.b` therefore accounts for `a`. This is strictly more
    # permissive than before, so it cannot fail a source that passes today; it
    # only stops demanding that a subtree be mapped as a scalar, which no
    # parser could do anyway.
    for key in list(declared):
        if isinstance(key, str) and "." in key:
            parts = key.split(".")
            for i in range(1, len(parts)):
                declared.add(".".join(parts[:i]))
    # The key an inner grok reads is read: its values are the captures (A4).
    inner_src = ((extraction or {}).get("inner") or {}).get("source") if isinstance(
        (extraction or {}).get("inner"), dict) else None
    if inner_src:
        parts = inner_src.split(".")
        for i in range(1, len(parts) + 1):
            declared.add(".".join(parts[:i]))

    misses: dict[str, int] = {}
    seen_keys: set[str] = set()
    for s in source.samples:
        line_keys = _keys_in(s.raw, extraction)
        seen_keys |= line_keys
        for key in line_keys - declared:
            misses[key] = misses.get(key, 0) + 1

    total = max(len(source.samples), 1)
    # Recorded whether or not anything tolerates it, because the number is
    # worth having even when the strict rule is in force.
    if seen_keys:
        rep.metrics["key_coverage"] = len(seen_keys & declared) / len(seen_keys)
        rep.metrics["keys_seen"] = len(seen_keys)
        rep.metrics["keys_accounted"] = len(seen_keys & declared)
    for key, n in sorted(misses.items(), key=lambda kv: -kv[1]):
        if n / total >= (1 - MIN_COVERAGE):
            rep.findings.append(
                Finding(
                    "V2",
                    "key_not_accounted_for",
                    f"{key!r} appears in {n}/{total} samples but is neither mapped "
                    f"nor listed as unresolved.",
                    STAGE_INTERPRET,
                    key,
                )
            )

    # A VALUE MAP THAT DOES NOT COVER THE DATA DELETES IT.
    #
    # The compiler turns a value_map into a Logstash `translate`, and a
    # translate with no `fallback` writes NOTHING when the value is absent from
    # its dictionary. The ECS field then does not exist on those documents, and
    # nothing says so: the parser ran, the other fields are there, the document
    # indexes.
    #
    # It is decidable here, because this rung is the one that reads the
    # samples. Found the hard way: a proposal mapped a DNS response code
    # through {NOERROR: success, REFUSED: failure}, which is an OUTCOME
    # vocabulary applied to a field that holds an rcode, and the two values it
    # omitted vanished. V4 reported it sixty seconds later as a detection
    # mismatch, which reads as "the field is in the wrong place" when the field
    # was simply deleted. Ten of 240 proposals from a 32B teacher declared a
    # value_map and all ten omitted the fallback.
    for vm in ir.get("value_maps", []):
        key = vm.get("from_source_key")
        if not key or vm.get("fallback"):
            continue
        covered = set(vm.get("map") or {})
        seen: dict[str, int] = {}
        for sample in source.samples:
            v = _value_of(sample.raw, key, extraction)
            if v is not None and v not in covered:
                seen[v] = seen.get(v, 0) + 1
        if seen:
            worst = ", ".join(
                f"{v!r} ({n})" for v, n in sorted(seen.items(), key=lambda kv: -kv[1])[:4])
            rep.findings.append(
                Finding(
                    "V2",
                    "value_map_drops_values",
                    f"the value_map for {key!r} has no fallback and its dictionary "
                    f"does not cover {worst}. Logstash's translate writes nothing "
                    f"when a value is missing, so {vm['ecs_field']} will be absent "
                    "from those documents rather than wrong. Add a fallback, or "
                    "cover every value the samples show.",
                    STAGE_MAP,
                    key,
                )
            )

    rep.metrics["coverage"] = 1 - (len(misses) / max(len(declared) + len(misses), 1))
    # Recorded so a coverage of 1.0 can be told apart from a rung that saw
    # nothing to cover. The first is a result; the second was the bug above.
    rep.metrics["keys_observed"] = len(declared) + len(misses)
    _tolerate_partial_coverage(rep)
    rep.passed = not rep.findings
    return rep

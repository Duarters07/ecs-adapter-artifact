"""Round 10, A2: the feedback a repair turn receives, diagnosed instead of listed.

PLAN_ROUND10_ARM_C.md, A2 (the diagnosis step of the ICISSP 2027 submission's repair loop, adapted). Round 9
handed the model the first eight findings verbatim. On Gitea (r6, org9) all eight slots carried copies of one
parse failure and none said where the pattern stopped; on RabbitMQ six findings each said "this key is not being
extracted" and none said where the values actually were. This module turns a report into at most `limit` entries,
one per cause, each saying what failed, where, and what would read it:

  lost values     every value the probe injected that reached no field, grouped, and located in the raw line:
                  the JSON key whose string holds it, or the text around it; plus the keys the extraction does
                  produce, so a key that does not exist is visible as such.
  unread lines    for a grok, the token where the closest pattern stops on the first unread line, what text is
                  there, and which grok classes (or a date composed from grok's date parts) would read it.
  the rest        grouped by rung and code: one entry with the count and the first message.

Rendering is the same for serving and training (corpus/repair_pairs.py calls `render`), and stays inside the
`errors` slot the prompts already have. `ECS_PIPELINE=round9` returns round 9's list.
"""
from __future__ import annotations

from collections import OrderedDict
from typing import Any
import json
import re

from adapter.types import STAGE_INTERPRET, Finding, Source, ValidationReport, grok_patterns, round9_pipeline

MAX_ENTRY = 1200
_VALUE = re.compile(r"the probe injected (.+?) as ([\w.@]+), and it appears in no field")

# Classes offered when a grok token fails. Dates first: they are the token models get wrong most.
_SUGGEST = ("TIMESTAMP_ISO8601", "SYSLOGTIMESTAMP", "HTTPDATE", "HTTPDERROR_DATE", "DATESTAMP",
            "IP", "IPORHOST", "HOSTNAME", "NUMBER", "INT", "WORD", "NOTSPACE", "USERNAME",
            "UNIXPATH", "URIPATHPARAM", "LOGLEVEL", "QUOTEDSTRING")


def render(report: ValidationReport, ir: dict[str, Any] | None, source: Source | None,
           stage: str | None = None, limit: int = 8) -> str:
    """The repair feedback for `report`, restricted to `stage` when given."""
    findings = [f for f in report.findings if stage is None or f.stage == stage]
    if round9_pipeline() or not hasattr(source, "parser_input"):
        return ValidationReport(findings=findings).feedback(limit)
    entries: list[str] = []
    lost = [f for f in findings if f.code == "value_not_found"]
    if lost:
        entries.append(_lost_values(lost, ir or {}, source))
    # Lines the parser does not read. V3's tags carry no reason, so they become
    # one entry with the diagnosis; V2's findings already name the line and the
    # token, and only gain what would read the text there.
    v3_unread = [f for f in findings if f.code in ("parse_failure_tag", "events_lost")]
    v2_unread = [f for f in findings if f.code in ("grok_matches_only_some_lines", "extraction_yields_nothing",
                                                   "extraction_yields_little", "inner_matches_only_some_lines")]
    diag, fits = _unread_lines(ir or {}, source) if (v3_unread or v2_unread) else (None, None)
    if v3_unread:
        entries.append(_grouped(v3_unread, diag or v3_unread[0].message))
    for f in v2_unread:
        entries.append(_line(f) + (f" {fits}" if fits else ""))
    done = set(map(id, lost + v3_unread + v2_unread))
    groups: "OrderedDict[tuple[str, str], list[Finding]]" = OrderedDict()
    for f in findings:
        if id(f) not in done:
            groups.setdefault((f.rung, f.code), []).append(f)
    order = sorted(groups.values(), key=lambda fs: fs[0].stage != STAGE_INTERPRET)
    for fs in order:
        entries.append(_line(fs[0]) if len(fs) == 1 else _grouped(fs, fs[0].message))
    return "\n".join(e[:MAX_ENTRY] for e in entries[:limit])


def _line(f: Finding) -> str:
    return f"- [{f.rung}/{f.code}]{' field=' + f.source_key if f.source_key else ''}: {f.message}"


def _grouped(fs: list[Finding], message: str) -> str:
    keys = sorted({f.source_key for f in fs if f.source_key})
    more = f" Fields: {', '.join(keys)}." if keys else ""
    return f"- [{fs[0].rung}/{fs[0].code}] x{len(fs)}: {message}{more}"


# ------------------------------------------------------------------ lost values


def _lost_values(fs: list[Finding], ir: dict[str, Any], source: Source) -> str:
    lines = list(source.parser_input())
    keys_by_field: dict[str, list[str]] = {}
    for m in ir.get("fields") or []:
        if isinstance(m, dict) and m.get("ecs_field") and m.get("source_key"):
            keys_by_field.setdefault(m["ecs_field"], []).append(m["source_key"])
    items, places = [], []
    for f in fs:
        m = _VALUE.search(f.message)
        if not m:
            continue
        value, field = m.group(1).strip("'\""), m.group(2)
        mapped = keys_by_field.get(field)
        items.append(f"{field} {value!r}" + (f" (mapped from {', '.join(repr(k) for k in mapped)})" if mapped else
                                             " (no key is mapped to it)"))
        where = _locate(value, lines)
        if where and not any(where.split(":")[0] == p.split(":")[0] for p in places):
            places.append(where)
    produced = _produced_keys(ir, lines)
    text = (f"- [V3.5/value_not_found] x{len(items)}: values the probe put in the line reach no field: "
            + "; ".join(items) + ".")
    if places:
        text += " In the raw line they are " + "; ".join(places[:3]) + "."
    if produced is not None:
        text += f" The extraction produces only the keys {', '.join(sorted(produced)[:20]) or '(none)'}."
        missing = sorted({k for ks in keys_by_field.values() for k in ks} - produced)
        if missing:
            text += f" Mapped keys no line has: {', '.join(missing[:12])}."
    return text


def _locate(value: str, lines: list[str]) -> str | None:
    """Where `value` sits in the first line holding it."""
    for line in reversed(lines):          # the probe line is last
        if value not in line:
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            obj = None
        if isinstance(obj, dict):
            path = _json_path(obj, value)
            if path:
                k, v, exact = path
                if exact:
                    return f"the value of JSON key `{k}`"
                i = v.find(value)
                return (f"inside the string of JSON key `{k}`: the line holds them as text, e.g. "
                        f"{v[max(0, i - 50): i + len(value) + 50]!r}, and a json extraction keeps `{k}` whole, "
                        f"so no key holds one of them alone. `extraction.inner` with source `{k}` reads that "
                        f"text with a grok, whose captures become keys")
        i = line.find(value)
        return f"in the text {line[max(0, i - 40): i + len(value) + 40]!r}"
    return None


def _json_path(obj: Any, value: str, prefix: str = "") -> tuple[str, str, bool] | None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                r = _json_path(v, value, p)
                if r:
                    return r
            elif str(v) == value:
                return p, str(v), True
            elif isinstance(v, str) and value in v:
                return p, v, False
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            r = _json_path(v, value, f"{prefix}[{i}]")
            if r:
                return r
    return None


def _produced_keys(ir: dict[str, Any], lines: list[str]) -> set[str] | None:
    from validators.v2_consistency import _keys_in

    ex = ir.get("extraction")
    if not isinstance(ex, dict) or not ex.get("kind"):
        return None
    keys: set[str] = set()
    for line in lines:
        try:
            keys |= set(_keys_in(line, ex))
        except Exception:   # a malformed extraction is V1's to report
            return None
    return keys


# ------------------------------------------------------------------ unread lines


def _unread_lines(ir: dict[str, Any], source: Source) -> tuple[str | None, str | None]:
    """For a grok: (where the closest pattern stops on the first unread line, what would read the text there)."""
    from validators.v2_consistency import _grok_closest, _grok_first_failure, _grok_to_regex

    ex = ir.get("extraction") or {}
    lines = list(source.parser_input())
    inner = ex.get("inner") if ex.get("kind") == "json" else None
    if isinstance(inner, dict) and inner.get("source"):
        # The inner grok is diagnosed on the texts it is given (A4).
        from adapter.types import json_lookup

        texts = []
        for l in lines:
            try:
                o = json.loads(l)
            except (ValueError, TypeError):
                continue
            t = json_lookup(o, inner["source"]) if isinstance(o, dict) else None
            if isinstance(t, str):
                texts.append(t)
        pats, lines = grok_patterns(inner), texts
    elif ex.get("kind") == "grok":
        pats = grok_patterns(ex)
    else:
        return None, None
    try:
        rxs = [re.compile(_grok_to_regex(p)[0]) for p in pats]
    except re.error as exc:
        return (f"the grok does not compile ({exc}); check every group is closed and every name is a "
                f"grok name.", None)
    unread = [l for l in lines if not any(r.match(l) for r in rxs)]
    if not unread:
        return None, None
    line = unread[0]
    # An alternation written inside one pattern (`A$|^B`) is diagnosed branch
    # by branch, as if the model had used `alternatives`: a walk from the left
    # across `|` would report the other branch's token.
    branches = [b for p in pats for b in _branches(p)]
    closest = _grok_closest(branches, line, search=False)
    diag = (f"{len(unread)} of {len(lines)} lines are not read and would be dropped. First: {line[:160]!r}. "
            + _grok_first_failure(closest, line) + ".")
    at = _failure_text(closest, line)
    fits = None
    if at:
        reads = _what_reads(at)
        if reads:
            fits = f"At that point the line has {at[:40]!r}; " + "; ".join(reads[:4]) + " would read it."
            nxt = _next_stop(closest, line, best_read(at))
            if nxt:
                fits += f" With that fixed, the pattern next {nxt}."
    return (diag + (f" {fits}" if fits else "")), fits


def _branches(pattern: str) -> list[str]:
    """The pattern split at every `|` outside all groups and character classes."""
    out, depth, in_set, i, start = [], 0, False, 0, 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if in_set:
            in_set = c != "]"
        elif c == "[":
            in_set = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "|" and depth == 0:
            out.append(pattern[start:i])
            start = i + 1
        i += 1
    out.append(pattern[start:])
    return [b for b in out if b]


def _top_level_alternation(pattern: str) -> bool:
    """Does the pattern contain a `|` outside every group and character class?"""
    return len(_branches(pattern)) > 1


def _next_stop(pattern: str, line: str, reader: str | None) -> str | None:
    """Where the pattern stops once its failing token reads the line (one step of look-ahead).

    Three repair turns are not enough when each turn reveals only the next
    broken token: Gitea's org9 pattern had a wrong date class AND a LOGLEVEL
    that grok does not accept for `I`, two turns for what one message can say.
    """
    from validators.v2_consistency import _GROK_TOKEN, _grok_to_regex

    if not reader or _top_level_alternation(pattern):
        return None
    toks = list(_GROK_TOKEN.finditer(pattern))
    for k in range(1, len(toks) + 1):
        try:
            ok = re.match(_grok_to_regex(pattern[: toks[k - 1].end()], search=False)[0], line)
        except re.error:
            continue
        if ok:
            continue
        t = toks[k - 1]
        name = t.group(2)
        repl = f"%{{{reader[2:-1]}:{name}}}" if reader.startswith("%{") and reader.count("%{") == 1 and name \
            else (f"(?<{name}>{reader})" if name and re.fullmatch(r"\w+", name) else f"(?:{reader})")
        fixed = pattern[: t.start()] + repl + pattern[t.end():]
        try:
            if re.match(_grok_to_regex(fixed, search=False)[0], line):
                return "reads the line"
        except re.error:
            return None
        ftoks = [m for m in _GROK_TOKEN.finditer(fixed) if m.start() >= t.start() + len(repl)]
        prev_end = t.start() + len(repl)
        for m in ftoks:
            try:
                if re.match(_grok_to_regex(fixed[: m.end()], search=False)[0], line):
                    prev_end = m.end()
                    continue
                before = re.match(_grok_to_regex(fixed[:prev_end], search=False)[0], line)
                lead_ok = re.match(_grok_to_regex(fixed[: m.start()], search=False)[0], line)
            except re.error:
                continue
            here = line[before.end():] if before else line
            if not lead_ok:
                return (f"does not find the literal text {fixed[prev_end:m.start()]!r} before {m.group(0)}; "
                        f"the line has {here[:40]!r} there")
            at = line[lead_ok.end():]
            reads = _what_reads(at)
            tail = f"; {'; '.join(reads[:3])} would read it" if reads else ""
            return f"stops at {m.group(0)}, on {at[:40]!r}{tail}"
        return "stops in the literal text after its last capture"
    return None


def _failure_text(pattern: str, line: str) -> str | None:
    """The line's text where the pattern's matched prefix ends, literal text skipped."""
    from validators.v2_consistency import _GROK_TOKEN, _grok_to_regex

    toks = list(_GROK_TOKEN.finditer(pattern))
    end = 0
    for k in range(1, len(toks) + 1):
        try:
            m = re.match(_grok_to_regex(pattern[: toks[k - 1].end()], search=False)[0], line)
        except re.error:
            continue
        if not m:
            lead = pattern[toks[k - 2].end() if k > 1 else 0: toks[k - 1].start()]
            try:
                lm = re.match(_grok_to_regex(pattern[: toks[k - 1].start()], search=False)[0], line) \
                    if lead else None
            except re.error:
                lm = None
            return line[(lm.end() if lm else end):]
        end = m.end()
    return None


def _what_reads(text: str) -> list[str]:
    """Grok classes, and dates composed from grok's date parts, that match at the start of `text`."""
    from adapter.normalise import _DATE_LAYOUTS
    from validators.v2_consistency import _grok_to_regex

    found: list[tuple[int, str]] = []
    for c in _SUGGEST:
        m = re.match(_grok_to_regex(f"^%{{{c}}}", search=False)[0], text)
        if m and m.end() > 0:
            found.append((m.end(), f"%{{{c}}}"))
    for layout in _DATE_LAYOUTS:
        m = re.match(_grok_to_regex("^" + layout, search=False)[0], text)
        if m:
            found.append((m.end(), layout))
            break
    if not found:
        return []
    best = max(n for n, _ in found)
    # A class reading `2026` of `2026/10/27 16:27:43` is noise beside one reading the whole date.
    keep = sorted((x for x in found if x[0] * 2 >= best), key=lambda x: -x[0])
    return [f"{c} (reads {text[:n][:40]!r})" for n, c in keep]


def best_read(text: str) -> str | None:
    """The grok text that reads the most of `text` at its start (used to look past a failure)."""
    reads = _what_reads(text)
    return reads[0].split(" (reads ")[0] if reads else None

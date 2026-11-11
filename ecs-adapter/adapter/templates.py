"""Log templates mined from the sample lines, compiled into grok (round 2b, exploratory).

WHY THIS EXISTS
---------------
Round 2 measured where the students fail on free text, and it is not meaning.
Arm C-gold maps the fields it extracts with 86-97% precision on every level,
and still loses most free-text sources at V2 (`extraction_yields_nothing`) or
at V4, where the scenario's lines are parsed by a pattern written for the
samples. Writing one exact regular expression for a family of lines is the
step a 7B does worst, and it is the step classic log parsing solved long ago.

So the work is split. A deterministic miner (a minimal Drain: He et al.,
ICWS 2017) groups lines by message type and marks the positions that vary;
each template compiles into a grok whose captures are numbered slots. What is
left for a model is to say what each slot IS - the task it already does well.
The ladder judges the result exactly as before.

WHAT THIS MODULE DOES NOT DO
----------------------------
It does not name slots, choose ECS fields or read documentation. A slot's grok
type (IP, INT, NUMBER, MAC, NOTSPACE, GREEDYDATA) is read off the values it
held on the samples, nothing more. It never sees truth.json, line truth or a
detection rule: it is built from the samples alone, which is what the
deployed system has.

STATUS
------
Declared after the round-2 results (2026-10-18) and outside the
pre-registration. Measured offline by `bench/template_probe.py`; the
write-up is ROUND2B_STRATEGIES.md.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
import signal
import threading

# Delimiters split off a token and kept as literal tokens: `host[1.2.3.4]:`
# becomes `host [ 1.2.3.4 ] :`, so the IP is a token of its own.
_DELIMS = r"\[\]\(\)<>=,;\"'|{}"
_TOKEN = re.compile(rf"[{_DELIMS}]|[^\s{_DELIMS}]+")
# The same class for EMITTED patterns, quotes spelled as escapes: the compiler
# refuses a grok holding both quote kinds, since no Logstash string literal can.
_CLASS = r"\[\]\(\)<>=,;\x22\x27|{}"


def _lit(tok: str) -> str:
    return re.escape(tok).replace('"', r"\x22").replace("'", r"\x27")

_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_IPV6 = re.compile(r"^[0-9A-Fa-f:]*:[0-9A-Fa-f:]+$")
_MAC = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
_INT = re.compile(r"^-?\d+$")
_NUM = re.compile(r"^-?\d+(?:\.\d+)?$")
_HAS_DIGIT = re.compile(r"\d")

WILDCARD = "<*>"


def tokens(line: str) -> list[str]:
    return _TOKEN.findall(line)


def _variable_looking(tok: str) -> bool:
    """Drain's pre-masking: a token carrying a digit is a value, not a keyword."""
    return bool(_HAS_DIGIT.search(tok))


@dataclass
class Template:
    tokens: list[str]                     # literal tokens and WILDCARD
    values: list[list[str]] = field(default_factory=list)  # per slot, observed values
    tail: bool = False                    # the last slot swallows the rest of the line
    lines: int = 0

    @property
    def slots(self) -> int:
        return sum(t == WILDCARD for t in self.tokens)

    def text(self) -> str:
        return " ".join(self.tokens) + (" <...>" if self.tail else "")


def _similarity(a: list[str], b: list[str]) -> float:
    same = sum(x == y for x, y in zip(a, b) if x != WILDCARD and y != WILDCARD)
    return same / max(len(a), 1)


def mine(lines: list[str], threshold: float = 0.4, prefix: int = 2,
         tail_merge: bool = False) -> list[Template]:
    """Drain, minimally: group by token count and leading literals, merge by similarity.

    A line goes to the template of the same length, sharing its first `prefix`
    literal tokens, whose positional similarity is at least `threshold`;
    differing positions become wildcards. Templates sharing a long literal
    prefix but differing in length are then merged into one with a free-text
    tail, which is how a message such as apache's error text - a sentence of
    any length - stays one template instead of one per sentence.

    THE DEFAULTS ARE DRAIN'S, NOT TUNED HERE. threshold 0.4 and a prefix of 2
    (Drain's depth 4) are drain3's defaults; the tail merge is this module's
    addition and is off, because Drain has none. A sweep on round 2's
    scenarios (ROUND2B_STRATEGIES.md) found the merge lowers how many rule
    values a capture isolates (0.62 -> 0.42 at 0.4), and choosing settings on
    those scenarios would be tuning on the test - so the sweep is reported as
    sensitivity and the literature's values are kept.
    """
    groups: list[Template] = []
    for line in lines:
        toks = [WILDCARD if _variable_looking(t) else t for t in tokens(line)]
        key = [t for t in toks[:prefix]]
        best, score = None, -1.0
        for g in groups:
            if len(g.tokens) != len(toks) or g.tail or g.tokens[:prefix] != key:
                continue
            s = _similarity(g.tokens, toks)
            if s >= threshold and s > score:
                best, score = g, s
        if best is None:
            groups.append(Template(tokens=toks, lines=1))
        else:
            best.tokens = [a if a == b else WILDCARD for a, b in zip(best.tokens, toks)]
            best.lines += 1
    if tail_merge:
        groups = _merge_tails(groups)
    for g in groups:
        g.values = [[] for _ in range(g.slots)]
    for line in lines:
        hit = match(groups, line)
        if hit:
            g, vals = hit
            for i, v in enumerate(vals):
                g.values[i].append(v)
    return groups


def _merge_tails(groups: list[Template], min_prefix: int = 4) -> list[Template]:
    out: list[Template] = []
    for g in sorted(groups, key=lambda t: len(t.tokens)):
        for o in out:
            n = _common_prefix(o.tokens, g.tokens)
            if n >= min_prefix and (n < len(o.tokens) or n < len(g.tokens)):
                o.tokens = o.tokens[:n] + [WILDCARD]
                o.tail = True
                o.lines += g.lines
                break
        else:
            out.append(g)
    return out


def _common_prefix(a: list[str], b: list[str]) -> int:
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n


def _slot_type(values: list[str], last_tail: bool) -> str:
    if last_tail:
        return "GREEDYDATA"
    vs = [v for v in values if v]
    if vs and all(_IPV4.match(v) for v in vs):
        return "IP"
    if vs and all(_MAC.match(v) for v in vs):
        return "MAC"
    if vs and all(_IPV6.match(v) for v in vs):
        return "IPV6"
    if vs and all(_INT.match(v) for v in vs):
        return "INT"
    if vs and all(_NUM.match(v) for v in vs):
        return "NUMBER"
    return "NOTSPACE"


def to_grok(t: Template, names: list[str] | None = None) -> str:
    """The template as an anchored grok; slots captured as `names` or slot_1..n."""
    names = names or [f"slot_{i + 1}" for i in range(t.slots)]
    parts, slot = [], 0
    for i, tok in enumerate(t.tokens):
        if tok == WILDCARD:
            last = t.tail and i == len(t.tokens) - 1
            kind = _slot_type(t.values[slot] if t.values else [], last)
            # grok's NOTSPACE is \S+, which would swallow the `]:` after a
            # bracketed value; a token stops at the same delimiters it was cut on.
            parts.append(f"(?<{names[slot]}>[^\\s{_CLASS}]+)" if kind == "NOTSPACE"
                         else f"%{{{kind}:{names[slot]}}}")
            slot += 1
        else:
            parts.append(_lit(tok))
    return "^" + r"\s*".join(parts) + "$"


def _regex(t: Template) -> re.Pattern:
    """The same shape as `to_grok`, in Python regex, for matching without Logstash."""
    parts = []
    for i, tok in enumerate(t.tokens):
        if tok == WILDCARD:
            last = t.tail and i == len(t.tokens) - 1
            parts.append("(.+)" if last else rf"([^\s{_DELIMS}]+)")
        else:
            parts.append(re.escape(tok))
    return re.compile("^" + r"\s*".join(parts) + "$")


# A BOUNDED MATCH (Task 3, deviation 6, 2026-11-08).
#
# `_regex` joins two wildcards with `\s*`, so a run of non-space characters can
# be split between them in many ways, and a line that does not fit is refused
# only after trying them all: exponential in the number of adjacent wildcards.
# Attacker-written lines (the dose trees of Task 3) made one template take
# hours, and the full-system run stalled in `patterns_for_unread`. Making the
# class possessive would remove the backtracking but change which lines match
# (95 of 2,324 bench sources mined differently), so the pattern is kept and
# each match gets a time limit instead; a match that runs out counts as no
# match. On every bench source whose mining finishes the result is identical,
# and the slowest successful match took 0.2 ms, a five-hundredth of the limit.
#
# The limit is a timer signal around `re`, not the `regex` module's timeout:
# `regex` reads some model patterns differently (`${int:src_line}` is its fuzzy
# syntax, a literal for `re`), so it would change matches or fail to compile.
# CPython's `re` checks for signals while it backtracks, so the timer stops it.
# Off the main thread a signal cannot be installed and the match is unbounded,
# as before; nothing in the system matches lines off the main thread.
MATCH_TIMEOUT_S = 0.1


class _MatchTimeout(Exception):
    pass


def _raise_timeout(*_: object) -> None:
    raise _MatchTimeout


def _rmatch(rx: re.Pattern, line: str) -> re.Match | None:
    """`rx.match(line)`, or None if it runs past MATCH_TIMEOUT_S.

    Used for every match of a whole line in this module: the template regexes
    (`_regex`, `_token_regex`) and the model's own patterns in `align` and
    `patterns_for_unread`, which stalled on the same lines once `match` alone
    was bounded.
    """
    if threading.current_thread() is not threading.main_thread():
        return rx.match(line)
    previous = signal.signal(signal.SIGALRM, _raise_timeout)
    try:
        signal.setitimer(signal.ITIMER_REAL, MATCH_TIMEOUT_S)
        try:
            return rx.match(line)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
    except _MatchTimeout:
        return None
    finally:
        signal.signal(signal.SIGALRM, previous)


def match(templates: list[Template], line: str) -> tuple[Template, list[str]] | None:
    for t in templates:
        m = _rmatch(_regex(t), line.strip())
        if m:
            return t, list(m.groups())
    return None


# ------------------------------------------------------------------ naming from the model
#
# The students write a grok whose capture names are their own keys, and on
# free text that grok often reads only some lines. Where it does read a line,
# the SPAN of each capture says which stretch of the template it covers, so the
# names can be carried over to the template - which reads every sample line -
# without asking the model anything new. A key whose capture never lines up
# with a token boundary is simply not carried, and the ladder then judges the
# parser that results; nothing here is trusted because it was rewritten.

_WORD_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _token_regex(t: Template) -> re.Pattern:
    """Every token its own group, so token spans can be read off a match."""
    parts = []
    for i, tok in enumerate(t.tokens):
        if tok == WILDCARD:
            last = t.tail and i == len(t.tokens) - 1
            parts.append("(.+)" if last else rf"([^\s{_DELIMS}]+)")
        else:
            parts.append(f"({re.escape(tok)})")
    return re.compile("^" + r"\s*".join(parts) + "$")


def _token_piece(t: Template, i: int) -> str:
    tok = t.tokens[i]
    if tok != WILDCARD:
        return _lit(tok)
    last = t.tail and i == len(t.tokens) - 1
    return ".+" if last else f"[^\\s{_CLASS}]+"


def _capture(name: str, t: Template, i: int, j: int, slot_of: dict[int, int]) -> str:
    if i == j and t.tokens[i] == WILDCARD:
        kind = _slot_type(t.values[slot_of[i]] if t.values else [],
                          t.tail and i == len(t.tokens) - 1)
        if kind != "NOTSPACE":
            return f"%{{{kind}:{name}}}"
    body = r"\s*".join(_token_piece(t, k) for k in range(i, j + 1))
    if _WORD_NAME.match(name):
        return f"(?<{name}>{body})"
    # A name grok's inline groups cannot carry (a dot, a bracket): the
    # region's shape is lost, but the capture and its name are kept.
    return f"%{{{'DATA' if j > i else 'NOTSPACE'}:{name}}}"


def named_grok(t: Template, regions: dict[tuple[int, int], str]) -> str:
    """The template as grok, with `regions` (token span -> key) captured and nothing else."""
    slot_of, n = {}, 0
    for i, tok in enumerate(t.tokens):
        if tok == WILDCARD:
            slot_of[i] = n
            n += 1
    parts, i = [], 0
    starts = {a: (b, name) for (a, b), name in regions.items()}
    while i < len(t.tokens):
        if i in starts:
            j, name = starts[i]
            parts.append(_capture(name, t, i, j, slot_of))
            i = j + 1
        else:
            parts.append(_token_piece(t, i))
            i += 1
    return "^" + r"\s*".join(parts) + "$"


def align(templates: list[Template], model_patterns: list[str], lines: list[str]
          ) -> dict[int, dict[tuple[int, int], str]]:
    """For each template, token span -> model key, by majority over the lines both read."""
    from collections import Counter
    from validators.v2_consistency import _GROK_TOKEN, _grok_to_regex

    model_rx = []
    original: dict[str, str] = {}  # V2's regex-safe group name -> the key the model wrote
    for p in model_patterns:
        try:
            src, names = _grok_to_regex(p, search=False)
            model_rx.append(re.compile(src))
        except Exception:
            continue
        for n in names:
            original.setdefault(re.sub(r"[^0-9A-Za-z_]", "_", n), n)
    # PREFIXES. On free text the model's grok usually gets the start of the
    # line right (time, host, program) and dies in the middle, and a pattern
    # that reads no line names nothing. Each pattern is therefore also tried
    # cut after each of its captures, longest first, unanchored at the end;
    # the captures of the longest prefix that matches still mark true spans.
    prefixes: list[re.Pattern] = []
    for p in model_patterns:
        ends = [m.end() for m in _GROK_TOKEN.finditer(p)]
        for end in reversed(ends):
            # A prefix names spans only if it holds a literal WORD of the
            # message, not just captures: `^%{WORD:outcome}` matches the first
            # word of ANY line, and on round 3 it named `Connection` as the
            # outcome of an sshd line of another type (phase 1.5).
            if not re.search(r"[A-Za-z]{3,}", _GROK_TOKEN.sub("", p[:end]).replace("\\s", " ")):
                continue
            try:
                prefixes.append(re.compile(_grok_to_regex(p[:end], search=False)[0]))
            except Exception:
                continue
            src, names = _grok_to_regex(p[:end], search=False)
            for n in names:
                original.setdefault(re.sub(r"[^0-9A-Za-z_]", "_", n), n)
    votes: dict[int, Counter] = {}
    for line in lines:
        line = line.strip()
        ti = next((k for k, t in enumerate(templates) if _rmatch(_token_regex(t), line)), None)
        mm = next((m for m in (_rmatch(rx, line) for rx in model_rx) if m), None)
        if mm is None:
            mm = next((m for m in (_rmatch(rx, line) for rx in prefixes) if m), None)
        if ti is None or mm is None:
            continue
        tm = _rmatch(_token_regex(templates[ti]), line)
        starts = {tm.start(g + 1): g for g in range(len(templates[ti].tokens))}
        ends = {tm.end(g + 1): g for g in range(len(templates[ti].tokens))}
        for raw_name, value in mm.groupdict().items():
            if value is None:
                continue
            safe = re.sub(r"__d\d+$", "", raw_name)  # V2's renaming of a repeated name
            key = original.get(safe, safe)
            a, b = mm.span(raw_name)
            if a in starts and b in ends and starts[a] <= ends[b]:
                votes.setdefault(ti, Counter())[(starts[a], ends[b], key)] += 1
    out: dict[int, dict[tuple[int, int], str]] = {}
    for ti, c in votes.items():
        taken_tokens: set[int] = set()
        taken_keys: set[str] = set()
        regions: dict[tuple[int, int], str] = {}
        for (a, b, key), _n in c.most_common():
            span = set(range(a, b + 1))
            if key in taken_keys or span & taken_tokens:
                continue
            regions[(a, b)] = key
            taken_keys.add(key)
            taken_tokens |= span
        out[ti] = regions
    return out


def transfer(templates: list[Template], named: dict[int, dict[tuple[int, int], str]]
             ) -> dict[int, dict[tuple[int, int], str]]:
    """Names carried to templates the model's grok never read, by keyword context.

    A single-token slot preceded by the same literal token (`from <*>`,
    `port <*>`, `user=<*>`) and holding the same kind of value (IP, INT, ...)
    as a named slot elsewhere takes that slot's name - the assumption every
    key-word log parser makes, and the only one made here. A context that
    names two different keys is ambiguous and transfers nothing; a key never
    lands twice in one template.
    """
    context: dict[tuple[str, str], set[str]] = {}
    for ti, regions in named.items():
        t = templates[ti]
        slot_of = {i: n for n, i in enumerate(k for k, tok in enumerate(t.tokens) if tok == WILDCARD)}
        for (a, b), key in regions.items():
            if a == b and a > 0 and t.tokens[a] == WILDCARD and t.tokens[a - 1] != WILDCARD:
                kind = _slot_type(t.values[slot_of[a]] if t.values else [], False)
                context.setdefault((t.tokens[a - 1], kind), set()).add(key)
    out = {ti: dict(r) for ti, r in named.items()}
    for ti, t in enumerate(templates):
        regions = out.setdefault(ti, {})
        used_tokens = {k for (a, b) in regions for k in range(a, b + 1)}
        used_keys = set(regions.values())
        slot = -1
        for i, tok in enumerate(t.tokens):
            if tok != WILDCARD:
                continue
            slot += 1
            if i == 0 or i in used_tokens or t.tokens[i - 1] == WILDCARD:
                continue
            kind = _slot_type(t.values[slot] if t.values else [], False)
            keys = context.get((t.tokens[i - 1], kind), set())
            if len(keys) == 1 and (key := next(iter(keys))) not in used_keys:
                regions[(i, i)] = key
                used_keys.add(key)
                used_tokens.add(i)
    return {ti: r for ti, r in out.items() if r}


MAX_ALTERNATIVES = 7  # schema/ir.schema.json: extraction.alternatives maxItems


def patterns_for_unread(model_patterns: list[str], lines: list[str],
                        name_patterns: list[str] | None = None) -> list[str]:
    """Named template patterns for the lines `model_patterns` do not read - and only those.

    The first version appended every named template, including ones for lines
    the model's grok already read. Measured on round 3 (phase 1.5): on
    r3_sshd_deb12 that added four patterns where one line was missing, pushed
    `alternatives` past the schema's seven and failed V1, and carried
    misaligned names (`(?<method>user)` on an `Invalid user` line). A template
    is now kept only if it reads at least one line no model pattern reads, and
    the total never exceeds what the schema allows.

    `name_patterns` are extra sources of capture names (in edit mode, the
    previous version's parser); the model's own patterns always come first.
    """
    from validators.v2_consistency import _grok_to_regex

    def _rx(ps):
        out = []
        for p in ps:
            try:
                out.append(re.compile(_grok_to_regex(p, search=False)[0]))
            except re.error:
                pass
        return out

    model_rx = _rx(model_patterns)
    unread = [l for l in lines if not any(_rmatch(r, l) for r in model_rx)]
    if not unread:
        return []
    mined = mine(lines)
    named = transfer(mined, align(mined, list(model_patterns) + list(name_patterns or []), lines))
    room = MAX_ALTERNATIVES + 1 - len(model_patterns)
    out: list[str] = []
    for i, regions in sorted(named.items()):
        if not regions or room <= 0:
            continue
        # A template mined from ONE line is that line with its digits masked:
        # every user name, path and command stays literal, so it reads its own
        # sample and nothing else (phase 4, 2026-10-21: r3_syslog_5424 got six
        # such patterns, `sudo - - - rui : ... COMMAND=/usr/bin/whoami`, and the
        # scenario lines - same shape, other words - were tagged unparsed).
        # Two lines of a shape are the least that shows which tokens vary.
        if mined[i].lines < 2:
            continue
        p = named_grok(mined[i], regions)
        if p in model_patterns or p in out:
            continue
        rx = _rx([p])
        if rx and any(_rmatch(rx[0], l) for l in unread):
            out.append(p)
            room -= 1
    return out

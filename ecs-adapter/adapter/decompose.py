"""Split a source by message shape before stage 1, and merge what comes back.

WHY THIS EXISTS
---------------
A real log source is rarely one message. `linux_auth` interleaves sshd, sudo,
systemd-logind and CRON; postfix writes smtpd, cleanup and qmgr lines into one
file. Asking a 7B model for ONE answer that covers every shape at once is the
task the literature avoids: LLM log parsers cluster first and ask the model one
template at a time (LILAC, FSE 2024), and the pilot of 2026-10-17 measured the
cost of not doing so - every arm left variants unread and failed V2 on the
mixed sources. The model sees at most twelve samples, so in a mixed source each
shape is shown by two or three lines, if at all.

This is that decomposition, as an architecture VARIANT that any arm can run:

    1. group the samples by shape, deterministically - no model involved;
    2. stage 1 once per group, on that group's lines only, same template;
    3. merge the answers deterministically into one roles object
       (one grok pattern per group -> `pattern` + `alternatives`);
    4. stage 2 once, on the merged roles, exactly as before.

One group means the variant IS the plain staged architecture: the same source
object, the same prompts, the same calls (tests/test_decompose.py checks it).

WHAT IS NOT DONE HERE, STATED
-----------------------------
Two groups may name the same value differently (`user` in one pattern,
`username` in another). Nothing here can tell that from two different values,
so both names survive and the ladder judges the result. A role conflict - one
key, two meanings - is resolved for the larger group and recorded on the
architecture (`last_split`), never silently.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Any
import csv
import json
import re

from adapter import diagnose
from adapter.architectures import CombinedArchitecture, StagedArchitecture
from adapter.types import Source, Usage, ValidationReport

MAX_GROUPS = 8
# Two lines belong together when the literal words they share are at least
# this fraction of the words either has (Jaccard). sshd's `Accepted password
# for alice from ...` and `Failed password for invalid user bob from ...` share
# well over half; sshd and sudo lines never meet because the program differs.
SIMILARITY = 0.5

# ----------------------------------------------------------------- shapes

_SYSLOG_3164 = re.compile(
    r"^(?:<\d+>)?(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|"
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+(?:\S+\s+)?(?P<prog>[A-Za-z][\w./-]*)(?:\[\d+\])?:\s"
)
_MASK = [
    re.compile(r'"[^"]*"'),
    re.compile(r"'[^']*'"),
    re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"),       # IPv4[:port]
    re.compile(r"\b[0-9a-fA-F]*:[0-9a-fA-F:]{2,}\b"),          # IPv6-ish
    re.compile(r"\b0x[0-9a-fA-F]+\b|\b[0-9a-fA-F]{8,}\b"),     # hex ids
    re.compile(r"\b\d+(?:[.,:/-]\d+)*\b"),                     # numbers, times, dates
]
_WORD = re.compile(r"[A-Za-z][A-Za-z_-]*")
_KV = re.compile(r"(?:^|[\s,;|])([A-Za-z_][\w.\-]*)=")


def _json_keys(line: str) -> frozenset[str] | None:
    s = line.strip()
    if not s.startswith("{"):
        return None
    try:
        obj = json.loads(s)
    except ValueError:
        return None
    return frozenset(obj) if isinstance(obj, dict) else None


def shape(line: str) -> tuple[str, frozenset[str]]:
    """(kind, words): the line's family and the evidence it is compared on.

    json      the object's top-level keys
    kv        the keys written before `=` (two or more of them)
    text      `program` (from a syslog header, when there is one) and the
              literal words left once numbers, addresses, quoted strings and
              hex identifiers are masked
    """
    keys = _json_keys(line)
    if keys is not None:
        return "json", keys
    kv = _KV.findall(line)
    if len(kv) >= 2:
        return "kv", frozenset(kv)
    prog = ""
    body = line
    if m := _SYSLOG_3164.match(line):
        prog = m.group("prog")
        body = line[m.end():]
    for rx in _MASK:
        body = rx.sub(" ", body)
    return f"text:{prog}", frozenset(_WORD.findall(body))


def _one_table(lines: list[str], min_columns: int = 4) -> bool:
    """Every line splits into the same number (>= `min_columns`) of csv or tsv fields."""
    if not lines or any(_json_keys(ln) is not None or _SYSLOG_3164.match(ln) for ln in lines):
        return False
    for delim in (",", "\t", ";", "|"):
        try:
            widths = {len(row) for row in csv.reader(lines, delimiter=delim)}
        except csv.Error:
            continue
        if len(widths) == 1 and widths.pop() >= min_columns:
            return True
    return False


def _jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b)


def group_lines(lines: list[str], similarity: float = SIMILARITY,
                max_groups: int = MAX_GROUPS) -> list[list[int]]:
    """Indices of `lines`, grouped by shape, largest group first.

    Deterministic: lines are taken in order, a line joins the first existing
    group of the same kind holding a member it is at least `similarity` alike
    to, otherwise it opens a group. Then singletons are folded into the most
    alike group of the same kind (a lone line still reaches stage 1, beside the
    lines it most resembles), and the smallest groups are folded until at most
    `max_groups` remain. Ties keep the earlier group, so a re-run is identical.
    """
    # A DELIMITED FILE IS ONE SHAPE, whatever its free-text columns say.
    # postgres_csv's message column ("connection authorized", "password
    # authentication failed") split it into four groups by wording, and a csv
    # extraction is one column list or nothing: splitting it can only hurt.
    if _one_table(lines):
        return [list(range(len(lines)))] if lines else []
    shapes = [shape(ln) for ln in lines]
    groups: list[list[int]] = []
    for i, (kind, words) in enumerate(shapes):
        for g in groups:
            if shapes[g[0]][0] == kind and any(
                _jaccard(words, shapes[j][1]) >= similarity for j in g
            ):
                g.append(i)
                break
        else:
            groups.append([i])

    def words_of(g: list[int]) -> frozenset[str]:
        return frozenset().union(*(shapes[j][1] for j in g))

    def fold(small: list[int]) -> bool:
        """Move `small` into the most alike other group; False if there is none."""
        best, best_s = None, -1.0
        for g in groups:
            if g is small:
                continue
            same_kind = shapes[g[0]][0] == shapes[small[0]][0]
            s = _jaccard(words_of(g), words_of(small)) + (1.0 if same_kind else 0.0)
            if s > best_s:
                best, best_s = g, s
        if best is None:
            return False
        best.extend(small)
        best.sort()
        groups.remove(small)
        return True

    # Singletons: only when a group of two or more exists to receive them.
    if any(len(g) >= 2 for g in groups):
        for g in [g for g in groups if len(g) < 2]:
            fold(g)
    while len(groups) > max_groups:
        fold(min(groups, key=lambda g: (len(g), -groups.index(g))))
    return sorted(groups, key=lambda g: (-len(g), g[0]))


def split_source(source: Source) -> list[Source]:
    """The source once per shape group; the source itself when there is one group."""
    lines = [s.raw for s in source.samples]
    groups = group_lines(lines)
    if len(groups) <= 1:
        return [source]
    return [replace(source, samples=tuple(source.samples[i] for i in g)) for g in groups]


# ----------------------------------------------------------------- merging

def merge_roles(parts: list[dict[str, Any]], sizes: list[int]) -> tuple[dict[str, Any], dict[str, Any]]:
    """One stage-1 answer from several, and a record of what had to be decided.

    `parts` are ordered largest group first (`sizes` alike), which is also the
    order of precedence: where two groups disagree, the larger one is kept.
    """
    parts = [p or {} for p in parts]
    lead = parts[0]
    out: dict[str, Any] = {k: v for k, v in lead.items()
                           if k not in ("roles", "unresolved", "extraction")}
    record: dict[str, Any] = {"groups": len(parts), "sizes": list(sizes),
                              "role_conflicts": [], "extraction": "lead"}

    exts = [p.get("extraction") or {} for p in parts]
    if all(e.get("kind") == "grok" for e in exts) and exts:
        patterns: list[str] = []
        for e in exts:
            for pat in [e.get("pattern") or ""] + list(e.get("alternatives") or []):
                if pat and pat not in patterns:
                    patterns.append(pat)
        ext = {k: v for k, v in exts[0].items() if k not in ("pattern", "alternatives")}
        if patterns:
            ext["pattern"] = patterns[0]
            if len(patterns) > 1:
                ext["alternatives"] = patterns[1:]
        record["extraction"] = f"grok, {len(patterns)} pattern(s)"
    elif all(e == exts[0] for e in exts):
        ext = dict(exts[0])
        record["extraction"] = "agreed"
    else:
        ext = dict(exts[0])
    if ext:
        out["extraction"] = ext

    roles: dict[str, dict[str, Any]] = {}
    for p, size in zip(parts, sizes):
        for r in p.get("roles") or []:
            key = r.get("source_key")
            if not key:
                continue
            if key not in roles:
                roles[key] = r
            elif (r.get("role") or "") != (roles[key].get("role") or ""):
                record["role_conflicts"].append(
                    {"source_key": key, "kept": roles[key].get("role"),
                     "dropped": r.get("role"), "group_size": size})
    out["roles"] = list(roles.values())

    unresolved: dict[str, dict[str, Any]] = {}
    for p in parts:
        for u in p.get("unresolved") or []:
            key = u.get("source_key")
            if key and key not in roles and key not in unresolved:
                unresolved[key] = u
    if unresolved:
        out["unresolved"] = list(unresolved.values())

    if ext.get("kind") == "csv":
        for p in parts:
            if p.get("column_order"):
                out["column_order"] = p["column_order"]
                break
    return out, record


def merge_irs(parts: list[dict[str, Any]], sizes: list[int]) -> tuple[dict[str, Any], dict[str, Any]]:
    """The combined arm's equivalent: several IRs into one, the larger group first."""
    parts = [p or {} for p in parts]
    as_roles = [{"extraction": p.get("extraction"), "roles": [], "unresolved": []} for p in parts]
    merged_ext, record = merge_roles(as_roles, sizes)
    out = {k: v for k, v in parts[0].items() if k not in ("fields", "unresolved", "value_maps")}
    if "extraction" in merged_ext:
        out["extraction"] = merged_ext["extraction"]
    fields: dict[str, dict[str, Any]] = {}
    taken: set[str] = set()
    for p, size in zip(parts, sizes):
        for f in p.get("fields") or []:
            key, target = f.get("source_key"), f.get("ecs_field")
            if not key or key in fields:
                if key in fields and fields[key].get("ecs_field") != target:
                    record["role_conflicts"].append(
                        {"source_key": key, "kept": fields[key].get("ecs_field"),
                         "dropped": target, "group_size": size})
                continue
            if target in taken:  # one key per field, the IR's rule
                continue
            fields[key] = f
            taken.add(target)
    out["fields"] = list(fields.values())
    vmaps: dict[str, dict[str, Any]] = {}
    for p in parts:
        for v in p.get("value_maps") or []:
            if v.get("ecs_field") not in vmaps and v.get("ecs_field") not in taken:
                vmaps[v["ecs_field"]] = v
    if vmaps:
        out["value_maps"] = list(vmaps.values())
    unresolved = {}
    for p in parts:
        for u in p.get("unresolved") or []:
            k = u.get("source_key")
            if k and k not in fields and k not in unresolved:
                unresolved[k] = u
    if unresolved:
        out["unresolved"] = list(unresolved.values())
    return out, record


# ----------------------------------------------------------------- architectures

class SplitStagedArchitecture(StagedArchitecture):
    """B, T or C with stage 1 run once per message shape. Name: `<arm>+split`."""

    def __init__(self, *args, name: str = "B", **kw) -> None:
        super().__init__(*args, name=f"{name}+split", **kw)
        self.last_split: dict[str, Any] | None = None
        self._groups: list[Source] = []

    def _interpret_split(self, usage: Usage, errors: str = "",
                         previous_roles: str = "") -> dict[str, Any]:
        assert self._source is not None
        if len(self._groups) <= 1:
            # The plain staged call, on the very same source object.
            return self._interpret(self._source, usage, errors=errors,
                                   previous_roles=previous_roles)
        parts = [self._interpret(g, usage, errors=errors, previous_roles=previous_roles)
                 for g in self._groups]
        merged, self.last_split = merge_roles(parts, [len(g.samples) for g in self._groups])
        merged["source_id"] = self._source.source_id
        return merged

    def propose(self, source: Source, usage: Usage) -> dict[str, Any]:
        self._source = source
        self._groups = split_source(source)
        self.last_split = {"groups": len(self._groups),
                           "sizes": [len(g.samples) for g in self._groups]}
        self.last_roles = self._interpret_split(usage)
        return self._map(source, self.last_roles, usage)

    def repair(self, ir: dict[str, Any], report: ValidationReport,
               usage: Usage) -> dict[str, Any]:
        assert self._source is not None, "repair() called before propose()"
        if report.blames_interpretation():
            self.last_roles = self._interpret_split(
                usage, errors=diagnose.render(report, ir, self._source),
                previous_roles=json.dumps(self.last_roles, indent=2, sort_keys=True))
            return self._map(self._source, self.last_roles or {}, usage)
        return super().repair(ir, report, usage)


class SplitCombinedArchitecture(CombinedArchitecture):
    """A with one combined call per message shape, the IRs merged. Name: `A+split`."""

    name = "A+split"

    def __init__(self, *args, **kw) -> None:
        super().__init__(*args, **kw)
        self.last_split: dict[str, Any] | None = None

    def propose(self, source: Source, usage: Usage) -> dict[str, Any]:
        groups = split_source(source)
        if len(groups) <= 1:
            self.last_split = {"groups": 1, "sizes": [len(source.samples)]}
            return super().propose(source, usage)
        # The ECS candidates are the WHOLE source's: the subset is cached by
        # source id, so it is fixed here before any group could fix it from a
        # fraction of the keys.
        self.subset(source)
        parts = [super(SplitCombinedArchitecture, self).propose(g, usage) for g in groups]
        self._source = source  # repair and the subset speak about the whole source
        merged, self.last_split = merge_irs(parts, [len(g.samples) for g in groups])
        merged["source_id"] = source.source_id
        return merged

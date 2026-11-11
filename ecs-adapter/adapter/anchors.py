"""History anchors: the oracle a format drift brings with it.

THE PROBLEM
-----------
Deploying a parser without a person requires an oracle that holds without a
person. V4 is that oracle when a source has detection scenarios, but a drift
captured from the live queue has none: its scenarios would have to be attack
events written in a format that did not exist an hour ago. Without them the
ladder can accept a candidate that nobody verified, and `suricata_eve` on
2026-10-13 showed what that ships - an accepted parser with three wrong
fields, `http.http_user_agent` in `user.name` among them.

WHAT A DRIFT HAS THAT A NEW SOURCE DOES NOT
-------------------------------------------
A source that drifted was being parsed correctly until the moment it drifted.
Elasticsearch still holds what the old parser produced: which ECS field held
which value. A format change alters how a line is written, not who is on the
network - the same clients, accounts, hosts and paths appear on both sides of
the break. So the old parser's output is a set of observations of the form

    10.10.1.13 was source.ip        alice was user.name

and a candidate parser for the new format can be checked against them: if the
new lines carry 10.10.1.13, the new parser must put it in source.ip. That is
V3.5's question - "the value we know, which field is holding it?" - answered
with values harvested from history instead of injected by a probe.

It is also the right criterion for a drift specifically. The detection rules
in production were written against the fields the OLD parser populated. A new
parser that puts the request path in `url.path` where the old one used
`url.original` is defensible in the abstract and breaks every rule that reads
`url.original`. Continuity with the old parser is what keeps detection alive,
which is the objective.

WHICH VALUES ARE SAFE TO USE
----------------------------
An anchor must be unambiguous on both sides, or it would verify a wrong
mapping as readily as a right one:

    history     the value occurred in exactly ONE ECS field. An address that
                was both source.ip and destination.ip says nothing about which
                one a new key is.
    new lines   the value occurs as a whole token, and at most once per line.
                Twice on one line means two keys could hold it.
    shape       not a short number. "200" is a status code in one field and a
                byte count in another, and history has not seen every byte
                count. Numbers must be long enough to be specific.

Fields that are constants of the old pipeline (`event.*`, `ecs.version`,
`tags`, ...) are not observations of the line and are never anchored.

WHAT THIS IS NOT
----------------
It is not ground truth: it reads no `truth.json` and makes no judgement about
what a key means. Like `known_values.json` it records what was observed. And it
is blind to a field the new format introduced, which history has never seen -
such a field is reported as untested, never as verified.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable
import json
import re

# Fields the old pipeline sets as constants, or that describe the pipeline
# rather than the line. Anchoring them would "verify" a value no line carries.
NOT_OBSERVATIONS = (
    "@timestamp", "@version", "event.", "ecs.", "tags", "message",
    "log.original", "event.original", "agent.", "data_stream.", "input.",
    "_raw", "labels.",
)

MIN_TEXT_LEN = 3
# Three digits: an HTTP status code is the field a 401-burst rule reads, and at
# five it could never be anchored, so it was never verified and never shipped.
# Coincidence is what the unambiguity checks below are for - one historical
# field, one occurrence per line - not the length.
MIN_NUMBER_LEN = 3
DEFAULT_MAX_PER_FIELD = 12


def _flatten(doc: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in doc.items():
        path = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, f"{path}."))
        else:
            out[path] = v
    return out


def _is_observation(field_name: str) -> bool:
    return not any(
        field_name == p or (p.endswith(".") and field_name.startswith(p))
        for p in NOT_OBSERVATIONS
    )


def _scalars(value: Any) -> Iterable[str]:
    if isinstance(value, list):
        for v in value:
            yield from _scalars(v)
    elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
        yield str(value)


def _specific(value: str) -> bool:
    """Long enough that seeing it in a line is evidence, not coincidence."""
    v = value.strip()
    if not v or "\n" in v:
        return False
    if re.fullmatch(r"-?\d+(\.\d+)?", v):
        return len(v.replace("-", "").replace(".", "")) >= MIN_NUMBER_LEN
    return len(v) >= MIN_TEXT_LEN


def _json_scalars(obj: Any) -> list[str]:
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _json_scalars(v)]
    if isinstance(obj, list):
        return [s for v in obj for s in _json_scalars(v)]
    return [] if obj is None or isinstance(obj, bool) else [str(obj)]


def _occurrences(value: str, line: str) -> int:
    """Whole-token occurrences: `10.0.0.1` must not count inside `10.0.0.12`.

    A JSON line is compared value by value. The text rule treats `:` as part of
    a token so that `20` is not found inside `08:01:20`, and in JSON every value
    follows a `:` - so `"status":200` never matched and a status code in a JSON
    log could not be anchored at all.
    """
    stripped = line.lstrip()
    if stripped.startswith("{"):
        try:
            return _json_scalars(json.loads(stripped)).count(value)
        except ValueError:
            pass
    rx = re.compile(r"(?<![\w.:/@-])" + re.escape(value) + r"(?![\w.:/@-])")
    return len(rx.findall(line))


def history_from_documents(
    documents: Iterable[dict[str, Any]],
) -> dict[str, Counter[str]]:
    """ECS field -> how often each value was seen there, over the old output."""
    hist: dict[str, Counter[str]] = defaultdict(Counter)
    for doc in documents:
        for name, value in _flatten(doc).items():
            if not _is_observation(name):
                continue
            for s in _scalars(value):
                if _specific(s):
                    hist[name][s] += 1
    return dict(hist)


def fill_rates(documents: list[dict[str, Any]]) -> dict[str, float]:
    """Fraction of the old documents in which each observed field was present.

    The shadow check compares the new parser against these, so a field the old
    parser filled on 90% of lines and the new one on 10% is caught.
    """
    if not documents:
        return {}
    present: Counter[str] = Counter()
    for doc in documents:
        for name, value in _flatten(doc).items():
            if _is_observation(name) and value not in (None, "", []):
                present[name] += 1
    return {k: v / len(documents) for k, v in present.items()}


@dataclass
class Anchors:
    """Values the old parser placed, that the new lines also carry."""

    values: dict[str, list[str]] = field(default_factory=dict)
    # Fields the old parser populated for which no new line carries a usable
    # value. Reported, never verified: absence of evidence is not evidence.
    unanchored: list[str] = field(default_factory=list)
    ambiguous_values: int = 0

    @property
    def fields(self) -> list[str]:
        return sorted(self.values)

    def known_values(self) -> dict[str, str]:
        """One value per field, in the shape V3.5 reads from known_values.json.

        The most widespread value is chosen, so the repair loop's attribution
        message names something the model can find in the samples it was shown.
        """
        return {f: vs[0] for f, vs in sorted(self.values.items()) if vs}

    def to_json(self) -> dict[str, Any]:
        return {
            "values": {k: list(v) for k, v in sorted(self.values.items())},
            "unanchored": sorted(self.unanchored),
            "ambiguous_values": self.ambiguous_values,
        }


def anchor(
    history: dict[str, Counter[str]],
    lines: list[str],
    max_per_field: int = DEFAULT_MAX_PER_FIELD,
) -> Anchors:
    """The history values that identify a field unambiguously in the new lines."""
    owners: dict[str, set[str]] = defaultdict(set)
    for name, counter in history.items():
        for value in counter:
            owners[value].add(name)

    out = Anchors()
    for name in sorted(history):
        picked: list[tuple[int, str]] = []
        for value, _seen in history[name].most_common():
            if len(owners[value]) != 1:
                out.ambiguous_values += 1
                continue
            counts = [_occurrences(value, ln) for ln in lines]
            carrying = sum(1 for c in counts if c)
            if not carrying:
                continue
            if any(c > 1 for c in counts):
                out.ambiguous_values += 1
                continue
            picked.append((carrying, value))
        if picked:
            picked.sort(key=lambda cv: (-cv[0], cv[1]))
            out.values[name] = [v for _, v in picked[:max_per_field]]
        else:
            out.unanchored.append(name)
    return out


def harvest(
    es,
    index: str,
    failure_tag: str,
    size: int = 500,
) -> list[dict[str, Any]]:
    """The old parser's most recent good output for this index.

    A document carrying the failure tag is the broken half of the drift and is
    excluded: it holds the raw line and no ECS field, so it would anchor
    nothing - and if a past adapted pipeline mis-parsed it, it would anchor
    the wrong thing.
    """
    resp = es.search(
        index=index,
        size=size,
        sort=[{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        query={"bool": {"must_not": [{"term": {"tags": failure_tag}}]}},
    )
    return [h.get("_source", {}) for h in resp.get("hits", {}).get("hits", [])]


# ------------------------------------------------- computed fields, by token
#
# WHY VALUE ANCHORS ARE NOT ENOUGH.
#
# `event.outcome` is the field a brute-force rule filters on, and its values -
# `success`, `failure` - appear in no log line: the old pipeline computed them,
# from `Accepted` and `Failed`. A value anchor cannot see such a field, and the
# loop used to skip every `event.*` field as a pipeline constant. So a repair
# could be declared complete with the field the detection depends on lost.
#
# History still holds the answer, because the old parser kept each line it
# parsed in `message`. For a field with few values, the words that occur in
# EVERY old line carrying one value and in NO old line carrying another are that
# value's markers: `Failed` for `failure`. A format change moves the framing of
# a line and rarely its vocabulary, so the same markers predict the field on the
# new lines - one expectation per line, checkable on the parsed document.

MAX_COMPUTED_VALUES = 8
_WORD_RE = re.compile(r"[A-Za-z][A-Za-z_-]{2,}")
# Fields that are part of every document and say nothing about the line.
_NEVER_COMPUTED = ("@timestamp", "@version", "tags", "message", "event.original",
                   "ecs.", "agent.", "data_stream.", "input.", "labels.", "_raw",
                   "log.file.", "log.offset")


def _words(text: str) -> set[str]:
    return set(_WORD_RE.findall(text or ""))


def detection_fields(documents: list[dict[str, Any]]) -> list[str]:
    """Every field of the old output a detection rule could depend on.

    Observations (values the line carries) plus COMPUTED fields - fields with
    more than one value across history, like `event.outcome`. A field with one
    value everywhere is a constant of the pipeline (`event.kind: event`) and is
    the generated pipeline's job to set, not a repair's to recover.
    """
    # A field counts when the LINE is where it comes from - its value is in the
    # message on most documents - or when it varies, which a pipeline constant
    # does not. That excludes what the shipper adds (filebeat's `host.name`,
    # `log.file.path`): it is not in the line, it never varies per event, and
    # no parser of the line could restore it.
    values: dict[str, set[str]] = defaultdict(set)
    in_line: Counter[str] = Counter()
    seen: Counter[str] = Counter()
    for doc in documents:
        msg = doc.get("message") if isinstance(doc.get("message"), str) else ""
        for name, v in _flatten(doc).items():
            if any(name == p or (p.endswith(".") and name.startswith(p)) for p in _NEVER_COMPUTED):
                continue
            vals = list(_scalars(v))
            if not vals:
                continue
            seen[name] += 1
            if msg and any(x in msg for x in vals):
                in_line[name] += 1
            for x in vals:
                values[name].add(x)
    return sorted(f for f, vs in values.items()
                  if in_line[f] / seen[f] >= 0.5 or len(vs) > 1)


@dataclass
class TokenRule:
    field: str
    markers: dict[str, list[str]]       # value -> words that identify it

    def expect(self, line: str) -> str | None:
        hits = {v for v, ws in self.markers.items() if _words(line) & set(ws)}
        return next(iter(hits)) if len(hits) == 1 else None


def token_rules(documents: list[dict[str, Any]]) -> list[TokenRule]:
    """Marker words for each low-cardinality field.

    Mostly computed fields (`event.outcome`, `log.level`), but an observation
    with few values (`http.request.method`) gets a rule too when its values are
    words; both checks then apply, and they must agree."""
    per: dict[str, dict[str, list[set[str]]]] = defaultdict(lambda: defaultdict(list))
    for doc in documents:
        msg = doc.get("message") or (doc.get("event") or {}).get("original")
        if not isinstance(msg, str):
            continue
        words = _words(msg)
        for name, v in _flatten(doc).items():
            if any(name == p or (p.endswith(".") and name.startswith(p)) for p in _NEVER_COMPUTED):
                continue
            vals = list(_scalars(v))
            if len(vals) == 1:
                per[name][vals[0]].append(words)
    rules: list[TokenRule] = []
    for name, by_value in sorted(per.items()):
        if not 2 <= len(by_value) <= MAX_COMPUTED_VALUES:
            continue
        markers: dict[str, list[str]] = {}
        for value, lines in by_value.items():
            common = set.intersection(*lines)
            others = set().union(*(w for v2, ls in by_value.items() if v2 != value for w in ls))
            only = sorted(common - others)
            if only:
                markers[value] = only[:4]
        if len(markers) == len(by_value):     # every value identifiable, or none trusted
            rules.append(TokenRule(name, markers))
    return rules


def expectations(rules: list[TokenRule], lines: list[str]) -> dict[str, dict[str, str]]:
    """{field: {line: expected value}} for the lines a rule decides."""
    out: dict[str, dict[str, str]] = {}
    for r in rules:
        exp = {ln: v for ln in lines if (v := r.expect(ln)) is not None}
        if exp:
            out[r.field] = exp
    return out

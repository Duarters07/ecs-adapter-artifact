"""Shared contracts.

Every module imports from here; nothing redefines these shapes. Keeping the
contracts in one place is what lets arms A, B, T and C be swapped at run time
without any other component knowing which one is active.

The arms are research comparisons, never deployment options. Exactly one
configuration is deployed: the two staged specialists, with escalation.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Protocol
import hashlib
import json
import re

# --------------------------------------------------------------------------- errors


class ModelError(RuntimeError):
    """The model could not be reached, or never produced parseable output.

    Defined here rather than in model_client so that the controller - and the
    escalation path inside it - can be imported and tested without an HTTP
    client installed. A load-bearing branch that only runs when a network
    library is present is a branch that never gets a unit test.
    """


# --------------------------------------------------------------------------- input


# ROUND 10 (A5): KEYS A LINE CARRIES BY ITS STRUCTURE, NOT BY A NAME.
#
# Retrieval saw only names: `k=v` keys, JSON keys and documented columns. A
# prose line names none of its parts, so its fields could be offered only if
# the source's category happened to cover them, and the category is one word
# for a source that often spans two: a proxy that logs HTTP requests
# (r6_tinyproxy, `network`), an FTP server that logs file transfers
# (r6_pureftpd, `authentication`), a syslog daemon whose header carries the
# host and the pid (r4_postfix, `email`). Three structures are recognised, each
# by its shape alone, and named with the words ECS uses for their parts:
#
#   an HTTP request line      GET /x HTTP/1.1          method, url, http_version
#   a syslog-style header     <ts> host prog[pid]:      hostname, pid
#   a file transfer           uploaded /a/b (7 bytes)   file_path, file_size
#
# They only steer which fields are OFFERED; the model still decides, and the
# ladder still judges. ECS_PIPELINE=round9 does not add them.
_HTTP_REQUEST = re.compile(r"\b(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) \S+ HTTP/\d(?:\.\d)?\b")
_SYSLOG_HEADER = re.compile(
    r"^(?:<\d{1,3}>\d? ?)?(?:[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d(?:\.\d+)?|\d{4}-\d\d-\d\d[T ]\S+)"
    r" (?P<host>[A-Za-z0-9][\w.-]*) [\w./-]+(?P<pid>\[\d+\])?:")
_PID = re.compile(r"(?:^|\s)[\w./-]*\[\d+\]:")
_FILE_TRANSFER = re.compile(r"\b(?:uploaded|downloaded|STOR|RETR|sent|received)\b.*?/[^\s/]+.*?\(\d+ bytes"
                            r"|/[^\s/]+(?:/[^\s/]*)*\s+(?:uploaded|downloaded)\b.*?\(\d+ bytes")


def _keys_from_structure(line: str) -> set[str]:
    """Key names for the parts of a line recognised by shape (see above)."""
    out: set[str] = set()
    if _HTTP_REQUEST.search(line):
        out |= {"method", "url", "http_version"}
    m = _SYSLOG_HEADER.match(line)
    if m:
        out.add("hostname")
        if m.group("pid"):
            out.add("pid")
    if _PID.search(line):
        out.add("pid")
    if _FILE_TRANSFER.search(line):
        out |= {"file_path", "file_size"}
    return out


@dataclass(frozen=True)
class Sample:
    """One representative raw event."""

    raw: str
    signature: str  # structural signature, see adapter/sampler.py

    @staticmethod
    def of(raw: str, signature: str) -> "Sample":
        return Sample(raw=raw.rstrip("\n"), signature=signature)


# ------------------------------------------------------------ extraction helpers

# THE PATTERNS A GROK EXTRACTION WILL RUN, IN THE ORDER IT RUNS THEM.
#
# The IR used to carry exactly one grok pattern, and a source whose lines are
# two different messages cannot be read by one pattern. Measured on stage F,
# 2026-10-13, arm C, sshd_auth: semantic accuracy 1.000, all four mappings
# correct, and the run died at V2 because
#
#     Accepted password for deploy from 172.18.0.23 port 48610 ssh2
#     Failed password for invalid user deploy from 172.18.0.23 port 39026 ssh2
#
# are two kinds of event, and the pattern matched 9 of 18 lines. Logstash has
# always accepted a list - `match => { "message" => [p1, p2] }`, first match
# wins - and every hand-written pipeline in stack/pipelines/ that reads syslog
# uses it. The language the model answers in simply had no word for it.
#
# `pattern` stays required and is tried first, so an IR written before
# `alternatives` existed means exactly what it meant then. Everything that asks
# "which patterns will run" asks this function, so the compiler, V2 and the
# deterministic layer cannot disagree about it.
# A raw named group, in either spelling: Python's (?P<name>...) or
# Oniguruma's (?<name>...). Not a lookbehind, (?<= or (?<!.
RAW_NAMED_GROUP = re.compile(r"\(\?P?<([A-Za-z_][A-Za-z0-9_]*)>")


def oniguruma_groups(pattern: str) -> str:
    """Python-spelled named groups rewritten in the spelling grok runs on.

    Grok IS Oniguruma, and Oniguruma names a group `(?<name>...)`; a model that
    writes regex in Python's `(?P<name>...)` has written a capture Logstash
    rejects. The gold-trained student did so on sshd_auth in two of three seeds
    (2026-10-17) and V2 reported "no named captures". Both spellings name the
    same group, so this is a spelling, not a repair, and it applies to every arm
    in every mode: a named group is a capture whichever way it is written.
    """
    return re.sub(r"\(\?P<([A-Za-z_][A-Za-z0-9_]*)>", r"(?<\1>", pattern)


def grok_patterns(extraction: dict[str, Any] | None) -> list[str]:
    """``[pattern] + alternatives`` for a grok extraction, empty strings dropped,
    named groups in grok's own spelling (oniguruma_groups)."""
    ex = extraction or {}
    out: list[str] = []
    first = ex.get("pattern")
    if isinstance(first, str) and first:
        out.append(oniguruma_groups(first))
    for alt in ex.get("alternatives") or []:
        if isinstance(alt, str) and alt:
            out.append(oniguruma_groups(alt))
    return out


def with_grok_patterns(extraction: dict[str, Any], patterns: list[str]) -> dict[str, Any]:
    """The extraction, carrying ``patterns`` - and nothing else changed.

    An extraction that never had `alternatives` does not acquire an empty one:
    the IR must stay byte for byte what it was when only `pattern` moved,
    because the training corpus and every recorded result were written in that
    shape.
    """
    out = {**extraction, "pattern": patterns[0] if patterns else ""}
    if len(patterns) > 1 or "alternatives" in extraction:
        out["alternatives"] = list(patterns[1:])
    return out


# A DOTTED KEY ON A JSON LINE NAMES A PATH, UNLESS THE LINE SAYS OTHERWISE.
#
# Suricata EVE writes `{"alert": {"signature": "..."}}`; the IR addresses it as
# `alert.signature`, which is how every vendor document and every model writes
# it. Some JSON logs - ECS-flavoured application loggers among them - write the
# dotted name as a literal top-level key instead: `{"user.name": "alice"}`.
#
# The rule, applied identically here, in V2 and in the compiled parser: a
# literal top-level key wins when the line carries one; otherwise the dotted
# key is walked as a path into nested objects.
def json_lookup(obj: Any, key: str) -> Any:
    """The value ``key`` addresses in a parsed JSON line, or None."""
    if not isinstance(obj, dict):
        return None
    if key in obj:
        return obj[key]
    if "." not in key:
        return None
    cur: Any = obj
    for part in key.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def json_paths(obj: Any, prefix: str = "", depth: int = 0) -> set[str]:
    """Every key of a JSON object as a DOTTED PATH: top-level keys unchanged.

    Kept apart from ``_json_keys`` on purpose. That function feeds retrieval,
    is folded into ``ecs_index.retrieval_digest`` and matches leaf names
    against ECS leaves; changing it would move which ECS fields are offered for
    every JSON source in the corpus. This one answers a different question -
    "which keys can a mapping address on this line" - and is used only by the
    rungs that judge a mapping.
    """
    if depth > 4 or not isinstance(obj, dict):
        return set()
    out: set[str] = set()
    for k, v in obj.items():
        path = f"{prefix}{k}"
        out.add(path)
        if isinstance(v, dict):
            out |= json_paths(v, f"{path}.", depth + 1)
    return out


# ------------------------------------------------------------------ key harvest

# A key=value token may be separated from the next by whitespace or by any of
# these. Splitting on whitespace alone is what made `a=1|b=2` look like one key.
_KV_DELIMITERS = re.compile(r"[\s|;,]+")

# Backticked identifiers in documentation: "- `src_ip` - remote ip".
_DOC_BACKTICK = re.compile(r"`([A-Za-z_][A-Za-z0-9_.\-]*)`")

# "Columns, in order: src_ip, url, m, http_status" - the only place a
# positional format states its field names.
_DOC_COLUMNS = re.compile(r"columns[^:\n]*:\s*(.+)", re.IGNORECASE)

# A field-definition bullet: "- `sent` - bytes". The DESCRIPTION is harvested
# as well as the key, because it is the only place the meaning of an opaque
# key is written down. `verb`, `sent` and `ref` have no lexical relationship
# to `http.request.method`, `http.response.body.bytes` or
# `http.request.referrer`; their descriptions do. Vendor documentation is
# where a human reads this too.
#
# It is a hint, not an answer: these are human field names, never ECS field
# names, and nothing downstream treats them as a mapping.
_DOC_BULLET = re.compile(
    r"^\s*[-*+]\s*`([A-Za-z_][A-Za-z0-9_.\-]*)`\s*[-\u2013\u2014:]\s*(.+)$",
    re.MULTILINE,
)
_WORD = re.compile(r"[A-Za-z][A-Za-z0-9]+")

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_.\-]*\Z")


def _json_keys(obj: Any, depth: int = 0) -> set[str]:
    """Every key in a JSON document, nested included, depth-capped."""
    if depth > 4:
        return set()
    out: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.add(str(k))
            out |= _json_keys(v, depth + 1)
    elif isinstance(obj, list):
        for v in obj[:10]:
            out |= _json_keys(v, depth + 1)
    return out


def _keys_from_line(raw: str) -> set[str]:
    line = raw.strip()
    if line.startswith("{"):
        try:
            return _json_keys(json.loads(line))
        except (json.JSONDecodeError, ValueError):
            pass  # not JSON after all; fall through to the k=v pass
    keys: set[str] = set()
    for tok in _KV_DELIMITERS.split(line):
        if "=" in tok:
            k = tok.split("=", 1)[0].strip("\"' \t")
            if k and _IDENT.match(k):
                keys.add(k)
    return keys


# Words that documentation uses about EVERY field and that therefore
# discriminate between none of them.
_DOC_STOPWORDS = frozenset({
    "the", "a", "an", "of", "for", "from", "with", "and", "or", "in", "on",
    "this", "that", "its", "it", "is", "are", "was", "were", "be", "been",
    "field", "fields", "value", "values", "name", "names", "id", "identifier",
    "type", "types", "string", "number", "code", "codes", "data", "log",
    "logs", "event", "events", "message", "messages", "source", "target",
    "ambiguous", "optional", "required", "see", "above", "below", "example",
})


def _keys_from_documentation(doc: str) -> set[str]:
    """Only the KEYS the documentation names, never the words describing them.

    A backtick is not by itself evidence of a key. The same document that
    defines its fields as bullets also writes prose - "Layout: `kv_comma`",
    "recovered from `windows-security.conf`" - and a greedy pass over every
    backtick harvested those two as keys. `windows-security.conf` alone put
    `windows`, `security` and `conf` into the retrieval vocabulary of a source
    that has none of them.

    So when a document states its fields structurally, in bullets or in a
    column listing, that statement is taken as complete and the prose is left
    alone. A document with neither still falls back to every backtick, because
    for those the alternative is no keys at all.
    """
    if not doc:
        return set()
    keys = {k for k, _desc in _DOC_BULLET.findall(doc)}
    for listing in _DOC_COLUMNS.findall(doc):
        for part in listing.split(","):
            part = part.strip().strip("`").strip()
            if part and _IDENT.match(part):
                keys.add(part)
    if not keys:
        keys = set(_DOC_BACKTICK.findall(doc))
    return keys


def _hints_from_documentation(doc: str) -> set[str]:
    """Words a field's DESCRIPTION uses, which are a hint and not a key.

    WHY THESE ARE HELD APART, AND WHAT HAPPENED WHEN THEY WERE NOT.

    A key named `dev` says nothing; its description, "IpAddress", says a great
    deal, and vendor documentation is where a human reads this too. Harvesting
    those words is deliberate and it works.

    They were added to the same set as the keys, and retrieval treats an
    observed key as the strongest signal it has: a field whose last segment
    matches one is promoted to the top tier ahead of everything else. So a
    source documented as

        - `node`     - computer name
        - `username` - name

    contributed the token `name`, and every ECS field ending in `.name` was
    promoted - 148 of the 240 candidates offered for one source, against 15 for
    a source whose descriptions happened to be more specific. `user.name` was
    among them, beside `destination.user.name`, `client.user.name` and nineteen
    more, all promoted for the same reason and all equally plausible to anyone
    reading the list.

    The model was not choosing badly between good options. It was choosing among
    options this function had made indistinguishable, and the resulting failures
    were recorded against the teacher.

    Stopwords go further: `name`, `identifier`, `type` and `code` appear in the
    description of almost every field in every schema, so they separate nothing
    even as a weak hint.
    """
    if not doc:
        return set()
    hints: set[str] = set()
    for _key, description in _DOC_BULLET.findall(doc):
        hints |= set(_WORD.findall(description.lower()))
    return {h for h in hints if h not in _DOC_STOPWORDS and len(h) >= 3}


def KEY_HARVEST_SOURCE() -> str:
    """The key-harvest functions, as text, for `ecs_index.retrieval_digest`.

    What a source is understood to contain is decided half here and half in
    the index. A digest over the index alone would have missed the day the
    documentation harvest stopped treating description words as keys.
    """
    import inspect

    return "".join(
        inspect.getsource(f)
        for f in (
            _json_keys, _keys_from_line,
            _keys_from_documentation, _hints_from_documentation,
        )
    ) + repr(sorted(_DOC_STOPWORDS))


@dataclass(frozen=True)
class Source:
    """An unfamiliar log source awaiting a parser."""

    source_id: str
    samples: tuple[Sample, ...]
    documentation: str = ""  # may legitimately be empty
    category_hint: str | None = None  # "web" | "authentication" | "network" | ...
    # THE PROBE LINE, AND WHY IT IS NOT A SAMPLE.
    #
    # It carries the values recorded in known_values.json, and V3.5 asks which
    # ECS field each of them ended up in. So it must reach the PARSER - and it
    # must not reach the MODEL, whose job is to read a source as it really is.
    # Marker values like `probe-endpoint` and `probe-agent` announce themselves;
    # showing them to the model would be handing it a labelled example.
    #
    # It was neither, which is the defect this field fixes. The probe is the
    # last line of samples.ndjson, and deduplicate() caps the sample set at 20
    # of 41 lines, so it was dropped before the sandbox ever saw it. V3.5 then
    # looked for a value that had never been offered to the parser and reported
    # it missing - for every source, in every run.
    probe_lines: tuple[str, ...] = ()
    # THE FIELDS THE PREVIOUS PARSER PRODUCED, WHEN THIS SOURCE IS A DRIFT.
    #
    # A format change alters how a line is written, not what it describes, and
    # the detection rules in production read the fields the old parser filled.
    # Offering them to the mapping stage turns "choose from ~300 fields" into
    # "these are the fields this source has always had" - the information an
    # engineer repairing the parser by hand would start from. Field NAMES only:
    # stage 2 never sees a value, and stage 1 never sees ECS vocabulary
    # (tests/test_blindness.py). Empty for every benchmark source, so the arms'
    # prompts render exactly as before.
    previous_fields: tuple[str, ...] = ()

    def parser_input(self) -> tuple[str, ...]:
        """Every line the sandbox should feed the candidate parser.

        The samples the model reasoned about, plus the probe it never saw.
        """
        return tuple(s.raw for s in self.samples) + self.probe_lines

    def sample_text(self, limit: int = 12) -> str:
        return "\n".join(s.raw for s in self.samples[:limit])

    def observed_keys(self) -> list[str]:
        """Best-effort key extraction, used only to steer ECS field retrieval.

        This is deliberately crude: it informs which ECS fields are offered to
        the model, never what the mapping should be. Over-extraction costs a
        little budget; under-extraction makes a correct answer unreachable,
        which is measured as subset recall and is the worse error by far.

        Three sources of keys, because a log format carries them in three
        different places:

            k=v pairs   split on any of space, tab, ``|``, ``,`` or ``;``.
                        The first version split on whitespace only, so
                        ``a=1|b=2`` yielded the single key ``a`` and a
                        pipe-delimited source arrived at retrieval almost
                        blind.
            JSON        the object's own keys, nested included. A JSON line
                        has no ``=`` at all and used to yield nothing.
            documentation
                        a positional format (CSV) has no keys in the line by
                        definition; the column list is the only place they
                        exist. Ignoring it left every CSV source with zero
                        observed keys.

        The documentation is already an input to this system - Stage 1 reads
        it - so harvesting names from it introduces no information the
        pipeline did not already have. Only the KEYS it names, though: the
        words describing them are returned by :meth:`documentation_hints` and
        are weighted far lower. :func:`_hints_from_documentation` records what
        happened when the two were merged.
        """
        keys: set[str] = set()
        for s in self.samples:
            keys |= _keys_from_line(s.raw)
            if not round9_pipeline():
                keys |= _keys_from_structure(s.raw)
        keys |= _keys_from_documentation(self.documentation)
        return sorted(k for k in keys if k)

    def documentation_hints(self) -> list[str]:
        """Description words, a weak signal, deliberately kept out of the keys.

        Returned separately so retrieval can weight them separately. They are
        never observed keys: nothing in the log line contains them.
        """
        return sorted(_hints_from_documentation(self.documentation))


# --------------------------------------------------------------------------- usage


@dataclass
class Usage:
    """Accumulated across every model call in one run."""

    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    parse_failures: int = 0

    def add(self, prompt_tokens: int, completion_tokens: int) -> None:
        self.calls += 1
        self.prompt_tokens += prompt_tokens
        self.completion_tokens += completion_tokens


# --------------------------------------------------------------------- validation

STAGE_INTERPRET = "interpret"
STAGE_MAP = "map"
STAGE_UNKNOWN = "unknown"


def round9_pipeline() -> bool:
    """`ECS_PIPELINE=round9` runs the pipeline as round 9 ran it (PLAN_ROUND10_ARM_C.md).

    Every round-10 change to the shared pipeline is switched off under it, so the
    round-9 results and org9's corpus builders can be reproduced exactly.
    """
    import os

    return os.environ.get("ECS_PIPELINE", "").strip() == "round9"


@dataclass(frozen=True)
class Finding:
    """One validation failure, attributed to a stage where possible."""

    rung: str  # "V1" | "V2" | "V3" | "V4"
    code: str  # machine-readable, e.g. "unknown_ecs_field"
    message: str  # fed back to the model verbatim
    stage: str = STAGE_UNKNOWN
    source_key: str | None = None


@dataclass
class ValidationReport:
    rung_reached: str = "none"
    passed: bool = False
    findings: list[Finding] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)

    @property
    def is_abstention(self) -> bool:
        """The run stopped because the model declined, not because it was wrong."""
        return bool(self.metrics.get("abstained", False))

    def blames_interpretation(self) -> bool:
        """Route repair feedback. Used by architectures B and C.

        ROUND 10 (A1): BY CAUSE, NOT BY VOTE. Stage 1 owns the extraction and
        stage 2 cannot change it (architectures._carry_extraction), so a single
        extraction fault is enough to send the repair to stage 1: with the
        extraction wrong, no field stage 2 maps can reach a document. Round 9
        took a majority, and the validators after V2 tagged every finding as
        stage 2's, so an extraction fault found at V3 or later was never shown
        to the one stage that could fix it (15 of org9's 20 failed runs ended
        there). `ECS_PIPELINE=round9` keeps the majority.
        """
        if not self.findings:
            return False
        interp = sum(f.stage == STAGE_INTERPRET for f in self.findings)
        if round9_pipeline():
            return interp > len(self.findings) / 2
        return interp > 0

    def feedback_for(self, stage: str, limit: int = 8) -> str:
        """`feedback`, restricted to one stage's findings."""
        part = ValidationReport(findings=[f for f in self.findings if f.stage == stage])
        return part.feedback(limit)

    def feedback(self, limit: int = 8) -> str:
        return "\n".join(
            f"- [{f.rung}/{f.code}]"
            f"{' field=' + f.source_key if f.source_key else ''}: {f.message}"
            for f in self.findings[:limit]
        )


# --------------------------------------------------------------------------- run


@dataclass
class RunRecord:
    """Exactly one of these per run. This is the experimental unit."""

    run_id: str
    architecture: str
    model: str
    model_digest: str
    backend: str
    hardware_tier: int
    source_id: str
    split: str
    seed: int
    ecs_version: str
    repair_budget: int
    prompt_digest: str

    outcome: str = "failed"  # accepted | abstained | failed
    rung_reached: str = "none"
    repairs: int = 0
    usage: Usage = field(default_factory=Usage)

    # Escalation: the teacher is loaded for ONE case, then unloaded. The rate is a
    # reported metric - it decides whether the minimal deployment tier is viable,
    # so it has to survive into the run record rather than being logged.
    escalated: bool = False
    escalation_seconds: float = 0.0
    escalation_model: str | None = None

    # Best-of-k: how many independent candidates were drawn, and which one this
    # record reports (0-based). 1 and 0 for every run before 2026-10-14.
    samples: int = 1
    sample_chosen: int = 0
    sample_outcomes: list[str] = field(default_factory=list)
    # PLAN_R2.md's two evaluation modes. "model-only": one call, no repair,
    # k=1, NO deterministic normalisation - the model's own output. "full-
    # system": the deployed loop. Every record before 2026-10-15 is the second.
    mode: str = "full-system"

    wall_seconds: float = 0.0
    # peak_rss_mb is THIS process's high-water mark, which is the cost of the
    # orchestration. peak_vram_mb and footprint describe what the MODEL SERVER
    # holds, which is what the tier claim in the paper is about. See
    # adapter/footprint.py for why the two are not interchangeable.
    peak_rss_mb: float = 0.0
    peak_vram_mb: float = 0.0
    server_footprint: dict[str, Any] | None = None

    ecs_subset_size: int = 0
    ecs_subset_recall: float | None = None

    scores: dict[str, Any] = field(default_factory=dict)
    detection: dict[str, Any] = field(default_factory=dict)
    # Which ECS fields detection replay confirmed INDIVIDUALLY, as opposed to
    # whether the proposal survived as a whole. Computed before `results` is
    # dropped from `detection`, because that is where the per-target counts
    # live and dropping them first is how this was invisible until now.
    verified_ecs_fields: list[str] = field(default_factory=list)
    stage_attribution: dict[str, int] = field(default_factory=dict)
    # What the deterministic layer changed before the ladder saw the IR. Kept
    # per run so the paper can report how much of the accepted set this layer
    # is responsible for, instead of crediting it to the model.
    normalisations: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    ir: dict[str, Any] | None = None

    # Stage 1 output, kept verbatim. Without it a Stage 2 error cannot be told
    # apart from a Stage 1 error after the fact, and the attribution claim in the
    # paper would be unfalsifiable. None for the single-call arm A.
    roles: dict[str, Any] | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, default=str)


# ----------------------------------------------------------------- architectures


class Architecture(Protocol):
    """The arms differ ONLY in how model calls are structured.

    Identical validation, budget and documentation access are enforced by the
    controller, not by convention. If the arms differed in code, a difference in
    results could not be attributed to the variable under study.

    ``last_roles`` is the Stage 1 output for a staged arm and None for arm A.
    The controller reads it through getattr, so a single-stage arm need not
    define it.
    """

    name: str

    def propose(self, source: Source, usage: Usage) -> dict[str, Any]: ...

    def repair(
        self, ir: dict[str, Any], report: ValidationReport, usage: Usage
    ) -> dict[str, Any]: ...


def digest(obj: Any) -> str:
    """Stable digest for prompts and configs, so a run record identifies its apparatus."""
    payload = obj if isinstance(obj, str) else json.dumps(obj, sort_keys=True)
    return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()[:16]

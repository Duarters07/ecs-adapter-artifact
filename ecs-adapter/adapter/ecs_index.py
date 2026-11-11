"""Load ECS and select a per-source field subset that fits a token budget.

ECS 8.11 defines roughly 1400 fields. A flat dump costs ~40 000 tokens, will not
fit a 7B model's useful context, and measurably degrades selection quality even
when it does fit. This module picks the ~180 fields the model is actually
offered, and measures whether the correct answer was among them.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import functools

import yaml

# Field sets worth offering per source category. Conservative: over-inclusion
# costs tokens, under-inclusion makes a correct answer impossible - which is
# measured as subset recall, not silently absorbed.
CATEGORY_FIELDSETS: dict[str, set[str]] = {
    "web": {
        "source", "destination", "http", "url", "user_agent",
        "user", "client", "server", "network", "rule",
    },
    "authentication": {
        "source", "destination", "user", "process", "host", "related", "client",
        "rule",
        # sshd and fail2ban both carry a level and a logger name.
        "log",
    },
    "network": {
        # `dns` belongs here because ECS has no dns category: a resolver log is
        # event.category "network" carrying dns.*. Without it the CoreDNS family
        # was labelled network and then offered a subset with no dns root, so
        # every dns.question.* answer was unreachable and the model would have
        # been recorded as failing a field it was never shown.
        "source", "destination", "network", "client", "server", "observer",
        "related", "dns",
        # An IDS is event.category `network` and its substance is a rule name
        # and a severity. `rule` is already reachable from `firewall` and
        # `web`; `network` was the odd one out.
        "rule", "log",
    },
    "firewall": {"source", "destination", "network", "observer", "rule", "related"},
    "endpoint": {"process", "file", "host", "user", "registry", "hash", "related"},
    # `file` is an allowed event.category in ECS 8.11 and was missing here, in
    # exactly the way `email` and `database` were. A file-server log declaring
    # itself `file` fell through to an empty root set, so file.*, process.* and
    # user.domain were never offered: subset recall on the three filesvc
    # families was 0.71, and any model scored on them would have been penalised
    # for a retrieval failure it could not see. Caught by
    # test_subset_recall_is_perfect_for_every_benchmark_source on 2026-10-10.
    #
    # The roots are those a network file service really writes: the file, the
    # daemon that served it, the account, and the two ends of the connection.
    "file": {
        "file", "user", "host", "source", "destination",
        "network", "observer", "related",
    },
    # Both of the following are allowed `event.category` values in ECS 8.11, so
    # naming them here follows the schema rather than extending it. They were
    # missing, and the held-out set is what found them: Postfix was labelled
    # `network`, which cannot reach email.*, and PostgreSQL was labelled
    # `authentication`, which says nothing about a database. In both cases the
    # correct answer was unreachable and the model would have been scored for
    # a retrieval failure.
    "email": {
        # `process` because a mail log is written BY a daemon and names it: every
        # Postfix line carries the program and its pid.
        "source", "destination", "email", "user", "network", "related", "observer",
        "process",
    },
    # ECS 8.11 has no database FIELDSET, only the category. A database log is
    # therefore mostly unmappable, which is a fact about ECS and is exactly what
    # the postgres_csv source is in the corpus to measure. The roots offered are
    # the ones such a log really does carry.
    "database": {
        "user", "process", "source", "destination", "client", "server",
        "host", "related",
        # A database log reports errors and carries a severity. Added
        # 2026-10-11 with the `appsvc` family, which exists because no
        # recovered family emitted either and postgres_csv needs both.
        "error", "log",
    },
}

# The candidate budget, defined ONCE. It used to be the literal 180 repeated in
# eight places - two architectures, escalation, the index, the regression
# fallback and four argparse defaults - while "every arm is offered
# byte-identical fields" was a stated invariant of the experiment. One edit in
# one of those places would have broken the comparison without failing
# anything.
#
# The value is measured, not chosen, and it has been measured twice.
#
#   17 sources, 3 families   recall 1.00 at 200, below it at 180  ->  240
#   42 sources, 8 families   recall 1.00 at 300, below it at 280  ->  320
#
# The requirement rose because the corpus did. Squid and CoreDNS brought keys
# that retrieve weakly on their own - `rc`, `sent`, `ctype`, `subject_id` - and
# ten keys competing for one budget push the category baseline out of it, so at
# 240 the answer for three of Squid's fields was never offered and the model
# would have been recorded as failing a field it could not see.
#
# The margin is deliberate and the reason has not changed: the held-out
# families that decide the experiment are not in the corpus this was measured
# on. The sweep is re-run by tests/test_retrieval.py, which fails the build
# rather than letting recall drop quietly, and it runs with embeddings OFF, so
# 320 is a floor and not a best case.
#
# Cost: ~8.3k tokens of field list, against ~6.2k at 240.
DEFAULT_MAX_FIELDS = 320

# The share of the budget any single ECS root may take before its tail is
# deferred. Measured over all 1042 required fields on 2026-10-11:
#
#   no cap  0.9923    40%  1.0000    30%  1.0000    25%  0.9904    20%  0.9846
#
# Both 30% and 40% reach perfect recall, so the value is the middle of that
# plateau rather than its edge: a threshold sitting on the boundary is one
# corpus change away from being wrong. Below 30% the cap starves roots that
# legitimately need many fields - `http.*` on a web log - and recall falls
# again.
DEFAULT_ROOT_CAP: float | None = 0.35

# Offered whatever the category, because they describe the RECORD rather than
# what the record is about. `log` was missing: a logger name and a severity can
# appear on a line from any source, and three held-out families carry one
# (fail2ban, PostgreSQL, Traefik). Without it `log.level` was unreachable from
# every category, so the correct answer was never offered.
# WHY @timestamp IS NOT HERE.
#
# It is a valid ECS field, it is the field every time-windowed detection rule
# depends on, and the hand-written pipelines in stack/ all set it. It is absent
# from this set deliberately.
#
# The IR expresses a timestamp through its own top-level `timestamp` construct,
# which the compiler turns into a Logstash `date` filter. It cannot be expressed
# as a rename, because renaming a string into @timestamp is how you break the
# event rather than how you set it. Offering the field among the candidates
# while the only construct that can legally use it is undocumented in the
# prompts produced exactly one outcome, measured on the frozen gate of
# 2026-10-04: three of ten sources died at V1 with
#
#     '@timestamp' does not match '^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)*$'
#
# one of them (demo_auth) with every mappable field correct. The repair loop
# burned its whole budget against a JSON-Schema regex that does not name the
# fix.
#
# So timestamp extraction is out of scope for semantic field mapping and is
# left to Logstash's `date` filter, which has solved it for twenty years. This
# is a stated limitation of the contribution, not an oversight: a deployed
# adapter needs it, and this version does not cover it.
#
# Nothing measured depends on the choice - 0 of 50 ground truths and 0 of 240
# teacher proposals ever used the field.
# Round 10 (A5): the roots a structure recognised in the line brings in (see relevant_subset).
STRUCTURE_ROOTS = {"http_version": {"http", "url"}, "file_path": {"file"}, "file_size": {"file"}}

ALWAYS = {"event", "message", "tags", "labels", "ecs", "log"}

# Removing @timestamp from ALWAYS is not enough and the first attempt to do it
# measured 34 of 50 sources still offering the field: it is a real, relevant ECS
# field, so category expansion and the embedding stage both put it back. A field
# the IR cannot legally express has to be excluded explicitly, at the end, or it
# returns by another route.
OUT_OF_SCOPE = frozenset({"@timestamp"})

# Offered for EVERY category, whatever the source looks like. These three are
# the distinction this project exists to get right - who initiated, who
# received, who reported - and they are confusable precisely because they are
# all "an address". A subset that omits one of them cannot express the error,
# which means the benchmark could not detect it either. Endpoint telemetry in
# particular looks like it has no network fields until it logs a connection.
CONFUSABLE = {"source", "destination", "observer"}

# ECS FIELDS THAT ARE TWO NAMES FOR THE SAME ANSWER.
#
# Not a convenience, and not derived from what any model answered. ECS itself
# carries the same information under two names in a few places, and a parser
# that picks either one has understood the log. Scoring them as errors measures
# which CONVENTION the corpus happened to adopt, not whether the mapping is
# right, and it does so loudly: measured over 240 proposals from a 32B teacher,
# the fields with a synonym scored 3 to 10 per cent while the fields without one
# scored 100 per cent. Caddy's method, status and version were 30/30; its
# source.ip and url.original were 20/30 and 2/30.
#
# THE JUSTIFICATION IS THE SCHEMA'S OWN TEXT, quoted below, decided before
# looking at which families it rescues. Every set here is a pair of VIEWS on one
# entity, never two entities.
#
# WHAT IS DELIBERATELY ABSENT, and why it has to stay absent:
#
#   source.ip / destination.ip      two ENDS of a connection. The confusion this
#                                   project exists to catch. Never equivalent.
#   url.original / url.path         "Path of the request, such as /search"
#                                   discards the scheme and the host. Different.
#   url.domain / http.request.referrer   what was asked for, versus where the
#                                   request came from. Different.
#   host.name / destination.address the machine the event happened on, versus
#                                   the machine it was sent to. Different.
#   http.response.body.bytes /
#     http.response.bytes           "Size in bytes of the response body" versus
#                                   "Total size ... (body and headers)". Two
#                                   different quantities. A log that says only
#                                   `bytes` does not settle it, and that is a
#                                   defect in the SOURCE, fixed by naming the
#                                   key, not by widening the oracle.
#
# Used by bench/score.py, which reports strict and equivalence-aware side by
# side, and by the scenario builders, which emit a `should` over the set.
ECS_EQUIVALENTS: list[frozenset[str]] = [
    # "IP address of the source" / "IP address of the client". ECS keeps a
    # network view (source, destination) and a role view (client, server) of the
    # same two endpoints, and for a client-initiated event they are the same
    # host. The IR can write one field per key, so a parser must choose a view;
    # choosing either is not an error.
    frozenset({"source.ip", "client.ip"}),
    frozenset({"source.port", "client.port"}),
    frozenset({"source.address", "client.address"}),
    frozenset({"source.domain", "client.domain"}),
    frozenset({"source.bytes", "client.bytes"}),
    frozenset({"destination.ip", "server.ip"}),
    frozenset({"destination.port", "server.port"}),
    frozenset({"destination.address", "server.address"}),
    frozenset({"destination.domain", "server.domain"}),
    frozenset({"destination.bytes", "server.bytes"}),
    # user.name and source.user.name carry the SAME SENTENCE in ECS: "Short
    # name or login of the user." The root set describes the user involved in
    # the event; the source set describes the user on the originating side, and
    # for an authentication event they are one person.
    frozenset({"user.name", "source.user.name", "client.user.name"}),
    frozenset({"user.domain", "source.user.domain", "client.user.domain"}),
    frozenset({"user.id", "source.user.id", "client.user.id"}),
    # url.original is "the URL as it was observed, complete or not". url.full is
    # for full URLs "whether this field is reconstructed OR PRESENT IN THE EVENT
    # SOURCE". When the log carries an absolute URL both sentences describe it.
    frozenset({"url.original", "url.full"}),
]

# ecs field -> the whole set it belongs to, including itself.
EQUIVALENT_TO: dict[str, frozenset[str]] = {
    name: group for group in ECS_EQUIVALENTS for name in group
}


def equivalents(ecs_field: str) -> list[str]:
    """Every ECS field that is the same answer as this one, excluding itself."""
    return sorted(EQUIVALENT_TO.get(ecs_field, frozenset()) - {ecs_field})


# Subtrees that ELABORATE a field rather than carry one. `source.geo.*` is
# derived from `source.ip` by an enrichment processor; no raw log key maps to
# it. ECS spends a lot of its 1659 fields on these - `geo` alone is 12 per
# entity - so leaving them at full priority lets them crowd out the fields a
# parser actually assigns. They stay reachable through the embedding stage, and
# a source that genuinely needs one will surface it there.
# Key FRAGMENTS that every schema uses and that therefore separate nothing.
# They are stripped from the decomposed parts only, never from the whole key: a
# source whose key is literally `name` still reaches `*.name` at the top tier,
# because that is a real statement about the log. What is not a real statement
# is that `uid_name` is about `destination.geo.name`, `client.user.name`,
# `process.parent.name` and nineteen others equally - which is what happened
# when the fragment `name` was allowed to promote on its own.
GENERIC_KEY_PARTS = {
    "name", "id", "ident", "identifier", "type", "num", "no", "val",
    "value", "data", "info", "str", "text", "field", "key", "entry",
}

# Process ANCESTRY and identity variants: `process.entry_leader.*`,
# `process.group_leader.real_user.id` and the like. ECS describes a process's
# lineage in depth, and a log line never carries it - no training answer and
# no held-out truth names one. Offered anyway, they took the candidate list:
# the gold-trained student mapped auditd's `comm` to `process.group_leader.pid`
# and `exe` to `process.entry_leader.real_user.id` (2026-10-17). Never offered,
# to any arm. `process.parent.*` stays: a parent pid IS in many logs.
LINEAGE_SEGMENTS = {
    "entry_leader", "group_leader", "session_leader", "previous", "entry_meta",
    "real_user", "saved_user", "real_group", "saved_group", "attested_user",
    "attested_groups", "supplemental_groups",
}

ELABORATION_SEGMENTS = {
    "geo", "as", "nat", "registered_domain", "subdomain", "top_level_domain",
    "hash", "pe", "elf", "code_signature", "x509",
}


# ECS type -> the IR's type vocabulary (schema/ir.schema.json).
IR_TYPE = {"keyword": "keyword", "constant_keyword": "keyword", "wildcard": "keyword",
           "match_only_text": "text", "text": "text", "ip": "ip", "long": "long",
           "integer": "long", "short": "long", "byte": "long", "unsigned_long": "long",
           "float": "float", "double": "float", "scaled_float": "float",
           "half_float": "float", "boolean": "boolean", "date": "date",
           "flattened": "keyword", "object": "keyword", "nested": "keyword", "geo_point": "keyword"}


@dataclass(frozen=True)
class EcsField:
    name: str
    type: str
    level: str  # "core" | "extended" | "custom"
    description: str

    def as_prompt_line(self) -> str:
        desc = self.description.strip().replace("\n", " ")
        if len(desc) > 140:
            desc = desc[:137] + "..."
        return f"{self.name} ({self.type}): {desc}"


class EcsIndex:
    def __init__(self, path: Path, version: str) -> None:
        self.version = version
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        self.fields: dict[str, EcsField] = {
            name: EcsField(
                name=name,
                type=str(spec.get("type", "keyword")),
                level=str(spec.get("level", "extended")),
                description=str(spec.get("description", "")),
            )
            for name, spec in raw.items()
        }
        self._embeddings = None
        self._embedded_names: list[str] = []

    # ---------------------------------------------------------------- basics
    def exists(self, name: str) -> bool:
        return name in self.fields

    def type_of(self, name: str) -> str | None:
        f = self.fields.get(name)
        return f.type if f else None

    def ir_type(self, name: str) -> str | None:
        """The IR type of an ECS field, which follows from the field and nothing else.

        Since 2026-10-17 the model is not asked for it. `process.pid` is long
        because ECS says so; a model that wrote keyword was not expressing a
        view about the source, it was failing a lookup, and in model-only mode
        that lookup error stopped 9 of 24 gold-trained runs at V1 before any
        line was read. The compiler and V1 derive it here, for every arm.
        """
        if name not in self.fields:
            return None
        return IR_TYPE.get(self.type_of(name) or "keyword", "keyword")

    def all_names(self) -> set[str]:
        return set(self.fields)

    # ------------------------------------------------------------- selection
    @functools.cached_property
    def _model(self):
        from sentence_transformers import SentenceTransformer

        return SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

    def _ensure_embeddings(self) -> None:
        if self._embeddings is not None:
            return
        self._embedded_names = sorted(self.fields)
        corpus = [self.fields[n].as_prompt_line() for n in self._embedded_names]
        self._embeddings = self._model.encode(
            corpus, normalize_embeddings=True, batch_size=128, show_progress_bar=False
        )

    def relevant_subset(
        self,
        observed_keys: list[str],
        documentation: str,
        category_hint: str | None,
        max_fields: int = DEFAULT_MAX_FIELDS,
        use_embeddings: bool = True,
        doc_hints: list[str] | None = None,
        root_cap: float | None = DEFAULT_ROOT_CAP,
    ) -> list[EcsField]:
        """Deterministic given the same inputs - required for reproducible runs.

        The budget is spent by PRIORITY, never by alphabet. That sounds obvious
        and the first version of this function got it wrong in a way that was
        invisible from the outside: it gathered every core and category field
        (727 for an authentication source), sorted them by name and took the
        first 180. The cut landed at ``observer.vendor``, so every field after
        "o" was unreachable - including ``source.ip``, ``url.path``,
        ``user.name`` and ``server.*``.

        The effect was not a slightly worse subset. It was a hard ceiling on
        what any model could possibly answer, on exactly the fields this project
        is about, reported as a model error. Subset recall exists to catch
        precisely this, which is why it is a first-class metric and why it is
        printed with a warning rather than logged.

        Priority order, highest first:

            0  a field whose leaf name matches an observed log key
               (``client_ip`` -> ``source.ip`` will not be lost to a budget)
            1  ALWAYS roots, and the core fields of the confusable trio
            2  in-category, a DISCRIMINATING key word matching the leaf
            3  in-category, a discriminating key word matching the root (core)
            4  the same, extended
            5  in-category, a documentation word - or a generic key fragment
               such as ``name`` - matching the leaf
            6  in-category core, 7 in-category extended
            8  core fields outside the category
            9  only reachable through the embedding search

        ``doc_hints`` are the words a source's documentation uses to DESCRIBE
        its keys, and they enter at tier 5 - below every match on a real key
        and above a field that the category merely admits. They are held apart
        from ``observed_keys`` on purpose. When they were passed in as keys,
        one source's descriptions ("computer name", "user name") contributed
        the token ``name``, tier 0 promoted every ECS field whose last segment
        is ``name``, and 148 of that source's 240 candidates ended in ``.name``
        - against 15 for a source whose documentation happened to be more
        specific. The list stopped discriminating, the model picked
        ``destination.geo.name`` over ``host.name``, and the failure was
        recorded against the model. See ``Source.documentation_hints``.

        Set ``use_embeddings=False`` to skip the embedding stage - useful in tests and on
        machines without the embedding model downloaded. Stages 0-3 are lexical
        and always available, so a missing embedding model degrades the subset;
        it does not decapitate it.
        """
        wanted_roots = CATEGORY_FIELDSETS.get(category_hint or "", set()) | CONFUSABLE
        key_tokens = {k.lower().replace("-", "_") for k in observed_keys}
        # "client_ip" should reach "ip"/"client"; a leaf or root hit is enough.
        #
        # The threshold is >= 2, not > 2. It was > 2, which dropped the token
        # "ip" - two characters, and the single most load-bearing token in this
        # entire schema. A source whose key was `src_ip` could not reach
        # `source.ip` by any lexical route: the full key did not match the leaf,
        # and the part that did was filtered out before the comparison. The
        # confusion this project exists to catch was the one it could not see.
        # Single characters stay out; they carry no meaning and match everything.
        key_parts = {p for k in key_tokens for p in k.split("_") if len(p) >= 2}
        hint_parts = {
            p
            for h in (doc_hints or [])
            for p in h.lower().replace("-", "_").split("_")
            if len(p) >= 3
        } - key_parts
        # A fragment that separates nothing cannot buy the top in-category
        # tier on its own; it drops to the same rank as a documentation hint,
        # which keeps the field reachable without letting it flood the budget.
        strong_parts = key_parts - GENERIC_KEY_PARTS
        # ROUND 10 (A5): A STRUCTURE IN THE LINE BRINGS ITS ROOT IN.
        #
        # The category is one word; a source often spans two. An HTTP request
        # line or a file transfer recognised in the line by its shape
        # (types._keys_from_structure) is evidence that `http`/`url` or `file`
        # belongs to this source, so those fields are ranked as in-category
        # ones instead of competing with every core field outside it. Only
        # those structural keys count: letting every key that happens to name
        # a root do the same (Suricata's `http`, `tls`, `dns`, `flow` ...)
        # flooded the budget and evicted fields four sources needed (measured
        # in F4). Off under ECS_PIPELINE=round9.
        from adapter.types import round9_pipeline

        if not round9_pipeline():
            for k, roots in STRUCTURE_ROOTS.items():
                if k in key_tokens:
                    wanted_roots = wanted_roots | roots

        def name_tokens(part: str) -> set[str]:
            """Word tokens of an ECS name fragment, split on BOTH separators.

            Observed keys are split on ``_`` to build ``key_parts``; ECS names
            used to be split on ``.`` only. The comparison was therefore
            asymmetric, and the asymmetry was invisible because it only bites
            on compound segments: ``http.response.status_code`` tokenised to
            {"response", "status_code"}, so a source whose key was ``code``
            never matched it and the field fell two tiers. Splitting both sides
            the same way is the whole fix.
            """
            return {t for seg in part.split(".") for t in seg.split("_") if t}

        def priority(name: str, f: EcsField) -> int:
            root, _, leaf = name.partition(".")
            leaf = leaf or root
            leaf_tokens = name_tokens(leaf)
            # The LAST segment, not everything after the first dot. For a
            # depth-1 field the two are the same, which is why the original
            # `leaf in key_tokens` looked correct: `source.ip` matched a key
            # named `ip`. For anything deeper it silently stopped working -
            # `http.response.status_code` was compared against the key
            # `response.status_code`, which no log has ever emitted, so a
            # source with a literal `status_code` key still missed tier 0.
            last = name.rpartition(".")[2]
            if name in key_tokens or leaf in key_tokens or last in key_tokens:
                return 0
            if root in ALWAYS:
                return 1
            # The core fields of the confusable trio are RESERVED, not merely
            # offered. `source.ip` was being evicted by a crowded category tier
            # on a source whose own key was `src_ip` - the budget filled with
            # plausible category fields and dropped the one field whose
            # misassignment is the failure this project exists to catch. A
            # subset that cannot express source/destination/observer confusion
            # cannot detect it either, so this cannot be left to a tie-break.
            # About two dozen fields once `geo.*` is demoted as elaboration.
            if root in CONFUSABLE and f.level == "core":
                return 1
            if root in wanted_roots:
                # Inside the category, a match on the field's OWN words is a
                # much stronger signal than a match on its root, and the two
                # used to share a tier. A single key named `url` promoted the
                # whole `url.*` subtree to the same rank as the field the
                # source actually named, and on a source with many keys that
                # tier alone overflowed the budget - evicting `source.ip`,
                # which is the one field this project cannot afford to lose.
                if strong_parts & leaf_tokens:
                    return 2
                if strong_parts & name_tokens(root):
                    return 3 if f.level == "core" else 4
                # A description word is evidence, but weaker evidence: it names
                # what the key MEANS, not what the log calls it. So is a
                # generic fragment. Either can lift a field above its category
                # peers and no further.
                if (hint_parts | key_parts) & leaf_tokens:
                    return 5
                return 6 if f.level == "core" else 7
            if f.level == "core":
                return 8
            return 9  # only reachable via the embedding stage

        def rank(name: str, f: EcsField) -> int:
            p = priority(name, f)
            if p < 9 and set(name.split(".")) & ELABORATION_SEGMENTS:
                # Demoted, not excluded: it lands at worst level with the core
                # fields outside the category, where the level tie-break puts
                # those first, and it stays reachable by embedding search.
                return min(p + 3, 8)
            return p

        # Tie-break inside a tier by DEPTH before name. ECS nests detail under
        # the field it elaborates, so depth is a good proxy for how commonly a
        # field is actually populated: `user.name` (2) over
        # `destination.geo.continent_code` (3). Without this, a tier that
        # overflows the budget by a handful of fields loses whichever ones sort
        # last - and `user.*` sorts last.
        # A STRUCTURAL field is never a correct answer, so it is never offered.
        #
        # `labels` is type `object` in ECS: it holds `labels.<key>`, never a
        # scalar. V1 rejects an assignment to it unconditionally - that is what
        # `_STRUCTURAL` in v1_schema is - so a proposal that names it is dead
        # before the ladder starts. It was offered anyway, being in ALWAYS, and
        # four of ninety proposals took it for the deliberately ambiguous key
        # and died at V1. Between four and eight such fields were offered per
        # source.
        #
        # Reusing v1_schema's own set rather than restating it: the rule about
        # what may be assigned belongs to the validator, and two copies of it
        # would drift.
        from validators.v1_schema import _STRUCTURAL

        ranked = sorted(
            (
                (rank(n, f), f.level != "core", n.count("."), n, f)
                for n, f in self.fields.items()
                if rank(n, f) < 9 and f.type not in _STRUCTURAL
                and not set(n.split(".")) & LINEAGE_SEGMENTS
            )
        )

        # A CEILING ON HOW MUCH ONE ROOT MAY TAKE.
        #
        # ECS roots are wildly uneven. `process.*` carries the whole ancestry -
        # process.parent.*, process.entry_leader.*, process.session_leader.* -
        # and on an `authentication` source it took 212 of 320 slots, leaving
        # two for `user.*` and four for `host.*`. `user.name` was then
        # unreachable on a source whose own category is authentication, which
        # is not a budget being spent badly so much as one root eating it.
        #
        # The cap is a fraction of the budget, applied in rank order, so a root
        # keeps its best candidates and loses only its tail. Set to None it is
        # disabled and the ordering is exactly as before.
        selected: dict[str, EcsField] = {}
        per_root: dict[str, int] = {}
        cap = (
            int(max_fields * root_cap)
            if root_cap and 0 < root_cap < 1
            else max_fields
        )
        overflow: list[tuple[str, EcsField]] = []
        for *_, name, f in ranked:
            if len(selected) >= max_fields:
                break
            root = name.split(".", 1)[0]
            if per_root.get(root, 0) >= cap:
                overflow.append((name, f))
                continue
            per_root[root] = per_root.get(root, 0) + 1
            selected[name] = f
        # A budget left unspent helps nobody: if capping freed slots that
        # nothing else claimed, give them back to the roots that were capped.
        for name, f in overflow:
            if len(selected) >= max_fields:
                break
            selected[name] = f

        # Stage 4: spend any remaining budget on semantic retrieval.
        remaining = max_fields - len(selected)
        if use_embeddings and remaining > 0 and (observed_keys or documentation):
            import numpy as np

            self._ensure_embeddings()
            query = " ".join(observed_keys) + " " + documentation[:2000]
            q = self._model.encode([query], normalize_embeddings=True)[0]
            scores = self._embeddings @ q
            for idx in np.argsort(-scores):
                name = self._embedded_names[int(idx)]
                if (name not in selected and self.fields[name].type not in _STRUCTURAL
                        and not set(name.split(".")) & LINEAGE_SEGMENTS):
                    selected[name] = self.fields[name]
                    remaining -= 1
                    if remaining <= 0:
                        break

        # Fields the IR has no construct for are dropped here, after the budget
        # has been spent, so that excluding one frees a slot for something the
        # model can actually use. Dropping them earlier would be equivalent;
        # dropping them here keeps the priority logic above unaware of scope,
        # which is a different concern from relevance.
        for name in OUT_OF_SCOPE:
            selected.pop(name, None)

        # Alphabetical for RENDERING only: a stable, readable prompt. The budget
        # was already spent above, so this sort can no longer drop anything.
        return sorted(selected.values(), key=lambda f: f.name)

    @staticmethod
    def subset_recall(subset: list[EcsField], truth_fields: list[str]) -> float:
        """Fraction of ground-truth ECS fields actually offered to the model.

        Essential: if this is below 1.0, some errors are OURS, not the model's -
        the correct field was never among its choices. Report it beside accuracy,
        never instead of it.
        """
        wanted = {f for f in truth_fields if f}
        if not wanted:
            return 1.0
        offered = {f.name for f in subset}
        return len(wanted & offered) / len(wanted)


def retrieval_digest() -> str:
    """The retrieval POLICY, hashed. The third thing that decides an answer.

    `prompt_digest` hashes the templates and `schema_digest` the output
    contract, so between them a run record said what the model was asked and
    what it was allowed to answer. Neither says which 240 of 1659 ECS fields it
    was shown, and that is decided here.

    It was not an academic gap. Changing the tiering in this module took one
    source's candidate list from 148 of 240 fields ending in `.name` to 67,
    which is a different question put to the model - while every proposal's
    provenance stayed byte for byte identical to the previous corpus. Two runs
    that are not comparable would again have looked comparable.

    The module text is hashed, not the selection policy in the abstract, so a
    comment edit bumps it. That is the safe direction: this may report a change
    that did not happen, and it cannot miss one that did. The per-source subset
    is deliberately not part of it, for the same reason the per-source enum is
    not part of `schema_digest` - it identifies the apparatus, not the input.
    """
    from adapter.types import digest, KEY_HARVEST_SOURCE

    return digest(Path(__file__).read_text(encoding="utf-8") + KEY_HARVEST_SOURCE())


def render_fields(subset: list[EcsField]) -> str:
    return "\n".join(f.as_prompt_line() for f in subset)

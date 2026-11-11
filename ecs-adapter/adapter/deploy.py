"""Deploying a repaired parser without a person, inside stated bounds.

THE DESIGN THIS REPLACES
------------------------
Until 2026-10-14 the watcher parked every candidate and a person installed it.
That kept a human in the one place the thesis says there is none: an SME with
no analyst on shift has no-one to answer the prompt, so detection for the
drifted source stayed down until somebody happened to look. The author's
decision on 2026-10-14 is that a verified repair deploys itself and the analyst
is told; an unverified one goes to the analyst with a report.

WHAT BOUNDS THE AUTONOMY - STRUCTURALLY, NOT BY SUPERVISION
-----------------------------------------------------------
Every limit below holds with nobody watching, and each is a refusal rather
than a warning:

  1. The model never writes configuration. It fills the IR; the compiler, which
     is allow-listed and escapes everything, writes Logstash. Unchanged.
  2. Only VERIFIED FIELDS ship. A field reaches production when detection
     replay (V4) or continuity with the old parser (VC) proved it, and never
     when either contradicted it. Everything else is cut from the IR before it
     is compiled (`adapter/partial.py`). An accepted candidate whose fields no
     oracle examined ships nothing - `suricata_eve` on 2026-10-13 was accepted
     with three wrong fields, and under this rule those three never deploy.
  3. A SHADOW WINDOW comes first. The parser runs on live traffic into a shadow
     index; production is untouched until the shadow has parsed enough lines
     with a low enough failure rate and fills each delivered field about as
     often as the old parser did.
  4. AUTOMATIC ROLLBACK. After promotion the live failure rate is watched; past
     the threshold the previous version is restored, or the pipeline removed.
  5. RATE LIMITS. At most `max_deploys_per_family_per_day` deployments per
     source, on top of the watcher's own cooldown and daily cap, so a stream of
     crafted lines cannot make the SIEM rewrite its configuration at will.
  6. EVERY ACTION IS ANNOUNCED. `adapter/notify.py` writes each message to an
     outbox before sending it.

The hand-written pipeline is never edited. The generated one consumes the
unknown-format queue, keeps only the events the hand-written pipeline tagged as
failures for this source, and writes to the same index - so the detection rules
that read that index see the repaired documents with no change of their own.
The copy the hand-written pipeline indexed with its failure tag stays where it
is: it carries the raw line and no ECS field, so a rule that filters on an ECS
field does not count it twice. A rule matching on `message` alone does, and
that is stated rather than hidden.

Every side effect is injected - the filesystem paths, the shadow statistics,
the clock - so each refusal is testable without Logstash or Elasticsearch.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable
import hashlib
import json
import re
import time

from adapter import pipeline_registry


# --------------------------------------------------------------------- policy

@dataclass
class DeployPolicy:
    # A partial deployment must deliver at least this many verified fields.
    min_fields: int = 1
    shadow_window_s: float = 600.0
    shadow_min_docs: int = 20
    # Share of shadow documents that must parse. Lower for a partial delivery:
    # a parser that reads half the lines correctly beats the old one, which
    # reads none of them - and the unread half is in the analyst's report.
    min_parse_success_full: float = 0.95
    min_parse_success_partial: float = 0.5
    # A delivered field must be filled on at least this share of what the old
    # parser achieved, measured over the shadow documents that parsed.
    min_fill_ratio: float = 0.8
    live_watch_s: float = 3600.0
    max_live_failure: float = 0.2
    max_deploys_per_family_per_day: int = 2

    def validate(self) -> None:
        for name in ("min_parse_success_full", "min_parse_success_partial",
                     "min_fill_ratio", "max_live_failure"):
            v = getattr(self, name)
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{name} must be within [0, 1], not {v}")
        if self.min_fields < 1:
            raise ValueError("min_fields below 1 deploys a parser that delivers nothing")
        if self.shadow_min_docs < 1:
            raise ValueError(
                "shadow_min_docs below 1 promotes a parser no live line has passed through")


# ---------------------------------------------------------------- enrichment
#
# ENRICHMENT IS NOT A MAPPING DECISION.
#
# The hand-written nginx pipeline adds `source.geo.*` from the address and
# `user_agent.*` from the agent string. No model chooses those fields; they
# follow mechanically once `source.ip` or `user_agent.original` is right. So
# the deployed pipeline applies the same enrichment whenever its base field was
# verified, and a field derived this way is not counted missing. The IR and the
# compiler are untouched: the arms, the training data and every recorded result
# are produced without this block, exactly as before.
DERIVED = {
    "source.geo.": "source.ip",
    "destination.geo.": "destination.ip",
    "client.geo.": "client.ip",
    "user_agent.": "user_agent.original",
}


def derived_from(field_name: str) -> str | None:
    for prefix, base in DERIVED.items():
        if field_name.startswith(prefix) and field_name != base:
            return base
    return None


def enrichment_block(delivered: list[str]) -> str:
    """Fixed enrichment for the delivered base fields. Constants only."""
    parts = []
    for base, tgt in (("source.ip", "[source][geo]"), ("destination.ip", "[destination][geo]"),
                      ("client.ip", "[client][geo]")):
        if base in delivered:
            path = "".join(f"[{p}]" for p in base.split("."))
            parts.append(f'  geoip {{ source => "{path}" target => "{tgt}" '
                         'tag_on_failure => [] }')
    if "user_agent.original" in delivered:
        parts.append('  useragent { source => "[user_agent][original]" target => "[user_agent]" }')
    return "filter {\n" + "\n".join(parts) + "\n}\n" if parts else ""


# ------------------------------------------------------------------- decision

@dataclass
class Decision:
    kind: str                      # repaired | partial | escalated
    deliver: list[str] = field(default_factory=list)
    contradicted: list[str] = field(default_factory=list)
    untested: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    # The constants that may ship, or None when no previous parser was given and the
    # IR's own constants pass as before. See `admit_constants`.
    constants: dict[str, Any] | None = None
    refused_constants: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


# ------------------------------------------------------------------ constants
#
# No oracle verifies a constant: replay checks the fields a rule reads, and a
# constant is written into every document whatever the line says. So it was the
# one implant that could pass the gate (Section 6 of the paper). The rule added
# on 2026-11-09 (POSTHOC_REVIEW_ANALYSES.md, B3): a constant reaches production
# only if the previous parser wrote the same field with the same value on every
# document it produced. A refused constant falls back to the previous parser's
# value when it had one, so the categorisation keys the IR contract requires stay
# filled with a value that was already in production, and is dropped otherwise.

def _canon(v: Any) -> str:
    return json.dumps(sorted(v) if isinstance(v, list) else v, sort_keys=True, default=str)


def _flat_get(doc: dict[str, Any], dotted: str) -> Any:
    if dotted in doc:
        return doc[dotted]
    cur: Any = doc
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def constants_from_documents(docs: list[dict[str, Any]], keys: list[str]) -> dict[str, Any]:
    """The keys the previous parser wrote with one value on every document, and that value."""
    out: dict[str, Any] = {}
    for k in keys:
        vals = [_flat_get(d, k) for d in docs]
        if docs and all(v is not None for v in vals) and len({_canon(v) for v in vals}) == 1:
            out[k] = vals[0]
    return out


def admit_constants(constants: dict[str, Any], previous: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """(the constants that may ship, the keys refused). See the block comment above."""
    keep: dict[str, Any] = {}
    refused: list[str] = []
    for k, v in (constants or {}).items():
        if k in previous and _canon(previous[k]) == _canon(v):
            keep[k] = v
            continue
        refused.append(k)
        if k in previous:
            keep[k] = previous[k]
    return keep, sorted(refused)


def decide(
    record: dict[str, Any],
    continuity: dict[str, Any],
    old_fields: list[str],
    policy: DeployPolicy,
    v35_objections: list[str] | None = None,
    previous_constants: dict[str, Any] | None = None,
) -> Decision:
    """Which fields, if any, may reach production unattended.

    ``record`` is the RunRecord as a dict; ``continuity`` the VC metrics;
    ``old_fields`` what the previous parser produced for this source, whether
    or not an anchor could test it - a field missing from the new parser is
    missing whether or not we could have verified it. ``previous_constants``
    are the constants the previous parser wrote (`constants_from_documents`).
    When given, only the constants it carried with the same value ship.
    """
    ir = record.get("ir") or {}
    # A value map is a proposal too: `event.outcome` reaches the document
    # through one, never through `fields`, and leaving it out meant the field a
    # brute-force rule reads was cut from every repair however well verified.
    proposed = sorted({f.get("ecs_field") for f in ir.get("fields") or []
                       if f.get("ecs_field")}
                      | {vm.get("ecs_field") for vm in ir.get("value_maps") or []
                         if vm.get("ecs_field")})
    v4 = set(record.get("verified_ecs_fields") or [])
    vc = set(continuity.get("verified_fields") or [])
    contradicted = set(continuity.get("contradicted_fields") or []) | set(v35_objections or ())

    d = Decision(kind="escalated")
    d.contradicted = sorted(contradicted & set(proposed))
    d.deliver = sorted((v4 | vc) & set(proposed) - contradicted)
    d.untested = sorted(set(proposed) - set(d.deliver) - contradicted)
    d.missing = sorted(f for f in set(old_fields) - set(d.deliver)
                       if derived_from(f) not in d.deliver)
    if previous_constants is not None:
        d.constants, d.refused_constants = admit_constants(ir.get("constants") or {}, previous_constants)

    if not ir:
        d.reasons.append("the attempt produced no mapping at all")
        return d
    if record.get("rung_reached") in (None, "", "pre", "V1"):
        d.reasons.append(
            f"the proposal stopped at {record.get('rung_reached') or 'the model call'}: "
            "it is not a parser that compiles")
        return d
    if len(d.deliver) < policy.min_fields:
        d.reasons.append(
            f"{len(d.deliver)} field(s) verified, {policy.min_fields} needed: no oracle "
            "confirmed enough of the mapping to deploy any of it")
        return d

    if d.missing or record.get("outcome") != "accepted":
        d.kind = "partial"
        if record.get("outcome") != "accepted":
            d.reasons.append(
                f"the whole proposal did not clear the ladder ({record.get('outcome')} at "
                f"{record.get('rung_reached')}); only its verified fields deploy")
        if d.missing:
            d.reasons.append(f"{len(d.missing)} field(s) of the old parser are not back")
    else:
        d.kind = "repaired"
        d.reasons.append("every field the old parser produced is back and verified")
    if d.contradicted:
        d.reasons.append(f"{len(d.contradicted)} field(s) contradicted history and were cut")
    if d.untested:
        d.reasons.append(f"{len(d.untested)} field(s) no oracle tested were cut")
    if d.refused_constants:
        d.reasons.append(f"{len(d.refused_constants)} constant(s) the previous parser did not "
                         "write with that value were refused")
    return d


# -------------------------------------------------------------- the pipeline

def shadow_index(index: str) -> str:
    """`logs-nginx.access-default` -> `logs-nginx.access-shadow`.

    Same dataset, different namespace, so the shadow lands in the same index
    template's mapping as production and its documents are comparable.
    """
    m = re.match(r"\A(logs-[^-]+)-[^-]+\Z", index)
    return f"{m.group(1)}-shadow" if m else f"{index}-shadow"


def render_pipeline(
    family: str,
    pipeline_id: str,
    filter_block: str,
    failure_tag: str,
    index: str,
    stage: str,
    run_id: str,
    unknown_topic: str = "logs-unknown-default",
    delivered: list[str] | None = None,
) -> str:
    """A complete pipeline around the compiled filter, for one stage.

    The consumer group differs by stage on purpose. The live group is stable
    per source and starts from the earliest retained offset, so the FIRST live
    deployment re-reads every event of this source that failed since the
    break: the blind window is back-filled, not only closed. The shadow group is
    per run, so each candidate is judged on the same backlog.
    """
    if stage not in ("shadow", "live"):
        raise ValueError(f"stage must be shadow or live, not {stage!r}")
    if not re.fullmatch(r"_[a-z0-9_]+_grok_failure", failure_tag):
        raise pipeline_registry.RegistryError(f"refusing failure tag {failure_tag!r}")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,200}", index):
        raise pipeline_registry.RegistryError(f"refusing index name {index!r}")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,120}", run_id):
        raise pipeline_registry.RegistryError(f"refusing run id {run_id!r}")
    if "filter {" not in filter_block or "input {" in filter_block or "output {" in filter_block:
        raise pipeline_registry.RegistryError("only a compiler filter block may be deployed")
    pipeline_registry.names(pipeline_id)  # validates the id

    group = (f"logstash-{pipeline_id}-live" if stage == "live"
             else f"logstash-{pipeline_id}-shadow-{run_id[-6:]}")
    target = index if stage == "live" else shadow_index(index)
    return f"""#=========================
#   {pipeline_id}  (generated, {stage})
#=========================
#
# Deployed automatically by the ECS adapter (adapter/deploy.py) after the
# hand-written pipeline for '{family}' stopped parsing. Run {run_id}.
# Only fields an oracle verified are mapped below. Do not edit by hand: the
# next deployment or rollback rewrites this file.

input {{
  kafka {{
    bootstrap_servers => "kafka:9092"
    topics            => ["{unknown_topic}"]
    group_id          => "{group}"
    codec             => json
    auto_offset_reset => "earliest"
    consumer_threads  => 1
  }}
}}

filter {{
  if "{failure_tag}" not in [tags] {{
    drop {{ }}
  }}
  mutate {{
    remove_tag => ["{failure_tag}"]
    add_tag    => ["ecs_adapter_generated"]
    add_field  => {{
      "[labels][ecs_adapter_run]"   => "{run_id}"
      "[labels][ecs_adapter_stage]" => "{stage}"
    }}
  }}
}}

{filter_block.strip()}
{enrichment_block(delivered or [])}
output {{
  elasticsearch {{
    hosts    => ["https://es01:9200"]
    index    => "{target}"
    action   => "create"
    user     => "${{ELASTIC_USER}}"
    password => "${{ELASTIC_PASSWORD}}"
    ssl_enabled                 => true
    ssl_certificate_authorities => ["/certs/ca/ca.crt"]
  }}
}}
"""


# --------------------------------------------------------------- deployments

@dataclass
class Deployer:
    """Owns the generated pipeline files, the registry entries and their history.

    State lives in ``state_dir/<pipeline_id>.json``: the current version and
    every version that was live before it, with the full pipeline text, so a
    rollback restores exactly what ran rather than recompiling something
    similar.
    """

    pipelines_dir: Path
    registry: Path
    state_dir: Path
    policy: DeployPolicy = field(default_factory=DeployPolicy)
    clock: Callable[[], float] = time.time

    # ------------------------------------------------------------ state
    def _state_path(self, pipeline_id: str) -> Path:
        return self.state_dir / f"{pipeline_id}.json"

    def state(self, pipeline_id: str) -> dict[str, Any]:
        p = self._state_path(pipeline_id)
        if p.is_file():
            return json.loads(p.read_text(encoding="utf-8"))
        return {"pipeline_id": pipeline_id, "current": None, "history": [], "deploys": {}}

    def _save(self, st: dict[str, Any]) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._state_path(st["pipeline_id"]).write_text(
            json.dumps(st, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def _day(self) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime(self.clock()))

    def refusal(self, pipeline_id: str) -> str | None:
        st = self.state(pipeline_id)
        used = st.get("deploys", {}).get(self._day(), 0)
        if used >= self.policy.max_deploys_per_family_per_day:
            return (f"deployment cap reached for {pipeline_id} today "
                    f"({used}/{self.policy.max_deploys_per_family_per_day})")
        cur = st.get("current")
        if cur and cur.get("stage") == "shadow":
            return f"{pipeline_id} already has a candidate in its shadow window"
        return None

    # ------------------------------------------------------------ writes
    def _write(self, pipeline_id: str, text: str) -> None:
        n = pipeline_registry.names(pipeline_id)
        self.pipelines_dir.mkdir(parents=True, exist_ok=True)
        (self.pipelines_dir / n["conf"]).write_text(text, encoding="utf-8")
        pipeline_registry.register(pipeline_id, self.registry)

    def deploy_shadow(
        self,
        pipeline_id: str,
        family: str,
        filter_block: str,
        failure_tag: str,
        index: str,
        run_id: str,
        case: dict[str, Any],
    ) -> dict[str, Any]:
        why = self.refusal(pipeline_id)
        if why:
            raise pipeline_registry.RegistryError(why)
        st = self.state(pipeline_id)
        deliver = (case.get("decision") or {}).get("deliver", [])
        shadow_text = render_pipeline(family, pipeline_id, filter_block, failure_tag,
                                      index, "shadow", run_id, delivered=deliver)
        live_text = render_pipeline(family, pipeline_id, filter_block, failure_tag,
                                    index, "live", run_id, delivered=deliver)
        prev = st.get("current")
        if prev and prev.get("stage") == "live":
            st["history"].append(prev)
        version = 1 + max([h.get("version", 0) for h in st["history"]] + [0])
        st["current"] = {
            "version": version, "stage": "shadow", "run_id": run_id,
            "family": family, "index": index, "failure_tag": failure_tag,
            "shadow_since": self.clock(), "live_since": None,
            "pipeline_text": shadow_text, "live_text": live_text,
            "sha256": hashlib.sha256(live_text.encode()).hexdigest()[:16],
            "kind": (case.get("decision") or {}).get("kind"),
            "deliver": (case.get("decision") or {}).get("deliver", []),
            "fill_rates": case.get("fill_rates", {}),
        }
        day = self._day()
        st.setdefault("deploys", {})[day] = st.get("deploys", {}).get(day, 0) + 1
        # ONE ID, ONE FILE. The shadow replaces a previous live version in the
        # file for the length of the window, and a failed shadow restores it
        # from `history`. The cost is that lines the previous version still
        # parsed go unparsed meanwhile; a second drift on a source already
        # repaired once is the only case that reaches here with a live
        # predecessor, and that predecessor is failing on the new shape anyway.
        self._write(pipeline_id, shadow_text)
        self._save(st)
        return st["current"]

    def promote(self, pipeline_id: str) -> dict[str, Any]:
        st = self.state(pipeline_id)
        cur = st.get("current")
        if not cur or cur.get("stage") != "shadow":
            raise pipeline_registry.RegistryError(f"{pipeline_id} has no shadow to promote")
        cur["stage"] = "live"
        cur["live_since"] = self.clock()
        cur["pipeline_text"] = cur.pop("live_text")
        self._write(pipeline_id, cur["pipeline_text"])
        self._save(st)
        return cur

    def rollback(self, pipeline_id: str, reason: str) -> dict[str, Any]:
        """Restore the last live version, or remove the pipeline if there is none."""
        st = self.state(pipeline_id)
        cur = st.get("current")
        if cur:
            cur["rolled_back"] = {"at": self.clock(), "reason": reason}
            st.setdefault("rolled_back", []).append(cur)
        previous = st["history"].pop() if st["history"] else None
        n = pipeline_registry.names(pipeline_id)
        if previous:
            st["current"] = previous
            self._write(pipeline_id, previous["pipeline_text"])
            restored = previous.get("version")
        else:
            st["current"] = None
            (self.pipelines_dir / n["conf"]).unlink(missing_ok=True)
            pipeline_registry.unregister(pipeline_id, self.registry)
            restored = None
        self._save(st)
        return {"restored_version": restored, "reason": reason}

    # ---------------------------------------------------------- judgement
    def judge_shadow(self, cur: dict[str, Any], stats: dict[str, Any]) -> tuple[str, str]:
        """('promote' | 'rollback' | 'wait', why) from the shadow's statistics.

        ``stats``: {"docs": int, "failures": int, "fill": {ecs_field: rate}},
        over the documents this run wrote to the shadow index.
        """
        p = self.policy
        docs, fails = int(stats.get("docs", 0)), int(stats.get("failures", 0))
        elapsed = self.clock() - float(cur.get("shadow_since") or 0)
        if docs < p.shadow_min_docs:
            if elapsed < p.shadow_window_s * 3:
                return "wait", f"{docs} shadow documents, {p.shadow_min_docs} needed"
            return "rollback", (f"only {docs} shadow documents after "
                                f"{int(elapsed)}s - the source is too quiet to judge")
        if elapsed < p.shadow_window_s:
            return "wait", f"shadow window {int(elapsed)}/{int(p.shadow_window_s)}s"
        success = (docs - fails) / docs
        need = (p.min_parse_success_full if cur.get("kind") == "repaired"
                else p.min_parse_success_partial)
        if success < need:
            return "rollback", f"parsed {success:.0%} of shadow lines, {need:.0%} needed"
        old = cur.get("fill_rates") or {}
        for f in cur.get("deliver") or []:
            before = float(old.get(f, 0.0))
            now = float((stats.get("fill") or {}).get(f, 0.0))
            if before > 0 and now < before * p.min_fill_ratio:
                return "rollback", (f"{f} filled on {now:.0%} of parsed lines against "
                                    f"{before:.0%} under the old parser")
        return "promote", f"parsed {success:.0%} of {docs} shadow lines; every field filled"

    def judge_live(self, cur: dict[str, Any], stats: dict[str, Any]) -> tuple[str, str]:
        """('keep' | 'rollback' | 'settled', why) during the live watch."""
        p = self.policy
        elapsed = self.clock() - float(cur.get("live_since") or 0)
        docs, fails = int(stats.get("docs", 0)), int(stats.get("failures", 0))
        if docs and fails / docs > p.max_live_failure:
            return "rollback", f"live failure rate {fails / docs:.0%} above {p.max_live_failure:.0%}"
        if elapsed >= p.live_watch_s:
            return "settled", f"live for {int(elapsed)}s within bounds"
        return "keep", f"live {int(elapsed)}/{int(p.live_watch_s)}s, {fails}/{docs} failures"


def shadow_stats(es, index: str, run_id: str, source_id: str,
                 fields: list[str]) -> dict[str, Any]:
    """Counts the shadow (or live) documents this run wrote, and how full they are."""
    base = {"term": {"labels.ecs_adapter_run": run_id}}
    tag = f"_{source_id}_parse_failure"
    docs = es.count(index=index, query={"bool": {"filter": [base]}}).get("count", 0)
    fails = es.count(index=index, query={"bool": {"filter": [base, {"term": {"tags": tag}}]}}
                     ).get("count", 0)
    parsed = max(docs - fails, 0)
    fill: dict[str, float] = {}
    for f in fields:
        n = es.count(index=index, query={"bool": {
            "filter": [base, {"exists": {"field": f}}],
            "must_not": [{"term": {"tags": tag}}]}}).get("count", 0)
        fill[f] = (n / parsed) if parsed else 0.0
    return {"docs": docs, "failures": fails, "fill": fill}

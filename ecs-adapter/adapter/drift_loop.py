"""The closed loop: a parser breaks, the module repairs it or hands it over.

    watcher confirms a drift
        -> notify "detected"
        -> harvest the old parser's output, anchor it in the new lines
        -> propose (the arm the deployment runs), with the ladder's repair loop
        -> run the candidate, check continuity with the old parser per field
        -> decide: repaired | partial | escalated
              repaired / partial -> restrict to verified fields, shadow deploy
              escalated          -> report + notify, nothing deployed
    every tick, for each deployment:
        shadow -> promote (notify repaired|partial) or roll back (notify)
        live   -> keep watching until settled, or roll back (notify)

Nothing here decides what a field means. The decisions are `deploy.decide`
and `Deployer.judge_*`; this module only sequences them and keeps the record
of each case under `results/cases/`, which is what the paper's operational
numbers - automation rate, wrong deployments, analyst hand-overs, time to
restore - are computed from.

Every collaborator is injected, so the sequencing is tested without a model,
Logstash or Elasticsearch, and the deployment code cannot drift into a second,
laxer path than the one the arms are measured on: `propose` is the same CLI
proposal the benchmark runs.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
import json
import time

from adapter import anchors as anchors_mod
from adapter import pipeline_registry, report
from adapter.deploy import Decision, Deployer, decide, shadow_index, shadow_stats
from adapter.notify import Notifier
from adapter.partial import restrict_to_verified
from validators import continuity


def _stamp(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def _v35_objections(record: dict[str, Any]) -> list[str]:
    """Fields V3.5 said hold a value that belongs elsewhere.

    With history anchors as the known values these are continuity failures
    observed inside the ladder, and they block the field like VC's own.
    """
    return sorted({
        f.get("source_key") for f in record.get("findings") or []
        if f.get("rung") == "V3.5" and f.get("code") == "value_in_wrong_field"
        and f.get("source_key")
    })


def _deployable_ir(ir: dict[str, Any], deliver: list[str],
                   constants: dict[str, Any] | None = None) -> dict[str, Any]:
    """The IR cut to the delivered fields, in a shape the compiler accepts.

    `restrict_to_verified` annotates its result with a `partial` block for the
    record; the IR contract has no such key, so it is lifted off here and kept
    in the case instead.
    """
    cut = restrict_to_verified(ir, deliver)
    cut.pop("partial", None)
    if constants is not None:
        cut["constants"] = dict(constants)
    return cut


@dataclass
class DriftLoop:
    root: Path
    deployer: Deployer
    notifier: Notifier
    # source_id -> the RunRecord, as a dict, of one proposal over that source
    propose: Callable[[str], dict[str, Any] | None]
    # (filter block, lines) -> the documents Logstash produced from those
    # lines. The V3 sandbox in production. Continuity is judged on EVERY
    # captured line, not on the deduplicated samples the model is shown: a
    # JSON source dedupes to three samples, and most anchors would never be
    # parsed at all.
    run_parser: Callable[[str, list[str]], list[dict[str, Any]]]
    compile: Callable[[dict[str, Any]], str]
    write_source: Callable[[str, list[str], str | None], Any]
    es: Any = None
    clock: Callable[[], float] = time.time
    history_size: int = 500
    # Offer the old parser's fields to the mapping stage (Source.previous_fields).
    # Off only for the ablation that measures what the hint is worth.
    offer_previous_fields: bool = True
    # Whether a field exists in the pinned ECS version. A hand-written pipeline
    # may emit fields outside ECS (`auth.method`); no IR can produce one, so
    # counting it missing would make every repair partial by construction.
    known_field: Callable[[str], bool] | None = None

    # ------------------------------------------------------------- records
    @property
    def cases_dir(self) -> Path:
        return self.root / "results" / "cases"

    def _save_case(self, case: dict[str, Any]) -> None:
        self.cases_dir.mkdir(parents=True, exist_ok=True)
        (self.cases_dir / f"{case['case_id']}.json").write_text(
            json.dumps(case, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")

    def _load_case(self, case_id: str) -> dict[str, Any] | None:
        p = self.cases_dir / f"{case_id}.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else None

    def _tell(self, kind: str, case: dict[str, Any]) -> None:
        attachments = {}
        if kind != "detected":
            attachments["report.md"] = report.render(case)
            if (case.get("record") or {}).get("ir"):
                attachments["proposal-ir.json"] = json.dumps(case["record"]["ir"], indent=2)
        rec = self.notifier.notify(
            kind, case["family"], report.email_body(kind, case), attachments,
            facts={"case_id": case["case_id"],
                   "decision": (case.get("decision") or {}).get("kind")})
        case.setdefault("notifications", []).append(rec)

    # ---------------------------------------------------------------- drift
    def handle(self, source_id: str, lines: list[str],
               category: str | None = None) -> dict[str, Any]:
        """One confirmed drift, end to end up to the shadow. The watcher's propose_fn."""
        t0 = self.clock()
        family = source_id.removesuffix("-adapted")
        case: dict[str, Any] = {
            "case_id": f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(t0))}_{family}",
            "family": family, "source_id": source_id,
            "detected_at": _stamp(t0), "t_detected": t0,
            "new_lines": lines[:20], "stage": "detected",
        }
        self._tell("detected", case)

        # The watcher turned `_linux_auth_grok_failure` into `linux-auth-adapted`,
        # because the id becomes a filename and a Kafka group that refuse
        # underscores. The tag itself keeps them.
        tag_family = family.replace("-", "_")
        target = pipeline_registry.family_target(tag_family, self.deployer.pipelines_dir)
        if target is None:
            return self._escalate(case, Decision(kind="escalated", reasons=[
                f"no single hand-written pipeline sets _{tag_family}_grok_failure, so "
                "the index the detection rules read is unknown"]))
        case["index"] = target["index"]
        case["failure_tag"] = target["failure_tag"]

        # History: what the old parser produced, and which of it the new lines carry.
        docs: list[dict[str, Any]] = []
        if self.es is not None:
            try:
                docs = anchors_mod.harvest(self.es, target["index"], target["failure_tag"],
                                           size=self.history_size)
            except Exception as exc:  # an unreachable index is a finding, not a crash
                case["history_error"] = f"{type(exc).__name__}: {exc}"
        hist = anchors_mod.history_from_documents(docs)
        fills = anchors_mod.fill_rates(docs)
        anc = anchors_mod.anchor(hist, lines)
        case["anchors"] = anc.to_json()
        case["fill_rates"] = fills
        # Observations AND computed fields: `event.outcome` is what a
        # brute-force rule reads, and it is computed, not carried by the line.
        rare = {f for f, r in fills.items() if r < 0.05}
        detect = [f for f in anchors_mod.detection_fields(docs) if f not in rare]
        if self.known_field is not None:
            case["non_ecs_fields"] = [f for f in detect if not self.known_field(f)]
            detect = [f for f in detect if self.known_field(f)]
        case["old_fields"] = detect
        rules = anchors_mod.token_rules(docs)
        expected = anchors_mod.expectations(rules, lines)
        case["computed_expectations"] = {f: len(v) for f, v in expected.items()}
        case["old_lines"] = [d.get("event", {}).get("original") or d.get("message")
                             for d in docs[:6]
                             if (d.get("event", {}) or {}).get("original") or d.get("message")]

        self.write_source(source_id, lines, category)
        self._write_known_values(source_id, anc,
                                 case["old_fields"] if self.offer_previous_fields else [])

        rec = self.propose(source_id) or {}
        case["record"] = rec
        case["t_proposed"] = self.clock()

        # Continuity, judged on what the WHOLE candidate does to the samples.
        vc_metrics: dict[str, Any] = {}
        ir = rec.get("ir")
        if ir and rec.get("rung_reached") not in (None, "", "pre", "V1"):
            try:
                parsed = self.run_parser(self.compile(ir), lines)
            except Exception as exc:
                parsed = []
                case["continuity_error"] = f"{type(exc).__name__}: {exc}"
            vc_metrics = continuity.validate(parsed, anc.values, expected).metrics
        case["continuity"] = {k: v for k, v in vc_metrics.items() if k != "results"}

        prev_const = None
        if ir and docs:
            from adapter.deploy import constants_from_documents
            prev_const = constants_from_documents(docs, sorted((ir.get("constants") or {}).keys()))
        decision = decide(rec, vc_metrics, case["old_fields"], self.deployer.policy,
                          v35_objections=_v35_objections(rec), previous_constants=prev_const)
        case["decision"] = decision.to_json()
        if decision.kind == "escalated":
            return self._escalate(case, decision)

        # The parser that ships: verified fields only, re-run and re-checked,
        # because cutting fields changes the compiled pipeline.
        cut = _deployable_ir(ir, decision.deliver, decision.constants)
        try:
            filter_block = self.compile(cut)
            parsed = self.run_parser(filter_block, lines)
        except Exception as exc:
            decision.kind = "escalated"
            decision.reasons.append(f"the restricted parser did not run: {exc}")
            case["decision"] = decision.to_json()
            return self._escalate(case, decision)
        recheck = continuity.validate(
            parsed, {f: v for f, v in anc.values.items() if f in decision.deliver},
            {f: v for f, v in expected.items() if f in decision.deliver})
        if not parsed or recheck.metrics.get("contradicted_fields"):
            decision.kind = "escalated"
            decision.reasons.append(
                "the restricted parser produced no documents" if not parsed else
                "the restricted parser contradicted history on "
                + ", ".join(recheck.metrics["contradicted_fields"]))
            case["decision"] = decision.to_json()
            return self._escalate(case, decision)

        self._keep_candidate(rec, cut, filter_block, case)
        pipeline_id = f"{family}-adapted"
        case["extraction"] = cut.get("extraction")
        case["ir_source_id"] = cut.get("source_id")
        try:
            cur = self.deployer.deploy_shadow(
                pipeline_id, family, filter_block, target["failure_tag"],
                target["index"], rec.get("run_id", case["case_id"]), case)
        except pipeline_registry.RegistryError as exc:
            decision.kind = "escalated"
            decision.reasons.append(f"deployment refused: {exc}")
            case["decision"] = decision.to_json()
            return self._escalate(case, decision)
        cur["case_id"] = case["case_id"]
        cur["extraction"] = case["extraction"]
        cur["ir_source_id"] = case["ir_source_id"]
        st = self.deployer.state(pipeline_id)
        st["current"] = cur
        self.deployer._save(st)

        case["stage"] = "shadow"
        case["deployment"] = {"pipeline_id": pipeline_id, "stage": "shadow",
                              "version": cur["version"],
                              "shadow_index": shadow_index(target["index"])}
        self._save_case(case)
        return {"outcome": f"shadow:{decision.kind}", "rung_reached": rec.get("rung_reached"),
                "run_id": rec.get("run_id"), "case_id": case["case_id"]}

    def _escalate(self, case: dict[str, Any], decision: Decision) -> dict[str, Any]:
        case["decision"] = decision.to_json()
        case["stage"] = "escalated"
        case["t_closed"] = self.clock()
        rec = case.get("record") or {}
        if rec.get("ir"):
            self._keep_candidate(rec, None, None, case)
        self._tell("escalated", case)
        self._save_case(case)
        return {"outcome": "escalated", "rung_reached": rec.get("rung_reached"),
                "run_id": rec.get("run_id"), "case_id": case["case_id"]}

    def _write_known_values(self, source_id: str, anc: anchors_mod.Anchors,
                            old_fields: list[str]) -> None:
        """History anchors, in the file V3.5 already reads.

        This gives the ladder's repair loop attribution it otherwise lacks on a
        captured source: "the value history says is source.ip is in
        destination.ip" instead of a bare count. One value per field, because
        that is V3.5's contract; the full set stays with the case for VC.
        """
        d = self.root / "bench" / "sources" / source_id
        d.mkdir(parents=True, exist_ok=True)
        (d / "known_values.json").write_text(json.dumps({
            "note": ("NOT ground truth. Values the previous parser placed in these "
                     "fields before the format changed, found again in the new lines."),
            "origin": "history anchors (adapter/anchors.py)",
            # Every line in samples.ndjson is a captured line; none is a probe.
            "probe_line": False,
            "source_id": source_id,
            "values": anc.known_values(),
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        # The fields the old parser produced, offered to the mapping stage.
        # See Source.previous_fields.
        (d / "previous.json").write_text(json.dumps({
            "note": "Fields the previous parser for this source produced.",
            "fields": sorted(old_fields),
        }, indent=2) + "\n", encoding="utf-8")
        (d / "anchors.json").write_text(
            json.dumps(anc.to_json(), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def _keep_candidate(self, rec: dict[str, Any], cut: dict[str, Any] | None,
                        filter_block: str | None, case: dict[str, Any]) -> None:
        cand = self.root / "candidates" / (rec.get("run_id") or case["case_id"])
        cand.mkdir(parents=True, exist_ok=True)
        (cand / "ir.json").write_text(json.dumps(rec.get("ir"), indent=2), encoding="utf-8")
        if cut is not None:
            (cand / "ir.deployed.json").write_text(json.dumps(cut, indent=2), encoding="utf-8")
        if filter_block is not None:
            (cand / "pipeline.conf").write_text(filter_block, encoding="utf-8")
        (cand / "report.md").write_text(report.render(case), encoding="utf-8")

    # ------------------------------------------------------------- supervise
    def supervise(self) -> list[dict[str, Any]]:
        """Advance every deployment one step. Called on every watcher tick."""
        actions: list[dict[str, Any]] = []
        if self.es is None or not self.deployer.state_dir.is_dir():
            return actions
        for path in sorted(self.deployer.state_dir.glob("*.json")):
            st = json.loads(path.read_text(encoding="utf-8"))
            cur = st.get("current")
            if not cur or cur.get("settled"):
                continue
            pid = st["pipeline_id"]
            case = self._load_case(cur.get("case_id", "")) or {
                "case_id": cur.get("case_id", pid), "family": cur.get("family", pid)}
            src = cur.get("ir_source_id") or f"{cur.get('family')}-adapted"
            if cur["stage"] == "shadow":
                stats = shadow_stats(self.es, shadow_index(cur["index"]), cur["run_id"],
                                     src, cur.get("deliver") or [])
                verdict, why = self.deployer.judge_shadow(cur, stats)
                case["shadow"] = {**stats, "verdict": verdict, "why": why}
                if verdict == "promote":
                    self.deployer.promote(pid)
                    case["stage"] = "live"
                    case["t_restored"] = self.clock()
                    case.setdefault("deployment", {})["stage"] = "live"
                    self._tell(cur.get("kind") or "partial", case)
                elif verdict == "rollback":
                    self.deployer.rollback(pid, why)
                    case["stage"] = "escalated"
                    case["t_closed"] = self.clock()
                    (case.setdefault("decision", {}).setdefault("reasons", [])
                     .append(f"shadow rejected: {why}"))
                    self._tell("escalated", case)
            elif cur["stage"] == "live":
                stats = shadow_stats(self.es, cur["index"], cur["run_id"], src,
                                     cur.get("deliver") or [])
                verdict, why = self.deployer.judge_live(cur, stats)
                if verdict == "rollback":
                    self.deployer.rollback(pid, why)
                    case["stage"] = "rolled_back"
                    case["t_closed"] = self.clock()
                    (case.setdefault("decision", {}).setdefault("reasons", [])
                     .append(f"live check failed: {why}"))
                    self._tell("rolled_back", case)
                elif verdict == "settled":
                    st2 = self.deployer.state(pid)
                    st2["current"]["settled"] = True
                    self.deployer._save(st2)
                    case["stage"] = "settled"
                    case["t_closed"] = self.clock()
            else:
                continue
            actions.append({"pipeline_id": pid, "stage": cur["stage"], "verdict": verdict,
                            "why": why})
            self._save_case(case)
        return actions

    # --------------------------------------------------------------- handled
    def handled(self, source_id: str, raw: str) -> bool:
        """Whether a deployed parser for this source already reads the line.

        The hand-written pipeline keeps tagging every line of a drifted source,
        so without this the watcher would see the same shape again after the
        repair and propose it again once its cooldown ran out. A line the
        deployed parser does NOT read is a new drift, and still counts.
        """
        from adapter.normalise import _yield_of

        family = source_id.removesuffix("-adapted")
        st = self.deployer.state(f"{family}-adapted")
        cur = st.get("current")
        if not cur or not cur.get("extraction"):
            return False
        try:
            return _yield_of(cur["extraction"], [raw]) > 0
        except Exception:
            return False

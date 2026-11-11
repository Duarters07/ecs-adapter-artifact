"""The run loop.

One call to ``run_once`` is one experimental unit: one arm, one model, one
source, one seed, producing exactly one RunRecord.

The repair budget is enforced here rather than inside any arm, so it is provably
identical across A, B, T and C. An arm that could grant itself extra attempts
would make the comparison meaningless.
"""
from __future__ import annotations

from dataclasses import dataclass, field as dataclass_field
from typing import Any
import json
import os
import time
import uuid

from adapter.footprint import endpoint_of, process_peak_rss_mb, server_resident_mb
from adapter.normalise import apply_all, carry_demotions
from validators import v4_detection
from adapter.types import (
    STAGE_INTERPRET,
    STAGE_MAP,
    Architecture,
    ModelError,
    RunRecord,
    Source,
    Usage,
    ValidationReport,
)


@dataclass
class Attempt:
    """The outcome of one propose-and-repair cycle, by the students or the teacher."""

    ir: dict[str, Any] | None
    report: ValidationReport
    repairs: int
    outcome: str  # accepted | abstained | failed
    error: dict[str, Any] | None = None
    # Every change the deterministic layer made, so the result can be read with
    # this layer's contribution separated out rather than folded into the
    # model's. See adapter/normalise.py.
    normalisations: list[dict[str, Any]] = dataclass_field(default_factory=list)
    # Fresh proposals drawn because a grok was unusable (ECS_REGEX_GUARD).
    regex_resamples: int = 0


def regex_guard_budget() -> int:
    """`ECS_REGEX_GUARD=N`: up to N fresh proposals when a grok cannot compile. Off by default."""
    import os

    try:
        return max(0, int(os.environ.get("ECS_REGEX_GUARD", "0")))
    except ValueError:
        return 0


def regex_defect(ir: dict[str, Any] | None) -> str | None:
    """Why this IR's grok cannot run at all, or None.

    Two defects only, both fatal to every line rather than to some: a pattern
    name grok does not define (Logstash refuses the whole filter) and a pattern
    that is not a valid regular expression. Neither is a judgement a repair
    round adds anything to - the model wrote something that cannot execute -
    so a fresh draw is cheaper than a round of feedback. Round 2 measured
    these as 46 of 796 model-only failures and 5 of 138 full-system ones.
    """
    import re as _re
    from adapter.types import grok_patterns
    from validators.v2_consistency import _GROK_TOKEN, _grok_to_regex, _load_grok_names

    e = (ir or {}).get("extraction") or {}
    if e.get("kind") != "grok":
        return None
    patterns = grok_patterns(e)
    known = _load_grok_names()
    if known:
        unknown = sorted({m.group(1) for p in patterns for m in _GROK_TOKEN.finditer(p)} - known)
        if unknown:
            return f"unknown grok pattern(s): {', '.join(unknown)}"
    for p in patterns:
        try:
            _re.compile(_grok_to_regex(p)[0])
        except _re.error as exc:
            return f"invalid regular expression: {exc}"
    return None


def _trace(arch, source, candidate_id: str, attempt: int, ir, report, raw_ir=None) -> None:
    """Round 10, F5 (T2/T3): with ECS_TRACE_FILE set, append every judged attempt to that file. Off by default.

    One JSON line per attempt: the roles stage 1 wrote, the IR the model wrote (``raw_ir``, before the deterministic
    layer; Task 3 attribution), the IR the ladder judged, its verdict and findings. Training
    examples are built from it afterwards (own failures + the real diagnosis -> the gold answer; verified against
    refuted answers for DPO). Nothing here changes what the run does.
    """
    path = os.environ.get("ECS_TRACE_FILE")
    if not path:
        return
    from adapter import diagnose
    from adapter.types import STAGE_MAP
    feedback = {}
    if not report.passed and ir is not None:
        # The text the repair would hand each stage (StagedArchitecture.repair), rendered here so a training example
        # can carry exactly what the model would have read.
        try:
            feedback = {"full": diagnose.render(report, ir, source),
                        "map_only": diagnose.render(report, ir, source, stage=STAGE_MAP),
                        "blames_interpretation": report.blames_interpretation()}
        except Exception as exc:  # a trace must never break a run
            feedback = {"error": f"{type(exc).__name__}: {exc}"}
    row = {"source_id": source.source_id, "candidate_id": candidate_id, "attempt": attempt,
           "roles": getattr(arch, "last_roles", None), "raw_ir": raw_ir, "ir": ir, "passed": report.passed,
           "rung_reached": report.rung_reached,
           "findings": [{"rung": f.rung, "code": f.code, "message": f.message, "stage": f.stage,
                         "source_key": f.source_key} for f in report.findings],
           "feedback": feedback}
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, default=str) + "\n")


def _cycle(
    arch: Architecture,
    source: Source,
    ladder,
    candidate_id: str,
    repair_budget: int,
    usage: Usage,
    normalise: bool = True,
) -> Attempt:
    """Propose once, then repair until the budget is spent.

    ``normalise=False`` is the model-only evaluation mode (PLAN_R2.md): the
    deterministic layer does not run, so what is judged is what the model
    wrote.

    Shared by the students and by the escalated teacher so that neither gets a
    structurally different chance at the problem. The only difference between
    them is which model is behind ``arch``.
    """
    try:
        ir = arch.propose(source, usage)
    except ModelError as exc:
        return Attempt(
            ir=None,
            report=ValidationReport(),
            repairs=0,
            outcome="failed",
            error={"rung": "pre", "code": "model_error", "message": str(exc)},
        )

    repairs = 0
    report = ValidationReport()
    changes: list[dict[str, Any]] = []

    # A GROK THAT CANNOT EXECUTE IS REDRAWN, NOT REPAIRED (full-system only).
    # Model-only stays one call by definition. The check runs on the
    # NORMALISED IR, so an unknown name the deterministic layer renames
    # (rename_unknown_grok_patterns) does not cost a draw.
    resamples = 0
    if normalise:
        _probe_lines = list(source.parser_input())
        for _ in range(regex_guard_budget()):
            if regex_defect(apply_all(ir, _probe_lines, ladder.ecs)[0]) is None:
                break
            try:
                ir = arch.propose(source, usage)
            except ModelError:
                break
            resamples += 1

    for attempt in range(repair_budget + 1):
        # NORMALISE, THEN JUDGE, THEN REPAIR FROM WHAT WAS JUDGED.
        #
        # The deterministic layer runs here, in the controller, for the same
        # reason the repair budget does: every arm must get it identically, and
        # an arm that could grant itself a different one would make the
        # comparison meaningless.
        #
        # The repaired IR is the normalised one, not the model's original. The
        # alternative - judge the normalised IR and hand the raw one back - would
        # ask the model to fix an object that nobody evaluated.
        # The extraction decides whether ANY key reaches the mapping, so it is
        # settled first, against the samples the model actually saw.
        # The deterministic layer, in one call, so that the corpus is built
        # under exactly the apparatus the runs are judged by.
        # EVERY LINE THE PARSER WILL FACE, NOT ONLY THE ONES THE MODEL SAW.
        #
        # The deterministic layer tested against `samples` while V3 runs the
        # parser over `parser_input()` - the samples PLUS the probe line. A
        # pattern could match all twenty samples, be accepted here, and be
        # tagged a parse failure in the sandbox by the one line nobody had
        # checked it against. That is what killed every syn_caddy_prose
        # proposal on 2026-10-11.
        #
        # The probe must never reach the MODEL, and it does not: this is
        # deterministic code asking whether a pattern matches a line, which is
        # the same question V3 asks and the same question the compiler's output
        # will have to answer in production.
        raw_ir = json.loads(json.dumps(ir, default=str)) if os.environ.get("ECS_TRACE_FILE") else None
        if normalise:
            _lines = list(source.parser_input())
            ir, made = apply_all(ir, _lines, ladder.ecs)
            changes.extend(made)

        report = ladder.run(ir, candidate_id=f"{candidate_id}-{attempt}")
        _trace(arch, source, candidate_id, attempt, ir, report, raw_ir)

        if report.passed:
            return Attempt(ir, report, repairs, "accepted", normalisations=changes,
                           regex_resamples=resamples)
        if report.is_abstention:
            return Attempt(ir, report, repairs, "abstained", normalisations=changes,
                           regex_resamples=resamples)
        if attempt == repair_budget:
            return Attempt(ir, report, repairs, "failed", normalisations=changes,
                           regex_resamples=resamples)

        try:
            judged = ir
            ir = arch.repair(ir, report, usage)
            # What the deterministic layer demoted must survive the repair. The
            # model drops those entries, and the ladder then reports the key as
            # unaccounted for - a failure the handoff created, not the mapping.
            if normalise:
                ir, carried = carry_demotions(judged, ir)
                changes.extend(carried)
            repairs += 1
        except ModelError as exc:
            return Attempt(
                ir,
                report,
                repairs,
                "failed",
                {"rung": "repair", "code": "model_error", "message": str(exc)},
                normalisations=changes,
            )

    return Attempt(ir, report, repairs, "failed", normalisations=changes)


# How far an attempt got, for choosing among sampled candidates. An accepted
# candidate always wins; among failures the one that cleared more rungs is the
# better starting point for whoever picks the case up.
_RUNG_ORDER = {"pre": 0, "none": 0, "V1": 1, "V2": 2, "V3": 3, "V3.5": 4, "V4": 5}
_OUTCOME_ORDER = {"failed": 0, "abstained": 1, "accepted": 2}


def _rank(a: Attempt) -> tuple[int, int]:
    return (_OUTCOME_ORDER.get(a.outcome, 0), _RUNG_ORDER.get(a.report.rung_reached, 0))


def _set_seed(arch: Architecture, seed: int) -> None:
    client = getattr(arch, "client", None)
    if client is not None and hasattr(client, "cfg"):
        client.cfg.seed = seed


def _sampled_cycle(
    arch: Architecture,
    source: Source,
    ladder,
    candidate_id: str,
    repair_budget: int,
    usage: Usage,
    samples: int,
    base_seed: int,
    normalise: bool = True,
) -> tuple[Attempt, int, list[str]]:
    """Best of ``samples`` independent cycles, the ladder as the judge.

    WHY THIS IS A FAIR THING TO DO, AND WHY IT IS HERE.
    The ladder is a verifier, and a verifier makes sampling worth something: a
    candidate either survives it or does not, so drawing several and keeping
    one that survives does not pick the answer that LOOKS best - it picks one
    that was checked. It lives in the controller, beside the repair budget, for
    the same reason the budget does: every arm gets exactly the same k, and an
    arm that could grant itself more draws would make the comparison
    meaningless. Every draw's tokens and calls are charged to the run.

    It stops at the first accepted candidate. Drawing the rest would cost
    model time and change nothing reported.
    """
    best: Attempt | None = None
    chosen = 0
    outcomes: list[str] = []
    for i in range(samples):
        if samples > 1:
            _set_seed(arch, base_seed * 1000 + i)
        a = _cycle(arch, source, ladder, f"{candidate_id}-k{i}" if samples > 1
                   else candidate_id, repair_budget, usage, normalise)
        # "+gN": N fresh draws the regex guard made before this one was judged.
        outcomes.append(f"{a.outcome}@{a.report.rung_reached}"
                        + (f"+g{a.regex_resamples}" if a.regex_resamples else ""))
        if best is None or _rank(a) > _rank(best):
            best, chosen = a, i
        if a.outcome == "accepted":
            break
    assert best is not None
    return best, chosen, outcomes


def run_once(
    arch: Architecture,
    source: Source,
    ladder,
    meta: dict[str, Any],
    repair_budget: int = 3,
    escalation=None,
    samples: int = 1,
    normalise: bool = True,
) -> RunRecord:
    """One experimental unit.

    ``escalation`` is None on the minimal deployment tier, where a failed run
    means a human writes the parser exactly as today. Graceful degradation is a
    deployment property, and it is expressed by passing None here rather than by
    a fallback hidden inside a model client.

    ``samples`` > 1 draws that many independent candidates (see
    `_sampled_cycle`). It is refused at temperature 0, where every draw is the
    same draw and k candidates would be one candidate charged k times.
    """
    if samples < 1:
        raise ValueError("samples must be at least 1")
    if samples > 1:
        cfg = getattr(getattr(arch, "client", None), "cfg", None)
        if cfg is not None and float(getattr(cfg, "temperature", 0.0)) <= 0.0:
            raise ValueError(
                f"samples={samples} at temperature 0: every draw would be identical. "
                "Set ECS_MODEL_TEMPERATURE above 0, or sample once.")
    run_id = (
        f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}_{arch.name}_"
        f"{source.source_id}_{meta['seed']}_{uuid.uuid4().hex[:6]}"
    )
    rec = RunRecord(
        run_id=run_id,
        architecture=arch.name,
        source_id=source.source_id,
        repair_budget=repair_budget,
        model=meta["model"],
        model_digest=meta["model_digest"],
        backend=meta["backend"],
        hardware_tier=meta["hardware_tier"],
        split=meta["split"],
        seed=meta["seed"],
        ecs_version=meta["ecs_version"],
        prompt_digest=meta["prompt_digest"],
    )
    usage = Usage()
    t0 = time.perf_counter()

    result, rec.sample_chosen, rec.sample_outcomes = _sampled_cycle(
        arch, source, ladder, run_id, repair_budget, usage, samples, int(meta["seed"]),
        normalise)
    rec.samples = samples
    rec.repairs = result.repairs
    rec.roles = getattr(arch, "last_roles", None)
    rec.normalisations = list(result.normalisations)
    if result.error:
        rec.findings.append(result.error)

    # ----------------------------------------------------------- escalation
    # The teacher is loaded HERE and nowhere else in the run-time path. If it
    # were resident, the minimal tier's RAM figure would be a fiction.
    if result.outcome == "failed" and escalation is not None:
        rec.escalated = True
        rec.escalation_model = escalation.model
        t_esc = time.perf_counter()
        try:
            escalated = _cycle(
                escalation, source, ladder, f"{run_id}-esc", repair_budget, usage, normalise
            )
            if escalated.outcome != "failed":
                result = escalated
                rec.roles = escalation.last_roles
            rec.repairs += escalated.repairs
            rec.normalisations.extend(escalated.normalisations)
            if escalated.error:
                rec.findings.append(escalated.error)
        finally:
            escalation.unload()
            rec.escalation_seconds = time.perf_counter() - t_esc

    # ------------------------------------------------------------- footprint
    # Sampled here, after the model work and BEFORE any unload, because an
    # escalation releases the teacher in its finally block and a reading taken
    # afterwards would report the tier as cheaper than it was.
    rec.peak_rss_mb = process_peak_rss_mb()
    resident = server_resident_mb(endpoint_of(arch))
    if resident is not None:
        rec.peak_vram_mb = resident["vram_mb"]
        rec.server_footprint = resident

    report = result.report
    rec.outcome = result.outcome
    rec.rung_reached = report.rung_reached
    rec.wall_seconds = time.perf_counter() - t0
    rec.usage = usage
    rec.ir = result.ir
    # Taken BEFORE `results` is dropped: the per-target counts live there, and
    # computing this afterwards would silently return the empty set. The same
    # mistake, in teacher/revalidate.py, cost a day of proposals in October.
    rec.verified_ecs_fields = sorted(
        v4_detection.verified_fields({"metrics": report.metrics})
    )
    rec.detection = {
        k: v for k, v in report.metrics.items() if k not in ("results", "documents")
    }
    rec.findings.extend(
        {
            "rung": f.rung,
            "code": f.code,
            "message": f.message,
            "stage": f.stage,
            "source_key": f.source_key,
        }
        for f in report.findings
    )
    rec.stage_attribution = {
        "interpretation_errors": sum(
            f.stage == STAGE_INTERPRET for f in report.findings
        ),
        "mapping_errors": sum(f.stage == STAGE_MAP for f in report.findings),
    }
    return rec

"""Phase 1a-ter - give the ladder's findings back to the teacher, once.

WHY THIS EXISTS
---------------
Measured over 240 proposals from a 32B teacher, with the corpus and the oracle
both audited:

    0 fields wrong    77 proposals    32%
    1 field  wrong    94 proposals    39%     <- one correction away
    2 fields wrong    49 proposals    20%
    3 or more         20 proposals     8%

Verification is conjunctive: V4 requires every rule for the source to pass, so
a mapping is accepted only if essentially every field is right. With per-field
accuracy at 85 per cent and eight fields, 0.85^8 is 27 per cent, and that is
what was observed. The teacher is not failing to read the logs - on fields
with no ECS synonym it scores 100 per cent - it is failing to get eight things
right at once.

Sampling more seeds attacks the wrong term. It raises the number of draws
while leaving p and n alone, so lifting Squid from 2 per cent to 90 would take
roughly 114 seeds per source. Repair attacks n: instead of drawing all eight
again, the model is told which one was wrong.

If repair fixed one field, 171 of 240 would verify instead of 77, and eleven
of the fifteen sources that currently yield nothing would yield something.

WHY THIS IS NOT A CHANGE TO THE METHOD
--------------------------------------
The deployment path already repairs. `adapter/controller.py` carries
`repair_budget: int = 3`, `prompts/repair.md` has existed since the start, and
`bench/arms.py` - which measures arm T, the teacher this distillation is from -
runs through `run_once` and therefore repairs. Phase 1a was the odd one out,
and only because it was written to be splittable across machines.

Generating the training data from a teacher that gets one attempt, while the
arm it is compared against gets four, understates the teacher and widens the
gap between T and C before a single epoch is trained.

WHY THE SPLIT IN teacher/revalidate.py SURVIVES THIS
----------------------------------------------------
That file warns that a repair loop inside generation would invalidate it,
because the model would need the validator's findings while still generating.
This is a separate PASS, run after validation, and the distinction is not a
technicality: for any one proposal the sequence is identical either way -
propose, judge, repair, judge - because no state is shared between proposals.
Only the interleaving across proposals differs, and nothing reads that.

WHAT IS AND IS NOT TOUCHED
--------------------------
Repair sees `scenario_split="repair"`, the same pool generation saw, and never
the holdout scenarios that measure the finished system. The two pools exist for
exactly this.

Every record keeps `original_ir` and gains `repair_rounds`, so "verified" can
be reported split into verified first time and verified after N corrections.
Arm T repairs too, so the comparison is fair - but it has to be stated.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
import argparse
import json
from adapter.normalise import apply_all
import os
import sys
import time

from adapter.ecs_index import DEFAULT_MAX_FIELDS
from adapter.types import ModelError, Usage
from adapter.wiring import ROOT, _ecs_index, _es, _load_known_values, _load_source, _model_client
from validators.ladder import Ladder

PROPOSALS = ROOT / "teacher" / "out" / "proposals.ndjson"


# Two or three in a row is a network, not a model having a bad day.
UNREACHABLE_LIMIT = 3

_DEAD = ("connection refused", "connection reset", "disconnected without",
         "failed to establish", "cannot connect", "connection aborted",
         "name or service not known", "timed out")


def _looks_like_a_dead_endpoint(message: str) -> bool:
    """Is this the model refusing, or the network losing the model?"""
    m = message.lower()
    return any(d in m for d in _DEAD)


def _load() -> list[dict[str, Any]]:
    if not PROPOSALS.is_file():
        sys.exit(f"{PROPOSALS} does not exist. Run:  make ecs-generate")
    return [json.loads(l) for l in PROPOSALS.read_text(encoding="utf-8").splitlines() if l.strip()]


def _write(records: list[dict[str, Any]]) -> None:
    """Atomic: this file is the only copy of hours of rented GPU."""
    tmp = PROPOSALS.with_suffix(".ndjson.tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    tmp.replace(PROPOSALS)


def _needs_repair(rec: dict[str, Any], budget: int) -> bool:
    if not rec.get("ir"):
        return False                      # generation failed; nothing to repair
    rep = rec.get("report") or {}
    if rep.get("passed"):
        return False
    if rep.get("rung_reached") in (None, "", "V0"):
        return False                      # never validated; run ecs-revalidate first
    return int(rec.get("repair_rounds", 0)) < budget


def _refuse_if_revalidate_is_running() -> None:
    """Two writers, one file, and the loser loses silently.

    Both this and teacher/revalidate.py rewrite proposals.ndjson whole, through
    a temp file and a rename, after every record. Run together, whichever
    renames last replaces the other's work with a copy that predates it. No
    error is raised, the file stays valid, and hours of validation are gone.

    Cheap to check and easy to do by accident, so it is checked.
    """
    import subprocess

    try:
        out = subprocess.run(
            ["pgrep", "-f", "teacher[.]revalidate"],
            capture_output=True, text=True, check=False,
        ).stdout.strip()
    except (OSError, FileNotFoundError):
        return                      # no pgrep: nothing to assert, say nothing
    if out:
        sys.exit(
            f"teacher.revalidate is still running (pid {out.split()[0]}).\n\n"
            "Both rewrite teacher/out/proposals.ndjson in full, so running them "
            "together loses whichever finishes first - silently, because the file "
            "stays valid.\n\n"
            "  until ! pgrep -f '[t]eacher.revalidate' >/dev/null; do sleep 30; done"
        )


# ---------------------------------------------------------------- targeted
#
# FIELD-TARGETED REPAIR (2026-10-15, the author's proposal).
#
# The whole-IR pass above asks the teacher to rewrite everything, and a rewrite
# can break mappings an oracle had already proved: round 1's pass fixed 9 of 40
# and degraded others. Here a near miss - a proposal that failed but carries at
# least one field V4 or VT verified - keeps those fields FROZEN: the model is
# told which mappings are settled, is shown only the findings about the rest,
# and whatever it answers, the frozen mappings and the extraction are restored
# by code before the ladder judges again. A prompt is a request; this makes it
# true, the same lesson as _carry_extraction and carry_demotions.
#
# Success is counted in verified fields gained, not only in sources passed:
# the corpus credits fields one at a time (teacher.filter.training_fields).

def _as_record(rec: dict[str, Any], report) -> dict[str, Any]:
    out = dict(rec)
    out["report"] = {"passed": report.passed, "rung_reached": report.rung_reached,
                     "metrics": report.metrics,
                     "findings": [f.__dict__ for f in report.findings]}
    return out


def _is_near_miss(rec: dict[str, Any]) -> bool:
    from teacher.filter import training_fields

    rep = rec.get("report") or {}
    return (bool(rec.get("ir")) and not rep.get("passed")
            and rep.get("rung_reached") in ("V3.5", "V4")
            and bool(training_fields(rec)))


def _frozen(rec: dict[str, Any]) -> frozenset[str]:
    from teacher.filter import training_fields

    return training_fields(rec)


def _restore(original: dict[str, Any], proposed: dict[str, Any],
             frozen: frozenset[str]) -> dict[str, Any]:
    """The proposed IR with the frozen mappings and the extraction put back."""
    out = json.loads(json.dumps(proposed))
    out["extraction"] = json.loads(json.dumps(original.get("extraction") or {}))
    if original.get("timestamp"):
        out["timestamp"] = original["timestamp"]
    keep = [f for f in original.get("fields") or [] if f.get("ecs_field") in frozen]
    keep_keys = {f["source_key"] for f in keep}
    out["fields"] = keep + [f for f in proposed.get("fields") or []
                            if f.get("ecs_field") not in frozen
                            and f.get("source_key") not in keep_keys]
    keep_vm = [vm for vm in original.get("value_maps") or [] if vm.get("ecs_field") in frozen]
    out["value_maps"] = keep_vm + [vm for vm in proposed.get("value_maps") or []
                                   if vm.get("ecs_field") not in frozen]
    out["unresolved"] = [u for u in proposed.get("unresolved") or []
                         if u.get("source_key") not in keep_keys]
    return out


def _targeted_report(report, frozen: frozenset[str], ir: dict[str, Any]):
    """The findings about the unsettled fields only, plus the list of settled ones."""
    from adapter.types import STAGE_MAP, Finding, ValidationReport

    settled_keys = {f["source_key"] for f in ir.get("fields") or [] if f.get("ecs_field") in frozen}
    out = ValidationReport(rung_reached=report.rung_reached)
    out.findings = [f for f in report.findings
                    if not (f.source_key in frozen or f.source_key in settled_keys)]
    settled = ", ".join(sorted(f"{f['source_key']} -> {f['ecs_field']}"
                               for f in ir.get("fields") or [] if f.get("ecs_field") in frozen))
    out.findings.insert(0, Finding(
        report.rung_reached, "settled_mappings",
        f"These mappings are VERIFIED and will be kept whatever you answer: {settled}. "
        "Do not change them; fix only what the findings below identify.", STAGE_MAP))
    return out


def repair(budget: int, only: list[str] | None, limit: int | None,
           targeted: bool = False) -> int:
    from adapter.architectures import StagedArchitecture
    from adapter.prompts import Prompts

    _refuse_if_revalidate_is_running()

    records = _load()
    ecs = _ecs_index()
    es = _es()
    if es is None:
        sys.exit(
            "No Elasticsearch. Repair without V4 would feed the model the findings of "
            "a ladder that stopped at V2, which is worse than not repairing.\n"
            "  export ELASTICSEARCH_HOST ELASTICSEARCH_CA ELASTIC_USER ELASTIC_PASSWORD"
        )
    prompts = Prompts(ROOT / "prompts")
    teacher_model = os.environ.get("ECS_TEACHER_MODEL") or os.environ.get("ECS_MODEL_NAME", "")
    if not teacher_model:
        sys.exit("Set ECS_TEACHER_MODEL to the teacher that produced these proposals.")

    todo = [r for r in records if _needs_repair(r, budget)
            and (not targeted or _is_near_miss(r))]
    if only:
        todo = [r for r in todo if r["source_id"] in only]
    if limit:
        todo = todo[:limit]

    print(f"teacher      : {teacher_model}")
    print(f"proposals    : {len(records)}")
    print(f"already pass : {sum(1 for r in records if (r.get('report') or {}).get('passed'))}")
    print(f"to repair    : {len(todo)}   (budget {budget} round(s) each)")
    if not todo:
        print("nothing to do.")
        return 0

    ladders: dict[str, Ladder] = {}
    fixed = still = 0
    consecutive_unreachable = 0
    for n, rec in enumerate(todo, 1):
        sid = rec["source_id"]
        source, _ = _load_source(sid)
        if sid not in ladders:
            ladders[sid] = Ladder(
                ecs, source, es, ROOT / "bench",
                os.environ.get("STACK_VERSION", "8.19.7"),
                scenario_split="repair",
                known_values=_load_known_values(sid),
            )
        ladder = ladders[sid]

        client = _model_client(seed=rec["seed"])
        client.cfg.model = teacher_model
        arch = StagedArchitecture(client, prompts, ecs,
                                  rec.get("max_fields") or DEFAULT_MAX_FIELDS, name="T")
        # Resume the architecture where generation left it, rather than
        # re-running Stage 1: the roles are in the record, and re-interpreting
        # would change the premise the IR was built on.
        arch._source = source
        arch.last_roles = rec.get("roles")

        ir = rec["ir"]
        rec.setdefault("original_ir", json.loads(json.dumps(ir)))
        rounds = int(rec.get("repair_rounds", 0))
        usage = Usage()
        t0 = time.perf_counter()

        # THE DETERMINISTIC LAYER RUNS BEFORE EVERY JUDGEMENT, HERE TOO.
        #
        # This is the third place the same defect was found. adapter/controller
        # normalises before the ladder; teacher/revalidate did not until A10;
        # teacher/generate did not until the same day, and lost every prose
        # proposal for the appsvc family to a `duplicate_ecs_target` the layer
        # resolves. Repair is the fourth caller and had the same gap: it would
        # ask the model to fix findings that were never going to be raised
        # against the IR the deployed system actually judges.
        #
        # bench/mutate.py is the one caller that must NOT do this. It corrupts
        # an IR on purpose to check the ladder notices; normalising there would
        # repair the mutation and the test would pass for the wrong reason.
        _lines = list(source.parser_input())
        ir, _ = apply_all(ir, _lines, ecs)

        # A live report: the stored one is a dict, and repair needs the object
        # that knows how to phrase its own findings and which stage to blame.
        report = ladder.run(ir, candidate_id=f"rep-{sid}-{rec['seed']}-0")

        unreachable = False
        frozen = _frozen(_as_record(rec, report)) if targeted else frozenset()
        credited_before = len(frozen)
        while not report.passed and rounds < budget:
            try:
                if targeted:
                    settled = ir
                    ir = _restore(settled, arch.repair(ir, _targeted_report(report, frozen, ir),
                                                       usage), frozen)
                else:
                    ir = arch.repair(ir, report, usage)
            except ModelError as exc:
                rec["repair_error"] = str(exc)
                unreachable = _looks_like_a_dead_endpoint(str(exc))
                break
            rounds += 1
            ir, _ = apply_all(ir, _lines, ecs)
            if targeted:
                ir = _restore(settled, ir, frozen)
            report = ladder.run(ir, candidate_id=f"rep-{sid}-{rec['seed']}-{rounds}")
            if targeted:
                # A field verified in this round is settled for the next one.
                frozen = frozen | _frozen(_as_record(rec | {"ir": ir}, report))

        # A DEAD ENDPOINT IS NOT A FAILED REPAIR, AND MUST NOT BE RECORDED AS ONE.
        #
        # An SSH tunnel to a rented card dies quietly: the process stays up and
        # the socket starts refusing. This loop then walked 32 proposals in a
        # row, each raising "Connection refused", each recorded as repaired
        # with zero rounds, each still failing. The run reported 166 of 166
        # done. Twenty-nine of the thirty windows-security proposals - the
        # family the pass existed to measure - were never shown to a model at
        # all, and nothing in the output said so.
        #
        # Those records stay retryable, because `repair_rounds` is 0 and
        # `_needs_repair` admits anything below the budget. What was missing is
        # that the run should have stopped.
        if unreachable:
            consecutive_unreachable += 1
            if consecutive_unreachable >= UNREACHABLE_LIMIT:
                _write(records)
                sys.exit(
                    f"\nSTOPPED: the model endpoint refused {consecutive_unreachable} "
                    f"calls in a row.\n  {rec.get('repair_error')}\n\n"
                    f"{n - consecutive_unreachable} proposal(s) were repaired before "
                    "that. The rest are untouched and will be retried on the next "
                    "run.\n\n"
                    "If the model is behind an SSH tunnel, the tunnel is probably up "
                    "and dead at the same time. Reopen it with a keepalive so it "
                    "exits instead of lying:\n"
                    "  ssh -N -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \\\n"
                    "      -o ExitOnForwardFailure=yes -L 11434:127.0.0.1:11434 ..."
                )
        else:
            consecutive_unreachable = 0

        rec["ir"] = ir
        rec["roles"] = arch.last_roles
        rec["repair_rounds"] = rounds
        if targeted:
            rec["repair_mode"] = "targeted"
            rec["credited_before_repair"] = credited_before
        rec["report"] = {
            "passed": report.passed,
            "rung_reached": report.rung_reached,
            "metrics": report.metrics,
            "findings": [f.__dict__ for f in report.findings],
        }
        if report.passed:
            fixed += 1
        else:
            still += 1
        gained = (f" fields {credited_before}->{len(_frozen(rec))}" if targeted else "")
        print(f"  {sid:<30} seed={rec['seed']:<2} rounds={rounds} "
              f"{'FIXED' if report.passed else 'still ' + report.rung_reached:<10}{gained} "
              f"{time.perf_counter() - t0:>6.1f}s   [{n}/{len(todo)}]")
        _write(records)        # after every one: the GPU time is not recoverable

    print(f"\nrepaired to passing : {fixed}")
    print(f"still failing       : {still}")
    print(f"total passing now   : {sum(1 for r in records if (r.get('report') or {}).get('passed'))}"
          f"/{len(records)}")
    print("\nNext:  make ecs-filter")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--budget", type=int, default=3, help="repair rounds per proposal")
    p.add_argument("--only", nargs="*", help="restrict to these source ids")
    p.add_argument("--limit", type=int, help="stop after this many proposals")
    p.add_argument("--targeted", action="store_true",
                   help="near misses only; verified fields frozen, feedback on the rest")
    a = p.parse_args(argv)
    return repair(a.budget, a.only, a.limit, a.targeted)


if __name__ == "__main__":
    raise SystemExit(main())

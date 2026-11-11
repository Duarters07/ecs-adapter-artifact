"""Phase 1a-bis - run the ladder over proposals that were generated elsewhere.

WHY THIS EXISTS
---------------
Generation and validation want opposite machines.

  generation   180 model calls against a 32B teacher. Wants a GPU, wants
               nothing else, and is billed by the hour.
  validation   the ladder. V3 launches an isolated Logstash container per
               candidate and V4 queries a running Elasticsearch. Wants Docker
               and the SIEM stack, and is pure CPU work that no GPU accelerates.

Renting a GPU machine that can also run Docker-in-Docker is the awkward
requirement, not renting a GPU. Splitting the two removes it: generate on the
rented card with --skip-v3 --skip-v4, bring back one NDJSON file, and run the
ladder at home where Docker already works.

WHY THE SPLIT IS SOUND, AND WHEN IT WOULD NOT BE
------------------------------------------------
Phase 1a proposes once per (source, seed) and never repairs: teacher/generate.py
calls `arch.propose` a single time and the ladder only judges the result. No
validator output is ever fed back into a prompt, so nothing the ladder computes
can change what the teacher would have produced.

That is the whole argument. If GENERATION ever gains an inline repair loop,
this file becomes wrong and must be deleted rather than adapted, because the
model would then need the validator's findings while it is still generating.

A repair PASS is a different thing and does not break it. teacher/repair.py
runs after this file, hands the findings back and re-validates. For any one
proposal the sequence is identical to an inline loop - propose, judge, repair,
judge - because no state is shared between proposals; only the interleaving
across them differs, and nothing reads that. The check to apply is not "does
repair happen" but "does the model see a validator's output before the
proposal that output is about".

The deployment path (adapter/main.py) DOES repair, and is unaffected: it runs
the ladder inline, on one machine, as it always did.

WHAT IT REWRITES, AND WHAT IT REFUSES TO TOUCH
----------------------------------------------
Only `report`, plus a `validation` block recording that the two halves ran
apart and when. The proposal itself - the IR, the roles, the teacher, the seed,
the prompt digest - is what the teacher produced and is never modified. A record
whose generation raised a ModelError has no IR to validate and is left exactly
as it is.

Validation uses `scenario_split="repair"`, the same split generation uses. The
holdout scenarios measure the finished system and must not be visible to
anything that produces training data - including this.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import argparse
import json
import os
import sys
import time

from adapter.wiring import ROOT, _ecs_index, _es, _load_known_values, _load_source

OUT_DIR = ROOT / "teacher" / "out"
# PARALLEL SHARDS, AND WHY THE FILE IS OVERRIDABLE.
#
# `_write` rewrites the WHOLE proposals file every CHECKPOINT_EVERY records, so
# two processes pointed at it destroy each other's work: the last writer wins
# and everything the other revalidated is gone. Revalidating 383 proposals
# serially takes about nineteen hours, because each one spins a Logstash
# container for V3 and replays detections for V4.
#
# So each worker is given its own copy through ECS_PROPOSALS_FILE, revalidates
# a disjoint set of sources with --only, and the shards are merged afterwards.
# Nothing about the ladder changes; only which file the records live in.
PROPOSALS = Path(
    os.environ.get("ECS_PROPOSALS_FILE") or (OUT_DIR / "proposals.ndjson")
)


def _read(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        sys.exit(
            f"{path} does not exist.\n"
            "Generate first, here or on the rented machine:\n"
            "  make ecs-generate N=6 ARGS=\"--skip-v3 --skip-v4\""
        )
    out: list[dict[str, Any]] = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            # A partial last line from an interrupted generation run. Anything
            # earlier is a corrupted file and worth stopping for.
            sys.exit(f"{path}:{i} is not valid JSON. Refusing to rewrite the file.")
    return out


# WHICH APPARATUS JUDGED THIS RECORD.
#
# Bumped whenever a change to the ladder or the deterministic layer alters what
# the corpus accepts. A record carries the stamp of the apparatus that produced
# its verdict, which does two things: a resumed run knows what is genuinely
# done, and a reader of the corpus can tell records judged under different
# rules apart instead of having to trust that they were not.
#
# v2 (2026-10-11): A1-A10 - the grok library, double-escaping in the probe and
# in the compiler, the unknown-pattern check, JSON leaf accounting, the
# deterministic layer applied here at all.
# v3 (2026-10-11, later): A12 faithful URI, A13 the chain now tests every
# line the parser will face (probe included), and the grok target is every
# line rather than 80% - V3 does not tolerate one tagged line.
# v4 (2026-10-12): A14 - PATH, UNIXPATH and URIPATH require a leading slash in
# real grok and were approximated as `\S+`, so the probe accepted
# `%{PATH:exe}` against `sudo` and the sandbox refused every
# syn_linux_auditd_prose proposal. The change is NOT one-sided - a stricter
# approximation can fail a pattern the previous one passed - so every record
# is rejudged rather than re-stamped.
# v5 (2026-10-12): A15 and A16 - the per-scenario verdicts are recorded rather
# than discarded, and each target is counted alone so that a correct field is
# not denied credit by the wrong field beside it in the same rule. No VERDICT
# moves, which is why the stamp was almost left alone - and that would have
# been a mistake, because the stamp is also the resume key. A record judged
# before A16 looks current to --force, is skipped, and keeps a report from
# which field-level credit cannot be computed. The rule is therefore not "bump
# when a verdict could change" but "bump when the RECORD changes", which is the
# wider of the two and the one that keeps resume honest.
# v6, 2026-10-14. The deterministic layer gained four rules since v5 and the
# verdicts they change are not marginal: replaying stage F's arm C runs through
# it took V2 from 6 of 24 to 12 of 24 with no model involved.
#   reconcile_csv_columns              a short column list, padded from the line
#   dedupe_grok_captures               a repeated capture name does not compile
#   drop_literals_absent_from_every_line  a literal no sample carries
#   declare_captured_but_unmapped      the IR disagreeing with its own extraction
# plus HOST/PID/PROGRAM in the alias table and key-coverage metrics in V2.
# A record stamped v5 was judged by a weaker ladder and is NOT done.
# v7, 2026-10-14, later. The IR gained grok `alternatives` and nested JSON keys,
# and V2 and every grok repair in the deterministic layer now reason per
# pattern. The V2 finding for a partial grok match changed its text, and a JSON
# IR with a dotted key now compiles to a field that can be filled. The first
# rejudging under v7 also ran V3 natively (ECS_SANDBOX_LOGSTASH) on the rented
# card rather than in Docker at home; same Logstash version, same template.
#
# v8, 2026-10-17. Field types follow the ECS index and are no longer V1's to
# refuse; named groups count as captures in either spelling; V2 shows further
# missed shapes and V4 the values a rule wanted beside those the parser wrote;
# 70 orphan scenarios (filesvc, netflow) no longer replayed. Round-1 teacher
# proposals are re-judged under v8 so that gold and teacher are credited by
# the same ladder (PILOT_GS.md, round 2).
APPARATUS = "v8-20261017"


def _needs_work(rec: dict[str, Any], force: bool) -> bool:
    if rec.get("ir") is None:
        return False  # generation failed; there is nothing to run the ladder on
    if force:
        # Records already judged by THIS apparatus are done, even under
        # --force: otherwise an interrupted run restarts from zero, and this
        # one takes about seven hours.
        if (rec.get("validation") or {}).get("apparatus") != APPARATUS:
            return True
        # Belt and braces for the failure that produced this guard. The stamp
        # is a thing a human remembers to bump, and on 2026-10-12 one was not:
        # A16 began recording a per-target count beside each scenario verdict,
        # the stamp stayed, and a rerun skipped 20 of 24 records as done while
        # leaving them without the one field the credit is computed from. A
        # record that reached V4 and carries scenario results but no per-target
        # counts is not done, whatever its stamp says.
        results = ((rec.get("report") or {}).get("metrics") or {}).get("results")
        if results and not any(r.get("per_target") for r in results):
            return True
        return False
    return "validation" not in rec


# Findings that say the MACHINE is wrong, not the proposal.
#
# A proposal judged against a broken sandbox is not judged at all. Recording it
# as a parser failure is worse than recording nothing: `make ecs-filter` would
# read ninety environmental errors as ninety bad mappings, Gate 2 would report a
# teacher yield of zero, and the honest conclusion - "a fully local teacher
# cannot supply these fields" - would be drawn from a missing binary.
#
# It happened. Debian 13 split `docker.io` and the client moved to `docker-cli`;
# the image installed the old package, reported success, and shipped without
# /usr/bin/docker. Every V3 run failed in 0.0s and all ninety were written down
# as results.
ENVIRONMENTAL = frozenset({"docker_unavailable", "logstash_timeout", "no_documents"})


def _environmental(report) -> str | None:
    """The code of the first finding that indicts the machine, if any."""
    for f in report.findings:
        code = getattr(f, "code", None)
        if code in ENVIRONMENTAL:
            return code
    return None


# How often the file is rewritten while a run is in progress.
#
# The rewrite is atomic - temp file, then replace - because this file is the
# whole output of a rented session and a crash must not be able to truncate it.
# Writing ONLY at the end made the run all-or-nothing: a validation pass takes
# around two hours, and interrupting it discarded every record already
# revalidated, because nothing had reached disk. Checkpointing keeps the
# atomicity and bounds the loss to the records since the last one.
# Lowered from 10 on 2026-10-12. A checkpoint is a whole-file rewrite of a few
# megabytes, which is nothing next to the ~200s a single proposal costs, and the
# window it bounds is what an interrupted run loses. Three restarts in one
# morning made that window the expensive number, not the write.
CHECKPOINT_EVERY = 5


def _write(records: list[dict[str, Any]]) -> None:
    tmp = PROPOSALS.with_suffix(".ndjson.tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, sort_keys=True, default=str) + "\n")
    tmp.replace(PROPOSALS)


def revalidate(force: bool, only: list[str] | None) -> int:
    from validators.ladder import Ladder

    records = _read(PROPOSALS)
    ecs = _ecs_index()
    es = _es()
    stack_version = os.environ.get("STACK_VERSION", "8.19.7")

    todo = [
        r for r in records
        if _needs_work(r, force) and (not only or r.get("source_id") in only)
    ]
    no_ir = sum(1 for r in records if r.get("ir") is None)

    print(f"proposals    : {len(records)}")
    print(f"to validate  : {len(todo)}")
    print(f"no IR        : {no_ir}  (generation failed; left untouched)")
    print(f"already done : {len(records) - len(todo) - no_ir}")
    print()
    if not todo:
        print("Nothing to do. Next:  make ecs-filter")
        return 0

    # THE CORPUS MUST BE BUILT UNDER THE APPARATUS IT IS CONSUMED BY.
    #
    # This module used to call the ladder directly, while the run loop in
    # adapter/controller.py normalises first. So a proposal the deployed system
    # would accept could still be refused when deciding whether it becomes a
    # training example, and the corpus systematically under-represented what
    # the method can do.
    #
    # Measured on 2026-10-11: revalidating all 387 proposals against the
    # repaired LADDER recovered exactly zero extra cases - the same 213, the
    # same 7 grok - because the rule that matters most for grok lives in the
    # deterministic layer and never ran here. On those same proposals it takes
    # the patterns matching every sample line from 24 to 44.
    from adapter.normalise import apply_all

    # One ladder per source: constructing it loads the source and its scenarios.
    ladders: dict[str, Any] = {}
    sources: dict[str, Any] = {}
    passed = 0
    done = 0

    for rec in todo:
        source_id = rec["source_id"]
        if source_id not in ladders:
            source, _ = _load_source(source_id)
            sources[source_id] = source
            ladders[source_id] = Ladder(
                ecs, source, es, ROOT / "bench", stack_version,
                scenario_split="repair",
                known_values=_load_known_values(source_id),
            )

        t0 = time.perf_counter()
        # The lines the parser will face, probe included. See the note in
        # adapter/controller.py: a pattern matching every sample can still be
        # tagged by the sandbox on the one line nothing checked it against.
        _lines = list(sources[source_id].parser_input())
        rec["ir"], _normalisations = apply_all(rec["ir"], _lines, ecs)
        report = ladders[source_id].run(
            rec["ir"], candidate_id=f"reval-{source_id}-{rec['seed']}"
        )
        elapsed = round(time.perf_counter() - t0, 2)

        rec["report"] = {
            "passed": report.passed,
            "rung_reached": report.rung_reached,
            "metrics": {
                # `results` is KEPT: the per-scenario verdicts are the only
                # record of which fields a passing scenario proved, and a
                # proposal rejected as a whole can still carry field mappings
                # that detection confirmed. Dropping it made every rescoring a
                # full re-run of Logstash. `documents` never reaches here - see
                # validators/ladder.py, which keeps only the count.
                k: v for k, v in report.metrics.items()
                if k not in ("documents",)
            },
            "findings": [asdict(f) for f in report.findings],
        }
        rec["normalisations"] = _normalisations
        rec["validation"] = {
            "apparatus": APPARATUS,
            # Recorded because it is a real difference in how the number was
            # produced, and a reader of the corpus is entitled to know.
            "separated_from_generation": True,
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "stack_version": stack_version,
            "scenario_split": "repair",
            "wall_seconds": elapsed,
        }

        status = "PASS" if report.passed else f"fail@{report.rung_reached}"
        passed += bool(report.passed)
        done += 1
        print(f"  {source_id:<20} seed={rec['seed']:<3} {status:<10} {elapsed:>7.1f}s")

        if done % CHECKPOINT_EVERY == 0:
            _write(records)

        # Stop on the first environmental failure, before anything is written.
        # A sandbox that cannot start will not start for the eighty-nine after
        # this one either, and grinding through them buries the cause under a
        # page of identical lines that look like findings about the proposals.
        env = _environmental(report)
        if env is not None:
            sys.exit(
                f"\n{source_id} seed={rec['seed']} did not fail validation - "
                f"validation could not run: {env}.\n"
                "Nothing has been written; the file is unchanged.\n\n"
                "  docker_unavailable  the adapter container has no docker client, or "
                "cannot reach\n"
                "                      the socket. Check with:\n"
                "                        docker exec siem-ecs-adapter docker version\n"
                "                      and rebuild if it is missing.\n"
                "  logstash_timeout    the sandbox started but did not finish. Check "
                "the host's load\n"
                "                      and that the Logstash image for STACK_VERSION "
                "is present.\n"
            )

    _write(records)

    print(f"\n{len(todo)} validated, {passed} passed.")
    print("Next:  make ecs-filter")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="teacher.revalidate", description=__doc__.splitlines()[0]
    )
    p.add_argument(
        "--force", action="store_true",
        help="re-run the ladder on proposals already validated (default: skip them)",
    )
    p.add_argument("--only", nargs="*", help="restrict to these source ids")
    a = p.parse_args(argv)
    return revalidate(a.force, a.only)


if __name__ == "__main__":
    raise SystemExit(main())

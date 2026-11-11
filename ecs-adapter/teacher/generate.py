"""Phase 1a - the teacher proposes, over the training pool.

This is where the training data comes from. It is not collected, downloaded or
hand-labelled: the teacher generates it and the ladder filters it (teacher/filter.py).

Four decisions are worth stating, because each of them is a place where a
plausible shortcut would quietly invalidate the result.

  Repeated sampling      One greedy proposal per source yields too few verified
                         examples to train on. Diversity is what the filter needs
                         to select from, so each source is proposed n times at a
                         non-zero temperature with distinct seeds.

  Everything is kept     Every proposal is written, passing or failing, with its
                         full validation report. The REJECTS are the data behind
                         "teacher yield by field difficulty", which is Gate 2.
                         Discarding them would throw the gate away.

  The pool boundary      Asserted at start-up, against the declared splits. A
                         training source that is also an evaluation source makes
                         every number downstream meaningless, so this refuses to
                         start rather than warning.

  Append-only            A 32B on CPU takes hours to a day. The job must survive
                         being interrupted, so each proposal is flushed as one
                         NDJSON line and an existing (source, seed) is skipped.
"""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any
import argparse
import json
import os
import sys
import time

from adapter.ecs_index import DEFAULT_MAX_FIELDS
from adapter.wiring import ROOT, _ecs_index, _es, _load_known_values, _load_source, _model_client

OUT_DIR = ROOT / "teacher" / "out"
PROPOSALS = OUT_DIR / "proposals.ndjson"

TRAINING_SPLIT = "train"
EVALUATION_SPLIT = "test"


# --------------------------------------------------------------------- the pool
# How many consecutive unreachable proposals before giving up. Three tells a
# dropped tunnel from one unlucky call, and costs three empty slots at most.
UNREACHABLE_LIMIT = 3


def training_pool() -> list[tuple[str, dict[str, Any]]]:
    """Sources declared ``split: train``, with the boundary checked."""
    sources_dir = ROOT / "bench" / "sources"
    by_family: dict[str, set[str]] = {}
    pool: list[tuple[str, dict[str, Any]]] = []

    for d in sorted(p for p in sources_dir.iterdir() if p.is_dir()):
        truth_path = d / "truth.json"
        if not truth_path.is_file():
            continue
        truth = json.loads(truth_path.read_text(encoding="utf-8"))
        split = truth.get("split")
        family = truth.get("family", truth.get("source_id", d.name))
        by_family.setdefault(family, set()).add(split)
        if split == TRAINING_SPLIT:
            pool.append((d.name, truth))

    # "test_id" (PLAN_R2.md) is an evaluation pool too: the in-distribution
    # test families must be as absent from training as the real held-out.
    crossing = {
        f: sorted(s) for f, s in by_family.items()
        if TRAINING_SPLIT in s and s & {EVALUATION_SPLIT, "test_id"}
    }
    if crossing:
        sys.exit(
            "Refusing to generate: these source families are in BOTH the training "
            f"and the evaluation pool: {crossing}\n"
            "Every number downstream of this run would be meaningless. Fix the "
            "splits in bench/sources/*/truth.json first."
        )
    return pool


def _done(path: Path) -> set[tuple[str, int]]:
    """(source_id, seed) pairs already on disk, so the job is resumable."""
    if not path.is_file():
        return set()
    out: set[tuple[str, int]] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
            out.add((rec["source_id"], int(rec["seed"])))
        except (json.JSONDecodeError, KeyError, ValueError):
            continue  # a partial last line from an interrupted run
    return out


# --------------------------------------------------------------------- the run
def generate(
    n: int,
    base_seed: int,
    temperature: float,
    only: list[str] | None,
    max_fields: int,
    skip_v3: bool,
    skip_v4: bool,
) -> int:
    from adapter.architectures import StagedArchitecture, schema_digest
    from adapter.ecs_index import retrieval_digest
    from adapter.model_client import ModelError
    from adapter.normalise import apply_all
    from adapter.prompts import Prompts
    from adapter.types import Usage
    from validators.ladder import Ladder

    pool = [(sid, t) for sid, t in training_pool() if not only or sid in only]
    if not pool:
        sys.exit(
            "The training pool is empty. Mark sources with \"split\": \"train\" in "
            "bench/sources/<id>/truth.json, or pass --only."
        )

    ecs = _ecs_index()
    prompts = Prompts(ROOT / "prompts")
    es = _es()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    already = _done(PROPOSALS)

    teacher_model = os.environ.get("ECS_TEACHER_MODEL") or os.environ.get("ECS_MODEL_NAME", "")
    # SELF-TRAINING (expert iteration, PILOT_GS.md round 2): the trained student
    # proposes over the training pool, the ladder judges as it judges the
    # teacher, and what it verifies may join the next round's data. Recorded as
    # `student:<interpret>|<map>` so its examples stay countable on their own.
    student = os.environ.get("ECS_GENERATE_STUDENT", "").strip() in ("1", "true", "yes")
    s_int = os.environ.get("ECS_STUDENT_INTERPRET_MODEL", "").strip()
    s_map = os.environ.get("ECS_STUDENT_MAP_MODEL", "").strip()
    if student:
        if not (s_int and s_map):
            sys.exit("ECS_GENERATE_STUDENT needs ECS_STUDENT_INTERPRET_MODEL and ECS_STUDENT_MAP_MODEL.")
        teacher_model = f"student:{s_int}|{s_map}"
    if not teacher_model:
        sys.exit("Set ECS_TEACHER_MODEL (or ECS_MODEL_NAME) to the teacher you are generating with.")

    print(f"teacher      : {teacher_model}")
    print(f"sources      : {len(pool)}  ({', '.join(sid for sid, _ in pool)})")
    print(f"proposals    : {n} per source, seeds {base_seed}..{base_seed + n - 1}")
    print(f"already done : {len(already)}")
    print(f"writing to   : {PROPOSALS}")
    print()

    written = 0
    with PROPOSALS.open("a", encoding="utf-8") as fh:
        unreachable = 0
        for source_id, truth in pool:
            source, _ = _load_source(source_id)
            ladder = Ladder(
                ecs, source, es, ROOT / "bench",
                os.environ.get("STACK_VERSION", "8.19.7"),
                # Generation validates against the REPAIR split only. The holdout
                # scenarios exist to measure the finished system and must never
                # be visible to the process that produces its training data.
                scenario_split="repair",
                known_values=_load_known_values(source_id),
                skip_v3=skip_v3,
                skip_v4=skip_v4,
            )

            for i in range(n):
                seed = base_seed + i
                if (source_id, seed) in already:
                    continue

                client = _model_client(seed=seed)
                client.cfg.temperature = temperature
                if student:
                    arch = StagedArchitecture(client, prompts, ecs, max_fields, name="C",
                                              interpret_model=s_int, map_model=s_map)
                else:
                    client.cfg.model = teacher_model
                    arch = StagedArchitecture(client, prompts, ecs, max_fields, name="T")

                usage = Usage()
                t0 = time.perf_counter()
                roles: dict[str, Any] | None = None
                ir: dict[str, Any] | None = None
                error: str | None = None
                try:
                    ir = arch.propose(source, usage)
                    roles = arch.last_roles
                    # THE SAME APPARATUS THAT WILL CONSUME THIS MUST JUDGE IT.
                    #
                    # A10 was fixed in teacher/revalidate.py and missed here.
                    # Generation called the ladder directly while the run loop
                    # in adapter/controller.py normalises first, so a proposal
                    # the deployed system would accept could still be refused
                    # when deciding whether it becomes a training example.
                    #
                    # Measured on syn_appsvc_prose, 2026-10-11: six of six
                    # seeds died at V1 on `duplicate_ecs_target` - a finding
                    # the deterministic layer resolves by keeping the
                    # higher-confidence claim. The corpus was losing exactly
                    # the prose proposals it most needs.
                    ir, _norm = apply_all(ir, list(source.parser_input()), ecs)
                    report = ladder.run(ir, candidate_id=f"gen-{source_id}-{seed}")
                except ModelError as exc:
                    from adapter.types import ValidationReport
                    from bench.arms import _looks_like_a_dead_endpoint

                    # A MODEL THAT IS NOT THERE IS NOT A PROPOSAL.
                    #
                    # This wrote the record anyway - `ir: null`, `calls=0`,
                    # `0.0s` - counted it and carried on. On 2026-10-11 an SSH
                    # tunnel to the rented card went down mid-run: generation
                    # wrote 116 empty records for the three new families,
                    # printed "116 new proposals written" and exited
                    # successfully. Nothing in the output said the teacher had
                    # never been asked anything.
                    #
                    # The predicate is imported from bench/arms.py rather than
                    # restated, so the two cannot drift about what
                    # "unreachable" means.
                    if _looks_like_a_dead_endpoint(str(exc)):
                        unreachable += 1
                        print(f"  {source_id:<20} seed={seed} UNREACHABLE "
                              f"({unreachable}/{UNREACHABLE_LIMIT}): "
                              f"{str(exc)[:80]}", flush=True)
                        if unreachable >= UNREACHABLE_LIMIT:
                            fh.flush()
                            raise SystemExit(
                                f"\n{UNREACHABLE_LIMIT} proposals in a row could "
                                f"not reach the teacher.\nNothing empty was "
                                f"written; what is in the file was really "
                                f"proposed.\n\n  If the model is served over an "
                                f"SSH tunnel, the tunnel is down. Reopen it and "
                                f"run again - completed seeds are skipped.\n"
                            )
                        continue

                    report = ValidationReport()
                    error = str(exc)

                unreachable = 0
                record = {
                    "source_id": source_id,
                    "family": truth.get("family", source_id),
                    "seed": seed,
                    "teacher": teacher_model,
                    "temperature": temperature,
                    "prompt_digest": prompts.digest,
                    # What the model was allowed to answer, not only what it was
                    # asked. The schemas are sent as structured output and
                    # constrain generation; see architectures.schema_digest.
                    "schema_digest": schema_digest(),
                    # Which 240 of 1659 ECS fields it was shown. A change here
                    # is a different question, and it used to be invisible.
                    "retrieval_digest": retrieval_digest(),
                    "ecs_version": ecs.version,
                    "roles": roles,
                    "ir": ir,
                    "error": error,
                    "report": {
                        "passed": report.passed,
                        "rung_reached": report.rung_reached,
                        "metrics": {
                            # See teacher/revalidate.py: `results` carries the
                            # per-scenario verdicts and their targets, which is
                            # what field-level credit is computed from.
                            k: v for k, v in report.metrics.items()
                            if k not in ("documents",)
                        },
                        "findings": [asdict(f) for f in report.findings],
                    },
                    "usage": asdict(usage),
                    "wall_seconds": round(time.perf_counter() - t0, 2),
                }
                fh.write(json.dumps(record, sort_keys=True, default=str) + "\n")
                fh.flush()  # a day-long job must survive being killed
                written += 1

                status = "PASS" if report.passed else f"fail@{report.rung_reached}"
                print(
                    f"  {source_id:<20} seed={seed:<3} {status:<10} "
                    f"{record['wall_seconds']:>7.1f}s  calls={usage.calls}"
                )

    print(f"\n{written} new proposal(s) written to {PROPOSALS}")
    print("Next:  make ecs-filter")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="teacher.generate", description=__doc__.splitlines()[0]
    )
    p.add_argument("-n", type=int, default=6, help="proposals per source (default 6)")
    p.add_argument("--seed", type=int, default=0, help="first seed (default 0)")
    p.add_argument(
        "--temperature", type=float, default=0.7,
        help="non-zero on purpose: the filter needs diversity to select from",
    )
    p.add_argument("--only", nargs="*", help="restrict to these source ids")
    p.add_argument("--max-fields", type=int, default=DEFAULT_MAX_FIELDS)
    p.add_argument("--skip-v3", action="store_true")
    p.add_argument("--skip-v4", action="store_true")
    a = p.parse_args(argv)
    return generate(
        a.n, a.seed, a.temperature, a.only, a.max_fields, a.skip_v3, a.skip_v4
    )


if __name__ == "__main__":
    raise SystemExit(main())

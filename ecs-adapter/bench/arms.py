"""Run the four arms over the evaluation pool.

    A   7B,  combined  untrained   is decomposition needed at all?
    B   7B,  staged    untrained   decomposition without training
    T   32B, staged    untrained   THE TEACHER - the ceiling to beat
    C   7B,  staged    TRAINED     the proposal

The headline is C vs T: small trained student against large untrained teacher,
same task, same hardware, both local. The other two isolate the variables -
C vs B is training at fixed size and shape, B vs A is decomposition with no
training anywhere, T vs B is what size alone buys.

Three things this runner enforces, all of which are ways a comparison like this
normally goes wrong:

  same fields     every arm is offered the identical ECS subset, and the subset
                  recall is recorded per source. If the arms saw different
                  candidates the experiment would measure retrieval.

  same budget     the repair budget is passed to the controller, which owns it.
                  No arm can grant itself another attempt.

  holdout only    scenarios come from the holdout split. The repair split is
                  what the loop is allowed to see; grading on it would let the
                  method fit its own tests.

Failures and abstentions stay in the denominator. Reporting only the accepted
candidates would describe a triumph while the system failed most of the time.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any
import argparse
import functools
import json
import os
import sys
import time

from adapter.architectures import VARIANTS
from adapter.ecs_index import DEFAULT_MAX_FIELDS
from adapter.wiring import (
    ROOT,
    _ecs_index,
    bench_root,
    _es,
    _load_known_values,
    _load_source,
    _model_client,
    _student_models,
)

RESULTS = ROOT / "results"
EVALUATION_SPLIT = "test"

# A DEAD ENDPOINT IS NOT A FAILED RUN, AND MUST NOT BE RECORDED AS ONE.
#
# When the model is served over an SSH tunnel to a rented card, the tunnel dies
# quietly: the ssh process stays up and the socket starts refusing. In Phase 1
# the repair pass walked 32 proposals that way, each raising "Connection
# refused", each written down as a genuine failure, and the run reported itself
# complete. The family the pass existed to measure was never shown to a model
# at all.
#
# So: a run that fails for a reason that looks like the network, rather than
# the model, is not written. After UNREACHABLE_LIMIT of them in a row the study
# stops, because the thirty-seventh will not go better than the third and every
# one of them corrupts the record.
UNREACHABLE_LIMIT = 3
_DEAD = ("connection refused", "connection reset", "disconnected without",
         "failed to establish", "cannot connect", "connection aborted",
         "name or service not known", "timed out", "read timeout")


def _looks_like_a_dead_endpoint(message: str) -> bool:
    """Is this the model refusing, or the network losing the model?"""
    m = message.lower()
    return any(d in m for d in _DEAD)

# Which model each arm is served by. B and C share a base; C adds the adapters,
# which Ollama exposes under a separate model name.
ARM_MODEL_ENV = {
    "A": "ECS_MODEL_NAME",
    "B": "ECS_MODEL_NAME",
    "T": "ECS_TEACHER_MODEL",
    "C": "ECS_STUDENT_MODEL",
}


# THE ROUND-1 POOL, NAMED SO IT CAN BE KEPT APART.
#
# These eight carried split "test" through round 1 and were then read to
# diagnose why the students failed (FAILURE_CATALOGUE.md, M10). A pool that has
# informed the method is a development set, whatever its truth.json says, so
# round 2 reports them as `dev` and never as out-of-distribution evidence
# (PLAN_R2.md). Listed by id rather than re-labelled on disk, so that every
# round-1 record stays reproducible against the files it was produced from.
ROUND1_DEV = (
    "fail2ban_jail", "postfix_smtpd", "postgres_csv", "sshd_auth",
    "suricata_eve", "traefik_access", "vsftpd_xfer", "zeek_conn",
)
# SIEMgen families held out of training whole, for the in-distribution test.
IN_DISTRIBUTION_SPLIT = "test_id"
POOLS = ("ood", "id", "drift", "dev", "r3", "r4", "r5", "r6", "r7", "t3", "t3lh", "train")
MODES = ("full-system", "model-only")


def evaluation_pool(only: list[str] | None, pool: str | None = None) -> list[str]:
    """Source ids to evaluate.

    ``pool=None`` is the round-1 behaviour: every source whose truth says
    split "test". The named pools are PLAN_R2.md's:

        ood   split "test", minus ROUND1_DEV - the new real held-out
        id    split "test_id" - SIEMgen families held out of training (level 1)
        drift split "test_drift" - training families in formats never trained
              on (corpus/drift_formats.py; level 2)
        dev   ROUND1_DEV, the round-1 pool, reported as a baseline only
        r3    split "test_r3" - round 3's NEW software versions
              (ROUND3_VERSION_DRIFT.md); their old versions are "train_r3",
              in no pool
    """
    if pool is not None and pool not in POOLS:
        raise ValueError(f"pool must be one of {POOLS}, not {pool!r}")
    out = []
    for d in sorted(p for p in (bench_root() / "sources").iterdir() if p.is_dir()):
        t_path = d / "truth.json"
        if not t_path.is_file():
            continue
        if only and d.name not in only:
            continue
        split = json.loads(t_path.read_text(encoding="utf-8")).get("split")
        if pool is None:
            keep = split == EVALUATION_SPLIT
        elif pool == "ood":
            keep = split == EVALUATION_SPLIT and d.name not in ROUND1_DEV
        elif pool == "id":
            keep = split == IN_DISTRIBUTION_SPLIT
        elif pool == "drift":
            keep = split == "test_drift"
        elif pool == "r3":
            keep = split == "test_r3"
        elif pool == "r4":   # fresh held-out changes, never used in development (2026-10-22)
            keep = split == "test_r4"
        elif pool == "r5":   # second held-out set, captured after the round-5 results (2026-10-25)
            keep = split == "test_r5"
        elif pool == "r6":   # third held-out set, round 8 (2026-10-27), rule fixed before any capture
            keep = split == "test_r6"
        elif pool == "r7":   # round 10's held-out set (2026-10-30), rule frozen in F0 before any capture
            keep = split == "test_r7"
        elif pool == "t3":   # Task 3, external data (TASK3_EXTERNAL.md); needs ECS_BENCH_ROOT
            keep = split == "test_t3"
        elif pool == "t3lh":   # Task 3, Loghub-2.0 (no ECS gold: scored by bench.task3_loghub); ECS_BENCH_ROOT
            keep = split == "test_t3lh"
        elif pool == "train":   # round 10 F5: org9 TRACED on training sources (T2/T3 input), never an evaluation
            keep = split == "train"
        else:
            keep = d.name in ROUND1_DEV
        if keep:
            out.append(d.name)
    return out


def _line_truth(source_id: str) -> list[dict[str, Any]]:
    p = bench_root() / "sources" / source_id / "line_truth.ndjson"
    if not p.is_file():
        return []
    return [json.loads(ln) for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]


def score_on_lines(ir: dict[str, Any], line_truth: list[dict[str, Any]],
                   stack_version: str) -> dict[str, Any] | None:
    """Per-field score of an IR against per-line truth, or None if it cannot run.

    The IR is compiled and run over EVERY truth line - not only the samples the
    model saw - and each document is joined to its line by `message`. Only the
    per-field counts are kept in the record, never the documents.
    """
    from adapter.compiler import CompileError, compile_ir
    from adapter.types import Sample, Source
    from bench.score import score_lines
    from validators import v3_sandbox, vt_truth

    if not ir or not line_truth:
        return None
    try:
        filter_block = compile_ir(ir, _index().all_names())
    except (CompileError, KeyError, TypeError):
        return score_lines({k: {**c, "agree": 0, "disagree": 0, "absent": c["lines"]}
                            for k, c in vt_truth.compare([], line_truth).items()})
    src = Source(source_id="score-lines",
                 samples=tuple(Sample.of(r["raw"], f"t{i}") for i, r in enumerate(line_truth)))
    docs = v3_sandbox.validate(filter_block, src, stack_version).metrics.get("documents", [])
    return score_lines(vt_truth.compare(docs, line_truth))


@functools.lru_cache(maxsize=1)
def _index():
    """Built once for the whole matrix.

    EcsIndex loads the 1659-field schema and an embedding model. Rebuilding it
    per run turned a 4-arm x 12-source matrix into hundreds of redundant model
    loads - and, worse, it would be the kind of cost that gets misread as the
    method being slow.
    """
    return _ecs_index()


@functools.lru_cache(maxsize=None)
def _source(source_id: str):
    return _load_source(source_id)


def run_arm(arm: str, source_id: str, seed: int, max_fields: int, repair_budget: int,
            samples: int = 1, mode: str = "full-system", variant: str = "staged"):
    """One (arm, source, seed) run.

    ``mode`` is applied HERE, identically for every arm: model-only forces one
    proposal, no repair, one sample and no deterministic layer, whatever the
    caller asked for. An arm cannot be run in a mode another arm is not.
    """
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, not {mode!r}")
    if mode == "model-only":
        repair_budget, samples = 0, 1
    from adapter.architectures import build
    from adapter.controller import run_once
    from adapter.prompts import Prompts
    from bench.score import score
    from validators.ladder import Ladder

    # Arm C is served by two models, one per stage - training produces two
    # adapters because the stages are blind to each other. Every other arm is one
    # model, and passing None per stage leaves their code path untouched.
    interpret_model = map_model = None
    if arm == "C":
        interpret_model, map_model = _student_models()
        if not (interpret_model or map_model):
            raise RuntimeError(
                "arm C needs ECS_STUDENT_INTERPRET_MODEL and ECS_STUDENT_MAP_MODEL "
                "(or ECS_STUDENT_MODEL).\n"
                "Train the adapters and register them with:\n"
                "  make ecs-export-adapter ADAPTER=<path> STAGE=interpret\n"
                "  make ecs-export-adapter ADAPTER=<path> STAGE=map"
            )
        model = interpret_model or map_model
        # Arm C is the distillation claim, so it must not be servable by the very
        # model it is meant to improve on. Pointing ECS_STUDENT_* at the base name
        # produces runs labelled C that are arm B with extra steps, and the summary
        # table cannot tell the two apart - only the per-record "model" field can.
        # This is how the 2026-10-12 run reported "C 6/23 0.737" for the base model.
        base = os.environ.get("ECS_MODEL_NAME", "").strip()
        collide = sorted({m for m in (interpret_model, map_model) if m and m == base})
        if collide:
            raise RuntimeError(
                f"arm C is pointed at the base model ({', '.join(collide)}).\n"
                "That measures arm B and reports it as C. Set "
                "ECS_STUDENT_INTERPRET_MODEL and ECS_STUDENT_MAP_MODEL to the "
                "registered adapters, or drop C from --arms."
            )
    else:
        model = os.environ.get(ARM_MODEL_ENV[arm], "")
        if not model:
            raise RuntimeError(f"arm {arm} needs {ARM_MODEL_ENV[arm]} to be set.")

    ecs = _index()
    source, truth = _source(source_id)
    prompts = Prompts(ROOT / "prompts")
    client = _model_client(seed=seed)
    client.cfg.model = model

    arch = build(arm, client, prompts, ecs, max_fields,
                 interpret_model=interpret_model, map_model=map_model, variant=variant)
    ladder = Ladder(
        ecs, source, _es(), bench_root(),
        os.environ.get("STACK_VERSION", "8.19.7"),
        scenario_split="holdout",
            known_values=_load_known_values(source_id),
    )
    subset = arch.subset(source)

    rec = run_once(
        arch, source, ladder,
        meta={
            "model": model,
            "model_digest": client.digest(),
            "backend": client.cfg.backend,
            "hardware_tier": int(os.environ.get("ECS_HARDWARE_TIER", "1")),
            "split": truth.get("split", "test"),
            "seed": seed,
            "ecs_version": ecs.version,
            # The edit prompt lives outside prompts/*.md (adapter/edit.py), so its
            # digest is appended rather than folded into the apparatus digest.
            "prompt_digest": prompts.digest + (
                "+edit:" + __import__("adapter.edit", fromlist=["edit_prompt_digest"]).edit_prompt_digest()
                if variant == "staged-edit" else ""),
        },
        repair_budget=repair_budget,
        # No escalation in the experiment. A run that escalated is a run the
        # teacher solved, and reporting it as the student's result would be the
        # single easiest way to fake the headline comparison.
        escalation=None,
        samples=samples,
        normalise=(mode == "full-system"),
    )
    rec.mode = mode
    rec.ecs_subset_size = len(subset)
    rec.ecs_subset_recall = ecs.subset_recall(
        subset, [f["ecs_field"] for f in truth.get("fields", []) if f.get("ecs_field")]
    )
    if truth.get("fields"):
        rec.scores = score(rec.ir or {}, truth)
    else:
        lines = _line_truth(source_id)
        if lines:
            rec.scores = score_on_lines(rec.ir or {}, lines,
                                        os.environ.get("STACK_VERSION", "8.19.7")) or {}
    return rec


def summarise(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_arm: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by_arm[r["architecture"]].append(r)

    out: dict[str, dict[str, Any]] = {}
    for arm, rs in by_arm.items():
        acc = [
            r["scores"]["semantic_accuracy"]
            for r in rs
            if (r.get("scores") or {}).get("semantic_accuracy") is not None
        ]
        recalls = [r["ecs_subset_recall"] for r in rs if r.get("ecs_subset_recall") is not None]
        out[arm] = {
            "runs": len(rs),
            "accepted": sum(r["outcome"] == "accepted" for r in rs),
            "abstained": sum(r["outcome"] == "abstained" for r in rs),
            "failed": sum(r["outcome"] == "failed" for r in rs),
            "reached_v4": sum(r["rung_reached"] == "V4" for r in rs),
            "mean_repairs": sum(r["repairs"] for r in rs) / len(rs),
            "mean_calls": sum(r["usage"]["calls"] for r in rs) / len(rs),
            "mean_wall_seconds": sum(r["wall_seconds"] for r in rs) / len(rs),
            "mean_semantic_accuracy": sum(acc) / len(acc) if acc else None,
            "mean_subset_recall": sum(recalls) / len(recalls) if recalls else None,
        }
    return out


def _print(summary: dict[str, dict[str, Any]]) -> None:
    print()
    print(f"  {'arm':<5}{'runs':>6}{'acc':>6}{'abs':>6}{'fail':>6}{'accuracy':>11}"
          f"{'recall':>9}{'repairs':>9}{'seconds':>9}")
    for arm in [a + v for v in ("", "+split") for a in ("A", "B", "T", "C")]:
        s = summary.get(arm)
        if not s:
            continue
        acc = f"{s['mean_semantic_accuracy']:.3f}" if s["mean_semantic_accuracy"] is not None else "-"
        rec = f"{s['mean_subset_recall']:.2f}" if s["mean_subset_recall"] is not None else "-"
        print(
            f"  {arm:<5}{s['runs']:>6}{s['accepted']:>6}{s['abstained']:>6}{s['failed']:>6}"
            f"{acc:>11}{rec:>9}{s['mean_repairs']:>9.2f}{s['mean_wall_seconds']:>9.1f}"
        )

    if summary.get("C") and summary.get("T"):
        c = summary["C"]["mean_semantic_accuracy"]
        t = summary["T"]["mean_semantic_accuracy"]
        if c is not None and t is not None:
            print()
            print(f"  C vs T  (the headline): student {c:.3f}  vs  teacher {t:.3f}")
            print(
                "  Remember what this can and cannot say: it is bounded to this task\n"
                "  and this distribution of sources. On a format genuinely unlike\n"
                "  anything in training, the larger model is expected to win."
            )
    if summary.get("C") is None:
        print("\n  Arm C absent - the adapters do not exist yet. A, B and T is still a result.")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="bench.arms", description=__doc__.splitlines()[0])
    p.add_argument("--arms", nargs="+", default=["A", "B", "T", "C"])
    # WHY A PREFIX AND NOT JUST ANOTHER arms_ FILE.
    #
    # report.compute takes the most recent arms_*.ndjson and never merges, which
    # is right: averaging two versions of the apparatus and calling it one
    # experiment is the error that rule prevents. But accuracy and latency are
    # deliberately run on different machines - the model's answer does not
    # depend on the hardware and its wall-clock does - and under one prefix the
    # second run would simply erase the first. Writing the timing run as
    # latency_<stamp>.ndjson keeps both, and keeps each one saying which machine
    # produced it.
    p.add_argument("--out-prefix", default="arms", choices=["arms", "latency"],
                   help="arms: the accuracy experiment. latency: the timing run "
                        "on the deployment host, read by R24.")
    p.add_argument("--only", nargs="*", help="restrict to these source ids")
    p.add_argument("--seeds", type=int, default=1, help="repeats per (arm, source)")
    # Extends an earlier run with new seeds (r6, 2026-10-29: seeds 2-4 after 0-1)
    # without repeating the ones already measured.
    p.add_argument("--seed-start", type=int, default=0,
                   help="first seed; the run covers seed-start .. seed-start+seeds-1")
    p.add_argument("--samples", type=int, default=int((os.environ.get("ECS_SAMPLES") or 1)),
                   help="independent candidates per run, the ladder choosing (best-of-k)")
    p.add_argument("--max-fields", type=int, default=DEFAULT_MAX_FIELDS)
    p.add_argument("--repair-budget", type=int,
                   default=int(os.environ.get("ECS_REPAIR_BUDGET", "3")))
    p.add_argument("--mode", choices=MODES, default="full-system",
                   help="model-only: one call, no repair, k=1, no deterministic layer, "
                        "for EVERY arm. full-system: the deployed loop (PLAN_R2.md)")
    # WHY NOT ECS_ARCHITECTURE. That variable already names the deployed ARM for
    # the watcher (adapter/main.py), so it cannot also carry a variant.
    p.add_argument("--architecture", choices=VARIANTS,
                   default=os.environ.get("ECS_ARCH_VARIANT", "staged"),
                   help="staged: every arm as it always was. staged-split: stage 1 once per "
                        "message shape, merged (adapter/decompose.py), recorded as <arm>+split. "
                        "Applies to every arm in the run")
    p.add_argument("--pool", choices=POOLS, default=None,
                   help="ood (new real held-out), id (SIEMgen held-out families), "
                        "dev (the round-1 eight). Omitted: every split 'test' source")
    a = p.parse_args(argv)
    if a.mode == "model-only" and (a.samples != 1 or a.seeds < 1):
        a.samples = 1

    pool = evaluation_pool(a.only, a.pool) if a.pool else evaluation_pool(a.only)
    if not pool:
        sys.exit(
            "The evaluation pool is empty. Mark held-out sources with "
            '"split": "test" in bench/sources/<id>/truth.json.\n'
            "Held out means ENTIRE FAMILIES, never random lines from a shared template."
        )

    print(f"arms    : {' '.join(a.arms)}")
    print(f"sources : {len(pool)}  ({', '.join(pool)})")
    print(f"seeds   : {a.seeds}" + (f"  (from {a.seed_start})" if a.seed_start else ""))
    print(f"samples : {a.samples}")
    print(f"mode    : {a.mode}" + (f"   pool: {a.pool}" if a.pool else ""))
    print(f"variant : {a.architecture}")

    # SEEDS AT TEMPERATURE 0 ARE ONE RUN REPORTED SEVERAL TIMES.
    #
    # Measured on stage F, 2026-10-13: all three seeds of every (arm, source)
    # cell produced the same outcome, rung and accuracy, because decoding is
    # greedy at the default temperature and the seed then changes nothing. The
    # 24 runs per arm were 8 observations, and a McNemar test over them was a
    # test over duplicates. Refused rather than warned, so it cannot recur.
    temperature = float(os.environ.get("ECS_MODEL_TEMPERATURE", "0") or 0)
    if (a.seeds > 1 or a.samples > 1) and temperature <= 0:
        sys.exit(
            f"--seeds {a.seeds} / --samples {a.samples} at temperature {temperature}: "
            "greedy decoding makes every repeat identical. Set ECS_MODEL_TEMPERATURE "
            "above 0 (and report it), or use --seeds 1 --samples 1."
        )
    if len(pool) < 12:
        print(
            f"\nWARNING: {len(pool)} sources. The protocol asks for at least 12, and\n"
            "         with fewer the study detects a large effect and nothing subtler."
        )

    RESULTS.mkdir(exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    # Parallel runs started in the same second would share a file name; a tag
    # (ECS_ARMS_TAG, e.g. "E-B-drift") keeps each run's records its own.
    if os.environ.get("ECS_ARMS_TAG", "").strip():
        stamp = f"{stamp}_{os.environ['ECS_ARMS_TAG'].strip()}"
    out = RESULTS / f"{a.out_prefix}_{stamp}.ndjson"
    records: list[dict[str, Any]] = []
    unreachable = 0

    with out.open("w", encoding="utf-8") as fh:
        for arm in a.arms:
            for source_id in pool:
                for seed in range(a.seed_start, a.seed_start + a.seeds):
                    try:
                        rec = run_arm(arm, source_id, seed, a.max_fields, a.repair_budget,
                                      a.samples, a.mode, a.architecture)
                    except RuntimeError as exc:
                        print(f"  {arm} {source_id:<20} SKIPPED: {exc}")
                        continue
                    except Exception as exc:
                        if not _looks_like_a_dead_endpoint(str(exc)):
                            raise
                        unreachable += 1
                        import traceback   # diagnosis only: which call lost the endpoint
                        traceback.print_exc(limit=12)
                        print(f"  {arm} {source_id:<20} seed={seed} "
                              f"UNREACHABLE ({unreachable}/{UNREACHABLE_LIMIT}): "
                              f"{str(exc)[:90]}")
                        if unreachable >= UNREACHABLE_LIMIT:
                            print(
                                f"\n{UNREACHABLE_LIMIT} runs in a row could not reach the model.\n"
                                "Nothing further has been written; what is in the file is real.\n\n"
                                "  If the model is served over an SSH tunnel, the tunnel is down.\n"
                                "  Reopen it so that the CONTAINER can see it - a plain -L binds to\n"
                                "  127.0.0.1 on the host, which the container cannot reach:\n\n"
                                "    ssh -p <port> -N -L 172.18.0.1:11435:localhost:11434 \\\n"
                                "        -o ServerAliveInterval=30 -o ServerAliveCountMax=3 <host>\n\n"
                                "  Then re-run; completed sources are in the file already.\n"
                            )
                            fh.flush()
                            raise SystemExit(2)
                        continue
                    # A SWALLOWED DEAD ENDPOINT IS NOT A RESULT.
                    #
                    # The guard above only sees an endpoint failure that reaches
                    # here as an exception, and most never do: run_once catches
                    # ModelError inside _cycle and returns an ordinary record,
                    # outcome "failed", rung "none", wall_seconds ~0. That is
                    # right for a deployment - a model that is not there is a
                    # graceful failure - and wrong for an experiment, where it
                    # is indistinguishable from the model getting the answer
                    # wrong.
                    #
                    # It has now happened twice. On 2026-10-10 an SSH tunnel
                    # dropped four minutes into arm C and the runner wrote 22
                    # of 24 records with rung "none" and 0.0 seconds, printed a
                    # summary, and exited 0. The supervisor saw rc=0 and did not
                    # retry. Those 22 records would have gone into R3, the
                    # paper's primary endpoint, as failures of the model.
                    #
                    # So the swallowed error is routed into the same guard: not
                    # written, counted, and fatal once the limit is reached.
                    dead = next(
                        (
                            f for f in rec.findings
                            if f.get("code") == "model_error"
                            and _looks_like_a_dead_endpoint(str(f.get("message", "")))
                        ),
                        None,
                    )
                    if dead is not None:
                        unreachable += 1
                        print(f"  {arm} {source_id:<20} seed={seed} "
                              f"UNREACHABLE ({unreachable}/{UNREACHABLE_LIMIT}): "
                              f"{str(dead.get('message'))[:90]}")
                        if unreachable >= UNREACHABLE_LIMIT:
                            print(
                                f"\n{UNREACHABLE_LIMIT} runs in a row could not reach the model.\n"
                                "Nothing further has been written; what is in the file is real.\n"
                            )
                            fh.flush()
                            raise SystemExit(2)
                        continue

                    unreachable = 0
                    payload = json.loads(rec.to_json())
                    if a.pool:
                        payload["pool"] = a.pool
                    records.append(payload)
                    fh.write(json.dumps(payload, sort_keys=True) + "\n")
                    fh.flush()
                    print(
                        f"  {arm} {source_id:<20} seed={seed} {rec.outcome:<10}"
                        f"@{rec.rung_reached:<4} {rec.wall_seconds:>7.1f}s"
                    )

    summary = summarise(records)
    _print(summary)
    (RESULTS / f"{a.out_prefix}_{stamp}_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(f"\n  runs    : {out}")
    print(f"  summary : {RESULTS / f'{a.out_prefix}_{stamp}_summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

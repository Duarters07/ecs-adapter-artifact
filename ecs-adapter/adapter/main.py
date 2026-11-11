"""CLI for the ECS adapter.

Designed so you can make progress without the whole stack running:

    health       needs the model server only
    ecs-info     needs nothing but the ECS schema file
    compile      needs nothing - compiles a hand-written IR and prints the parser
    check-ir     runs the ladder on a hand-written IR (the decisive V4 test)
    propose      the full run: model -> IR -> compile -> ladder
"""
from __future__ import annotations

from pathlib import Path
import argparse
import json
import os
import sys

import time
from typing import Any

from adapter.ecs_index import DEFAULT_MAX_FIELDS
from adapter.watcher import PENDING
from adapter.wiring import (
    ROOT,
    _ecs_index,
    _es,
    _load_known_values,
    _load_source,
    _model_client,
    _student_models,
)


# --------------------------------------------------------------------- helpers

# ---------------------------------------------------------------- subcommands

def cmd_health(args: argparse.Namespace) -> int:
    from adapter.model_client import ModelError

    try:
        print(_model_client().health())
    except ModelError as exc:
        print(f"FAILED\n{exc}", file=sys.stderr)
        return 1
    return 0


def cmd_ecs_info(args: argparse.Namespace) -> int:
    from adapter.ecs_index import render_fields


    ecs = _ecs_index()
    source, truth = _load_source(args.source)
    subset = ecs.relevant_subset(
        source.observed_keys(), source.documentation, source.category_hint,
        args.max_fields, use_embeddings=not args.no_embeddings,
        doc_hints=source.documentation_hints(),
    )
    truth_fields = [f["ecs_field"] for f in truth.get("fields", []) if f.get("ecs_field")]
    recall = ecs.subset_recall(subset, truth_fields)

    print(f"ECS fields loaded : {len(ecs.fields)}")
    print(f"Source            : {source.source_id} ({len(source.samples)} samples)")
    print(f"Observed keys     : {', '.join(source.observed_keys())}")
    print(f"Subset offered    : {len(subset)} fields (~{len(render_fields(subset)) // 4} tokens)")
    print(f"Subset recall     : {recall:.2f}  <- must be 1.00, or some errors are OURS")
    if recall < 1.0:
        missing = sorted(set(truth_fields) - {f.name for f in subset})
        print(f"  MISSING FROM SUBSET: {', '.join(missing)}")
        return 1
    return 0


def cmd_capture(args: argparse.Namespace) -> int:
    """Drain the unknown-format queue into a benchmark source directory."""
    from adapter.queue import QueueError, drain, write_source

    bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
    topic = args.topic or os.environ.get("UNKNOWN_TOPIC", "logs-unknown-default")

    print(f"Draining {topic} at {bootstrap} (up to {args.max} messages, "
          f"{args.timeout}s idle timeout)...")
    try:
        lines = drain(bootstrap, topic, args.max, args.timeout,
                      from_beginning=not args.only_new)
    except QueueError as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1

    print(f"Captured {len(lines)} raw lines.")
    if not lines:
        print(
            "\nNothing on the queue. Usual causes, in order of likelihood:\n"
            "  1. No traffic has failed to parse yet - generate some.\n"
            "  2. The topic does not exist:\n"
            "     make kafka-topic-create ARGS=\"--topic logs-unknown-default "
            "--partitions 1 --replication-factor 1\"\n"
            "  3. The pipeline's unknown-format route is missing or Logstash was\n"
            "     not restarted after it was added.",
            file=sys.stderr,
        )
        return 1

    try:
        d, samples = write_source(ROOT, args.source, lines, args.category)
    except QueueError as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1

    sigs = len({s.signature for s in samples})
    print(f"Wrote {len(samples)} deduplicated samples ({sigs} distinct shapes) to:")
    print(f"  {d}")
    print("\nFirst samples:")
    for s in samples[:3]:
        print(f"  {s.raw[:150]}")
    print(f"\nNext: review {d / 'truth.json'}, then")
    print(f"  make ecs-propose SOURCE={args.source} ARCH=A")
    return 0


def cmd_compile(args: argparse.Namespace) -> int:
    from adapter.compiler import CompileError, compile_ir

    ecs = _ecs_index()
    ir = json.loads(Path(args.ir).read_text(encoding="utf-8"))
    try:
        print(compile_ir(ir, ecs.all_names()))
    except CompileError as exc:
        print(f"CompileError: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_check_ir(args: argparse.Namespace) -> int:
    """Run the ladder against a hand-written IR. This is the decisive V4 test."""
    from validators.ladder import Ladder

    ecs = _ecs_index()
    source, _ = _load_source(args.source)
    ir = json.loads(Path(args.ir).read_text(encoding="utf-8"))

    ladder = Ladder(
        ecs, source, _es(), ROOT / "bench",
        os.environ.get("STACK_VERSION", "8.19.7"),
        scenario_split=args.scenario_split,
        skip_v3=args.skip_v3,
        skip_v4=args.skip_v4,
        known_values=_load_known_values(args.source),
    )
    report = ladder.run(ir, candidate_id=f"check-{Path(args.ir).stem}")

    print(f"IR            : {args.ir}")
    print(f"Rung reached  : {report.rung_reached}")
    print(f"Passed        : {report.passed}")
    for k, v in report.metrics.items():
        if k not in ("documents", "results"):
            print(f"  {k}: {v}")
    # Two rungs publish a `results` list and their shapes are NOT the same:
    #   V4    {scenario, expected, observed, indexed, passed}
    #   V3.5  {field, value, documents_with_value_in_place, also_found_in}
    # Printing one as the other raised KeyError('passed') the first time a run
    # actually stopped at V3.5 - which is exactly what the swapped fixture does.
    for r in report.metrics.get("results", []):
        if "scenario" in r:
            mark = "ok  " if r.get("passed") else "FAIL"
            print(f"  [{mark}] {r['scenario']}: "
                  f"expected {r['expected']}, observed {r['observed']}")
        elif "field" in r:
            placed = r.get("documents_with_value_in_place", 0)
            mark = "ok  " if placed else "FAIL"
            line = f"  [{mark}] {r['field']} = {r['value']!r} in {placed} document(s)"
            if r.get("also_found_in"):
                line += f"; also found in {sorted(r['also_found_in'])}"
            print(line)
    if report.findings:
        print("Findings:")
        print(report.feedback(limit=20))
    return 0 if report.passed else 1


def _build_escalation(prompts, ecs, max_fields: int):
    """The teacher, or None - and say which, because it changes what a failure means.

    ECS_TIER is the deployment choice the design calls "graceful degradation",
    and it is expressed by passing None to the controller rather than by a
    fallback hidden inside a model client:

        minimal  the specialists are on their own. When they fail, a human
                 writes the parser exactly as today. ~6 GB resident.
        full     the teacher is loaded for that one case and unloaded straight
                 after. ~24 GB peak, ~6 GB the rest of the time.

    Returning None silently would make a minimal-tier run indistinguishable
    from a misconfigured full-tier one, so both paths print what they chose.
    """
    from adapter.escalation import Escalation

    tier = os.environ.get("ECS_TIER", "minimal").strip().lower()
    if tier not in {"minimal", "full"}:
        sys.exit(f"ECS_TIER must be 'minimal' or 'full', not {tier!r}")
    if tier == "minimal":
        print("tier          : minimal - no escalation; a failure means a human writes it")
        return None

    teacher = os.environ.get("ECS_TEACHER_MODEL", "").strip()
    if not teacher:
        sys.exit(
            "ECS_TIER=full needs ECS_TEACHER_MODEL.\n"
            "Set it, or set ECS_TIER=minimal and accept that a failed run is handed "
            "to a person - which is a supported deployment, not a broken one."
        )

    t_client = _model_client()
    t_client.cfg.model = teacher
    print(f"tier          : full - escalating to {teacher} only if the specialists fail")
    return Escalation(t_client, prompts, ecs, max_fields)


def cmd_propose(args: argparse.Namespace) -> int:
    return propose_run(args)[0]


def propose_run(args: argparse.Namespace) -> tuple[int, dict[str, Any] | None]:
    """The full proposal, returning the exit code AND the record it wrote.

    Callers inside this process take the record from here. Looking it up
    afterwards in results/ is how the watcher came to park the outcome of an
    unrelated arms run: see adapter/run_records.py.
    """
    from adapter.architectures import build
    from adapter.controller import run_once
    from adapter.model_client import ModelError
    from adapter.prompts import Prompts
    from validators.ladder import Ladder

    ecs = _ecs_index()
    source, truth = _load_source(args.source)
    prompts = Prompts(ROOT / "prompts")
    client = _model_client(seed=args.seed)

    try:
        print(client.health())
    except ModelError as exc:
        print(f"FAILED\n{exc}", file=sys.stderr)
        return 1, None

    # Arm C is served by two models, one per stage. Without this the CLI built an
    # arm NAMED "C" on the generic student and reported it as arm C - a silent
    # mislabel that would have contaminated any result taken from `propose`.
    interpret_model = map_model = None
    if args.architecture.upper() == "C":
        interpret_model, map_model = _student_models()
        if not (interpret_model or map_model):
            sys.exit(
                "Arm C needs ECS_STUDENT_INTERPRET_MODEL and ECS_STUDENT_MAP_MODEL "
                "(or ECS_STUDENT_MODEL).\n"
                "Train the adapters, then register them:\n"
                "  make ecs-export-adapter ADAPTER=<path> STAGE=interpret\n"
                "  make ecs-export-adapter ADAPTER=<path> STAGE=map\n"
                "Arm C does not exist until both are served."
            )
        print(f"arm C models  : interpret={interpret_model}  map={map_model}")
    arch = build(args.architecture, client, prompts, ecs, args.max_fields,
                 interpret_model=interpret_model, map_model=map_model)
    escalation = _build_escalation(prompts, ecs, args.max_fields)
    ladder = Ladder(
        ecs, source, _es(), ROOT / "bench",
        os.environ.get("STACK_VERSION", "8.19.7"),
        scenario_split=args.scenario_split,
        skip_v3=args.skip_v3,
        skip_v4=args.skip_v4,
        known_values=_load_known_values(args.source),
    )

    subset = arch.subset(source)
    truth_fields = [f["ecs_field"] for f in truth.get("fields", []) if f.get("ecs_field")]

    rec = run_once(
        arch, source, ladder,
        meta={
            "model": client.cfg.model,
            "model_digest": client.digest(),
            "backend": client.cfg.backend,
            "hardware_tier": int(os.environ.get("ECS_HARDWARE_TIER", "1")),
            "split": truth.get("split", "dev"),
            "seed": args.seed,
            "ecs_version": ecs.version,
            "prompt_digest": prompts.digest,
        },
        repair_budget=args.repair_budget,
        escalation=escalation,
        samples=getattr(args, "samples", 1),
    )
    rec.ecs_subset_size = len(subset)
    rec.ecs_subset_recall = ecs.subset_recall(subset, truth_fields)

    # Only score against reviewed ground truth. A capture writes a stub with an
    # empty "fields" list; scoring that would report a meaningless 0/0.
    if truth.get("fields"):
        from bench.score import score

        rec.scores = score(rec.ir or {}, truth)
    elif truth:
        print("\nNOTE: truth.json has no reviewed fields yet - scoring skipped.")

    results_dir = ROOT / "results"
    results_dir.mkdir(exist_ok=True)
    (results_dir / f"{rec.run_id}.ndjson").write_text(rec.to_json() + "\n", encoding="utf-8")

    if rec.outcome == "accepted" and rec.ir:
        from adapter.compiler import compile_ir

        cand = ROOT / "candidates" / rec.run_id
        cand.mkdir(parents=True, exist_ok=True)
        (cand / "ir.json").write_text(json.dumps(rec.ir, indent=2), encoding="utf-8")
        (cand / "pipeline.conf").write_text(
            compile_ir(rec.ir, ecs.all_names()), encoding="utf-8"
        )

    print()
    print(f"run_id        : {rec.run_id}")
    print(f"outcome       : {rec.outcome}")
    if rec.escalated:
        print(
            f"escalated     : yes -> {rec.escalation_model} "
            f"({rec.escalation_seconds:.1f}s, then unloaded)"
        )
    print(f"rung reached  : {rec.rung_reached}")
    print(f"calls/repairs : {rec.usage.calls} / {rec.repairs}")
    print(f"wall seconds  : {rec.wall_seconds:.1f}")
    print(f"subset        : {rec.ecs_subset_size} fields, recall {rec.ecs_subset_recall}")
    if rec.scores:
        print(f"scores        : {json.dumps(rec.scores)}")
    if rec.findings:
        print("findings      :")
        for f in rec.findings[:10]:
            print(f"  [{f.get('rung')}/{f.get('code')}] {f.get('message')}")
    print(f"\nrecord        : results/{rec.run_id}.ndjson")
    if rec.outcome == "accepted":
        print(f"candidate     : candidates/{rec.run_id}/pipeline.conf")
    return (0 if rec.outcome in ("accepted", "abstained") else 1), json.loads(rec.to_json())


# --------------------------------------------------------------------- parser

def _runtime_propose_args(source_id: str) -> argparse.Namespace:
    """The proposal the deployment runs, from the same environment either way."""
    return argparse.Namespace(
        source=source_id,
        architecture=os.environ.get("ECS_ARCHITECTURE", "B"),
        max_fields=DEFAULT_MAX_FIELDS,
        repair_budget=int(os.environ.get("ECS_REPAIR_BUDGET", "3")),
        seed=0,
        samples=int((os.environ.get("ECS_SAMPLES") or 1)),
        scenario_split="repair",
        skip_v3=False,
        skip_v4=False,
    )


def _watch_propose(source_id: str, lines: list[str], category: str | None) -> dict[str, Any]:
    """Run the full proposal for a source the watcher captured, and park it.

    Deliberately reuses `cmd_propose`'s wiring by calling the same CLI path: the
    watcher must not be able to drift into a second, laxer pipeline. What it
    adds is the parking - the candidate is written under `results/pending/` and
    nothing installs it.
    """
    from adapter.queue import write_source

    write_source(ROOT, source_id, lines, category)
    args = _runtime_propose_args(source_id)
    rc, rec = propose_run(args)
    if rec is None:
        return {"outcome": "no_record", "rc": rc}

    PENDING.mkdir(parents=True, exist_ok=True)
    (PENDING / f"{rec.get('run_id', 'unknown')}.json").write_text(
        json.dumps({
            "source_id": source_id,
            "detected_by": "watcher",
            "detected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "outcome": rec.get("outcome"),
            "rung_reached": rec.get("rung_reached"),
            "run_id": rec.get("run_id"),
            "escalated": rec.get("escalated"),
            "awaiting": (
                f"make ecs-install CANDIDATE={rec.get('run_id')} SOURCE={source_id}"
                if rec.get("outcome") == "accepted"
                else "nothing to install - the candidate did not survive the ladder"
            ),
        }, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return rec


def _drift_loop():
    """The auto-deployment loop, assembled from the environment."""
    from adapter.compiler import compile_ir
    from adapter.deploy import Deployer, DeployPolicy
    from adapter.drift_loop import DriftLoop
    from adapter.notify import Notifier
    from adapter.pipeline_registry import PIPELINES, REGISTRY
    from adapter.queue import write_source
    from validators import v3_sandbox

    ecs = _ecs_index()
    stack_version = os.environ.get("STACK_VERSION", "8.19.7")
    policy = DeployPolicy(
        shadow_window_s=float((os.environ.get("ECS_SHADOW_WINDOW_S") or 600)),
        shadow_min_docs=int((os.environ.get("ECS_SHADOW_MIN_DOCS") or 20)),
        live_watch_s=float((os.environ.get("ECS_LIVE_WATCH_S") or 3600)),
        max_deploys_per_family_per_day=int((os.environ.get("ECS_MAX_DEPLOYS_PER_DAY") or 2)),
    )
    policy.validate()

    def run_parser(filter_block: str, lines: list[str]) -> list[dict[str, Any]]:
        from adapter.types import Sample, Source

        source = Source(source_id="drift-continuity",
                        samples=tuple(Sample.of(ln, f"c{i}") for i, ln in enumerate(lines)))
        return v3_sandbox.validate(filter_block, source, stack_version).metrics.get(
            "documents", [])

    def propose(source_id: str) -> dict[str, Any] | None:
        return propose_run(_runtime_propose_args(source_id))[1]

    return DriftLoop(
        root=ROOT,
        deployer=Deployer(PIPELINES, REGISTRY, ROOT / "results" / "deployments", policy),
        notifier=Notifier(ROOT / "results" / "notifications"),
        propose=propose,
        run_parser=run_parser,
        compile=lambda ir: compile_ir(ir, ecs.all_names()),
        write_source=lambda sid, lines, cat: write_source(ROOT, sid, lines, cat),
        es=_es(),
        known_field=ecs.exists,
    )


def cmd_watch(args: argparse.Namespace) -> int:
    """Poll the unknown-format queue and propose when a drift is confirmed."""
    from adapter.queue import drain_events
    from adapter.watcher import Policy, Watcher

    bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
    topic = os.environ.get("UNKNOWN_TOPIC", "logs-unknown-default")

    policy = Policy(
        min_occurrences=args.min_occurrences,
        min_window_s=args.min_window,
        cooldown_s=args.cooldown,
        max_proposals_per_source_per_day=args.daily_cap,
        poll_interval_s=args.interval,
    )
    try:
        policy.validate()
    except ValueError as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1

    mode = (os.environ.get("ECS_DEPLOY_MODE") or "auto").strip().lower()
    if mode not in ("auto", "park"):
        print(f"FAILED: ECS_DEPLOY_MODE must be 'auto' or 'park', not {mode!r}",
              file=sys.stderr)
        return 1
    loop = _drift_loop() if mode == "auto" else None

    w = Watcher(
        policy=policy,
        drain_fn=lambda n: drain_events(
            bootstrap, topic, max_messages=n, timeout_s=5.0,
            group_id="ecs-adapter-watcher", from_beginning=False,
        ),
        propose_fn=loop.handle if loop else _watch_propose,
        handled_fn=loop.handled if loop else None,
    )

    print(
        f"Watching {topic} every {policy.poll_interval_s:.0f}s.\n"
        f"  drift = the same NEW shape {policy.min_occurrences}x over "
        f"{policy.min_window_s:.0f}s\n"
        f"  cooldown {policy.cooldown_s:.0f}s per source, "
        f"cap {policy.max_proposals_per_source_per_day}/day\n"
        + ("  mode auto: verified fields are shadow-deployed, promoted or rolled\n"
           "  back, and the analyst is notified of every outcome.\n" if loop else
           "  mode park: proposals are PARKED in results/pending/ - nothing is installed.\n")
    )
    while True:
        try:
            for a in w.tick():
                print(f"  [{a['source_id']}] {a['action']}"
                      + (f" - {a.get('reason')}" if a.get("reason") else "")
                      + (f" -> {a.get('outcome')} @ {a.get('rung_reached')}"
                         if a.get("action") == "proposed" else ""))
            for a in (loop.supervise() if loop else []):
                print(f"  [{a['pipeline_id']}] {a['stage']} -> {a['verdict']}: {a['why']}")
        except KeyboardInterrupt:
            print("\nstopped")
            return 0
        except Exception as exc:  # a watcher that dies on one bad poll is useless
            print(f"  poll failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        time.sleep(policy.poll_interval_s)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="adapter", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("health", help="check the model server").set_defaults(fn=cmd_health)

    q = sub.add_parser("ecs-info", help="show the ECS subset for a source")
    q.add_argument("--source", required=True)
    q.add_argument("--max-fields", type=int, default=DEFAULT_MAX_FIELDS)
    q.add_argument("--no-embeddings", action="store_true")
    q.set_defaults(fn=cmd_ecs_info)

    cap = sub.add_parser("capture", help="drain the unknown-format queue into a source")
    cap.add_argument("--source", required=True, help="source id to create, e.g. nginx_kv")
    cap.add_argument("--topic", default=None)
    cap.add_argument("--max", type=int, default=500)
    cap.add_argument("--timeout", type=float, default=15.0)
    cap.add_argument("--category", default=None,
                     help="web | authentication | network | firewall | endpoint")
    cap.add_argument("--only-new", action="store_true",
                     help="read from the queue head instead of the beginning")
    cap.set_defaults(fn=cmd_capture)

    c = sub.add_parser("compile", help="compile a hand-written IR to a Logstash filter")
    c.add_argument("--ir", required=True)
    c.set_defaults(fn=cmd_compile)

    k = sub.add_parser("check-ir", help="run the validation ladder on a hand-written IR")
    k.add_argument("--ir", required=True)
    k.add_argument("--source", required=True)
    k.add_argument("--scenario-split", default="repair")
    k.add_argument("--skip-v3", action="store_true")
    k.add_argument("--skip-v4", action="store_true")
    k.set_defaults(fn=cmd_check_ir)

    wt = sub.add_parser("watch", help="poll the queue and propose when drift is confirmed")
    wt.add_argument("--interval", type=float, default=60.0, help="seconds between polls")
    wt.add_argument("--min-occurrences", type=int, default=20,
                    help="how many times a new shape must appear before it counts")
    wt.add_argument("--min-window", type=float, default=300.0,
                    help="and over how many seconds, so a burst is not a drift")
    wt.add_argument("--cooldown", type=float, default=3600.0,
                    help="seconds before the same source may be proposed again")
    wt.add_argument("--daily-cap", type=int, default=4,
                    help="maximum proposals per source per day")
    wt.set_defaults(fn=cmd_watch)

    r = sub.add_parser("propose", help="full run: model proposes, ladder validates")
    r.add_argument("--source", required=True)
    r.add_argument("--architecture", default="A")
    r.add_argument("--seed", type=int, default=1)
    r.add_argument("--samples", type=int, default=int((os.environ.get("ECS_SAMPLES") or 1)),
                   help="independent candidates, the ladder choosing (needs temperature > 0)")
    r.add_argument("--repair-budget", type=int,
                   default=int(os.environ.get("ECS_REPAIR_BUDGET", "3")))
    r.add_argument("--max-fields", type=int, default=DEFAULT_MAX_FIELDS)
    r.add_argument("--scenario-split", default="repair")
    r.add_argument("--skip-v3", action="store_true")
    r.add_argument("--skip-v4", action="store_true")
    r.set_defaults(fn=cmd_propose)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())

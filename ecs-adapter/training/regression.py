"""The frozen held-out gate. Nothing is deployed without clearing it.

The refresh loop is what makes this system improve with use, and it is also the
mechanism by which it could quietly get worse: each cycle retrains on cases the
system itself resolved, so an error that survives the ladder can be reinforced.
The defence is a set of sources that is fixed ONCE and never grows.

    frozen set     fixed at creation, never added to, never regenerated.
                   If it grew with each cycle, a later adapter would be measured
                   against different work from an earlier one and "no degradation"
                   would mean nothing.

    the decision   a new adapter ships only if it does not do worse on that set.
                   Equal is acceptable; worse is not. The previous adapter is kept
                   either way, because the cheapest rollback is the one that needs
                   no rebuild.

Note what this gate does NOT do: it does not certify that the new adapter is
better. A refresh that changes nothing measurable is still worth deploying if it
covers new sources, and this gate lets it through. It exists to catch regression,
not to prove progress.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
import argparse
import json
import sys

from adapter.ecs_index import DEFAULT_MAX_FIELDS
from adapter.wiring import ROOT, _load_known_values

FROZEN = ROOT / "bench" / "frozen.json"
BASELINES = ROOT / "training" / "baselines"


def _load_frozen() -> dict[str, Any]:
    if not FROZEN.is_file():
        sys.exit(
            f"{FROZEN} does not exist.\n\n"
            "Create it ONCE, listing the source ids and holdout scenarios the gate\n"
            "will use forever. It is not regenerated, it is not extended, and it is\n"
            "not the evaluation pool - those numbers go in the paper, these guard\n"
            "the deployment."
        )
    return json.loads(FROZEN.read_text(encoding="utf-8"))


def _exported_models(adapter: Path) -> tuple[str | None, str | None]:
    """Read the model names training/export_ollama.py registered for this adapter.

    Falls back to the per-stage environment variables, then to None - and None
    reaches StagedArchitecture as "use the client's model", which the caller
    reports rather than passing off as arm C.
    """
    import json as _json
    import os as _os

    rec = adapter / "export_record.json"
    if rec.is_file():
        data = _json.loads(rec.read_text(encoding="utf-8"))
        name = data.get("model_name")
        if data.get("stage") == "interpret":
            return name, _os.environ.get("ECS_STUDENT_MAP_MODEL") or None
        if data.get("stage") == "map":
            return _os.environ.get("ECS_STUDENT_INTERPRET_MODEL") or None, name
    from adapter.wiring import _student_models

    return _student_models()


def evaluate(adapter: Path, frozen: dict[str, Any], repair_budget: int) -> dict[str, Any]:
    """Run the staged arm with this adapter over every frozen source."""
    import os

    from adapter.architectures import StagedArchitecture
    from adapter.prompts import Prompts
    from adapter.wiring import _ecs_index, _es, _load_source, _model_client
    from adapter.controller import run_once
    from bench.score import score
    from validators.ladder import Ladder

    ecs = _ecs_index()
    prompts = Prompts(ROOT / "prompts")
    es = _es()
    rows: list[dict[str, Any]] = []

    for source_id in frozen["sources"]:
        source, truth = _load_source(source_id)
        client = _model_client(seed=frozen.get("seed", 0))
        interpret_model = map_model = None
        if adapter.name != "__base__":
            # The two adapters are registered as two models by
            # training/export_ollama.py, which writes the names it chose into
            # each adapter's export_record.json. Read them rather than guessing a
            # name, which is what this line used to do.
            interpret_model, map_model = _exported_models(adapter)
        arch = StagedArchitecture(
            client, prompts, ecs, frozen.get("max_fields", DEFAULT_MAX_FIELDS), name="C",
            interpret_model=interpret_model, map_model=map_model,
        )
        ladder = Ladder(
            ecs, source, es, ROOT / "bench",
            os.environ.get("STACK_VERSION", "8.19.7"),
            # The gate uses HOLDOUT scenarios. Using repair scenarios here would
            # measure the adapter on material the training loop could see.
            scenario_split="holdout",
            known_values=_load_known_values(source_id),
        )
        rec = run_once(
            arch, source, ladder,
            meta={
                "model": interpret_model or client.cfg.model,
                "model_digest": client.digest(),
                "backend": client.cfg.backend,
                "hardware_tier": int(os.environ.get("ECS_HARDWARE_TIER", "1")),
                "split": truth.get("split", "frozen"),
                "seed": frozen.get("seed", 0),
                "ecs_version": ecs.version,
                "prompt_digest": prompts.digest,
            },
            repair_budget=repair_budget,
        )
        # SUBSET RECALL, RECORDED RATHER THAN ASSUMED.
        #
        # It needs truth.json, and the controller may not read that, so every
        # harness has to compute it for itself - and this one never did. The
        # gate of 2026-10-04 accepted 1 of 10 and the record cannot say whether
        # the other nine were the model's errors or fields the retriever never
        # offered. Those are opposite conclusions and the number that separates
        # them was one line away.
        wanted = [
            f["ecs_field"] for f in (truth.get("fields") or []) if f.get("ecs_field")
        ]
        subset = arch.subset(source)
        recall = ecs.subset_recall(subset, wanted) if wanted else None

        s = score(rec.ir or {}, truth) if truth.get("fields") else {}
        rows.append(
            {
                "source_id": source_id,
                "outcome": rec.outcome,
                "rung_reached": rec.rung_reached,
                "ecs_subset_size": len(subset),
                "ecs_subset_recall": recall,
                "accepted": rec.outcome == "accepted",
                "semantic_accuracy": s.get("semantic_accuracy"),
                "correct_abstentions": (s.get("abstention") or {}).get("correct"),
                "repairs": rec.repairs,
            }
        )

    accepted = sum(r["accepted"] for r in rows)
    scored = [r["semantic_accuracy"] for r in rows if r["semantic_accuracy"] is not None]
    return {
        "adapter": adapter.name,
        "sources": len(rows),
        "accepted": accepted,
        "acceptance_rate": accepted / len(rows) if rows else None,
        "mean_semantic_accuracy": sum(scored) / len(scored) if scored else None,
        "rows": rows,
    }


def compare(new: dict[str, Any], old: dict[str, Any], tolerance: float) -> tuple[bool, list[str]]:
    reasons: list[str] = []

    if new["accepted"] < old["accepted"]:
        reasons.append(
            f"acceptance fell: {old['accepted']} -> {new['accepted']} of {old['sources']}"
        )

    a, b = new["mean_semantic_accuracy"], old["mean_semantic_accuracy"]
    if a is not None and b is not None and a < b - tolerance:
        reasons.append(f"mean semantic accuracy fell: {b:.3f} -> {a:.3f}")

    # Per-source, because a mean can hide one source collapsing while another
    # improves - and in deployment a collapsed source is an outage, not an average.
    old_by = {r["source_id"]: r for r in old["rows"]}
    for r in new["rows"]:
        prev = old_by.get(r["source_id"])
        if prev and prev["accepted"] and not r["accepted"]:
            reasons.append(f"{r['source_id']}: was accepted, now {r['outcome']}")

    return (not reasons), reasons


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="training.regression", description=__doc__.splitlines()[0])
    p.add_argument("--adapter", type=Path, required=True)
    p.add_argument("--baseline", type=Path, help="previous result JSON (default: newest in baselines/)")
    p.add_argument("--tolerance", type=float, default=0.0,
                   help="allowed drop in mean accuracy. 0.0 means equal-or-better")
    p.add_argument("--repair-budget", type=int, default=3)
    a = p.parse_args(argv)

    frozen = _load_frozen()
    print(f"frozen set : {len(frozen['sources'])} sources, fixed {frozen.get('created', '?')}")
    new = evaluate(a.adapter, frozen, a.repair_budget)

    BASELINES.mkdir(parents=True, exist_ok=True)
    result_path = BASELINES / f"{a.adapter.name}.json"
    result_path.write_text(json.dumps(new, indent=2, sort_keys=True), encoding="utf-8")

    baseline_path = a.baseline
    if baseline_path is None:
        prior = sorted(
            (q for q in BASELINES.glob("*.json") if q != result_path),
            key=lambda q: q.stat().st_mtime,
        )
        baseline_path = prior[-1] if prior else None

    print(f"\n  accepted           : {new['accepted']}/{new['sources']}")
    print(f"  mean accuracy      : {new['mean_semantic_accuracy']}")

    # An accuracy printed beside an unknown recall is not interpretable, and
    # printing it alone invites the reader to attribute every miss to the
    # model. Say which sources could not have answered correctly.
    starved = [r for r in new.get("rows", [])
               if r.get("ecs_subset_recall") is not None
               and r["ecs_subset_recall"] < 1.0]
    unknown = [r for r in new.get("rows", []) if r.get("ecs_subset_recall") is None]
    if starved:
        print(f"  subset recall < 1  : {len(starved)} source(s) - for these the "
              "correct field was NOT offered,")
        print("                       so the error is the retriever's, not the model's:")
        for r in starved:
            print(f"                         {r['source_id']}  recall {r['ecs_subset_recall']}")
    elif not unknown:
        print("  subset recall      : 1.0 on every source - every miss is the model's")
    if unknown:
        print(f"  subset recall      : UNKNOWN on {len(unknown)} source(s). The "
              "accuracy above cannot be attributed.")

    if baseline_path is None:
        print("\nNo previous baseline. This result becomes the baseline.")
        print("The gate is only meaningful from the SECOND adapter onwards.")
        return 0

    old = json.loads(baseline_path.read_text(encoding="utf-8"))
    ok, reasons = compare(new, old, a.tolerance)
    print(f"  compared against   : {old['adapter']}")

    if ok:
        print("\nGATE PASSED - no degradation. Safe to deploy.")
        print("Keep the previous adapter on disk; it is the rollback.")
        return 0

    print("\nGATE FAILED - do NOT deploy this adapter:")
    for r in reasons:
        print(f"  - {r}")
    print("\nKeep the previous adapter. A failed gate is the mechanism working.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

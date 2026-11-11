"""Phase 1b - the ladder filters the teacher's proposals. GATE 2.

Two outputs, and they answer different questions.

  verified.ndjson   the proposals that passed V4, which become training data.
                    Only the corrected version of anything is ever kept: the
                    student never sees a mapping the ladder rejected.

  the yield table   for each field in the ground truth, how many VERIFIED
                    proposals assigned it correctly. This is Gate 2, and it is
                    run BEFORE any training because training is the expensive
                    step.

Why the gate exists. Filtering can only select from what the teacher produces.
If the teacher never once gets a hard distinction right across every attempt,
there is no correct example of it to learn from and the student inherits the
blind spot exactly. A hard field with zero verified examples is not a small
problem to be fixed with more epochs; it is an absence in the training set.

If the hard-field yield is near zero, the distilled arms do not proceed - and
that is a real, reportable finding about what a fully-local teacher can supply.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any
import argparse
import json
import sys

from adapter.wiring import ROOT
from validators.v4_detection import (
    indistinguishable_targets,
    is_detection_verified,
    verified_fields,
)
from validators.v4_detection import load_scenarios

OUT_DIR = ROOT / "teacher" / "out"
PROPOSALS = OUT_DIR / "proposals.ndjson"
VERIFIED = OUT_DIR / "verified.ndjson"
YIELD = OUT_DIR / "yield.json"

DIFFICULTIES = ("easy", "medium", "hard")


def _load(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        sys.exit(f"{path} does not exist. Run:  make ecs-generate")
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # partial last line from an interrupted generation
    return out


def _truth(source_id: str) -> dict[str, Any]:
    p = ROOT / "bench" / "sources" / source_id / "truth.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}


def is_verified(rec: dict[str, Any]) -> bool:
    """Was this proposal actually contradicted-or-confirmed by detection replay?

    Delegates to validators.v4_detection, which owns the semantics of what a V4
    report means. It is NOT enough that the report says passed and V4: a source
    with no scenarios for the split produces exactly that, having verified
    nothing. See is_detection_verified for why the distinction is load-bearing.
    """
    return is_detection_verified(rec.get("report") or {})


_BLIND_CACHE: dict[tuple[str, str], frozenset[str]] = {}


def _blind_fields(source_id: str, split: str) -> frozenset[str]:
    key = (source_id, split)
    if not source_id:
        return frozenset()
    if key not in _BLIND_CACHE:
        _BLIND_CACHE[key] = indistinguishable_targets(
            load_scenarios(ROOT / "bench", source_id, split)
        )
    return _BLIND_CACHE[key]


def extraction_verified(rec: dict[str, Any]) -> bool:
    """Did a real Logstash compile this extraction and parse every line with it?

    V3 is the exam for stage 1. It builds the filter the proposal describes,
    runs it in a sandboxed Logstash over every line the parser will face - the
    samples plus the probe line, since A13 - and requires all of them to parse.
    V4, which comes after, tests stage 2: whether the right value reaches the
    right ECS field.

    A proposal that REACHED V4 therefore has an extraction that passed V3,
    whatever V4 then decided about the mapping. Until 2026-10-13 the interpret
    stage was fed only from proposals that passed V4 WHOLE, which is to say it
    was taught only from cases where the other stage also got everything right
    - marking one student down because their neighbour failed a different
    exam. Measured on the corpus of that date: 219 proposals passed V4 whole,
    437 reached it, so half the verified extractions were being discarded.

    `is_detection_verified` is the right predicate to ask here even though its
    name speaks of detection: reaching V4 with scenarios present is exactly
    "the sandbox ran this parser over every line and the replay harness then
    had documents to query".
    """
    rep = rec.get("report") or {}
    metrics = rep.get("metrics") or {}
    if metrics.get("verified") is not True:
        return False
    return int(metrics.get("scenarios_total", 0)) > 0


def training_fields(rec: dict[str, Any]) -> frozenset[str]:
    """The ECS fields of this proposal that may become training data.

    Two regimes, and the split between them is deliberate.

    One regime, and the uniformity is the point: a field is credited when a
    detection rule that filtered on it fired correctly, and never otherwise.

    V4 is all-or-nothing - one misplaced value on a twelve-field source
    discards eleven correct mappings with it - and that is a property of the
    acceptance rule, not of the oracle. The oracle is unchanged: still a
    detection rule, still replayed, still the only thing that confers credit.
    What changes is that a rule which fires is taken to prove the fields it
    filtered on, rather than the whole line.

    It cuts the other way too, and that half was added later and matters more.
    A proposal that passed every scenario used to be accepted WHOLE, which
    credited the fields no scenario had tested along with the ones it had. On
    `syn_idsalert_kv_pipe` seed 1 - the first proposal in the new families to
    pass all six scenarios - that admitted `dev -> observer.name`, a key the
    ground truth says has no ECS field at all. Nothing tested it and nothing
    could have: no rule names `observer.name`. Measured over the training
    families the scenarios exercise 96 per cent of the fields that have ground
    truth, so refusing the rest costs little and makes the claim exact.

    "Not contradicted is not verified" is this project's own sentence, written
    in corpus/synthesise.build_scenarios, and it applies per field.
    """
    ir = rec.get("ir") or {}
    # A value map is a mapping too: `event.outcome` reaches the document only
    # through one. It is credited by the same oracles, on the same terms.
    assigned = {
        f["ecs_field"] for f in ir.get("fields") or [] if f.get("ecs_field")
    } | {
        vm["ecs_field"] for vm in ir.get("value_maps") or [] if vm.get("ecs_field")
    }
    # Never credit a field the scenario that tested it cannot tell from the
    # field beside it. See indistinguishable_targets: a rule whose two targets
    # carry the same marker fires either way, including for a mapping that is
    # the exact inverse of the truth.
    blind = _blind_fields(
        rec.get("source_id") or "",
        (rec.get("validation") or {}).get("scenario_split", "repair"),
    )
    v4 = assigned & verified_fields(rec.get("report") or {})
    # VT: per-line truth from SIEMgen (validators/vt_truth.py), carried in the
    # report by the ladder. A field VT verified is proved as directly as a rule
    # that fired on it; a field VT contradicted is excluded whatever V4 said.
    # Records without line truth carry no "vt" block and are unaffected.
    vt = ((rec.get("report") or {}).get("metrics") or {}).get("vt") or {}
    vt_ok = set(vt.get("verified_fields") or [])
    vt_bad = set(vt.get("contradicted_fields") or [])
    return frozenset(((v4 | (assigned & vt_ok)) - vt_bad) - blind)


def analyse(records: list[dict[str, Any]]) -> dict[str, Any]:
    by_source: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by_source[r["source_id"]].append(r)

    # field_key -> difficulty, and how many verified proposals got it right
    field_rows: list[dict[str, Any]] = []
    by_difficulty: dict[str, dict[str, int]] = {
        d: {"fields": 0, "with_examples": 0, "examples": 0,
            "earned_fields": 0, "earned_with_examples": 0, "earned_examples": 0}
        for d in DIFFICULTIES
    }
    unverified_passes = 0
    credited_partials = 0

    for source_id, recs in sorted(by_source.items()):
        truth = _truth(source_id)
        verified = [r for r in recs if is_verified(r)]
        # Proposals that contribute at least one field, whether or not they
        # survived as a whole. A failed proposal with one credited mapping is
        # one more verified example than discarding it produces.
        contributing = [(r, training_fields(r)) for r in recs]
        contributing = [(r, f) for r, f in contributing if f]
        credited_partials += sum(1 for r, _ in contributing if not is_verified(r))
        # Counted, never dropped: a large number here means the benchmark is
        # short of scenarios, which is a fixable problem, whereas silently
        # training on them is not a problem anyone would ever notice.
        unverified_passes += sum(
            1 for r in recs
            if (r.get("report") or {}).get("passed") and not is_verified(r)
        )

        for tf in truth.get("fields", []):
            key = tf["source_key"]
            difficulty = tf.get("difficulty", "medium")
            expected = tf.get("ecs_field")
            acceptable_abstention = bool(tf.get("acceptable_abstention", False))

            correct = 0
            if expected is None or acceptable_abstention:
                # An abstention is not something a detection rule can confirm,
                # so it is counted only over proposals that survived whole.
                for r in verified:
                    abstained = {
                        u["source_key"]
                        for u in (r.get("ir") or {}).get("unresolved", [])
                    }
                    correct += key in abstained
            else:
                for r, credited in contributing:
                    assigned = {
                        f["source_key"]: f["ecs_field"]
                        for f in (r.get("ir") or {}).get("fields", [])
                    }
                    correct += (
                        assigned.get(key) == expected and expected in credited
                    )

            row = {
                "source_id": source_id,
                "source_key": key,
                "ecs_field": expected,
                "difficulty": difficulty,
                # Whether the generated key spells out its own answer. Recorded
                # by corpus/synthesise.py; see key_names_the_answer there.
                "key_names_the_answer": bool(tf.get("key_names_the_answer", False)),
                "acceptable_abstention": acceptable_abstention,
                "verified_proposals": len(verified),
                "contributing_proposals": len(contributing),
                "correct_examples": correct,
            }
            field_rows.append(row)

            bucket = by_difficulty.setdefault(
                difficulty, {"fields": 0, "with_examples": 0, "examples": 0,
                             "earned_fields": 0, "earned_with_examples": 0,
                             "earned_examples": 0}
            )
            bucket["fields"] += 1
            bucket["with_examples"] += correct > 0
            bucket["examples"] += correct
            # EARNED: the same counts with the giveaways removed.
            #
            # `difficulty` is a property of the ECS field - how many entity
            # roots offer that leaf name - and says nothing about the key the
            # field arrived under. `source.port` is confusable in the abstract
            # and `src_port -> source.port` is not confusable at all, yet both
            # land in the hard column. Measured over the corpus, 18 of the hard
            # fields had a key naming its own answer. Reporting only the first
            # number would overstate how much hard work the teacher did.
            if not row["key_names_the_answer"]:
                bucket["earned_fields"] += 1
                bucket["earned_with_examples"] += correct > 0
                bucket["earned_examples"] += correct

    return {
        "proposals": len(records),
        "verified": sum(1 for r in records if is_verified(r)),
        "credited_partials": credited_partials,
        "unverified_passes": unverified_passes,
        "by_difficulty": by_difficulty,
        "fields": field_rows,
        "starved_hard_fields": [
            f"{r['source_id']}.{r['source_key']}"
            for r in field_rows
            if r["difficulty"] == "hard" and r["correct_examples"] == 0
        ],
    }


def _report(a: dict[str, Any]) -> None:
    print(f"proposals            : {a['proposals']}")
    print(f"verified (passed V4) : {a['verified']}")
    if a.get("credited_partials"):
        print(
            f"credited at field    : {a['credited_partials']}  "
            "(failed as a whole; keep the fields a passing scenario proved)"
        )
    if a["unverified_passes"]:
        print(
            f"passed but NOT at V4 : {a['unverified_passes']}  "
            "(excluded - nothing verified them)"
        )
    print()
    print("Gate 2 - teacher yield by field difficulty")
    print("  'earned' excludes fields whose KEY names its own answer, such as")
    print("  src_port -> source.port. Those are hard in the schema and trivial in practice.")
    print(f"  {'difficulty':<12}{'fields':>8}{'with >=1':>10}{'examples':>10}"
          f"{'| earned':>10}{'with >=1':>10}{'examples':>10}")
    empty = {"fields": 0, "with_examples": 0, "examples": 0,
             "earned_fields": 0, "earned_with_examples": 0, "earned_examples": 0}
    for d in DIFFICULTIES:
        b = {**empty, **a["by_difficulty"].get(d, {})}
        if not b["fields"]:
            continue
        print(
            f"  {d:<12}{b['fields']:>8}{b['with_examples']:>10}{b['examples']:>10}"
            f"{b['earned_fields']:>10}{b['earned_with_examples']:>10}"
            f"{b['earned_examples']:>10}"
        )

    starved = a["starved_hard_fields"]
    print()
    if starved:
        print(f"  {len(starved)} HARD field(s) have NO verified example to learn from:")
        for f in starved:
            print(f"    - {f}")
        print()
        print("  GATE 2 NOT MET for these fields. The student would inherit the blind")
        print("  spot exactly. Either raise -n, use a larger teacher, or report this")
        print("  as the finding: a local teacher of this size cannot supply them.")
    else:
        print("  GATE 2 MET: every hard field has at least one verified example.")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="teacher.filter", description=__doc__.splitlines()[0])
    p.add_argument("--proposals", type=Path, default=PROPOSALS)
    p.add_argument("--out", type=Path, default=VERIFIED,
                   help="where the credited records go (default teacher/out/verified.ndjson); "
                        "a second corpus, such as generated gold, is kept apart with this")
    p.add_argument(
        "--min-examples", type=int, default=1,
        help="hard fields below this many verified examples fail the gate (default 1)",
    )
    a = p.parse_args(argv)

    records = _load(a.proposals)
    analysis = analyse(records)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with a.out.open("w", encoding="utf-8") as fh:
        for r in records:
            credited = training_fields(r)
            if not credited:
                continue
            # Carried on the record so that the dataset builder never has to
            # re-derive it, and so a reader of the corpus can see which
            # mappings were proved and which were merely proposed.
            r["credit"] = {
                "whole": is_verified(r),
                "fields": sorted(credited),
                # Whether V3 compiled this extraction and parsed every line
                # with it. Separate from `whole` on purpose: it is the verdict
                # on STAGE 1's work, where `whole` is a verdict on stage 2's.
                "extraction": extraction_verified(r),
            }
            fh.write(json.dumps(r, sort_keys=True, default=str) + "\n")
    YIELD.write_text(json.dumps(analysis, indent=2, sort_keys=True), encoding="utf-8")

    _report(analysis)
    print()
    print(f"verified cases : {a.out}")
    print(f"yield table    : {YIELD}")

    starved = [
        r for r in analysis["fields"]
        if r["difficulty"] == "hard" and r["correct_examples"] < a.min_examples
    ]
    if starved:
        return 2  # a distinct exit code: the gate was evaluated and not met
    print("\nNext:  make ecs-dataset")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

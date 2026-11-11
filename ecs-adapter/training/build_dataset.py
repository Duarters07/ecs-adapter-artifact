"""Verified proposals -> two training sets, one per stage.

The stages are trained separately because they are blind to each other, so a
verified case splits into two independent examples:

    interpret.jsonl   samples + documentation          ->  roles
    map.jsonl         roles + offered ECS fields       ->  IR

Building both from the SAME verified case is what keeps the two adapters
mutually consistent: the roles the mapper learns to consume are exactly the
roles the interpreter learns to produce.

Three rules, each of which is a way this could go quietly wrong:

  1. Only detection-verified MAPPINGS. Enforced upstream in teacher/filter.py
     and asserted again here, because a second reader of this file should not
     have to trust the first. The unit is the field, not the proposal: a
     proposal that failed V4 as a whole still contributes the fields a passing
     scenario proved, and contributes nothing else. The two stages are treated
     differently and deliberately so - see build().
  2. The prompt is REBUILT with the same templates the run-time path uses, never
     stored from generation. If the template changes, the training data has to
     change with it; a stored prompt would silently train the student on an
     apparatus that no longer exists.
  3. Exact duplicates are dropped. Six proposals for one source frequently agree,
     and six identical examples are one example with the loss counted six times.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
import argparse
import hashlib
import json
import sys

from adapter.ecs_index import DEFAULT_MAX_FIELDS
from adapter.wiring import ROOT, _ecs_index, _load_source
from validators.v4_detection import is_detection_verified

OUT_DIR = ROOT / "training" / "data"
VERIFIED = ROOT / "teacher" / "out" / "verified.ndjson"

STAGES = ("interpret", "map")


def _credited_ir(ir: dict[str, Any], credited: frozenset[str]) -> dict[str, Any]:
    """The IR with only the mappings a detection rule proved.

    Everything else is demoted to `unresolved` rather than deleted, for two
    reasons. The ladder's rule is that every key is accounted for even if only
    to say it could not be resolved, so a deletion would produce an example of
    a shape the ladder itself rejects. And an abstention states what the corpus
    actually knows about that key - that no rule confirmed it - where silence
    would state nothing.
    """
    kept: list[dict[str, Any]] = []
    demoted: list[dict[str, Any]] = list(ir.get("unresolved") or [])
    for f in ir.get("fields") or []:
        if f.get("ecs_field") in credited:
            kept.append(f)
        else:
            demoted.append(
                {
                    "source_key": f["source_key"],
                    "reason": "no detection scenario confirmed this mapping",
                }
            )
    out = dict(ir)
    out["fields"] = kept
    out["unresolved"] = demoted
    # A value map no oracle confirmed is dropped like an unconfirmed field. It
    # used to travel into every example untouched, which taught the student
    # outcome vocabularies nothing had verified (found 2026-10-15). Its source
    # key is then declared unresolved, unless something else accounts for it,
    # so the example still states every key - the ladder's rule.
    if "value_maps" in ir:
        out["value_maps"] = []
        accounted = {f["source_key"] for f in kept} | {u.get("source_key") for u in demoted}
        for vm in ir.get("value_maps") or []:
            if vm.get("ecs_field") in credited:
                out["value_maps"].append(vm)
            elif vm.get("from_source_key") and vm["from_source_key"] not in accounted:
                demoted.append({"source_key": vm["from_source_key"],
                                "reason": "no oracle confirmed this value mapping"})
                accounted.add(vm["from_source_key"])
    return out


def _credited_roles(roles: dict[str, Any], ir: dict[str, Any],
                    credited: frozenset[str]) -> dict[str, Any]:
    """The stage 1 answer with its extraction kept and its unproved roles declined.

    The EXTRACTION survives whole: V3 compiled it and parsed every line with
    it, which is the whole of what stage 1 is asked for on that front.

    The ROLES are another matter. V3 says nothing about whether `src_ip` was
    described as a source address or a destination one; what speaks to that is
    V4, one field at a time, and only for the fields some rule filtered on. So
    a role whose field no rule proved is moved to `unresolved` rather than
    shown as if it were known - the same rule `_credited_ir` applies to the
    mapping, for the same reason.
    """
    proved = {
        f["source_key"] for f in (ir.get("fields") or [])
        if f.get("ecs_field") in credited and f.get("source_key")
    }
    # A key the IR maps through a VALUE MAP is proved the same way, by its field.
    # Until 2026-10-17 only `fields` counted, so the role of every translated key
    # (`Failed` -> failure) was declined: stage 1 was never taught to state the
    # source's outcome words, and stage 2, which never sees a line, had nothing
    # to build the map from. The first gold-trained student then wrote sshd's
    # map backwards and left vsftpd's unmapped.
    proved |= {
        v["from_source_key"] for v in (ir.get("value_maps") or [])
        if v.get("ecs_field") in credited and v.get("from_source_key")
    }
    # The timestamp key is proved by V3, which parses every line's date with
    # the IR's formats; no detection rule filters on it, so without this its
    # role was always declined (2026-10-17).
    ts = (ir.get("timestamp") or {}).get("source_key")
    if ts:
        proved.add(ts)
    kept: list[dict[str, Any]] = []
    declined: list[dict[str, Any]] = list(roles.get("unresolved") or [])
    for r in roles.get("roles") or []:
        if r.get("source_key") in proved:
            kept.append(r)
        else:
            declined.append(
                {
                    "source_key": r["source_key"],
                    "reason": "no detection scenario confirmed what this key means",
                }
            )
    out = dict(roles)
    out["roles"] = kept
    out["unresolved"] = declined
    return out


def _without_types(ir: dict[str, Any]) -> dict[str, Any]:
    """The IR with no `type` on its fields: the type follows from the ECS field
    (ecs_index.ir_type) and is derived by the compiler for every arm since
    2026-10-17, so the student is no longer taught to write it."""
    out = dict(ir)
    out["fields"] = [{k: v for k, v in f.items() if k != "type"} for f in ir.get("fields") or []]
    return out


def _digest(obj: Any) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, default=str).encode()
    ).hexdigest()


def _sanitise_grok_names(ir: dict) -> dict:
    """Never train the student to write a name Logstash does not define.

    A proposal can be CREDITED while its raw pattern carries an invented name,
    because the deterministic layer renames it before the ladder ever sees it -
    `FLOAT` to `NUMBER`, `DOMAINNAME` to `HOSTNAME`. What gets stored as the
    training target is the model's own text, so the invention survives into the
    corpus. Measured 2026-10-14: 4 of the 72 credited grok examples, `FLOAT`
    three times and `DOMAINNAME` once.

    Four of seventy-two is small, and it would be teaching the student to
    contradict its own instructions: the prompt now lists the valid names and
    says in capitals that `FLOAT` is not one of them. Dropping the examples
    would be worse - grok is the scarce class, which is the whole of M9 - so
    they are repaired with the same alias table the runtime uses.

    Only renames. A pattern using a name with NO known alias is left exactly as
    it is and will be refused downstream, which is the right outcome: this is
    not a place to guess what the model meant.
    """
    ex = (ir or {}).get("extraction") or {}
    if ex.get("kind") != "grok" or not ex.get("pattern"):
        return ir
    from adapter.normalise import _GROK_ALIASES
    from validators.v2_consistency import _load_grok_names
    import re as _re

    known = _load_grok_names()
    if not known:
        return ir
    from adapter.types import grok_patterns, with_grok_patterns

    # Every alternative is sanitised the same way: an invented name in the
    # second pattern breaks the filter exactly as one in the first does.
    patterns = grok_patterns(ex)
    changed = False
    for i, pattern in enumerate(patterns):
        for name in sorted({m.group(1)
                            for m in _re.finditer(r"%\{([A-Z0-9_]+)", pattern)} - known):
            target = _GROK_ALIASES.get(name)
            if target and target in known:
                pattern = _re.sub(r"%\{" + _re.escape(name) + r"\b", "%{" + target, pattern)
                changed = True
        patterns[i] = pattern
    if not changed:
        return ir
    out = dict(ir)
    out["extraction"] = with_grok_patterns(ex, patterns)
    return out


def _rebalance_grok(
    written: dict, target_share: float, counts: dict[str, int]
) -> None:
    """Raise the grok share of interpret.jsonl by repeating what is there.

    WHY THIS IS NEEDED, WHICH IS M9.

    The corpus is generated balanced - 14 sources for each of 8 layouts, so 25%
    prose. What SURVIVES V3/V4 is not: grok is credited at 2.57 examples per
    source against 5.50 for key=value, and the dataset arrives at 14.1% grok.
    The verification gate under-samples the one shape that needs a grok
    pattern, the student sees less of it, fails it more, and is credited less
    on the next round. The skew is a property of the method, not of a run.

    WHAT THIS IS, AND WHAT IT IS NOT.

    Class rebalancing by repetition, nothing more. It adds NO information: the
    83 grok examples are still 83 distinct examples, repeated. It changes how
    often the optimiser sees them, which is the mechanism M9 describes, and it
    cannot fix a shape the corpus never contained. If the grok examples do not
    span enough forms, no weight makes them span more.

    Declared in the run record and in the paper: a reader must be able to tell
    a corpus of 800 examples from 500 examples with 300 repeats.
    """
    grok = written.get("grok") or []
    if not grok or not (0.0 < target_share < 1.0):
        return
    others = sum(len(v) for k, v in written.items() if k != "grok")
    # n copies of each grok example gives n*g / (n*g + others) = target
    need = (target_share * others) / (1 - target_share)
    repeats = max(0, round(need / len(grok)) - 1)
    if repeats <= 0:
        print(f"grok rebalance : already at or above {target_share:.0%}; nothing added")
        return
    path = OUT_DIR / "interpret.jsonl"
    with path.open("a", encoding="utf-8") as fh:
        for _ in range(repeats):
            for line in grok:
                fh.write(line)
    added = repeats * len(grok)
    counts["interpret"] += added
    total = len(grok) * (repeats + 1) + others
    print(f"grok rebalance : {len(grok)} distinct grok examples x{repeats + 1} "
          f"= {added} added; grok share "
          f"{len(grok) / (len(grok) + others):.1%} -> "
          f"{len(grok) * (repeats + 1) / total:.1%}")


def build(verified_path: Path, max_fields: int,
          balance_grok: float = 0.0, extra: list[Path] | None = None) -> dict[str, int]:
    from adapter.ecs_index import render_fields
    from adapter.prompts import Prompts
    from adapter.architectures import IR_SCHEMA, ROLES_SCHEMA
    from adapter.schema_order import grammar_order
    from corpus.roles import leaks

    if not verified_path.is_file():
        sys.exit(f"{verified_path} does not exist. Run:  make ecs-filter")

    records = [
        json.loads(line)
        for line in verified_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    # Records verified outside teacher.filter: the gold IRs and the augmented
    # variants (corpus/siemgen_gold.py, corpus/augment.py), each verified by VT
    # and carrying its own `credit`. Same shape, same crediting rules; read
    # alongside rather than merged into verified.ndjson so each source of
    # examples stays countable on its own.
    for path in extra or []:
        if not path.is_file():
            sys.exit(f"{path} does not exist.")
        added = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
                 if line.strip()]
        print(f"extra          : {len(added)} record(s) from {path.name}")
        records += added
    if not records:
        sys.exit(
            "No verified cases. Either generation has not run, or nothing passed "
            "V4 - which is itself the result, and belongs in the paper rather than "
            "being worked around."
        )

    ecs = _ecs_index()
    prompts = Prompts(ROOT / "prompts")
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    seen: dict[str, set[str]] = {s: set() for s in STAGES}
    # Interpret lines kept by extraction kind, so the grok share can be raised
    # after the fact without generating anything. See _rebalance_grok.
    written: dict[str | None, list[str]] = {}
    counts: dict[str, int] = {s: 0 for s in STAGES}
    dropped = 0
    leaked: list[tuple[str, str]] = []
    subset_cache: dict[str, str] = {}

    handles = {
        s: (OUT_DIR / f"{s}.jsonl").open("w", encoding="utf-8") for s in STAGES
    }
    try:
        for rec in records:
            # Asserted again here even though filter.py already selected for it.
            # This is the last point before data becomes weights, and a second
            # reader of this file should not have to trust the first.
            credit = rec.get("credit") or {}
            credited = frozenset(credit.get("fields") or [])
            assert credited, (
                f"{rec.get('source_id')} seed={rec.get('seed')}: a case with NO "
                "detection-credited field reached the dataset builder. Nothing in "
                "it was proved by a rule, so it is not evidence of anything."
            )
            whole = bool(credit.get("whole"))
            assert whole is is_detection_verified(rec.get("report") or {}), (
                f"{rec.get('source_id')} seed={rec.get('seed')}: credit.whole "
                "disagrees with the report it was derived from."
            )
            roles, ir = rec.get("roles"), rec.get("ir")
            if not roles or not ir:
                dropped += 1
                continue
            ir = _sanitise_grok_names(ir)

            source_id = rec["source_id"]
            source, _ = _load_source(source_id)

            if source_id not in subset_cache:
                subset_cache[source_id] = render_fields(
                    ecs.relevant_subset(
                        source.observed_keys(),
                        source.documentation,
                        source.category_hint,
                        max_fields,
                    )
                )

            # The two stages take credit differently, and the asymmetry is the
            # point.
            #
            # MAP learns one field at a time - roles in, ECS field out - so a
            # credited subset is a complete, correct example of exactly that.
            # The subset is taken even when the proposal passed every scenario:
            # passing proves the fields the rules filtered on, not the ones
            # nobody wrote a rule for. See teacher.filter.training_fields.
            # The pairing holds: the fields were proved by replaying a parser
            # COMPILED FROM THIS IR AND THESE ROLES, so the roles in the prompt
            # are the ones under which the mapping was confirmed.
            #
            # INTERPRET is gated on V3, not V4, since 2026-10-13. V3 is its own
            # exam: it compiles the extraction and runs it over every line. V4
            # is stage 2's exam. Feeding interpret only from whole V4 passes
            # taught it from 219 cases when 437 had a V3-verified extraction -
            # it was being marked down for its neighbour's mistakes. The roles
            # inside the example are still restricted to what V4 proved, field
            # by field, because V3 says nothing about what a key MEANS.
            examples = {
                "map": (
                    prompts.render(
                        "s2_map",
                        source_id=source_id,
                        ecs_version=ecs.version,
                        roles=json.dumps(roles, indent=2, sort_keys=True),
                        ecs_fields=subset_cache[source_id],
                        errors="",
                        previous_ir="",
                    ),
                    _credited_ir(ir, credited),
                ),
            }
            if credit.get("extraction"):
                target_roles = roles if whole else _credited_roles(roles, ir, credited)
                # THE ANSWER MAY NOT BE IN THE QUESTION. A role the source's own
                # documentation or samples already state teaches copying, not
                # reading (corpus/roles.py). Checked against what the source
                # supplies, not the whole prompt: the template's own wording is
                # identical in training and deployment and proves nothing.
                said = leaks([r.get("role", "") for r in target_roles.get("roles") or []],
                             source.documentation + "\n" + source.sample_text())
                if said:
                    leaked.append((source_id, said[0]))
                else:
                    examples["interpret"] = (
                        prompts.render(
                            "s1_interpret",
                            source_id=source_id,
                            samples=source.sample_text(),
                            documentation=source.documentation,
                            errors="",
                            previous_roles="",
                        ),
                        target_roles,
                    )

            for stage, (prompt, target) in examples.items():
                key = _digest(target)
                if key in seen[stage]:
                    dropped += 1
                    continue
                seen[stage].add(key)
                _line = json.dumps(
                        {
                            "source_id": source_id,
                            "family": rec.get("family", source_id),
                            "seed": rec.get("seed"),
                            # Where the target came from: the teacher's name,
                            # "gold" or "augment:<transform>" - the variable the
                            # supervision-source comparison turns on.
                            "origin": rec.get("teacher"),
                            "prompt": prompt,
                            # In the grammar's key order, not sorted: the
                            # students are served under `format: <schema>` and
                            # cannot write any other order (adapter/schema_order).
                            "completion": json.dumps(
                                grammar_order(_without_types(target) if stage == "map" else target,
                                              ROLES_SCHEMA if stage == "interpret" else IR_SCHEMA)),
                            "prompt_digest": prompts.digest,
                            # The apparatus is three things, not one. The prompt
                            # is what the teacher was ASKED; the schema is what
                            # it was ALLOWED to answer; retrieval is which 240
                            # of 1659 fields it was SHOWN. A corpus that records
                            # only the first cannot say whether two runs are
                            # comparable, and the adapter trained on it inherits
                            # the same silence. These are carried from the
                            # proposal rather than recomputed, because what
                            # matters is the apparatus that produced this
                            # example, not the one installed today.
                            "schema_digest": rec.get("schema_digest"),
                            "retrieval_digest": rec.get("retrieval_digest"),
                            "ecs_version": ecs.version,
                        },
                        sort_keys=True,
                    ) + "\n"
                handles[stage].write(_line)
                counts[stage] += 1
                if stage == "interpret":
                    _kind = (target.get("extraction") or {}).get("kind")
                    written.setdefault(_kind, []).append(_line)
    finally:
        for h in handles.values():
            h.close()

    if balance_grok:
        _rebalance_grok(written, balance_grok, counts)

    whole_cases = sum(1 for r in records if (r.get("credit") or {}).get("whole"))
    print(f"cases          : {len(records)}  "
          f"({whole_cases} verified whole, {len(records) - whole_cases} credited at field)")
    print(f"duplicates cut : {dropped}")
    print(f"answer in input: {len(leaked)} interpret example(s) refused"
          + (f"  (first: {leaked[0][0]} states {leaked[0][1]!r})" if leaked else ""))
    for stage in STAGES:
        print(f"  {stage:<10} {counts[stage]:>5} examples  ->  {OUT_DIR / f'{stage}.jsonl'}")

    families = {r.get("family", r["source_id"]) for r in records}
    print(f"\nsource families covered: {len(families)}  ({', '.join(sorted(families))})")
    if len(families) < 8:
        print(
            "\nNOTE: few families. Distillation on a narrow distribution will look "
            "better than it is; the evaluation pool must stay genuinely unlike this."
        )
    print("\nNext:  make ecs-train STAGE=interpret  &&  make ecs-train STAGE=map")
    return counts


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="training.build_dataset", description=__doc__.splitlines()[0]
    )
    p.add_argument("--verified", type=Path, default=VERIFIED)
    p.add_argument("--max-fields", type=int, default=DEFAULT_MAX_FIELDS)
    p.add_argument("--balance-grok", type=float, default=0.0, metavar="SHARE",
                   help="repeat the credited grok examples until they are this "
                        "share of interpret.jsonl (e.g. 0.33). Adds no "
                        "information - see M9 in FAILURE_CATALOGUE.md - and "
                        "must be declared wherever the dataset size is quoted.")
    p.add_argument("--extra", type=Path, nargs="*", default=[],
                   help="further verified-record files, e.g. teacher/out/gold.ndjson")
    p.add_argument("--out-dir", type=Path, default=None,
                   help="where interpret.jsonl and map.jsonl go (default training/data); the "
                        "supervision-source arms (gold, teacher, hybrid) each get their own")
    a = p.parse_args(argv)
    if a.out_dir:
        global OUT_DIR
        OUT_DIR = a.out_dir if a.out_dir.is_absolute() else ROOT / a.out_dir
    build(a.verified, a.max_fields, a.balance_grok, a.extra)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

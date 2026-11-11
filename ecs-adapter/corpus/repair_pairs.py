"""Round 4, phase 2.2: stage-1 REPAIR examples in the edit prompt - a wrong answer, its real feedback, the right one.

WHY THIS EXISTS
---------------
The repair loop never taught anything: every training prompt was a first
attempt (`previous_roles=""`), and the fine-tuned students, shown their own
failed answer and V2's diagnosis, rewrote the same answer. On OpenSSH 9.2 C-real
got the exact missing line three times and never added a pattern; on Apache
every model kept the 2.2 header through three rounds.

Each example here is one repair turn, rendered by adapter.edit.render_edit_prompt
with `errors` and `previous_roles` filled exactly as the edit architecture
fills them when it repairs (StagedArchitecture.repair -> _interpret). The
damaged answers are the errors actually observed in rounds 2-3:

    copied_old       the previous version's answer, unedited (Apache, every model)
    dropped_alt      a message type left out (OpenSSH 9.2: `Connection closed by`)
    unknown_grok     a syntax name grok does not define (`SYSLOGHOSTNAME`, `EMAIL`)
    invalid_regex    a group left unbalanced (Apache, phase 1.8)
    capture_removed  a mapped key no pattern captures any more (Apache, phase 1.1)

The feedback is V1/V2's REAL report on the damaged answer against the new
version's samples (the same report the ladder would give), and an example is
kept only if that report names a problem - a damage V2 cannot see teaches
nothing about reading feedback. The target is the new version's gold answer,
credited as training/build_dataset.py credits it.

No round-3 source is used, in any role.

    python -m corpus.repair_pairs --out training/data/edit --n 1000
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any
import argparse
import copy
import json
import random
import re

from corpus.edit_pairs import GOLD, ROOT, _source_lines, candidate_pairs

DAMAGES = ("copied_old", "dropped_alt", "unknown_grok", "invalid_regex", "capture_removed")
# Round 10 (PLAN_ROUND10_ARM_C.md, T1): two damages only the faithful grok simulator can see (F1), whose
# repair the diagnosis (F2) spells out - a date class that does not read the line's date (Gitea, r6), and a
# capture class too narrow for its values (LOGLEVEL on `I`, WORD on `node-7`). Off under ECS_PIPELINE=round9.
ROUND10_DAMAGES = ("wrong_date_class", "narrow_class")
_DATE_SWAP = {"TIMESTAMP_ISO8601": "HTTPDATE", "SYSLOGTIMESTAMP": "TIMESTAMP_ISO8601",
              "HTTPDATE": "SYSLOGTIMESTAMP", "HTTPDERROR_DATE": "TIMESTAMP_ISO8601"}
_NARROW = {"NOTSPACE": "WORD", "HOSTNAME": "WORD", "IPORHOST": "IP", "USERNAME": "WORD", "DATA": "WORD",
           "GREEDYDATA": "WORD", "NUMBER": "INT", "UNIXPATH": "WORD", "URIPATHPARAM": "URIPATH"}


def damages() -> tuple[str, ...]:
    from adapter.types import round9_pipeline

    return DAMAGES if round9_pipeline() else DAMAGES + ROUND10_DAMAGES
_TOKEN = re.compile(r"%\{([A-Z0-9_]+):([A-Za-z_][A-Za-z0-9_.]*)((?::[a-z]+)?)\}")
_FAKE = {"IP": "IPADDR", "HOSTNAME": "HOST", "INT": "INTEGER", "WORD": "STRING",
         "NOTSPACE": "TOKEN", "DATA": "TEXT", "TIMESTAMP_ISO8601": "TIMESTAMP"}


def _patterns(roles: dict) -> list[str]:
    e = roles.get("extraction") or {}
    return [p for p in [e.get("pattern")] + list(e.get("alternatives") or []) if p]


def _with_patterns(roles: dict, pats: list[str]) -> dict:
    out = copy.deepcopy(roles)
    out["extraction"]["pattern"] = pats[0]
    if len(pats) > 1 or "alternatives" in roles.get("extraction", {}):
        out["extraction"]["alternatives"] = pats[1:]
    return out


def damage(kind: str, target: dict, old_roles: dict, rng: random.Random) -> dict | None:
    """The target answer damaged in one named way, or None if this answer cannot be."""
    pats = _patterns(target)
    grok = (target.get("extraction") or {}).get("kind") == "grok"
    if kind == "copied_old":
        return copy.deepcopy(old_roles)
    if not grok or not pats:
        return None
    if kind == "dropped_alt":
        if len(pats) < 2:
            return None
        i = rng.randrange(len(pats))
        return _with_patterns(target, pats[:i] + pats[i + 1:])
    if kind == "unknown_grok":
        cands = [(i, m) for i, p in enumerate(pats) for m in _TOKEN.finditer(p) if m.group(1) in _FAKE]
        if not cands:
            return None
        i, m = rng.choice(cands)
        bad = pats[i][:m.start()] + "%{" + _FAKE[m.group(1)] + ":" + m.group(2) + m.group(3) + "}" + pats[i][m.end():]
        return _with_patterns(target, pats[:i] + [bad] + pats[i + 1:])
    if kind == "invalid_regex":
        i = rng.randrange(len(pats))
        p = pats[i]
        k = p.rfind(")")
        if k < 0:
            return None
        return _with_patterns(target, pats[:i] + [p[:k] + p[k + 1:]] + pats[i + 1:])
    if kind in ("wrong_date_class", "narrow_class"):
        table = _DATE_SWAP if kind == "wrong_date_class" else _NARROW
        cands = [(i, m) for i, p in enumerate(pats) for m in _TOKEN.finditer(p) if m.group(1) in table]
        if not cands:
            return None
        i, m = rng.choice(cands)
        bad = pats[i][:m.start()] + "%{" + table[m.group(1)] + ":" + m.group(2) + m.group(3) + "}" + pats[i][m.end():]
        return _with_patterns(target, pats[:i] + [bad] + pats[i + 1:])
    if kind == "capture_removed":
        cands = [(i, m) for i, p in enumerate(pats) for m in _TOKEN.finditer(p)]
        if not cands:
            return None
        i, m = rng.choice(cands)
        bare = pats[i][:m.start()] + "%{" + m.group(1) + "}" + pats[i][m.end():]
        return _with_patterns(target, pats[:i] + [bare] + pats[i + 1:])
    raise ValueError(kind)


def feedback(damaged_roles: dict, ir_b: dict, source) -> str:
    """V1/V2's real report on the IR the damaged answer would produce."""
    from adapter.architectures import _carry_extraction
    from adapter.wiring import _ecs_index
    from validators import v1_schema, v2_consistency

    ir = _carry_extraction(damaged_roles, copy.deepcopy(ir_b))
    rep = v1_schema.validate(ir, _ecs_index())
    if rep.passed:
        rep = v2_consistency.validate(ir, source)
    # The same renderer the repair loop serves with (round 10, A2): a model
    # trained on one wording and served another is round 1's C-gold failure.
    from adapter.diagnose import render

    return render(rep, ir, source) if rep.findings else ""


def build(n: int, out_dir: Path, seed: int = 5) -> dict[str, Any]:
    from adapter.architectures import ROLES_SCHEMA
    from adapter.edit import edit_prompt_digest, old_roles, render_edit_prompt
    from adapter.prompts import Prompts
    from adapter.schema_order import grammar_order
    from adapter.wiring import _ecs_index, _load_source
    from corpus.roles import leaks
    from training.build_dataset import _credited_roles, _sanitise_grok_names

    records = {}
    for line in GOLD.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            if r.get("ir") and r.get("roles") and (ROOT / "bench" / "sources" / r["source_id"]).is_dir():
                records[r["source_id"]] = r
    pairs = candidate_pairs(records)
    pool = pairs["header"] + pairs["layout"]
    rng = random.Random(seed)
    rng.shuffle(pool)
    prompts, ecs = Prompts(ROOT / "prompts"), _ecs_index()
    kinds = damages()
    per_kind = n // len(kinds)
    counts: dict[str, int] = defaultdict(int)
    skipped: dict[str, int] = defaultdict(int)
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "interpret_repair.jsonl").open("w", encoding="utf-8") as fh:
        for a, b in pool:
            if all(counts[k] >= per_kind for k in kinds):
                break
            ra, rb = records[a], records[b]
            credit = rb.get("credit") or {}
            if not credit.get("extraction"):
                continue
            old_ir = _sanitise_grok_names(ra["ir"])
            ir_b = _sanitise_grok_names(rb["ir"])
            credited = frozenset(credit.get("fields") or [])
            target = rb["roles"] if credit.get("whole") else _credited_roles(rb["roles"], ir_b, credited)
            source, _ = _load_source(b)
            if leaks([r.get("role", "") for r in target.get("roles") or []],
                     source.documentation + "\n" + source.sample_text()):
                skipped["answer in input"] += 1
                continue
            kind = min(kinds, key=lambda k: counts[k])  # fill the scarcest kind first
            wrong = damage(kind, target, old_roles(old_ir), rng)
            if wrong is None:
                skipped[f"{kind}: not applicable"] += 1
                continue
            fb = feedback(wrong, ir_b, source)
            if not fb:
                skipped[f"{kind}: V1/V2 silent"] += 1
                continue
            prompt = render_edit_prompt(prompts, source, old_ir, _source_lines(a), errors=fb,
                                        previous_roles=json.dumps(wrong, indent=2, sort_keys=True))
            fh.write(json.dumps({
                "source_id": b, "previous_source_id": a, "family": rb.get("family", b),
                "seed": rb.get("seed"), "origin": f"repair:{kind}", "prompt": prompt,
                "completion": json.dumps(grammar_order(target, ROLES_SCHEMA)),
                "prompt_digest": prompts.digest, "edit_prompt_digest": edit_prompt_digest(),
                "schema_digest": rb.get("schema_digest"), "retrieval_digest": rb.get("retrieval_digest"),
                "ecs_version": ecs.version,
            }, sort_keys=True) + "\n")
            counts[kind] += 1
    summary = {"written": dict(counts), "skipped": dict(skipped)}
    (out_dir / "repair_pairs_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--out", type=Path, default=ROOT / "training" / "data" / "edit")
    a = ap.parse_args(argv)
    print(json.dumps(build(a.n, a.out), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

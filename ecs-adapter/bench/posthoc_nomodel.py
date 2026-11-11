"""B4 (POSTHOC_REVIEW_ANALYSES.md): maintenance with no language model.

For each of the 20 test pairs, two candidates no model wrote:
  previous   the previous parser as it is, renamed to the new source (what "no action" deploys)
  layer      the previous parser after the system's deterministic layer (adapter/normalise.apply_all, with the flags
             the recorded runs used): template-miner alternatives for unread lines, the old grok nested in JSON,
             the old mappings carried, and every other rewrite that needs no model
Each goes through the same ladder (V1-V4, holdout scenarios) and gate as the recorded runs, and is judged with the
paper's judge. One run per pair: nothing here is random.

    ECS_SANDBOX_LOGSTASH=... ELASTICSEARCH_HOST=http://127.0.0.1:9201 \\
    python -m bench.posthoc_nomodel --out ~/.cache/ecs-r10/posthoc/b4_nomodel.json
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any
import argparse
import json
import os

from bench.replay import FROZEN_FLAGS

for _k, _v in FROZEN_FLAGS.items():
    os.environ.setdefault(_k, _v)

from adapter.edit import load_previous_ir  # noqa: E402 - the flags must be set before the layer is imported
from adapter.normalise import apply_all  # noqa: E402
from adapter.wiring import _es, _load_source  # noqa: E402
from bench.paper_r10 import R7, REAL  # noqa: E402
from bench.posthoc_gate import evaluate, ladder_for  # noqa: E402
from bench.posthoc_vc import rules_covered, rules_of  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    from bench.arms import _index
    ecs, es = _index(), _es()
    assert es is not None, "set ELASTICSEARCH_HOST"
    rows = []
    for sid in sorted(R7):
        prev = load_previous_ir(sid)
        if not prev:
            rows.append({"source": sid, "error": "no previous parser"})
            continue
        source, _ = _load_source(sid)
        base = deepcopy(prev)
        base["source_id"] = sid
        layer, made = apply_all(deepcopy(base), list(source.parser_input()), ecs)
        lad = ladder_for(sid, ecs, es)
        for name, ir in (("previous", base), ("layer", layer)):
            row: dict[str, Any] = {"source": sid, "real": sid in REAL, "group": R7[sid][3], "candidate": name}
            if name == "layer":
                row["rewrites"] = [m.get("rule") or m.get("action") for m in made]
            try:
                row.update(evaluate(ir, sid, lad, f"posthoc-nomodel-{sid}-{name}".lower()))
            except Exception as exc:  # noqa: BLE001
                row["error"] = f"{type(exc).__name__}: {exc}"
            ok, tot = rules_covered(sid, set(row.get("gate_deliver") or []))
            row["rules_total"] = len(rules_of(sid))
            row["rules_fire"] = tot if row.get("accepted") else ok
            rows.append(row)
            print(sid, name, {k: row.get(k) for k in ("rung", "accepted", "gate_deploys", "gate_wrong",
                                                      "rules_fire", "rules_total", "error")}, flush=True)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps({"rows": rows}, indent=1, default=str))


if __name__ == "__main__":
    main()

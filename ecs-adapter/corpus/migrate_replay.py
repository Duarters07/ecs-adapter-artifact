"""Round 10, F5: bring the interpret replay set to the prompts the model is served with.

The replay set (training/data/interpret.jsonl, 740 verified rows) was rendered with the prompts of prompt digest
sha256:b0920486257eb803. Round 10 changed s1_interpret in one place only (F3, nested extraction): the `json` line of the
extraction kinds gained the `inner` explanation. Every other byte of a replay prompt (samples, documentation, including
the augmented rows' own documentation, which no source on disk holds) is still what the current template renders.

So the migration is an exact substitution of that block, refused when the block does not occur exactly once, and the
row's prompt_digest becomes the current one. The completions are unchanged: `inner` is optional, and every replay
answer was verified by the ladder without it. tests/test_round10_migrate.py checks the result against a fresh render.

    python -m corpus.migrate_replay --data training/data/interpret.jsonl --out training/data/r10/replay_interpret.jsonl
"""
from __future__ import annotations

from pathlib import Path
import argparse
import json

ROOT = Path(__file__).resolve().parents[1]
FROM_DIGEST = "sha256:b0920486257eb803"
OLD = "   - `json`  the entire line is a JSON object, starting with `{`.\n"
NEW = ("   - `json`  the entire line is a JSON object, starting with `{`. If the\n"
       "             values you need sit as TEXT inside one key - \"msg\": \"Login failed\n"
       "             for user ana from 10.0.0.1\" - also give `inner`: `source` names\n"
       "             that key and `pattern` is a grok over its text, written like a\n"
       "             `grok` pattern below. Its capture names are keys beside the JSON\n"
       "             keys. Leave `inner` out when every value has its own JSON key.\n")


def migrate_row(row: dict, digest: str) -> dict:
    if row.get("prompt_digest") == digest:
        return row
    if row.get("prompt_digest") != FROM_DIGEST:
        raise ValueError(f"{row.get('source_id')}: prompt digest {row.get('prompt_digest')} is not {FROM_DIGEST}")
    if row["prompt"].count(OLD) != 1:
        raise ValueError(f"{row.get('source_id')}: the json block occurs {row['prompt'].count(OLD)} times, not once")
    return {**row, "prompt": row["prompt"].replace(OLD, NEW), "prompt_digest": digest,
            "migrated_from_digest": FROM_DIGEST}


def migrate(data: Path, out: Path) -> dict:
    from adapter.prompts import Prompts
    digest = Prompts(ROOT / "prompts").digest
    rows = [json.loads(l) for l in data.read_text(encoding="utf-8").splitlines() if l.strip()]
    done = [migrate_row(r, digest) for r in rows]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in done), encoding="utf-8")
    return {"rows": len(done), "digest": digest, "migrated": sum("migrated_from_digest" in r for r in done)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="corpus.migrate_replay")
    ap.add_argument("--data", type=Path, default=ROOT / "training" / "data" / "interpret.jsonl")
    ap.add_argument("--out", type=Path, default=ROOT / "training" / "data" / "r10" / "replay_interpret.jsonl")
    a = ap.parse_args(argv)
    print(json.dumps(migrate(a.data, a.out)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

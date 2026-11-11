"""Task 3 (TASK3_EXTERNAL.md): does a model complete Loghub-2.0 lines it should not know?

Loghub has been public since 2020 and may be in Qwen2.5's pretraining data. A model that has seen a log will complete
one of its lines verbatim from the line's first half: timestamps, PIDs, host names and addresses are not guessable
from the format alone. The probe is run once per model an arm serves (the 7B base, each arm C interpret adapter, the
14B), with no prompt but the half line, so it measures the model and not the pipeline.

  prepare  on the laptop: N lines per system, drawn with a fixed seed from the system's whole log, never one of the
           20 frozen samples; each cut at the whitespace nearest its middle (a line with no space there is skipped).
           Written to one JSON file, hashed before any model sees it.
  run      on the card: Ollama /api/generate, raw (no chat template), temperature 0, seed 0, up to 96 tokens; the
           completion is cut at its first newline.

Per line: `verbatim` when the completion, stripped of leading spaces, starts with the whole second half;
`prefix` the share of the second half's characters the completion reproduces before the first difference.
Per (model, system): the verbatim rate and the mean prefix share. The pre-registration's reading: no verbatim rate
above 5% for any arm, else that arm's Loghub numbers are reported as possibly contaminated.

    python -m bench.memorisation_probe prepare --root ~/.cache/ecs-r10/datasets/loghub-2.0/extracted \\
        --task3 ~/.cache/ecs-r10/task3 --n 100 --out ~/.cache/ecs-r10/F8a/memorisation_probe.json
    python -m bench.memorisation_probe run --probe memorisation_probe.json --model qwen2.5-coder:7b-instruct-q8_0 \\
        --out results/memo-B.json
"""
from __future__ import annotations

from pathlib import Path
import argparse
import json
import os
import random
import urllib.request

SEED = 0
MAX_TOKENS = 96


def cut(line: str) -> tuple[str, str] | None:
    """(first half, second half) at the space nearest the middle, the space kept on the first half; None if the line
    has no space in its middle half (nothing fair to complete)."""
    mid = len(line) // 2
    spaces = [i for i, c in enumerate(line) if c == " " and len(line) // 4 <= i <= 3 * len(line) // 4]
    if not spaces:
        return None
    i = min(spaces, key=lambda j: (abs(j - mid), j))
    return line[:i + 1], line[i + 1:]


def prepare(root: Path, task3: Path, systems: tuple[str, ...], n: int) -> dict:
    out: dict = {"seed": SEED, "n": n, "systems": {}}
    for system in systems:
        samples = {json.loads(l)["raw"] for l in (task3 / "loghub" / system / "samples.ndjson")
                   .read_text(encoding="utf-8").splitlines() if l.strip()}
        lines = [l for l in (root / system / f"{system}_full.log").read_text(errors="replace").splitlines()
                 if l.strip() and l not in samples]
        rng = random.Random(f"{SEED}:{system}")
        picked, seen = [], set()
        for i in rng.sample(range(len(lines)), len(lines)):
            if len(picked) == n:
                break
            if lines[i] in seen or (halves := cut(lines[i])) is None:
                continue
            seen.add(lines[i])
            picked.append({"line": i, "head": halves[0], "tail": halves[1]})
        out["systems"][system] = picked
    return out


def judge(tail: str, completion: str) -> dict:
    got = completion.split("\n", 1)[0].lstrip(" ")
    want = tail.lstrip(" ")
    k = 0
    while k < min(len(got), len(want)) and got[k] == want[k]:
        k += 1
    return {"verbatim": got.startswith(want), "prefix": round(k / len(want), 4) if want else 1.0}


def generate(model: str, prompt: str, endpoint: str) -> str:
    body = json.dumps({"model": model, "prompt": prompt, "raw": True, "stream": False,
                       "options": {"temperature": 0, "seed": SEED, "num_predict": MAX_TOKENS}}).encode()
    req = urllib.request.Request(endpoint.rstrip("/") + "/api/generate", body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.loads(r.read())["response"]


def run(probe: dict, model: str, endpoint: str) -> dict:
    per_system = {}
    for system, items in probe["systems"].items():
        verdicts = [judge(x["tail"], generate(model, x["head"], endpoint)) for x in items]
        per_system[system] = {
            "lines": len(verdicts),
            "verbatim_rate": round(sum(v["verbatim"] for v in verdicts) / max(len(verdicts), 1), 4),
            "mean_prefix": round(sum(v["prefix"] for v in verdicts) / max(len(verdicts), 1), 4),
            "lines_verdicts": verdicts,
        }
    return {"model": model, "systems": per_system,
            "contaminated": any(s["verbatim_rate"] > 0.05 for s in per_system.values())}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="bench.memorisation_probe")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--task3", type=Path, required=True)
    p.add_argument("--n", type=int, default=100)
    p.add_argument("--out", type=Path, required=True)
    r = sub.add_parser("run")
    r.add_argument("--probe", type=Path, required=True)
    r.add_argument("--model", required=True)
    r.add_argument("--endpoint", default=os.environ.get("ECS_MODEL_ENDPOINT", "http://127.0.0.1:11434"))
    r.add_argument("--out", type=Path, required=True)
    a = ap.parse_args(argv)
    if a.cmd == "prepare":
        from bench.task3_bench import LOGHUB
        out = prepare(a.root.expanduser(), a.task3.expanduser(), LOGHUB, a.n)
    else:
        out = run(json.loads(a.probe.read_text(encoding="utf-8")), a.model, a.endpoint)
        print(json.dumps({s: {k: v for k, v in x.items() if k != "lines_verdicts"}
                          for s, x in out["systems"].items()}))
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Task 3 (TASK3_EXTERNAL.md): assemble the bench tree the arms run on, outside the repository.

AIT-LDS is CC BY-NC-SA, so the six Task 3 sources live in ~/.cache/ecs-r10/task3 and never in bench/sources. This
module checks every frozen file against MANIFEST.sha256 (the pre-registration's input, 2026-10-30) and refuses to go
on if one differs; it then writes a tree with bench/'s layout, which bench.arms reads through ECS_BENCH_ROOT:

    <out>/sources/<sid>/samples.ndjson    the frozen samples, byte for byte
    <out>/sources/<sid>/truth.json        the frozen truth plus split "test_t3" and the family (derived, not frozen)
    <out>/scenarios/<sid>__t3_NN/         the frozen events and query; expected.json plus split "holdout"
    <out>/sources/t3lh_<system>/          Loghub-2.0: the frozen 20 samples, a truth with split "test_t3lh" and no
                                          fields (Loghub has no ECS gold; what is scored is the extraction, by
                                          bench.task3_loghub against the official templates), no scenario

Nothing else is given to a model: no documentation.md (the pre-registration names none, and every arm gets the same
nothing), no known_values.json (Task 3 has no probe line, so V3.5 does not run), no previous parser (Task 1's mode).

    python -m bench.task3_bench --task3 ~/.cache/ecs-r10/task3 --out ~/.cache/ecs-r10/task3/bench
    ECS_BENCH_ROOT=~/.cache/ecs-r10/task3/bench python -m bench.arms --pool t3 --architecture staged ...
"""
from __future__ import annotations

from pathlib import Path
import argparse
import hashlib
import json
import shutil

LOGHUB = ("Apache", "Linux", "OpenSSH", "Proxifier", "Zookeeper")   # the five frozen in the pre-registration
FAMILIES = {  # source id -> family, as TASK3_EXTERNAL.md names the formats
    "t3_ait_apache_access": "apache-access", "t3_ait_apache_error": "apache-error", "t3_ait_auth": "linux-auth",
    "t3_ait_audit": "linux-auditd", "t3_ait_dnsmasq": "dnsmasq", "t3_ait_openvpn": "openvpn",
}


def verify(task3: Path) -> int:
    """Every line of MANIFEST.sha256 must still hold; returns the number of files checked."""
    bad, n = [], 0
    for line in (task3 / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, rel = line.split(None, 1)
        p = task3 / rel.strip()
        n += 1
        if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest() != digest:
            bad.append(rel.strip())
    if bad:
        raise SystemExit(f"Task 3 files differ from the frozen manifest: {bad}")
    return n


def assemble(task3: Path, out: Path) -> dict[str, int]:
    verify(task3)
    if out.exists():
        shutil.rmtree(out)
    counts = {"sources": 0, "scenarios": 0}
    for sid, family in FAMILIES.items():
        src, dst = task3 / "sources" / sid, out / "sources" / sid
        dst.mkdir(parents=True)
        shutil.copyfile(src / "samples.ndjson", dst / "samples.ndjson")
        truth = json.loads((src / "truth.json").read_text(encoding="utf-8"))
        truth.update(split="test_t3", family=family)
        (dst / "truth.json").write_text(json.dumps(truth, indent=1) + "\n", encoding="utf-8")
        counts["sources"] += 1
    for sc in sorted((task3 / "scenarios").iterdir()):
        dst = out / "scenarios" / sc.name
        dst.mkdir(parents=True)
        for name in ("events.ndjson", "query.json"):
            shutil.copyfile(sc / name, dst / name)
        expected = json.loads((sc / "expected.json").read_text(encoding="utf-8"))
        expected["split"] = "holdout"
        (dst / "expected.json").write_text(json.dumps(expected, indent=1) + "\n", encoding="utf-8")
        counts["scenarios"] += 1
    for system in LOGHUB:
        dst = out / "sources" / f"t3lh_{system.lower()}"
        dst.mkdir(parents=True)
        shutil.copyfile(task3 / "loghub" / system / "samples.ndjson", dst / "samples.ndjson")
        truth = {"source_id": dst.name, "split": "test_t3lh", "family": f"loghub-{system.lower()}",
                 "loghub_system": system, "fields": []}
        (dst / "truth.json").write_text(json.dumps(truth, indent=1) + "\n", encoding="utf-8")
        counts["loghub"] = counts.get("loghub", 0) + 1
    return counts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="bench.task3_bench")
    ap.add_argument("--task3", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args(argv)
    print(json.dumps(assemble(a.task3.expanduser(), a.out.expanduser())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

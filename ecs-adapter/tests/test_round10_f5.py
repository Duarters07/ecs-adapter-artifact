"""Round 10, F5 (PLAN_ROUND10_ARM_C.md, section 4 rule 4): the test sets stay out of every round-10 training set.

The test is r7 plus Task 3, frozen 2026-10-30 (~/.cache/ecs-r10/F8a/). Their families are fixed, so no training row
may come from them, whatever its version:

  r7       every family of testbed/r3/r7specs (old and new versions alike: an r7 old version is only ever the
           previous parser, never training data)
  Task 3   AIT-LDS's source ids and dnsmasq, the one Task 3 family no training source covers (Apache, auth.log and
           auditd ARE covered by SIEMgen; TASK3_EXTERNAL.md says Task 3 does not measure unseen families)

r3-r6 are development in round 10. Their OLD versions may enter organisation data, as org9's recipe did; their NEW
versions (the `test_r*` sources) never.
"""
from __future__ import annotations

from pathlib import Path
import json
import os
import re
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "bench" / "sources"
R10_DATA = ROOT / "training" / "data" / "r10"
TASK3_FAMILIES = {"dnsmasq"}
TASK3_PREFIX = ("t3_", "t3lh_")   # AIT-LDS sources, Loghub-2.0 systems (F8a)


def _truths() -> list[dict]:
    out = []
    for t in sorted(SOURCES.glob("*/truth.json")):
        d = json.loads(t.read_text(encoding="utf-8"))
        d.setdefault("family", t.parent.name)
        d["_id"] = t.parent.name
        out.append(d)
    return out


def _r7() -> tuple[set[str], set[str]]:
    """(families, source ids) of r7, from the specs (R7=1 joins them)."""
    os.environ.setdefault("R7", "1")
    from testbed.r3.r7specs import R7_PAIRS
    fams = {s.family for pair in R7_PAIRS.values() for s in pair}
    ids = {s.source_id for pair in R7_PAIRS.values() for s in pair}
    return fams, ids


def _forbidden() -> tuple[set[str], set[str]]:
    fams, ids = _r7()
    ids |= {d["_id"] for d in _truths() if str(d.get("split", "")).startswith("test_r")}
    return fams | TASK3_FAMILIES, ids


def test_r7_has_twenty_pairs_and_its_families_are_new():
    fams, ids = _r7()
    assert len(ids) == 40, len(ids)
    training = {d["family"] for d in _truths() if d.get("split") == "train"}
    assert not (fams & training), sorted(fams & training)
    assert not (TASK3_FAMILIES & training)


def test_no_task3_line_lives_in_the_repository():
    """AIT-LDS is CC BY-NC-SA: its samples and gold stay in ~/.cache/ecs-r10/task3."""
    assert not [p.name for p in SOURCES.iterdir() if p.name.startswith(TASK3_PREFIX)]


def _rows(path: Path):
    with path.open(encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if line.strip():
                yield n, json.loads(line)


@pytest.mark.skipif(not R10_DATA.is_dir(), reason="no round-10 training data yet (F5)")
def test_no_round10_training_row_comes_from_a_test_family():
    fams, ids = _forbidden()
    bad = []
    for path in sorted(R10_DATA.rglob("*.jsonl")):
        for n, row in _rows(path):
            fam = str(row.get("family") or "")
            sids = {str(row.get(k) or "") for k in ("source_id", "previous_source_id")}
            if fam in fams or sids & ids or any(s.startswith(TASK3_PREFIX) for s in sids):
                bad.append(f"{path.relative_to(ROOT)}:{n} family={fam} ids={sorted(sids - {''})}")
    assert not bad, bad[:20]


def test_the_scan_catches_a_planted_row(tmp_path, monkeypatch):
    """The guard above must refuse a row from an r7 family, an r7 id, a test_r* id or a Task 3 id."""
    fams, ids = _forbidden()
    fam = sorted(fams - TASK3_FAMILIES)[0]
    rows = [{"family": fam, "source_id": "x"}, {"family": "x", "source_id": sorted(ids)[0]},
            {"family": "x", "source_id": "t3_ait_auth"}, {"family": "dnsmasq", "source_id": "x"}]
    d = tmp_path / "r10"; d.mkdir()
    (d / "planted.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "R10_DATA", d)
    monkeypatch.setattr(sys.modules[__name__], "ROOT", tmp_path)
    with pytest.raises(AssertionError) as e:
        test_no_round10_training_row_comes_from_a_test_family()
    caught = set(re.findall(r"planted\.jsonl:(\d+) ", str(e.value)))
    assert caught == {"1", "2", "3", "4"}, str(e.value)

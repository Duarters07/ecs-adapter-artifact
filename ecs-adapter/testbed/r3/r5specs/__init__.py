"""Round 6 (pool r5): the second held-out set (ROUND3_VERSION_DRIFT.md, "Round 6").

One module per pair, each exporting OLD and NEW. Kept apart from testbed/r3/specs.py
so that corpus/r3_real_old.py, which builds training material from specs.PAIRS,
can never pick up a round-6 source: these were captured after training and are
evaluation only. ALL_PAIRS is what the capture tooling (build, verify_gold, t3) reads.
"""
from __future__ import annotations

from importlib import import_module

from testbed.heldout_r2.specs import Spec
from testbed.r3.specs import PAIRS

# In the pre-registered order; a pair is listed once its module exists.
_ORDER = ("envoy", "tomcat", "grafana", "samba", "varnish", "mosquitto", "slapd",
          "proftpd", "freeradius", "dropbear", "clamav", "prosody", "openvpn")

R5_PAIRS: dict[str, tuple[Spec, Spec]] = {}
for _name in _ORDER:
    try:
        _m = import_module(f"testbed.r3.r5specs.{_name}")
    except ModuleNotFoundError as e:
        if e.name != f"testbed.r3.r5specs.{_name}":
            raise
        continue
    R5_PAIRS[f"r5_{_name}"] = (_m.OLD, _m.NEW)

ALL_PAIRS: dict[str, tuple[Spec, Spec]] = {**PAIRS, **R5_PAIRS}

# Round 8 (pool r6) joins only on request (R6=1): see testbed/r3/r6specs/__init__.py.
import os as _os
if _os.environ.get("R6"):
    from testbed.r3.r6specs import R6_PAIRS
    ALL_PAIRS.update(R6_PAIRS)

# Round 10 (pool r7) joins only on request (R7=1): see testbed/r3/r7specs/__init__.py.
if _os.environ.get("R7"):
    from testbed.r3.r7specs import R7_PAIRS
    ALL_PAIRS.update(R7_PAIRS)

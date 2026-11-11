"""Round 8 (pool r6): the third held-out set (ROUND3_VERSION_DRIFT.md, "Round 8").

As r5specs: one module per pair, outside specs.PAIRS, so corpus/r3_real_old.py never reads them.
R6_PAIRS joins the capture tooling's ALL_PAIRS only when R6=1 is set, so nothing that runs today
(round 7b's tools, the organisation data of C-org/7b) sees an r6 pair by accident.
"""
from __future__ import annotations

from importlib import import_module

from testbed.heldout_r2.specs import Spec

_ORDER = ("rabbitmq", "authelia", "unrealircd", "lighttpd", "opensmtpd", "pureftpd", "rsyncd",
          "tinyproxy", "courier", "coturn", "vaultwarden", "gitea", "jenkins")

R6_PAIRS: dict[str, tuple[Spec, Spec]] = {}
for _name in _ORDER:
    try:
        _m = import_module(f"testbed.r3.r6specs.{_name}")
    except ModuleNotFoundError as e:
        if e.name != f"testbed.r3.r6specs.{_name}":
            raise
        continue
    R6_PAIRS[f"r6_{_name}"] = (_m.OLD, _m.NEW)

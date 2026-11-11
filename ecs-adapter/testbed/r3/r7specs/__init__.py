"""Round 10 (pool r7): the fourth held-out set (ROUND3_VERSION_DRIFT.md, "r7 captures"; rule frozen at the end of F0).

As r6specs: one module per pair, outside specs.PAIRS, so corpus/r3_real_old.py never reads them. R7_PAIRS joins the
capture tooling's ALL_PAIRS only when R7=1 is set, so no round-10 training builder sees an r7 pair by accident.
The order is the frozen candidate order; controls are included, as in r6.
"""
from __future__ import annotations

from dataclasses import replace
from importlib import import_module

from testbed.heldout_r2.specs import Spec

_ORDER = ("389ds", "inspircd", "emqx", "ngircd", "radicale", "ocserv", "rspamd", "knot", "nsd", "sendmail", "icinga2",
          "unbound", "mumble", "stunnel", "privoxy", "pdnsrec", "synapse", "mattermost", "nextcloud", "kamailio")



def _unqueryable_abstentions(spec: Spec) -> Spec:
    """A field a parser may rightly leave unmapped (acceptable_abstention) is never a V4 rule's target.

    Otherwise a scenario would fail the parser that correctly declines it. r6 never needed this (its abstentions had
    no ECS field); some r7 abstentions name a plausible field (e.g. user.effective.name for an IRC operator account).
    """
    extra = {f["ecs_field"]: "acceptable abstention: a parser may rightly leave it unmapped"
             for f in spec.fields if f.get("acceptable_abstention") and f.get("ecs_field")}
    return replace(spec, unqueryable={**extra, **spec.unqueryable}) if extra else spec


R7_PAIRS: dict[str, tuple[Spec, Spec]] = {}
for _name in _ORDER:
    try:
        _m = import_module(f"testbed.r3.r7specs._{_name}" if _name[0].isdigit() else f"testbed.r3.r7specs.{_name}")
    except ModuleNotFoundError as e:
        if not (e.name or "").startswith("testbed.r3.r7specs."):
            raise
        continue
    R7_PAIRS[f"r7_{_name}"] = (_unqueryable_abstentions(_m.OLD), _unqueryable_abstentions(_m.NEW))

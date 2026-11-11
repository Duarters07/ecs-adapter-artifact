"""r7_nsd: NSD log (stderr, verbosity 2), Debian 12 (4.6.1) -> Debian 13 (4.12.0): zone transfer requests."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_HEAD = re.compile(r"^\[(?P<timestamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\] nsd\[(?P<pid>\d+)\]: (?P<level>[a-z]+): (?P<msg>.*)$")
_MSGS = (
    re.compile(r"^(?P<xfr_type>axfr|ixfr) for (?P<zone>\S+?)\.? from (?P<client_ip>[0-9.]+) (?P<reason>refused, no acl matches)$"),
    re.compile(r"^(?P<xfr_type>axfr|ixfr) for (?P<zone>\S+?)\.? from (?P<client_ip>[0-9.]+)(?: +(?P<verification>not-verified))?$"),
    re.compile(r"^(?P<action>ixfr fallback to axfr), (?P<reason>no ixfr info) for zone: (?P<zone>\S+?)\.?$"),
)


def _extract(line: str) -> dict[str, str]:
    m = _HEAD.match(line.strip())
    if not m:
        return {}
    for rx in _MSGS:
        mm = rx.match(m.group("msg"))
        if mm:
            out = {k: v for k, v in m.groupdict().items() if k != "msg"}
            out.update({k: v for k, v in mm.groupdict().items() if v is not None})
            return out
    return {}


def _doc(version: str, new: bool) -> str:
    allowed = "<xfr_type> for <zone>. from <client_ip>  not-verified" if new else "<xfr_type> for <zone>. from <client_ip>"
    extra = ("\n    ixfr fallback to axfr, no ixfr info for zone: <zone>.\n" if new else "\n")
    return f"""
# NSD {version} - log, verbosity 2, foreground on stderr

Source: nsd.conf(5) ("verbosity", "provide-xfr"), Debian package. The server is authoritative for four zones and
provides zone transfers to two secondary addresses. One line per event:

    [<yyyy-mm-dd hh:mm:ss.mmm>] nsd[<pid>]: <level>: <message>

## The messages kept

    {allowed}
    <xfr_type> for <zone>. from <client_ip> refused, no acl matches{extra}
- `xfr_type` - axfr (full) or ixfr (incremental) zone transfer request; `zone` - the zone requested
- `client_ip` - the requester; `pid` - the serving process; `level` - info
- `reason` - why the request was refused (no `provide-xfr` entry matches the requester){"" if not new else ", or why an IXFR falls back to AXFR"}
{"- `verification` - not-verified: the request was allowed without a TSIG key (NOKEY)" if new else ""}
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("zone", "dns.question.name", "keyword", "zone", "medium", "The zone is the transfer request's question name."),
    _f("xfr_type", "dns.question.type", "keyword", "transfer_type", "medium", "axfr/ixfr are query types (lowercase here)."),
    _f("reason", "event.reason", "keyword", "refusal_reason", "medium"),
    _f("action", "event.action", "keyword", "event_type", "medium"),
    _f("pid", "process.pid", "long", "process_id", "easy"),
    _f("level", "log.level", "keyword", "severity", "easy"),
    _f("verification", None, "keyword", "tsig_status", "hard", "No ECS field.", abstain=True),
    _f("timestamp", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r7_nsd_461", family="nsd",
    software="NSD 4.6.1 (Debian 12)", category="network",
    contamination="high", split="train_r7",
    notes="ROUND 10 (pool r7), OLD VERSION: NSD 4.6.1, four zones, transfers provided to two addresses, verbosity 2.",
    documentation=_doc("4.6.1", False), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r7_nsd_4120", family="nsd",
    software="NSD 4.12.0 (Debian 13)", category="network",
    contamination="high", split="test_r7",
    notes="ROUND 10 (pool r7), NEW VERSION of r7_nsd_461: allowed transfers gain `  not-verified`; new IXFR fallback line.",
    documentation=_doc("4.12.0", True), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

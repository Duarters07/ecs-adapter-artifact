"""r7_knot: Knot DNS server log (stdout, level info), Debian 12 (3.2.6) -> Debian 13 (3.4.6): outgoing zone transfers."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_LINE = re.compile(
    r"^(?P<timestamp>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d{4}) (?P<level>[a-z]+): \[(?P<zone>[^\]]+?)\.\] "
    r"(?P<xfr_type>[AI]XFR), (?P<direction>outgoing), remote (?P<client_ip>[0-9.]+)@(?P<client_port>\d+)"
    r"(?: (?P<transport>TCP|UDP))?, (?P<rest>.*)$")
_RESTS = (
    re.compile(r"^(?P<action>started), serial (?P<serial>\d+)$"),
    re.compile(r"^(?P<action>finished), (?P<duration>[\d.]+) seconds, (?P<messages>\d+) messages, (?P<bytes>\d+) bytes$"),
    re.compile(r"^(?P<action>incomplete history), serial (?P<serial>\d+), (?P<fallback>fallback to AXFR)$"),
)


def _extract(line: str) -> dict[str, str]:
    m = _LINE.match(line.strip())
    if not m:
        return {}
    for rx in _RESTS:
        mm = rx.match(m.group("rest"))
        if mm:
            out = {k: v for k, v in m.groupdict().items() if k != "rest" and v is not None}
            out.update({k: v for k, v in mm.groupdict().items() if v is not None})
            return out
    return {}


def _doc(version: str, new: bool) -> str:
    remote = "remote <client_ip>@<client_port> <transport>" if new else "remote <client_ip>@<client_port>"
    return f"""
# Knot DNS {version} - server log, target stdout, level info

Source: Knot DNS reference manual, "log" section (vendor documentation), Debian package. The server is authoritative
for four zones and allows zone transfers to two secondary addresses. One line per event:

    <timestamp> <level>: [<zone>.] <xfr_type>, outgoing, {remote}, <event>

`timestamp` is ISO 8601 with a numeric offset.

## The events kept (outgoing zone transfers)

    started, serial <serial>
    finished, <duration> seconds, <messages> messages, <bytes> bytes
    incomplete history, serial <serial>, fallback to AXFR

- `zone` - the zone transferred (the question name of the transfer request)
- `xfr_type` - AXFR (full) or IXFR (incremental) transfer; `direction` - outgoing (this server sends the zone)
- `client_ip`, `client_port` - the secondary that requested the transfer{"; `transport` - TCP or UDP" if new else ""}
- `serial` - the zone serial sent, or the serial the requester holds when an IXFR falls back to AXFR
- `duration`, `messages`, `bytes` - size and time of a finished transfer
- Transfers refused by the ACL are not logged at level info.
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("client_port", "source.port", "long", "client_port", "easy", "client.port is equivalent."),
    _f("zone", "dns.question.name", "keyword", "zone", "medium", "The zone is the transfer request's question name."),
    _f("xfr_type", "dns.question.type", "keyword", "transfer_type", "medium", "AXFR/IXFR are query types."),
    _f("action", "event.action", "keyword", "event_type", "medium"),
    _f("level", "log.level", "keyword", "severity", "easy"),
    _f("transport", None, "keyword", "transport", "hard", "Value convention: TCP on the wire, tcp in ECS (network.transport); declining accepted.", abstain=True),
    _f("direction", None, "keyword", "direction", "hard", "network.direction takes ingress/egress; declining accepted.", abstain=True),
    _f("serial", None, "long", "zone_serial", "hard", "No ECS field.", abstain=True),
    _f("duration", None, "keyword", "seconds", "hard", "event.duration is in nanoseconds; declining accepted.", abstain=True),
    _f("messages", None, "long", "message_count", "hard", "No ECS field.", abstain=True),
    _f("bytes", None, "long", "bytes_sent", "hard", "destination.bytes would be a guess about direction; declining accepted.", abstain=True),
    _f("fallback", None, "keyword", "fallback", "hard", "No ECS field.", abstain=True),
    _f("timestamp", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r7_knot_326", family="knot",
    software="Knot DNS 3.2.6 (Debian 12)", category="network",
    contamination="high", split="train_r7",
    notes="ROUND 10 (pool r7), OLD VERSION: Knot DNS 3.2.6, four zones, transfers allowed to two addresses, stdout info.",
    documentation=_doc("3.2.6", False), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r7_knot_346", family="knot",
    software="Knot DNS 3.4.6 (Debian 13)", category="network",
    contamination="high", split="test_r7",
    notes="ROUND 10 (pool r7), NEW VERSION of r7_knot_326: transfer lines gain the transport after the remote address.",
    documentation=_doc("3.4.6", True), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

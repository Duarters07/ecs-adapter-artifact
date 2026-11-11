"""r6_courier: Courier IMAP imapd syslog lines, Debian 11 -> Debian 12 (both 5.0.13, rebuilt)."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_LINE = re.compile(
    r"^(?P<timestamp>\d{4}-\d\d-\d\dT[\d:.]+[+-]\d\d:\d\d) (?P<host>\S+) (?P<process>imapd): "
    r"(?P<action>Connection|LOGIN FAILED|LOGIN|LOGOUT|Disconnected), (?:user=(?P<user>[^,]+), )?"
    r"ip=\[(?:::ffff:)?(?P<client_ip>[0-9.]+)\], port=\[(?P<client_port>\d+)\](?P<rest>.*)$")
_KV = re.compile(r", (\w+)=([^,]+)")


def _extract(line: str) -> dict[str, str]:
    m = _LINE.match(line.strip())
    if not m:
        return {}
    out = {k: v for k, v in m.groupdict().items() if v is not None and k != "rest"}
    out.update({k: v for k, v in _KV.findall(m.group("rest"))})
    return out


def _doc(debian: str) -> str:
    return f"""
# Courier IMAP 5.0 (Debian {debian}) - imapd syslog messages

Source: courier-imap documentation (imapd(8), "Logging") (https://www.courier-mta.org/imap/), Debian package. imapd logs
through syslog (facility mail); rsyslog writes them in its default high-precision format:

    <timestamp> <host> imapd: <event>, [user=<user>, ]ip=[<client_ip>], port=[<client_port>][, <key>=<value>...]

The address is shown as an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`).

## The events kept

    Connection, ip=[...], port=[...]
    LOGIN, user=<user>, ip=[...], port=[...], protocol=IMAP
    LOGIN FAILED, user=<user>, ip=[...], port=[...]
    LOGOUT, user=<user>, ip=[...], port=[...], headers=<n>, body=<n>, rcvd=<bytes>, sent=<bytes>, time=<s>
    Disconnected, ip=[...], port=[...], time=<s>

- `user` - the account; `client_ip`, `client_port` - the client's address and port
- `protocol` - IMAP; `rcvd`, `sent` - bytes received and sent in the session; `time` - its length in seconds
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("client_port", "source.port", "long", "client_port", "easy", "client.port is equivalent."),
    _f("user", "user.name", "keyword", "account", "easy"),
    _f("action", "event.action", "keyword", "event_type", "medium"),
    _f("host", "host.hostname", "keyword", "host", "easy", "host.name is equivalent."),
    _f("process", "process.name", "keyword", "program", "easy"),
    _f("rcvd", "source.bytes", "long", "bytes_received", "medium", "client.bytes is equivalent."),
    _f("sent", "destination.bytes", "long", "bytes_sent", "medium", "server.bytes is equivalent."),
    _f("protocol", None, "keyword", "mail_protocol", "hard", "network.protocol expects lowercase; declining accepted.", abstain=True),
    _f("headers", None, "long", "header_bytes", "hard", "No ECS field.", abstain=True),
    _f("body", None, "long", "body_bytes", "hard", "No ECS field.", abstain=True),
    _f("time", None, "long", "session_seconds", "hard", "event.duration is in nanoseconds; declining accepted.", abstain=True),
    _f("timestamp", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r6_courier_d11", family="courier",
    software="Courier IMAP 5.0.13 (Debian 11)", category="authentication",
    contamination="high", split="train_r6",
    notes="ROUND 8 (pool r6), OLD VERSION: courier-imap 5.0.13 on Debian 11, syslog via rsyslog to a file.",
    documentation=_doc("11"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r6_courier_d12", family="courier",
    software="Courier IMAP 5.0.13 (Debian 12)", category="authentication",
    contamination="high", split="test_r6",
    notes="ROUND 8 (pool r6), NEW VERSION of r6_courier_d11: the same upstream version rebuilt for Debian 12.",
    documentation=_doc("12"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

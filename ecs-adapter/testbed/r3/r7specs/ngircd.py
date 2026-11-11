"""r7_ngircd: ngIRCd console log, Debian 12 (26.1) -> Debian 13 (27). A control: the kept lines do not change."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_HEAD = re.compile(r"^\[(?P<pid>\d+):(?P<level>\d) +(?P<uptime>\d+)\] (?P<msg>.*)$")
_MASK = r'"(?P<nick>[^!"]+)!~?(?P<ident>[^@"]+)@(?P<client_ip>[0-9.]+)"'
_MSGS = (
    re.compile(r'^(?P<action>Accepted connection) (?P<conn>\d+) from "(?P<client_ip>[0-9.]+):(?P<client_port>\d+)" '
               r'on socket (?P<socket>\d+)\.$'),
    re.compile(r"^User " + _MASK + r" (?P<action>registered) \(connection (?P<conn>\d+)\)\.$"),
    re.compile(r"^User " + _MASK + r" (?P<action>rejected) \(connection (?P<conn>\d+)\): (?P<reason>.+?)!$"),
    re.compile(r"^User " + _MASK + r" (?P<action>unregistered) \(connection (?P<conn>\d+)\): (?P<reason>.+?)\.$"),
    re.compile(r'^Client "(?P<nick>[^"]+)" (?P<action>unregistered) \(connection (?P<conn>\d+)\): (?P<reason>.+?)\.$'),
    re.compile(r'^(?P<action>Shutting down connection) (?P<conn>\d+) \((?P<reason>[^)]+)\) with '
               r'"(?P<client_ip>[0-9.]+):(?P<client_port>\d+)" \.\.\.$'),
    re.compile(r'^(?P<action>Connection) (?P<conn>\d+) with "(?P<client_ip>[0-9.]+):(?P<client_port>\d+)" closed '
               r'\(in: (?P<bytes_in>[\d.]+k), out: (?P<bytes_out>[\d.]+k)\)\.$'),
    re.compile(r'^(?P<action>Got valid OPER) for "(?P<oper_name>[^"]+)" from ' + _MASK + r", user is an IRC operator now\.$"),
    re.compile(r"^(?P<action>Got invalid OPER) from " + _MASK + r': "(?P<oper_name>[^"]+)" -- (?P<reason>.+?)!$'),
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


def _doc(version: str) -> str:
    return f"""
# ngIRCd {version} - console log (`ngircd -n`)

Source: ngIRCd documentation and ngircd(8) manual page, Debian package; a server password and one IRC operator block.
In the foreground the daemon writes one line per event:

    [<pid>:<level> <uptime>] <message>

`level` is the syslog severity number (3 error, 5 notice, 6 info); `uptime` counts seconds since the server started.

## The messages kept

    Accepted connection <conn> from "<client_ip>:<client_port>" on socket <socket>.
    User "<nick>!~<ident>@<client_ip>" registered (connection <conn>).
    User "<nick>!~<ident>@<client_ip>" rejected (connection <conn>): <reason>!
    User "<nick>!~<ident>@<client_ip>" unregistered (connection <conn>): <reason>.
    Client "<nick>" unregistered (connection <conn>): <reason>.
    Shutting down connection <conn> (<reason>) with "<client_ip>:<client_port>" ...
    Connection <conn> with "<client_ip>:<client_port>" closed (in: <bytes_in>, out: <bytes_out>).
    Got valid OPER for "<oper_name>" from "<nick>!~<ident>@<client_ip>", user is an IRC operator now.
    Got invalid OPER from "<nick>!~<ident>@<client_ip>": "<oper_name>" -- <reason>!

- `conn` - the connection number, reused once a connection closes; `socket` - the listening socket
- `nick` - the client's nickname, `ident` - its user name; `client_ip`, `client_port` - the client
- `reason` - why the client left or was refused (`Bad server password`, `Got QUIT command`, `bad password`,
  `not configured`)
- `oper_name` - the IRC operator account the client asked for; a valid OPER grants operator rights
- `bytes_in`, `bytes_out` - traffic of the connection, in kilobytes with one decimal (`2.2k`)
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("client_port", "source.port", "long", "client_port", "easy", "client.port is equivalent."),
    _f("nick", "user.name", "keyword", "account", "medium"),
    _f("oper_name", "user.effective.name", "keyword", "privileged_account", "hard",
       "The operator account the user takes on; leaving it unmapped is acceptable.", abstain=True),
    _f("reason", "event.reason", "keyword", "refusal_reason", "medium"),
    _f("action", "event.action", "keyword", "event_type", "medium"),
    _f("pid", "process.pid", "long", "process_id", "easy"),
    _f("level", "log.syslog.severity.code", "long", "severity", "medium", "log.level is equivalent."),
    _f("ident", None, "keyword", "ident", "hard", "The IRC user name; user.name holds the nick.", abstain=True),
    _f("conn", None, "long", "connection_id", "hard", "No ECS field.", abstain=True),
    _f("socket", None, "long", "socket", "hard", "No ECS field.", abstain=True),
    _f("bytes_in", None, "keyword", "bytes_in", "hard", "Rounded kilobytes; not an ECS byte count.", abstain=True),
    _f("bytes_out", None, "keyword", "bytes_out", "hard", "As bytes_in.", abstain=True),
    _f("uptime", None, "long", "uptime", "hard", "Seconds since start, not a time; @timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r7_ngircd_261", family="ngircd",
    software="ngIRCd 26.1 (Debian 12)", category="network",
    contamination="high", split="train_r7",
    notes="ROUND 10 (pool r7), OLD VERSION: ngIRCd 26.1, server password and one OPER block, console log.",
    documentation=_doc("26.1"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r7_ngircd_27", family="ngircd",
    software="ngIRCd 27 (Debian 13)", category="network",
    contamination="high", split="test_r7",
    notes="ROUND 10 (pool r7), NEW VERSION of r7_ngircd_261. A CONTROL: the kept lines are unchanged.",
    documentation=_doc("27"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

"""r5_proftpd: ProFTPD system log, Debian 11 (1.3.7a) -> Debian 12 (1.3.8)."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_HEAD = re.compile(
    r"^(?P<timestamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3}) (?P<host>\S+) (?P<process>proftpd)\[(?P<pid>\d+)\] "
    r"(?P<server_ip>[0-9.]+) \((?P<client_name>[^\[\s]+)\[(?P<client_ip>[0-9.]+)\]\): (?P<msg>.*)$")
_MSGS = (
    re.compile(r"^USER (?P<user>\S+): (?P<result>Login successful)\.$"),
    re.compile(r"^USER (?P<user>\S+) \((?P<result>Login failed)\): (?P<reason>.+)$"),
    re.compile(r"^USER (?P<user>\S+): (?P<reason>no such user found) from \S+ \[[0-9.]+\] to [0-9.]+:(?P<server_port>\d+)$"),
    re.compile(r"^SECURITY VIOLATION: (?P<reason>.+)$"),
    re.compile(r"^FTP session (?P<session>opened)\.$"),
)


def _extract(line: str) -> dict[str, str]:
    m = _HEAD.match(line.strip())
    if not m:
        return {}
    for rx in _MSGS:
        mm = rx.match(m.group("msg"))
        if mm:
            out = {k: v for k, v in m.groupdict().items() if v is not None and k != "msg"}
            out.update({k: v for k, v in mm.groupdict().items() if v is not None})
            return out
    return {}


def _doc(version: str) -> str:
    return f"""
# ProFTPD {version} - system log

Source: ProFTPD documentation, "SystemLog" and "Logging" (http://www.proftpd.org/docs/howto/Logging.html),
and the Debian package's configuration. Run in the foreground, ProFTPD writes its system log to
standard error:

    <timestamp> <host> <process>[<pid>] <server_ip> (<client_name>[<client_ip>]): <message>

## The messages kept

    FTP session opened.
    USER <user>: Login successful.
    USER <user> (Login failed): <reason>
    USER <user>: no such user found from <client_name> [<client_ip>] to <server_ip>:<server_port>
    SECURITY VIOLATION: <reason>

- `timestamp` - local time, with milliseconds after a comma
- `host`, `process`, `pid` - the server's host name, the daemon, and the id of the session's process
- `server_ip` - the server address the client connected to
- `client_name`, `client_ip` - the client's name (its address, since reverse DNS is off) and address
- `user` - the account named in the USER command
- `result` - `Login successful` or `Login failed`
- `reason` - why a login was refused: `Incorrect password`, `no such user found`, or a security
  violation such as `Root login attempted` (root logins are refused by default)
- `server_port` - the server's FTP port
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("server_ip", "destination.ip", "ip", "server_ip", "medium", "server.ip is equivalent."),
    _f("server_port", "destination.port", "long", "server_port", "medium", "server.port is equivalent."),
    _f("user", "user.name", "keyword", "account", "easy"),
    _f("reason", "event.reason", "keyword", "refusal_reason", "medium"),
    _f("host", "host.hostname", "keyword", "host", "easy", "host.name is equivalent."),
    _f("process", "process.name", "keyword", "program", "easy"),
    _f("pid", "process.pid", "long", "process_id", "easy"),
    _f("result", None, "keyword", "auth_outcome", "hard",
       "event.outcome needs a value map (Login successful -> success); declining accepted.", abstain=True),
    _f("client_name", None, "keyword", "client_name", "hard", "Equal to the address here (reverse DNS off).", abstain=True),
    _f("session", None, "keyword", "session_state", "hard", "No ECS field.", abstain=True),
]

OLD = Spec(
    source_id="r5_proftpd_137", family="proftpd",
    software="ProFTPD 1.3.7a (Debian 11)", category="authentication",
    contamination="high", split="train_r5",
    notes="ROUND 6 (pool r5), OLD VERSION: ProFTPD 1.3.7a, the packaged configuration.",
    documentation=_doc("1.3.7"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r5_proftpd_138", family="proftpd",
    software="ProFTPD 1.3.8 (Debian 12)", category="authentication",
    contamination="high", split="test_r5",
    notes="ROUND 6 (pool r5), NEW VERSION of r5_proftpd_137. Captured as an upgrade; see T3 for whether the format changed.",
    documentation=_doc("1.3.8"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

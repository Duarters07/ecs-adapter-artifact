"""r6_pureftpd: Pure-FTPd syslog lines, Debian 11 (1.0.49) -> Debian 12 (1.0.50)."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_HEAD = re.compile(r"^(?P<timestamp>\d{4}-\d\d-\d\dT[\d:.]+[+-]\d\d:\d\d) (?P<host>\S+) (?P<process>pure-ftpd): "
                   r"\((?P<session_user>[^@)]*)@(?P<client_ip>[0-9.]+)\) \[(?P<level>[A-Z]+)\] (?P<msg>.*)$")
_MSGS = (
    re.compile(r"^New connection from (?P<client_ip2>[0-9.]+)$"),
    re.compile(r"^(?P<user>\S+) is now logged in$"),
    re.compile(r"^Authentication failed for user \[(?P<user>[^\]]*)\]$"),
    re.compile(r"^Logout\.$"),
    re.compile(r"^(?P<file>\S+) downloaded +\((?P<bytes>\d+) bytes, (?P<rate>[\d.]+[KMG]?B/sec)\)$"),
    re.compile(r"^Can't open (?P<file>\S+): (?P<reason>.+)$"),
)


def _extract(line: str) -> dict[str, str]:
    m = _HEAD.match(line.strip())
    if not m:
        return {}
    for rx in _MSGS:
        mm = rx.match(m.group("msg"))
        if mm:
            out = {k: v for k, v in m.groupdict().items() if v is not None and k != "msg"}
            d = {k: v for k, v in mm.groupdict().items() if v is not None}
            d.pop("client_ip2", None)
            out.update(d)
            return out
    return {}


def _doc(version: str) -> str:
    return f"""
# Pure-FTPd {version} - syslog messages

Source: Pure-FTPd README ("Logging") and the Debian package. Pure-FTPd logs through syslog (facility ftp); here
rsyslog writes them to a file in its default high-precision format, and the daemon runs with `-H` (no reverse
DNS), so the client is shown by address:

    <timestamp> <host> pure-ftpd: (<session_user>@<client_ip>) [<level>] <message>

## The messages kept

    New connection from <client_ip>
    <user> is now logged in
    Authentication failed for user [<user>]
    Logout.
    <file> downloaded  (<bytes> bytes, <rate>)
    Can't open <file>: <reason>

- `timestamp` - RFC 3339 with microseconds; `host` - the server's host name
- `session_user` - the session's account, `?` before a successful login
- `client_ip` - the client address; `level` - INFO, NOTICE, WARNING, ERROR
- `user` - the account that logged in, or the name a failed login used
- `file`, `bytes`, `rate` - a download: path, size and transfer rate; `reason` - why a file could not be opened
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("user", "user.name", "keyword", "account", "easy"),
    _f("host", "host.hostname", "keyword", "host", "easy", "host.name is equivalent."),
    _f("process", "process.name", "keyword", "program", "easy"),
    _f("level", "log.level", "keyword", "severity", "easy"),
    _f("file", "file.path", "keyword", "file_path", "medium"),
    _f("bytes", "file.size", "long", "file_size", "medium", "the bytes transferred, the whole file here."),
    _f("reason", "event.reason", "keyword", "error_reason", "medium"),
    _f("session_user", None, "keyword", "session_account", "hard", "`?` before login; user.name is taken from the message.", abstain=True),
    _f("rate", None, "keyword", "transfer_rate", "hard", "No ECS field.", abstain=True),
    _f("timestamp", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r6_pureftpd_1049", family="pureftpd",
    software="Pure-FTPd 1.0.49 (Debian 11)", category="authentication",
    contamination="high", split="train_r6",
    notes="ROUND 8 (pool r6), OLD VERSION: Pure-FTPd 1.0.49, syslog via rsyslog to a file, -H.",
    documentation=_doc("1.0.49"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r6_pureftpd_1050", family="pureftpd",
    software="Pure-FTPd 1.0.50 (Debian 12)", category="authentication",
    contamination="high", split="test_r6",
    notes="ROUND 8 (pool r6), NEW VERSION of r6_pureftpd_1049. Captured as an upgrade; see T3 for whether the format changed.",
    documentation=_doc("1.0.50"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

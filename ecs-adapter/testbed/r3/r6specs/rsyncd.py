"""r6_rsyncd: rsync daemon log, Debian 11 (3.2.3) -> Debian 12 (3.2.7)."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_HEAD = re.compile(r"^(?P<timestamp>\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) \[(?P<pid>\d+)\] (?P<msg>.*)$")
_PEER = r"from (?P<client_name>\S+) \((?P<client_ip>[0-9.]+)\)"
_MSGS = (
    re.compile(r"^(?P<action>connect) " + _PEER + r"$"),
    re.compile(r"^rsync (?P<action>allowed access) on module (?P<module>\S+) " + _PEER + r"$"),
    re.compile(r"^(?P<action>auth failed) on module (?P<module>\S+) " + _PEER + r" for (?P<user>[^:]+): (?P<reason>.+)$"),
    re.compile(r"^(?P<action>unknown module) '(?P<module>[^']*)' tried " + _PEER + r"$"),
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
# rsync {version} daemon - log file

Source: rsyncd.conf(5) ("log file", "log format") and rsync(1) (https://download.samba.org/pub/rsync/rsyncd.conf.5),
Debian package. With `--log-file` the daemon writes one line per event:

    <timestamp> [<pid>] <message>

## The messages kept

    connect from <client_name> (<client_ip>)
    rsync allowed access on module <module> from <client_name> (<client_ip>)
    auth failed on module <module> from <client_name> (<client_ip>) for <user>: <reason>
    unknown module '<module>' tried from <client_name> (<client_ip>)

- `timestamp` - local time `YYYY/MM/DD hh:mm:ss`; `pid` - the process serving the connection
- `client_name` - the client's reverse-DNS name, `UNDETERMINED` with `reverse lookup = no`; `client_ip` - its address
- `module` - the module requested; `user` - the rsync account presented
- `reason` - why authentication failed: `password mismatch`, or `no matching rule` for an account the module does
  not list
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("user", "user.name", "keyword", "account", "easy"),
    _f("reason", "event.reason", "keyword", "refusal_reason", "medium"),
    _f("action", "event.action", "keyword", "event_type", "medium"),
    _f("pid", "process.pid", "long", "process_id", "easy"),
    _f("module", None, "keyword", "rsync_module", "hard", "No ECS field for an rsync module (file.directory is not it).", abstain=True),
    _f("client_name", None, "keyword", "client_name", "hard", "Constant UNDETERMINED (reverse lookup off).", abstain=True),
    _f("timestamp", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r6_rsyncd_323", family="rsyncd",
    software="rsync 3.2.3 daemon (Debian 11)", category="authentication",
    contamination="high", split="train_r6",
    notes="ROUND 8 (pool r6), OLD VERSION: rsync 3.2.3 daemon, --log-file.",
    documentation=_doc("3.2.3"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r6_rsyncd_327", family="rsyncd",
    software="rsync 3.2.7 daemon (Debian 12)", category="authentication",
    contamination="high", split="test_r6",
    notes="ROUND 8 (pool r6), NEW VERSION of r6_rsyncd_323. Captured as an upgrade; see T3 for whether the format changed.",
    documentation=_doc("3.2.7"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

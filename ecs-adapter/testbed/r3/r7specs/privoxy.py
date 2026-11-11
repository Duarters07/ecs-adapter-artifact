"""r7_privoxy: Privoxy log (console under --no-daemon), Debian 12 3.0.34 -> Debian 13 4.0.0."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_HEAD = re.compile(r"^(?P<timestamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}) (?P<thread>[0-9a-f]+) (?P<msg>.*)$")
_MSGS = (
    re.compile(r"^(?P<action>Request): (?P<host>[^/\s]+)(?P<path>/\S*)$"),
    re.compile(r"^Crunch: (?P<action>[^:]+): (?P<url>\S+)$"),
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
# Privoxy {version} - log (debug 1, 1024, 4096, 8192), written to the console under --no-daemon

Source: Privoxy user manual, configuration file section "debug" and "logfile", Debian package. One line per event:

    <yyyy-mm-dd hh:mm:ss.mmm> <thread> <message>

## The messages kept

    Request: <host><path>
    Crunch: <reason>: <url>

- `thread` - the id of the thread serving the request (hexadecimal)
- `host`, `path` - the requested host and path (the request line in short form)
- Crunch: Privoxy answered the request itself instead of forwarding it; `reason` is why (`Blocked` for a block
  action, `DNS failure` for an unresolvable host) and `url` the full requested URL
- the client's address is not written in these lines
"""


_FIELDS = [
    _f("host", "url.domain", "keyword", "requested_host", "easy", "destination.domain is equivalent."),
    _f("path", "url.path", "keyword", "url_path", "easy"),
    _f("url", "url.original", "keyword", "url", "easy", "url.full is equivalent."),
    _f("action", "event.action", "keyword", "event_type", "medium"),
    _f("thread", None, "keyword", "thread_id", "hard", "Hexadecimal; process.thread.id is a number.", abstain=True),
    _f("timestamp", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r7_privoxy_3034", family="privoxy",
    software="Privoxy 3.0.34 (Debian 12)", category="network",
    contamination="high", split="train_r7",
    notes="ROUND 10 (pool r7), OLD VERSION: Privoxy 3.0.34, one block rule, console log.",
    documentation=_doc("3.0.34"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r7_privoxy_400", family="privoxy",
    software="Privoxy 4.0.0 (Debian 13)", category="network",
    contamination="high", split="test_r7",
    notes="ROUND 10 (pool r7), NEW VERSION of r7_privoxy_3034. CONTROL: Request and Crunch lines did not change.",
    documentation=_doc("4.0.0"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

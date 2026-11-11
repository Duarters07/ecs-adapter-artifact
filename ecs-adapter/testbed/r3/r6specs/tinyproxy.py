"""r6_tinyproxy: Tinyproxy log file (Info), Debian 11 (1.10.0) -> Debian 12 (1.11.1)."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_HEAD = re.compile(r"^(?P<level>[A-Z]+) +(?P<timestamp>[A-Z][a-z]{2} +\d+ [\d:.]+) \[(?P<pid>\d+)\]: (?P<msg>.*)$")
_MSGS = (
    re.compile(r"^(?P<action>Connect) \(file descriptor (?P<fd>\d+)\): (?:(?P<client_name>\S+) \[(?P<client_ip>[0-9.]+)\]|(?P<client_ip2>[0-9.]+))$"),
    re.compile(r"^(?P<action>Request) \(file descriptor (?P<fd>\d+)\): (?P<method>[A-Z]+) (?P<url>\S+) HTTP/(?P<http_version>[\d.]+)$"),
    re.compile(r'^(?P<action>Unauthorized connection) from "(?P<client_name>[^"]*)"(?: \[(?P<client_ip>[0-9.]+)\])?\.$'),
    re.compile(r'^(?P<action>Established connection) to host "(?P<dest_host>[^"]+)" using file descriptor (?P<fd>\d+)\.$'),
)


def _extract(line: str) -> dict[str, str]:
    m = _HEAD.match(line.strip())
    if not m:
        return {}
    for rx in _MSGS:
        mm = rx.match(m.group("msg"))
        if mm:
            out = {k: v for k, v in m.groupdict().items() if k != "msg"}
            d = {k: v for k, v in mm.groupdict().items() if v is not None}
            if "client_ip2" in d:
                d["client_ip"] = d.pop("client_ip2")
            if d.get("action") == "Unauthorized connection" and "client_ip" not in d:
                d["client_ip"] = d.pop("client_name")   # 1.11 names the client by its address only
            out.update(d)
            return out
    return {}


def _doc(version: str, new: bool) -> str:
    who = '<client_ip>' if new else '<client_name> [<client_ip>]'
    unauth = 'Unauthorized connection from "<client_ip>".' if new else 'Unauthorized connection from "<client_name>" [<client_ip>].'
    ts = "Mon DD hh:mm:ss.mmm (milliseconds)" if new else "Mon DD hh:mm:ss"
    return f"""
# Tinyproxy {version} - log file, LogLevel Info

Source: tinyproxy.conf(5) ("LogFile", "LogLevel", "Allow", "BasicAuth") (https://tinyproxy.github.io/), Debian package.
One line per event:

    <LEVEL> <timestamp> [<pid>]: <message>

`timestamp` is local time, {ts}.

## The messages kept

    Connect (file descriptor <fd>): {who}
    Request (file descriptor <fd>): <method> <url> HTTP/<http_version>
    {unauth}
    Established connection to host "<dest_host>" using file descriptor <fd>.

- `level` - CONNECT, NOTICE, INFO...; `pid` - the process serving the client
- `fd` - the descriptor that ties a client's Connect and Request lines together
- `client_ip` - the client address{"" if new else "; `client_name` its reverse-DNS name"}
- `method`, `url`, `http_version` - the proxied request; `dest_host` - the upstream host the proxy connected to
- Unauthorized connection: the client is outside the `Allow` list and is refused
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("method", "http.request.method", "keyword", "http_method", "easy"),
    _f("url", "url.original", "keyword", "url", "easy", "url.full is equivalent."),
    _f("http_version", "http.version", "keyword", "http_version", "easy"),
    _f("dest_host", "destination.domain", "keyword", "upstream_host", "medium", "server.domain is equivalent."),
    _f("level", "log.level", "keyword", "severity", "easy"),
    _f("pid", "process.pid", "long", "process_id", "easy"),
    _f("action", "event.action", "keyword", "event_type", "medium"),
    _f("fd", None, "long", "file_descriptor", "hard", "No ECS field.", abstain=True),
    _f("client_name", None, "keyword", "client_name", "hard", "A random container name here; source.domain would be wrong.", abstain=True),
    _f("timestamp", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r6_tinyproxy_110", family="tinyproxy",
    software="Tinyproxy 1.10.0 (Debian 11)", category="network",
    contamination="high", split="train_r6",
    notes="ROUND 8 (pool r6), OLD VERSION: Tinyproxy 1.10.0, LogLevel Info, Allow list and BasicAuth.",
    documentation=_doc("1.10.0", False), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r6_tinyproxy_111", family="tinyproxy",
    software="Tinyproxy 1.11.1 (Debian 12)", category="network",
    contamination="high", split="test_r6",
    notes="ROUND 8 (pool r6), NEW VERSION of r6_tinyproxy_110. Captured as an upgrade; see T3 for whether the format changed.",
    documentation=_doc("1.11.1", True), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

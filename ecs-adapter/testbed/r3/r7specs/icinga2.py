"""r7_icinga2: Icinga 2 main log, REST API client lines, Debian 12 2.13.6 -> Debian 13 2.14.6."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_HEAD = re.compile(r"^\[(?P<timestamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d [+-]\d{4})\] (?P<level>[a-z]+)/(?P<logger>\w+): (?P<msg>.*)$")
_PEER = r"\[::ffff:(?P<client_ip>[0-9.]+)\]:(?P<client_port>\d+)"
_MSGS = (
    re.compile(r"^(?P<action>New client connection) from " + _PEER + r" \((?P<cert>[^)]*)\)$"),
    re.compile(r"^(?P<action>Request):? (?P<method>[A-Z]+) (?P<path>\S+) \(from " + _PEER + r"\), user: (?P<user>[^,]+), "
               r"agent: (?P<agent>[^,]+), status: (?P<status>[^)]+)\)(?: took total (?P<took_ms>\d+)ms)?\.$"),
    re.compile(r"^(?P<action>HTTP client disconnected) \(from " + _PEER + r"\)$"),
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
    req = ("Request <method> <path> (from [<client_ip>]:<client_port>), user: <user>, agent: <agent>, status: <status>) "
           "took total <took_ms>ms." if new else
           "Request: <method> <path> (from [<client_ip>]:<client_port>), user: <user>, agent: <agent>, status: <status>).")
    took = "\n- `took_ms` - the time the request took, in milliseconds" if new else ""
    return f"""
# Icinga 2 {version} - main log (/var/log/icinga2/icinga2.log), REST API connections

Source: Icinga 2 documentation, "Logging" (the mainlog feature) and "Icinga 2 API" (ApiUser objects, HTTP basic
authentication), Debian package. One line per event:

    [<yyyy-mm-dd hh:mm:ss +zzzz>] <level>/<logger>: <message>

## The messages kept

    New client connection from [<client_ip>]:<client_port> (<cert>)
    {req}
    HTTP client disconnected (from [<client_ip>]:<client_port>)

- `level` - information for these lines; `logger` - the component (ApiListener, HttpServerConnection)
- `client_ip`, `client_port` - the API client (written as an IPv4-mapped IPv6 address, `::ffff:` + IPv4)
- `cert` - whether the client presented a TLS certificate
- `method`, `path` - the API request; `agent` - its User-Agent
- `user` - the ApiUser authenticated by basic auth, `<unauthenticated>` when authentication failed (the name
  attempted is not logged)
- `status` - the HTTP status phrase of the answer (OK, Unauthorized...){took}
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("client_port", "source.port", "long", "client_port", "easy", "client.port is equivalent."),
    _f("method", "http.request.method", "keyword", "http_method", "easy"),
    _f("path", "url.path", "keyword", "url_path", "easy", "url.original is equivalent."),
    _f("user", "user.name", "keyword", "account", "easy"),
    _f("agent", "user_agent.original", "keyword", "user_agent", "easy"),
    _f("status", "event.reason", "keyword", "http_status_phrase", "medium", "The phrase, not the numeric status code."),
    _f("level", "log.level", "keyword", "severity", "easy"),
    _f("logger", "log.logger", "keyword", "component", "medium"),
    _f("action", "event.action", "keyword", "event_type", "medium"),
    _f("cert", None, "keyword", "client_certificate_note", "hard", "No ECS field.", abstain=True),
    _f("took_ms", None, "long", "duration_ms", "hard", "event.duration is nanoseconds; declined.", abstain=True),
    _f("timestamp", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r7_icinga2_213", family="icinga2",
    software="Icinga 2 2.13.6 (Debian 12)", category="authentication",
    contamination="high", split="train_r7",
    notes="ROUND 10 (pool r7), OLD VERSION: Icinga 2 2.13.6, REST API with basic-auth ApiUsers, main log.",
    documentation=_doc("2.13.6", False), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r7_icinga2_214", family="icinga2",
    software="Icinga 2 2.14.6 (Debian 13)", category="authentication",
    contamination="high", split="test_r7",
    notes="ROUND 10 (pool r7), NEW VERSION of r7_icinga2_213: `Request:` -> `Request`, `took total <n>ms.` added.",
    documentation=_doc("2.14.6", True), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

"""r5_grafana: Grafana 11.3 server log, console logfmt (as shipped) -> console JSON."""
from __future__ import annotations

import json
import re

from testbed.heldout_r2.specs import Spec, _f

_PAIR = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S*)')


def _logfmt(line: str) -> dict[str, str]:
    if not line.startswith("logger=context "):
        return {}
    out = {}
    for k, v in _PAIR.findall(line):
        if v.startswith('"'):
            v = v[1:-1].replace('\\"', '"')
        out[k] = v
    return out


def _json(line: str) -> dict[str, str]:
    try:
        obj = json.loads(line)
    except ValueError:
        return {}
    if not isinstance(obj, dict) or obj.get("logger") != "context":
        return {}
    return {k: str(v) for k, v in obj.items() if not isinstance(v, (dict, list))}


_PARTS = """
## The keys of the request-context logger (`logger=context`)

Every request writes one `Request Completed` message; a request whose authentication fails also
writes a message carrying the authentication error.

- `logger` - the logger that wrote the message, here `context`
- `t` - the time of the message, RFC 3339 with nanoseconds
- `level` - the log level (`info`)
- `msg` - the message: `Request Completed`, `Unauthorized`, or empty on a failed API authentication
- `error` - the authentication error, for example `[password-auth.failed] ... invalid password` or
  `... [identity.not-found] no user found`
- `userId`, `uname` - the numeric id and the login name of the signed-in user; `0` and empty when none
- `orgId` - the organisation the request ran in; `0` when none
- `method`, `path` - the request method and URL path
- `status` - the HTTP status code of the response
- `remote_addr` - the address of the client
- `size` - the response body size, bytes
- `time_ms`, `duration` - the time taken to serve the request
- `handler` - the route that handled the request (`notfound` when none matched)
- `referer` - the Referer header, empty when absent
- `status_source` - which side decided the status (`server` here)
- `traceID` - the trace identifier, empty when tracing is off
"""
_FIELDS = [
    _f("remote_addr", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("method", "http.request.method", "keyword", "request_method", "easy"),
    _f("path", "url.path", "keyword", "request_path", "medium", "url.original is arguable: no query string in the capture."),
    _f("status", "http.response.status_code", "long", "status_code", "easy"),
    _f("size", "http.response.body.bytes", "long", "response_body_size", "medium"),
    _f("uname", "user.name", "keyword", "account", "easy"),
    _f("userId", "user.id", "keyword", "account_id", "medium"),
    _f("level", "log.level", "keyword", "severity", "easy"),
    _f("logger", "log.logger", "keyword", "logger", "medium"),
    _f("msg", "message", "keyword", "message", "medium"),
    _f("referer", "http.request.referrer", "keyword", "referrer", "medium", "Always empty in the capture."),
    _f("error", None, "keyword", "auth_error", "hard",
       "error.message is the home, but `error` is not offered for category web. Declining accepted.", abstain=True),
    _f("orgId", None, "keyword", "tenant_id", "hard",
       "organization.id is the home, but `organization` is not offered for category web.", abstain=True),
    _f("traceID", None, "keyword", "trace_id", "hard", "trace.id; not offered for web, and always empty.", abstain=True),
    _f("handler", None, "keyword", "route", "hard", "No ECS 8.11 field for a route template.", abstain=True),
    _f("time_ms", None, "long", "duration", "hard", "event.duration is in nanoseconds; declining accepted.", abstain=True),
    _f("duration", None, "keyword", "duration_text", "hard", "A duration with its unit; declining accepted.", abstain=True),
    _f("status_source", None, "keyword", "status_origin", "hard", "No ECS field.", abstain=True),
]

OLD = Spec(
    source_id="r5_grafana_logfmt", family="grafana",
    software="Grafana 11.3.0 (image grafana/grafana:11.3.0), console logfmt, router logging on", category="web",
    contamination="high", split="train_r5",
    notes="ROUND 6 (pool r5), OLD CONFIGURATION: Grafana's console log as shipped (logfmt), request-context lines.",
    documentation="""
# Grafana 11.3 - server log, console format `console` (logfmt)

Source: Grafana documentation, "Configure Grafana", sections [log], [log.console] and [server]
router_logging, https://grafana.com/docs/grafana/v11.3/setup-grafana/configure-grafana/

One message per line, as logfmt: `key=value` pairs separated by spaces; a value that contains a
space is written in double quotes, and an empty value is written as nothing after the `=`.

    logger=context userId=<userId> orgId=<orgId> uname=<uname> t=<t> level=<level> msg=<msg> method=<method> path=<path> status=<status> remote_addr=<remote_addr> time_ms=<time_ms> duration=<duration> size=<size> referer=<referer> handler=<handler> status_source=<status_source>
    logger=context userId=<userId> orgId=<orgId> uname=<uname> t=<t> level=<level> msg=<msg> error=<error> remote_addr=<remote_addr> traceID=<traceID>
""" + _PARTS,
    keep=lambda ln: bool(_logfmt(ln)), extract=_logfmt, fields=_FIELDS,
)

NEW = Spec(
    source_id="r5_grafana_json", family="grafana",
    software="Grafana 11.3.0 (image grafana/grafana:11.3.0), console format json, router logging on", category="web",
    contamination="high", split="test_r5",
    notes="ROUND 6 (pool r5), NEW CONFIGURATION of r5_grafana_logfmt: [log.console] format = json.",
    documentation="""
# Grafana 11.3 - server log, console format `json`

Source: Grafana documentation, "Configure Grafana", sections [log], [log.console] (`format = json`)
and [server] router_logging, https://grafana.com/docs/grafana/v11.3/setup-grafana/configure-grafana/

One JSON object per message, keys in alphabetical order. Numeric values (`userId`, `orgId`,
`status`, `size`, `time_ms`) are JSON numbers; the rest are strings.
""" + _PARTS,
    keep=lambda ln: bool(_json(ln)), extract=_json, fields=_FIELDS,
)

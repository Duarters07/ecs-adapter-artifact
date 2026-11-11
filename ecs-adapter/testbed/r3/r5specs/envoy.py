"""r5_envoy: Envoy 1.31 access log, default format -> the administrator's json_format."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f
from testbed.r3.specs import _json_dotted

_DEFAULT = re.compile(
    r'^\[(?P<start_time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<response_code>\d{3}) (?P<response_flags>\S+) (?P<bytes_received>\d+) (?P<bytes_sent>\d+) '
    r'(?P<duration>\S+) (?P<upstream_service_time>\S+) "(?P<x_forwarded_for>[^"]*)" '
    r'"(?P<user_agent>[^"]*)" "(?P<request_id>[^"]*)" "(?P<authority>[^"]*)" "(?P<upstream_host>[^"]*)"$')


def _default(line: str) -> dict[str, str]:
    m = _DEFAULT.match(line.strip())
    return {k: v for k, v in m.groupdict().items() if v is not None} if m else {}


def _json(line: str) -> dict[str, str]:
    out = _json_dotted(line, "response_code")
    return {k: v for k, v in out.items() if v != "None"}


_PARTS = """
- `start_time` - when the request started, ISO 8601 UTC with milliseconds
- `method`, `path`, `protocol` - the request line (`path` is the original path when a route rewrote it)
- `response_code` - the HTTP status code returned to the client
- `response_flags` - Envoy's response flags (`-` when none; for example `NR` no route, `UF` upstream failure)
- `bytes_received` - the request body bytes received
- `bytes_sent` - the response body bytes sent
- `duration` - the total time of the request, milliseconds
- `user_agent` - the User-Agent header of the request
- `request_id` - the X-Request-Id header, which Envoy generates when the client sends none
- `authority` - the :authority (Host) header of the request, `host[:port]`
- `upstream_host` - the upstream host that served the request, `ip:port`; `-` when Envoy answered itself
  (a direct response, as for the denied `/admin` paths)
"""
_FIELDS = [
    _f("method", "http.request.method", "keyword", "request_method", "easy"),
    _f("path", "url.original", "keyword", "request_uri", "medium", "url.path acceptable: no query string in the capture."),
    _f("response_code", "http.response.status_code", "long", "status_code", "easy"),
    _f("bytes_received", "http.request.body.bytes", "long", "request_body_size", "medium"),
    _f("bytes_sent", "http.response.body.bytes", "long", "response_body_size", "medium"),
    _f("user_agent", "user_agent.original", "keyword", "user_agent", "easy"),
    _f("request_id", "http.request.id", "keyword", "request_id", "medium"),
    _f("protocol", "http.version", "keyword", "protocol_version", "medium",
       "Value convention: HTTP/1.1 on the wire, 1.1 in ECS - no rule filters on it."),
    _f("authority", None, "keyword", "requested_host", "hard",
       "host:port in one token; url.domain would hold the port. Declining accepted.", abstain=True),
    _f("upstream_host", None, "keyword", "upstream_server", "hard", "ip:port in one token; declining accepted.", abstain=True),
    _f("response_flags", None, "keyword", "proxy_flags", "hard", "No ECS field for Envoy's response flags.", abstain=True),
    _f("duration", None, "long", "duration", "hard", "event.duration is in nanoseconds; declining accepted.", abstain=True),
]
_UNQ = {"http.version": "value convention: HTTP/1.1 on the wire, 1.1 in ECS"}

OLD = Spec(
    source_id="r5_envoy_default", family="envoy",
    software="Envoy 1.31.10 (image envoyproxy/envoy:v1.31-latest), default access-log format", category="web",
    contamination="high", split="train_r5",
    notes="ROUND 6 (pool r5), OLD CONFIGURATION: Envoy's default access-log format on stdout.",
    documentation="""
# Envoy 1.31 - access log, default format

Source: Envoy documentation, "Access logging", section "Default format string",
https://www.envoyproxy.io/docs/envoy/v1.31.10/configuration/observability/access_log/usage

    [<start_time>] "<method> <path> <protocol>" <response_code> <response_flags> <bytes_received> <bytes_sent> <duration> <upstream_service_time> "<x_forwarded_for>" "<user_agent>" "<request_id>" "<authority>" "<upstream_host>"

- `upstream_service_time` - the x-envoy-upstream-service-time response header, milliseconds; `-` when absent
- `x_forwarded_for` - the X-Forwarded-For header of the request; `-` when absent
""" + _PARTS,
    keep=lambda ln: bool(_default(ln)), extract=_default, fields=_FIELDS, unqueryable=_UNQ,
)

NEW = Spec(
    source_id="r5_envoy_json", family="envoy",
    software="Envoy 1.31.10 (image envoyproxy/envoy:v1.31-latest), administrator's json_format", category="web",
    contamination="high", split="test_r5",
    notes="ROUND 6 (pool r5), NEW CONFIGURATION of r5_envoy_default: the same proxy with a JSON access log.",
    documentation="""
# Envoy 1.31 - the site's JSON access log

Source: the site's envoy.yaml (`log_format.json_format`, Envoy documentation "Access logging",
"Format dictionaries").

    json_format:
      start_time: "%START_TIME%"
      client_ip: "%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%"
      client_port: "%DOWNSTREAM_REMOTE_PORT%"
      method: "%REQ(:METHOD)%"
      path: "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%"
      protocol: "%PROTOCOL%"
      response_code: "%RESPONSE_CODE%"
      response_flags: "%RESPONSE_FLAGS%"
      bytes_received: "%BYTES_RECEIVED%"
      bytes_sent: "%BYTES_SENT%"
      duration: "%DURATION%"
      user_agent: "%REQ(USER-AGENT)%"
      request_id: "%REQ(X-REQUEST-ID)%"
      authority: "%REQ(:AUTHORITY)%"
      upstream_host: "%UPSTREAM_HOST%"

One JSON object per request; numeric operators are written as JSON numbers, and a value that is not
available is written as `null`. The keys appear in no fixed order.

- `client_ip`, `client_port` - the address and port of the client that connected to Envoy
""" + _PARTS,
    keep=lambda ln: bool(_json(ln)), extract=_json,
    fields=_FIELDS + [
        _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
        _f("client_port", "source.port", "long", "client_port", "easy"),
    ],
    unqueryable=_UNQ,
)

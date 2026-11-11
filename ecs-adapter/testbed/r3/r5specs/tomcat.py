"""r5_tomcat: Tomcat 10.1 access log, AccessLogValve (common, as shipped) -> JsonAccessLogValve (combined)."""
from __future__ import annotations

import json
import re

from testbed.heldout_r2.specs import Spec, _f

_COMMON = re.compile(
    r'^(?P<host>\S+) (?P<logical_user>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<protocol>[^"]+)" (?P<status>\d{3}) (?P<bytes>\S+)$')
_REQUEST = re.compile(r"^(?P<method>[A-Z]+) (?P<path>\S+) (?P<protocol>\S+)$")


def _common(line: str) -> dict[str, str]:
    m = _COMMON.match(line.strip())
    return {k: v for k, v in m.groupdict().items() if v is not None} if m else {}


def _json(line: str) -> dict[str, str]:
    try:
        obj = json.loads(line)
    except ValueError:
        return {}
    if not isinstance(obj, dict) or "statusCode" not in obj:
        return {}
    out = {k: str(v) for k, v in obj.items() if not isinstance(v, (dict, list))}
    for k, v in (obj.get("requestHeaders") or {}).items():
        out[f"requestHeaders.{k}"] = str(v)
    m = _REQUEST.match(out.get("request", ""))
    if m:
        out.update(m.groupdict())
    return out


_FIELDS_COMMON = [
    _f("user", "user.name", "keyword", "account", "easy"),
    _f("method", "http.request.method", "keyword", "request_method", "easy"),
    _f("path", "url.original", "keyword", "request_uri", "medium", "url.path acceptable: no query string in the capture."),
    _f("protocol", "http.version", "keyword", "protocol_version", "medium",
       "Value convention: HTTP/1.1 on the wire, 1.1 in ECS - no rule filters on it."),
]
_UNQ = {"http.version": "value convention: HTTP/1.1 on the wire, 1.1 in ECS"}

OLD = Spec(
    source_id="r5_tomcat_common", family="tomcat",
    software="Apache Tomcat 10.1.61 (image tomcat:10.1-jre17), AccessLogValve, common pattern", category="web",
    contamination="high", split="train_r5",
    notes=("ROUND 6 (pool r5), OLD CONFIGURATION: the access log as Tomcat ships it. The manager application "
           "is deployed with BASIC authentication, so failed logins are 401 responses."),
    documentation="""
# Apache Tomcat 10.1 - access log (AccessLogValve, `common` pattern)

Source: Apache Tomcat 10.1 Configuration Reference, "The Valve Component", Access Log Valve,
https://tomcat.apache.org/tomcat-10.1-doc/config/valve.html#Access_Logging

The valve as shipped in conf/server.xml writes `%h %l %u %t "%r" %s %b`:

    <host> <logical_user> <user> [<time>] "<method> <path> <protocol>" <status> <bytes>

- `host` - the remote host: the client's IP address (host name lookups are off)
- `logical_user` - the remote logical user name from identd, always `-`
- `user` - the user authenticated by the application (BASIC authentication here); `-` when none
- `time` - date and time, in Common Log Format
- `method`, `path`, `protocol` - the first line of the request
- `status` - the HTTP status code of the response (401: authentication required or failed)
- `bytes` - bytes sent, excluding HTTP headers, or `-` if zero
""",
    keep=lambda ln: bool(_common(ln)), extract=_common,
    fields=[
        _f("host", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
        *_FIELDS_COMMON,
        _f("status", "http.response.status_code", "long", "status_code", "easy"),
        _f("bytes", "http.response.body.bytes", "long", "response_body_size", "medium"),
        _f("logical_user", None, "keyword", "ident_user", "hard", "identd user, always '-'.", abstain=True),
    ],
    unqueryable=_UNQ,
)

NEW = Spec(
    source_id="r5_tomcat_json", family="tomcat",
    software="Apache Tomcat 10.1.61 (image tomcat:10.1-jre17), JsonAccessLogValve, combined pattern", category="web",
    contamination="high", split="test_r5",
    notes=("ROUND 6 (pool r5), NEW CONFIGURATION of r5_tomcat_common: JsonAccessLogValve with the combined "
           "pattern. The request line stays one JSON string, so a parser that only decodes the JSON cannot "
           "fill the method or the path."),
    documentation="""
# Apache Tomcat 10.1 - access log as JSON (JsonAccessLogValve, `combined` pattern)

Source: Apache Tomcat 10.1 Configuration Reference, "The Valve Component", JSON Access Log Valve,
https://tomcat.apache.org/tomcat-10.1-doc/config/valve.html#JSON_Access_Log_Valve

One JSON object per request. The valve names each element of the `combined` pattern
(`%h %l %u %t "%r" %s %b "%{Referer}i" "%{User-Agent}i"`) and writes them in that order:

    {"host":"<host>","logicalUserName":"<..>","user":"<user>","time":"[<time>]","request":"<method> <path> <protocol>","statusCode":"<status>","size":"<bytes>","requestHeaders": {"Referer":"<referer>","User-Agent":"<user agent>"}}

Every value is a JSON string.

- `host` - the remote host: the client's IP address (host name lookups are off)
- `logicalUserName` - the remote logical user name from identd, always `-`
- `user` - the user authenticated by the application (BASIC authentication here); `-` when none
- `time` - date and time in Common Log Format, inside brackets
- `request` - the first line of the request: `<method> <path> <protocol>`
- `statusCode` - the HTTP status code of the response (401: authentication required or failed)
- `size` - bytes sent, excluding HTTP headers, or `-` if zero
- `requestHeaders.Referer`, `requestHeaders.User-Agent` - the Referer and User-Agent request headers; `-` when absent
""",
    keep=lambda ln: bool(_json(ln)), extract=_json,
    fields=[
        _f("host", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
        *_FIELDS_COMMON,
        _f("statusCode", "http.response.status_code", "long", "status_code", "easy"),
        _f("size", "http.response.body.bytes", "long", "response_body_size", "medium"),
        {**_f("requestHeaders.User-Agent", "user_agent.original", "keyword", "user_agent", "easy"),
         "source_key_aliases": ["user_agent"]},
        {**_f("requestHeaders.Referer", "http.request.referrer", "keyword", "referrer", "medium"),
         "source_key_aliases": ["referer"]},
        _f("logicalUserName", None, "keyword", "ident_user", "hard", "identd user, always '-'.", abstain=True),
        _f("request", None, "keyword", "request_line", "hard",
           "The whole request line; its parts are method, path and protocol. Declining accepted.", abstain=True),
    ],
    unqueryable=_UNQ,
)

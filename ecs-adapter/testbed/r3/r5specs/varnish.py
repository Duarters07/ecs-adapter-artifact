"""r5_varnish: Varnish 7.6 varnishncsa access log, stock NCSA format -> the site's JSON format."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f
from testbed.r3.specs import _json_dotted

_NCSA = re.compile(
    r'^(?P<client>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<url>\S+) (?P<protocol>[^"]+)" (?P<status>\d{3}) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"$')


def _ncsa(line: str) -> dict[str, str]:
    m = _NCSA.match(line.strip())
    return {k: v for k, v in m.groupdict().items() if v is not None} if m else {}


_UNQ = {"http.version": "value convention: HTTP/1.1 on the wire, 1.1 in ECS"}
_COMMON = [
    _f("client", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("method", "http.request.method", "keyword", "request_method", "easy"),
    _f("status", "http.response.status_code", "long", "status_code", "easy"),
    _f("user_agent", "user_agent.original", "keyword", "user_agent", "easy"),
    _f("referer", "http.request.referrer", "keyword", "referrer", "medium", "Always empty in the capture."),
    _f("protocol", "http.version", "keyword", "protocol_version", "medium",
       "Value convention: HTTP/1.1 on the wire, 1.1 in ECS - no rule filters on it."),
]

OLD = Spec(
    source_id="r5_varnish_ncsa", family="varnish",
    software="Varnish 7.6.5 (image varnish:7.6), varnishncsa default format", category="web",
    contamination="high", split="train_r5",
    notes="ROUND 6 (pool r5), OLD CONFIGURATION: varnishncsa's stock NCSA combined format.",
    documentation="""
# Varnish 7.6 - varnishncsa, default format

Source: varnishncsa(1), Varnish Cache 7.6 documentation,
https://varnish-cache.org/docs/7.6/reference/varnishncsa.html

With no -F, varnishncsa writes NCSA combined format, `%h %l %u %t "%r" %s %b "%{Referer}i" "%{User-agent}i"`:

    <client> <ident> <user> [<time>] "<method> <url> <protocol>" <status> <bytes> "<referer>" "<user_agent>"

- `client` - the remote host: the client's IP address
- `ident`, `user` - the remote log name and the authenticated user; `-` when none (always here)
- `time` - when the request was received, Common Log Format
- `method`, `url`, `protocol` - the first line of the request, with the URL rewritten as an absolute
  URL (`http://<host>/<path>`)
- `status` - the HTTP status code sent to the client
- `bytes` - the size of the response body, bytes; `-` when none
- `referer`, `user_agent` - the Referer and User-Agent request headers; `-` when absent
""",
    keep=lambda ln: bool(_ncsa(ln)), extract=_ncsa,
    fields=_COMMON + [
        _f("url", "url.original", "keyword", "request_uri", "medium", "The absolute URL as varnishncsa writes it."),
        _f("bytes", "http.response.body.bytes", "long", "response_body_size", "medium"),
        _f("ident", None, "keyword", "ident_user", "hard", "Always '-'.", abstain=True),
        _f("user", None, "keyword", "account", "hard", "Always '-' in the capture; user.name would be its home.", abstain=True),
    ],
    unqueryable=_UNQ,
)

NEW = Spec(
    source_id="r5_varnish_json", family="varnish",
    software="Varnish 7.6.5 (image varnish:7.6), varnishncsa -j -F <site JSON format>", category="web",
    contamination="high", split="test_r5",
    notes=("ROUND 6 (pool r5), NEW CONFIGURATION of r5_varnish_ncsa: the site's JSON format. The URL becomes "
           "the path and query (%U%q), and the size becomes the bytes sent with headers (%O)."),
    documentation="""
# Varnish 7.6 - varnishncsa, the site's JSON format

Source: the site's varnishncsa invocation, `varnishncsa -j -F '<format>'`, and varnishncsa(1),
https://varnish-cache.org/docs/7.6/reference/varnishncsa.html (-j makes every string JSON-safe)

    {"client":"%h","time":"%{%Y-%m-%dT%H:%M:%S%z}t","method":"%m","url":"%U%q","protocol":"%H","status":%s,"bytes_sent":%O,"referer":"%{Referer}i","user_agent":"%{User-agent}i","cache":"%{Varnish:hitmiss}x","duration_us":%D}

One JSON object per request.

- `client` - the remote host: the client's IP address
- `time` - when the request was received, ISO 8601 with offset
- `method`, `protocol` - the request method and protocol
- `url` - the URL path and query string of the request
- `status` - the HTTP status code sent to the client
- `bytes_sent` - total bytes sent to the client, headers included
- `referer`, `user_agent` - the Referer and User-Agent request headers; empty when absent
- `cache` - whether the object came from the cache: `hit` or `miss`
- `duration_us` - the time to serve the request, microseconds
""",
    keep=lambda ln: bool(_json_dotted(ln, "status")), extract=lambda ln: _json_dotted(ln, "status"),
    fields=_COMMON + [
        _f("url", "url.original", "keyword", "request_uri", "medium", "url.path acceptable: no query string in the capture."),
        _f("bytes_sent", "http.response.bytes", "long", "response_size", "medium"),
        _f("cache", None, "keyword", "cache_status", "hard", "No ECS field for a cache hit.", abstain=True),
        _f("duration_us", None, "long", "duration", "hard", "event.duration is in nanoseconds; declining accepted.", abstain=True),
    ],
    unqueryable=_UNQ,
)

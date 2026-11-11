"""r6_gitea: Gitea console log, official image 1.19.4 -> 1.22.6."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_TS = r"(?P<timestamp>\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)"
_ROUTER = (r"router: completed (?P<method>[A-Z]+) (?P<path>\S+) for (?P<client_ip>[0-9.]+):(?P<client_port>\d+), "
           r"(?P<status>\d{3}) (?P<status_text>[A-Za-z ]+?) in (?P<duration>[\d.]+[mµn]?s) @ (?P<handler>\S+)$")
_OLD = re.compile(r"^" + _TS + r" \[(?P<request_id>[0-9a-f-]+)\] " + _ROUTER)
_NEW = re.compile(r"^" + _TS + r" (?P<origin>\S+) \[(?P<level>[A-Z])\] (?:" + _ROUTER.replace("(?P<", "(?P<") + r")$")
_SIGNIN = re.compile(r"^" + _TS + r" (?P<origin>\S+) \[(?P<level>[A-Z])\] UserSignIn: (?P<reason>.+?) \[uid: (?P<uid>\d+), name: (?P<user>[^\]]+)\]$")


def _extract(line: str) -> dict[str, str]:
    s = line.strip()
    for rx in (_OLD, _NEW, _SIGNIN):
        m = rx.match(s)
        if m:
            return {k: v for k, v in m.groupdict().items() if v is not None}
    return {}


def _doc(version: str, new: bool) -> str:
    if new:
        fmt = ("    <timestamp> <origin> [<level>] router: completed <method> <path> for <client_ip>:<client_port>, "
               "<status> <status_text> in <duration> @ <handler>\n"
               "    <timestamp> <origin> [<level>] UserSignIn: <reason> [uid: <uid>, name: <user>]")
        extra = ("- `origin` - the source file, line and function that logged the event (shortened with `...`)\n"
                 "- `level` - one letter: I info, W warning, E error\n"
                 "- UserSignIn: a refused sign-in of an existing account; `reason`, `uid`, `user`")
    else:
        fmt = ("    <timestamp> [<request_id>] router: completed <method> <path> for <client_ip>:<client_port>, "
               "<status> <status_text> in <duration> @ <handler>")
        extra = "- `request_id` - the request's id, suffixed `-2`, `-3`... for requests that reuse a connection"
    return f"""
# Gitea {version} - console log (default logger)

Source: Gitea documentation, "Logging Configuration" (https://docs.gitea.com/administration/logging-config), official
image. The server writes one line per event to standard output:

{fmt}

## Fields

- `timestamp` - local time `YYYY/MM/DD hh:mm:ss`
- `method`, `path` - the HTTP request; `client_ip`, `client_port` - the client
- `status`, `status_text` - the response (401 Unauthorized for refused credentials)
- `duration` - the request's handling time; `handler` - the Go handler that answered
{extra}
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("client_port", "source.port", "long", "client_port", "easy", "client.port is equivalent."),
    _f("method", "http.request.method", "keyword", "http_method", "easy"),
    _f("path", "url.path", "keyword", "url_path", "easy", "url.original is equivalent."),
    _f("status", "http.response.status_code", "long", "http_status", "easy"),
    _f("user", "user.name", "keyword", "account", "easy"),
    _f("reason", "event.reason", "keyword", "refusal_reason", "medium"),
    _f("uid", "user.id", "keyword", "user_id", "medium"),
    _f("level", "log.level", "keyword", "severity", "easy"),
    _f("status_text", None, "keyword", "http_status_text", "hard", "Redundant with the code.", abstain=True),
    _f("duration", None, "keyword", "handling_time", "hard", "event.duration is in nanoseconds; declining accepted.", abstain=True),
    _f("handler", None, "keyword", "go_handler", "hard", "No ECS field.", abstain=True),
    _f("request_id", None, "keyword", "request_id", "hard", "http.request.id is acceptable; declining accepted.", abstain=True),
    _f("origin", None, "keyword", "log_origin", "hard", "log.origin.function would need splitting; declining accepted.", abstain=True),
    _f("timestamp", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r6_gitea_119", family="gitea",
    software="Gitea 1.19.4 (official image)", category="web",
    contamination="high", split="train_r6",
    notes="ROUND 8 (pool r6), OLD VERSION: Gitea 1.19.4, default console logger, API with basic auth.",
    documentation=_doc("1.19.4", False), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r6_gitea_122", family="gitea",
    software="Gitea 1.22.6 (official image)", category="web",
    contamination="high", split="test_r6",
    notes="ROUND 8 (pool r6), NEW VERSION of r6_gitea_119. Captured as an upgrade; see T3 for whether the format changed.",
    documentation=_doc("1.22.6", True), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

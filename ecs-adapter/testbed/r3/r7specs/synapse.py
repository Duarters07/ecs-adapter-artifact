"""r7_synapse: Matrix Synapse 1.120.2 login log, default text formatter -> TerseJsonFormatter (same version)."""
from __future__ import annotations

import json
import re

from testbed.heldout_r2.specs import Spec, _f

_TEXT = re.compile(r"^(?P<timestamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d+) - (?P<logger>\S+) - (?P<lineno>\d+) - "
                   r"(?P<level>[A-Z]+) - (?P<request>\S+) - (?P<msg>.*)$")
_MSGS = (
    re.compile(r"^(?P<action>Got login request) with identifier: \{'type': 'm\.id\.user', 'user': '(?P<login_user>[^']*)'\}, "
               r"medium: None, address: None, user: None$"),
    re.compile(r"^(?P<action>Logging in user) (?P<user_id>@\S+) on device (?P<device>\S+)$"),
    re.compile(r"^(?P<action>Failed password login) for user (?P<user_id>@\S+)$"),
    re.compile(r"^(?P<action>Attempted to login) as (?P<user_id>@\S+) but they do not exist$"),
    re.compile(r'^(?P<client_ip>\S+) - (?P<site>\d+) - \{(?P<requester>[^}]*)\} (?P<action>Processed request): (?P<timing>.+?) '
               r'(?P<bytes>\d+)B (?P<status>\d+) "(?P<method>[A-Z]+) (?P<url>\S+) HTTP/(?P<http_version>[\d.]+)" '
               r'"(?P<user_agent>[^"]*)" \[(?P<dbevts>\d+) dbevts\]$'),
)
_JSON_KEYS = {"time": "timestamp", "namespace": "logger", "level": "level", "request": "request", "ip_address": "client_ip",
              "site_tag": "site", "method": "method", "url": "url", "user_agent": "user_agent", "server_name": "server_name"}


def _msg(msg: str) -> dict[str, str]:
    for rx in _MSGS:
        m = rx.match(msg)
        if m:
            return {k: v for k, v in m.groupdict().items() if v is not None}
    return {}


def _extract(line: str) -> dict[str, str]:
    s = line.strip()
    if s.startswith("{"):
        try:
            o = json.loads(s)
        except ValueError:
            return {}
        if not isinstance(o, dict):
            return {}
        d = _msg(str(o.get("log", "")))
        if not d:
            return {}
        out = {new: str(o[k]) for k, new in _JSON_KEYS.items() if o.get(k) is not None}
        if str(o.get("protocol", "")).startswith("HTTP/"):
            out["http_version"] = o["protocol"][5:]
        # The access message repeats the request's address, method, URL, version and agent; the keys are kept.
        out.update({k: v for k, v in d.items() if k not in out})
        return out
    m = _TEXT.match(s)
    if not m:
        return {}
    d = _msg(m.group("msg"))
    if not d:
        return {}
    return {k: v for k, v in m.groupdict().items() if k != "msg"} | d


def _doc(fmt: str) -> str:
    if fmt == "text":
        head = """the default formatter of the packaged log configuration, one line per record:

    <yyyy-mm-dd hh:mm:ss,mmm> - <logger> - <lineno> - <level> - <request> - <message>

`logger` is the Python logger (synapse.rest.client.login, synapse.handlers.auth, synapse.access.http.<port>),
`lineno` the source line that logged it, `request` the request id (`POST-7`) that ties the lines of one request."""
    else:
        head = """synapse.logging.TerseJsonFormatter, one JSON object per record:

    {"log": "<message>", "namespace": "<logger>", "level": "<level>", "time": <epoch seconds>, "request": "<request>",
     "ip_address": "<client_ip>", "site_tag": "<port>", "requester": ..., "authenticated_entity": ...,
     "method": "<method>", "url": "<url>", "protocol": "HTTP/<version>", "user_agent": "<agent>",
     "server_name": "<server name>"}

Every record carries the request's client address, method, URL and agent; `request` ties the records of one request."""
    return f"""
# Matrix Synapse 1.120.2 - homeserver log, {'default text formatter' if fmt == 'text' else 'TerseJsonFormatter'}

Source: Synapse documentation, "Logging" / structured logging (vendor documentation), official image. The server writes
{head}

## The messages kept (password logins through the client API)

    Got login request with identifier: {{'type': 'm.id.user', 'user': '<login_user>'}}, medium: None, address: None, user: None
    Logging in user <user_id> on device <device>
    Failed password login for user <user_id>
    Attempted to login as <user_id> but they do not exist
    <client_ip> - <port> - {{<requester>}} Processed request: <timings> <bytes>B <status> "<method> <url> HTTP/<http_version>" "<user_agent>" [<n> dbevts]

- `login_user` - the user name the client submitted; `user_id` - the full Matrix id (`@name:server`)
- `device` - the device id a successful login is given
- `client_ip` - the client address (IPv4-mapped IPv6 here); `status` - 200 for a login, 403 for a refused one
- `bytes` - the response size; `method`, `url`, `http_version`, `user_agent` - the HTTP request
"""


def _fields(text: bool) -> list:
    out = [
        _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
        _f("login_user", "user.name", "keyword", "account", "easy"),
        _f("user_id", "user.id", "keyword", "account_id", "medium", "The full Matrix id."),
        _f("status", "http.response.status_code", "long", "http_status", "easy"),
        _f("method", "http.request.method", "keyword", "http_method", "easy"),
        _f("url", "url.path", "keyword", "url_path", "easy", "url.original is equivalent."),
        _f("http_version", "http.version", "keyword", "http_version", "easy"),
        _f("user_agent", "user_agent.original", "keyword", "user_agent", "easy"),
        _f("bytes", "http.response.body.bytes", "long", "response_bytes", "medium", "http.response.bytes is equivalent."),
        _f("request", "http.request.id", "keyword", "request_id", "medium"),
        _f("logger", "log.logger", "keyword", "logger", "easy"),
        _f("level", "log.level", "keyword", "severity", "easy"),
        _f("action", "event.action", "keyword", "event_type", "medium"),
        _f("device", None, "keyword", "device_id", "hard", "A Matrix device id; no ECS field.", abstain=True),
        _f("site", None, "keyword", "listener_port", "hard", "The listener's tag; no ECS field.", abstain=True),
        _f("requester", None, "keyword", "requester", "hard", "None for unauthenticated requests.", abstain=True),
        _f("timing", None, "keyword", "timings", "hard", "Several durations; no ECS field.", abstain=True),
        _f("dbevts", None, "long", "db_events", "hard", "No ECS field.", abstain=True),
        _f("timestamp", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
    ]
    if text:
        out.insert(12, _f("lineno", "log.origin.file.line", "long", "source_line", "medium"))
    else:
        out.append(_f("server_name", None, "keyword", "server_name", "hard", "Constant; host.name would be a guess.", abstain=True))
    return out


OLD = Spec(
    source_id="r7_synapse_text", family="synapse",
    software="Matrix Synapse 1.120.2 (official image), default text formatter", category="authentication",
    contamination="high", split="train_r7",
    notes="ROUND 10 (pool r7), OLD VERSION: Synapse 1.120.2, default text log formatter.",
    documentation=_doc("text"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_fields(True),
)

NEW = Spec(
    source_id="r7_synapse_json", family="synapse",
    software="Matrix Synapse 1.120.2 (official image), TerseJsonFormatter", category="authentication",
    contamination="high", split="test_r7",
    notes="ROUND 10 (pool r7), NEW VERSION of r7_synapse_text: synapse.logging.TerseJsonFormatter (same version).",
    documentation=_doc("json"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_fields(False),
)

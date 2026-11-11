"""r7_mattermost: Mattermost 10.5.2 console log at DEBUG, JSON (default) -> plain text (ConsoleJson=false), same version."""
from __future__ import annotations

import json
import re

from testbed.heldout_r2.specs import Spec, _f

_MSGS = ("Received HTTP request",
         "A user tried to sign in, which matched a Mattermost account, but the password was incorrect.",
         "Enter a valid email or username and/or password.")
_TEXT = re.compile(r"^(?P<level>[a-z]+) +\[(?P<timestamp>[^\]]+)\] (?P<msg>" + "|".join(map(re.escape, _MSGS)) + r") *(?P<kv>.*)$")
_KV = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S*)')
_KEYS = ("timestamp", "level", "msg", "caller", "method", "url", "path", "request_id", "user_id", "status_code", "ip_addr",
         "username", "err_where", "http_code", "error")


def _extract(line: str) -> dict[str, str]:
    s = line.strip()
    if s.startswith("{"):
        try:
            o = json.loads(s)
        except ValueError:
            return {}
        if not isinstance(o, dict) or o.get("msg") not in _MSGS:
            return {}
        # The JSON keeps an empty user_id as "", and so does a JSON parse of it.
        return {k: str(o[k]) for k in _KEYS if k in o and o[k] is not None}
    m = _TEXT.match(s)
    if not m:
        return {}
    out = {k: m.group(k) for k in ("level", "timestamp", "msg")}
    for k, v in _KV.findall(m.group("kv")):
        v = v[1:-1] if v.startswith('"') else v
        if k in _KEYS and v != "":      # `user_id=` with no value is no value
            out[k] = v
    return out


def _doc(fmt: str) -> str:
    head = ('one JSON object per line:\n\n    {"timestamp": "<yyyy-mm-dd hh:mm:ss.mmm Z>", "level": "<level>", "msg": "<message>", '
            '"caller": "<file:line>", <key>: <value>, ...}' if fmt == "json" else
            'one line per record, the message padded, then key=value pairs:\n\n    <level> [<yyyy-mm-dd hh:mm:ss.mmm Z>] '
            '<message> caller="<file:line>" <key>=<value> ...\n\nA value with spaces is quoted; an empty value is written `key=`.')
    return f"""
# Mattermost Team Edition 10.5.2 - server console log, {'JSON (default)' if fmt == 'json' else 'plain (LogSettings.ConsoleJson=false)'}

Source: Mattermost documentation, "Logging" settings (vendor documentation), official image. Console level DEBUG.
The server writes {head}

## The messages kept (password logins through the API, POST /api/v4/users/login)

    Received HTTP request                 caller, method, url, request_id, user_id, status_code
    A user tried to sign in, which matched a Mattermost account, but the password was incorrect.
                                          caller, path, request_id, ip_addr, user_id, method, username
    Enter a valid email or username and/or password.
                                          caller, path, request_id, ip_addr, user_id, method, err_where, http_code, error

- `request_id` ties the lines of one request; only the refusal lines carry the client address (`ip_addr`)
- `user_id` - the account id of a successful login (empty when refused); `username` - the account a wrong password was
  tried against (an unknown user is refused without it)
- `status_code` - the response status of the request line; `http_code` - the status the refusal sets (401)
- `url` (request line) and `path` (refusal lines) are both the request path; `caller` - source file and line
"""


_FIELDS = [
    _f("ip_addr", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("username", "user.name", "keyword", "account", "easy"),
    _f("user_id", "user.id", "keyword", "account_id", "medium"),
    _f("status_code", "http.response.status_code", "long", "http_status", "easy"),
    _f("method", "http.request.method", "keyword", "http_method", "easy"),
    _f("url", "url.original", "keyword", "url", "medium", "The request line's path; url.path would be equivalent."),
    _f("path", "url.path", "keyword", "url_path", "medium", "The refusal lines' path."),
    _f("request_id", "http.request.id", "keyword", "request_id", "medium", "trace.id is equivalent."),
    _f("error", "error.message", "keyword", "error", "medium"),
    _f("msg", "event.action", "keyword", "event_type", "medium", "The fixed message text names the event."),
    _f("caller", "log.origin.file.name", "keyword", "source_location", "medium", "file:line in one value."),
    _f("level", "log.level", "keyword", "severity", "easy"),
    _f("http_code", None, "long", "http_status", "hard", "Repeats the request line's status_code.", abstain=True),
    _f("err_where", None, "keyword", "error_origin", "hard", "No ECS field.", abstain=True),
    _f("timestamp", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r7_mattermost_json", family="mattermost",
    software="Mattermost Team Edition 10.5.2 (official image), console log JSON", category="authentication",
    contamination="high", split="train_r7",
    notes="ROUND 10 (pool r7), OLD VERSION: Mattermost 10.5.2, console JSON (default), level DEBUG.",
    documentation=_doc("json"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r7_mattermost_text", family="mattermost",
    software="Mattermost Team Edition 10.5.2 (official image), console log plain", category="authentication",
    contamination="high", split="test_r7",
    notes="ROUND 10 (pool r7), NEW VERSION of r7_mattermost_json: LogSettings.ConsoleJson=false (same version).",
    documentation=_doc("text"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

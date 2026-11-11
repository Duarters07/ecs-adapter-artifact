"""r6_authelia: Authelia 4.38.17 first-factor log, log.format text -> json (same version)."""
from __future__ import annotations

import json
import re

from testbed.heldout_r2.specs import Spec, _f

_MSG = re.compile(r"^Unsuccessful 1FA authentication attempt by user '(?P<user>[^']*)'"
                  r"(?: and they are banned until (?P<banned_until>.+))?$")
_KV = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')


def _extract(line: str) -> dict[str, str]:
    s = line.strip()
    if s.startswith("{"):
        try:
            o = json.loads(s)
        except ValueError:
            return {}
        if not isinstance(o, dict):
            return {}
        kv = {k: str(v) for k, v in o.items()}
    else:
        kv = {k: (v[1:-1] if v.startswith('"') else v) for k, v in _KV.findall(s)}
    m = _MSG.match(kv.get("msg", ""))
    if not m:
        return {}
    out = {k: kv[k] for k in ("time", "level", "error", "method", "path", "remote_ip") if k in kv}
    out.update({k: v for k, v in m.groupdict().items() if v is not None})
    return out


def _doc(fmt: str) -> str:
    head = ('one logfmt line per event (Go logrus text formatter):\n\n'
            '    time="<time>" level=<level> msg="<message>" [error="<error>"] method=<method> path=<path> remote_ip=<remote_ip>'
            if fmt == "text" else
            'one JSON object per line, keys in alphabetical order:\n\n'
            '    {["error": "<error>",] "level": "<level>", "method": "<method>", "msg": "<message>", "path": "<path>", '
            '"remote_ip": "<remote_ip>", "time": "<time>"}')
    return f"""
# Authelia 4.38 - server log, format {fmt}

Source: Authelia documentation, "Log" configuration (https://www.authelia.com/configuration/miscellaneous/logging/),
`log.format: {fmt}`. The server writes {head}

## The messages kept

    Unsuccessful 1FA authentication attempt by user '<user>'
    Unsuccessful 1FA authentication attempt by user '<user>' and they are banned until <banned_until>

Successful first-factor logins are not logged at level info.

- `time` - UTC, RFC 3339; `level` - error for these events
- `user` - the username submitted; `banned_until` - when regulation lifts the ban after repeated failures
- `error` - present when the backend gives a reason, such as `user not found`
- `method`, `path` - the HTTP request (`POST /api/firstfactor`)
- `remote_ip` - the client address
"""


_FIELDS = [
    _f("remote_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("user", "user.name", "keyword", "account", "easy"),
    _f("error", "event.reason", "keyword", "refusal_reason", "medium"),
    _f("method", "http.request.method", "keyword", "http_method", "easy"),
    _f("path", "url.path", "keyword", "url_path", "easy", "url.original is equivalent."),
    _f("level", "log.level", "keyword", "severity", "easy"),
    _f("banned_until", None, "keyword", "ban_end", "hard", "No ECS field for a ban's end.", abstain=True),
    _f("time", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r6_authelia_text", family="authelia",
    software="Authelia 4.38.17 (official image), log.format text", category="authentication",
    contamination="high", split="train_r6",
    notes="ROUND 8 (pool r6), OLD VERSION: Authelia 4.38.17, text log.",
    documentation=_doc("text"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r6_authelia_json", family="authelia",
    software="Authelia 4.38.17 (official image), log.format json", category="authentication",
    contamination="high", split="test_r6",
    notes="ROUND 8 (pool r6), NEW VERSION of r6_authelia_text: log.format json.",
    documentation=_doc("json"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

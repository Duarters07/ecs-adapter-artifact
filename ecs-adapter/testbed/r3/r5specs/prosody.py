"""r5_prosody: Prosody XMPP server info log, Debian 11 (0.11.9) -> Debian 12 (0.12.3)."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_LINE = re.compile(r"^(?P<timestamp>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (?P<session>c2s[0-9a-f]+)\t(?P<level>\w+)\t(?P<msg>.*)$")
_MSGS = (
    re.compile(r"^Client (?P<event>connected)$"),
    re.compile(r"^(?P<event>Authenticated) as (?P<user>[^@\s]+)@(?P<domain>\S+)$"),
    re.compile(r"^Client (?P<event>disconnected): (?P<reason>.+)$"),
)


def _extract(line: str) -> dict[str, str]:
    m = _LINE.match(line.rstrip("\n"))
    if not m:
        return {}
    for rx in _MSGS:
        mm = rx.match(m.group("msg"))
        if mm:
            out = {k: v for k, v in m.groupdict().items() if v is not None and k != "msg"}
            out.update({k: v for k, v in mm.groupdict().items() if v is not None})
            return out
    return {}


def _doc(version: str) -> str:
    return f"""
# Prosody {version} - log file, info level

Source: Prosody documentation, "Logging" (https://prosody.im/doc/logging), and the Debian package's
log sink, /var/log/prosody/prosody.log.

Every line is `<timestamp> <session>\\t<level>\\t<message>`, tab-separated after the session.

## The client-session messages kept

    Client connected
    Authenticated as <user>@<domain>
    Client disconnected: <reason>

- `timestamp` - local time, `Mmm dd HH:MM:SS`
- `session` - the id of the client-to-server session (`c2s` and a hexadecimal number); the same id
  on every line of one connection
- `level` - the log level (`info`)
- `event` - what happened: `connected`, `Authenticated`, `disconnected`
- `user`, `domain` - the account that authenticated, and its XMPP domain
- `reason` - why the session ended

A login that fails is logged at this level only as a connection followed by a disconnection,
with no `Authenticated` line between them.
"""


_FIELDS = [
    _f("user", "user.name", "keyword", "account", "easy"),
    _f("domain", "user.domain", "keyword", "account_domain", "medium"),
    _f("reason", "event.reason", "keyword", "disconnect_reason", "medium"),
    _f("level", "log.level", "keyword", "severity", "easy"),
    _f("event", None, "keyword", "session_event", "hard",
       "event.action is arguable for a free-text verb; declining accepted.", abstain=True),
    _f("session", None, "keyword", "session_id", "hard", "No ECS field fits a session id cleanly.", abstain=True),
]

OLD = Spec(
    source_id="r5_prosody_011", family="prosody",
    software="Prosody 0.11.9 (Debian 11)", category="authentication",
    contamination="high", split="train_r5",
    notes="ROUND 6 (pool r5), OLD VERSION: Prosody 0.11.9, info log file.",
    documentation=_doc("0.11"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r5_prosody_012", family="prosody",
    software="Prosody 0.12.3 (Debian 12)", category="authentication",
    contamination="high", split="test_r5",
    notes="ROUND 6 (pool r5), NEW VERSION of r5_prosody_011. Captured as an upgrade; see T3 for whether the format changed.",
    documentation=_doc("0.12"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

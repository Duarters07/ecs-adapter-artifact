"""r6_vaultwarden: Vaultwarden log, official image 1.25.2 -> 1.32.7."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_LINE = re.compile(r"^\[(?P<timestamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\]\[(?P<logger>vaultwarden::api::\w+)\]\[(?P<level>[A-Z]+)\] "
                   r"(?P<msg>.*)$")
_MSGS = (
    re.compile(r"^(?P<reason>Username or password is incorrect)\. Try again\. IP: (?P<client_ip>[0-9.]+)\. Username: (?P<user>\S+?)\.$"),
    re.compile(r"^(?P<reason>Invalid admin token)\. IP: (?P<client_ip>[0-9.]+)$"),
)


def _extract(line: str) -> dict[str, str]:
    m = _LINE.match(line.strip())
    if not m:
        return {}
    for rx in _MSGS:
        mm = rx.match(m.group("msg"))
        if mm:
            out = {k: v for k, v in m.groupdict().items() if k != "msg"}
            out.update({k: v for k, v in mm.groupdict().items() if v is not None})
            return out
    return {}


def _doc(version: str) -> str:
    return f"""
# Vaultwarden {version} - server log (LOG_LEVEL=warn, EXTENDED_LOGGING=true)

Source: Vaultwarden wiki, "Logging" and "Fail2Ban Setup" (https://github.com/dani-garcia/vaultwarden/wiki), official
image. The server writes to standard output, one line per event:

    [<timestamp>][<logger>][<level>] <message>

## The messages kept

    Username or password is incorrect. Try again. IP: <client_ip>. Username: <user>.
    Invalid admin token. IP: <client_ip>

- `timestamp` - local time with milliseconds; `logger` - the module (`vaultwarden::api::identity`, `::admin`)
- `level` - ERROR for these events
- `client_ip` - the client address; `user` - the account (an e-mail address) a refused vault login used
- the reason is the message itself: a refused vault login, or a wrong admin-panel token
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("user", "user.name", "keyword", "account", "easy", "user.email is equivalent here (an e-mail address)."),
    _f("reason", "event.reason", "keyword", "refusal_reason", "medium"),
    _f("level", "log.level", "keyword", "severity", "easy"),
    _f("logger", "log.logger", "keyword", "logger", "medium"),
    _f("timestamp", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r6_vaultwarden_125", family="vaultwarden",
    software="Vaultwarden 1.25.2 (official image)", category="authentication",
    contamination="high", split="train_r6",
    notes="ROUND 8 (pool r6), OLD VERSION: Vaultwarden 1.25.2, LOG_LEVEL=warn, EXTENDED_LOGGING.",
    documentation=_doc("1.25.2"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r6_vaultwarden_132", family="vaultwarden",
    software="Vaultwarden 1.32.7 (official image)", category="authentication",
    contamination="high", split="test_r6",
    notes="ROUND 8 (pool r6), NEW VERSION of r6_vaultwarden_125. Captured as an upgrade; see T3 for whether the format changed.",
    documentation=_doc("1.32.7"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

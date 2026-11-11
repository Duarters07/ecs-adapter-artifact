"""r5_dropbear: Dropbear SSH server log, Debian 11 (2020.81) -> Debian 13 (2025.89)."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_HEAD = re.compile(r"^\[(?P<pid>\d+)\] (?P<timestamp>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (?P<msg>.*)$")
_ADDR = r"(?P<client_ip>[0-9.]+):(?P<client_port>\d+)"
_MSGS = (
    re.compile(r"^Child connection from " + _ADDR + r"$"),
    re.compile(r"^(?P<result>Password auth succeeded) for '(?P<user>[^']*)' from " + _ADDR + r"$"),
    re.compile(r"^(?P<result>Bad password attempt) for '(?P<user>[^']*)' from " + _ADDR + r"$"),
    re.compile(r"^(?P<result>Login attempt for nonexistent user)(?: from " + _ADDR + r")?$"),
    re.compile(r"^Exit before auth from <" + _ADDR + r">: (?:\(user '(?P<user>[^']*)', (?P<fails>\d+) fails\): )?(?P<reason>.+)$"),
    re.compile(r"^Exit \((?P<user>[^)]*)\) from <" + _ADDR + r">: (?P<reason>.+)$"),
)


def _extract(line: str) -> dict[str, str]:
    m = _HEAD.match(line.strip())
    if not m:
        return {}
    for rx in _MSGS:
        mm = rx.match(m.group("msg"))
        if mm:
            out = {"pid": m.group("pid"), "timestamp": m.group("timestamp")}
            out.update({k: v for k, v in mm.groupdict().items() if v is not None})
            return out
    return {}


def _doc(version: str, nonexistent: str) -> str:
    return f"""
# Dropbear SSH server {version} - log

Source: dropbear(8), Debian package {version} (`-F` foreground, `-E` log to standard error).

Every line is `[<pid>] <timestamp> <message>`, with the id of the process that handles the
connection and the local time as `Mmm dd HH:MM:SS`.

## The messages kept

    Child connection from <client_ip>:<client_port>
    Password auth succeeded for '<user>' from <client_ip>:<client_port>
    Bad password attempt for '<user>' from <client_ip>:<client_port>
    {nonexistent}
    Exit before auth from <<client_ip>:<client_port>>: (user '<user>', <fails> fails): <reason>
    Exit before auth from <<client_ip>:<client_port>>: <reason>
    Exit (<user>) from <<client_ip>:<client_port>>: <reason>

- `pid` - the id of the process serving the connection
- `client_ip`, `client_port` - the address and port of the client
- `user` - the account the client tried, or logged in as
- `result` - what happened to the authentication attempt (the text of the message)
- `fails` - how many authentication attempts failed before the connection ended
- `reason` - why the connection ended (`Exited normally`, `Disconnect received`, ...)
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("client_port", "source.port", "long", "client_port", "easy"),
    _f("user", "user.name", "keyword", "account", "easy"),
    _f("pid", "process.pid", "long", "process_id", "easy"),
    _f("result", "event.action", "keyword", "auth_event", "hard",
       "The message names what happened; event.outcome would need a value map."),
    _f("reason", "event.reason", "keyword", "exit_reason", "medium"),
    _f("fails", None, "long", "failure_count", "hard", "No ECS field for a count of failures.", abstain=True),
]

OLD = Spec(
    source_id="r5_dropbear_2020", family="dropbear",
    software="Dropbear 2020.81 (Debian 11)", category="authentication",
    contamination="high", split="train_r5",
    notes="ROUND 6 (pool r5), OLD VERSION: Dropbear 2020.81.",
    documentation=_doc("2020.81", "Login attempt for nonexistent user"),
    keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r5_dropbear_2025", family="dropbear",
    software="Dropbear 2025.89 (Debian 13)", category="authentication",
    contamination="high", split="test_r5",
    notes=("ROUND 6 (pool r5), NEW VERSION of r5_dropbear_2020. Measured: `Login attempt for nonexistent user` "
           "gains ` from <ip>:<port>`; every other kept message is unchanged."),
    documentation=_doc("2025.89", "Login attempt for nonexistent user from <client_ip>:<client_port>"),
    keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

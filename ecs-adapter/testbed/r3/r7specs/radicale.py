"""r7_radicale: Radicale server log (stderr, level info), Debian 12 (3.1.8) -> Debian 13 (3.5.3)."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_HEAD = re.compile(r"^\[(?P<timestamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d [+-]\d{4})\] \[(?P<pid>\d+)/(?P<thread>[^\]]+)\] "
                   r"\[(?P<level>[A-Z]+)\] (?P<msg>.*)$")
_MSGS = (
    re.compile(r"^(?P<action>Successful login): '(?P<user>[^']*)'(?: \((?P<backend>[^)]+)\))?$"),
    re.compile(r"^(?P<action>Failed login attempt) from (?P<client_ip>[0-9.]+): '(?P<user>[^']*)'(?: \((?P<backend>[^)]+)\))?$"),
    re.compile(r"^(?P<action>Login verification failed) for user: '(?P<user>[^']*)' \((?P<auth_method>[^)]+)\)$"),
    re.compile(r"^(?P<action>Login verification user not found) \((?P<backend>[^)]+)\): '(?P<user>[^']*)'$"),
)


def _extract(line: str) -> dict[str, str]:
    m = _HEAD.match(line.strip())
    if not m:
        return {}
    for rx in _MSGS:
        mm = rx.match(m.group("msg"))
        if mm:
            out = {k: v for k, v in m.groupdict().items() if k != "msg"}
            out.update({k: v for k, v in mm.groupdict().items() if v is not None})
            return out
    return {}


def _doc(version: str, new: bool) -> str:
    if new:
        msgs = ("    Successful login: '<user>' (<backend>)\n"
                "    Failed login attempt from <client_ip>: '<user>' (<backend>)\n"
                "    Login verification failed for user: '<user>' (<auth_method>)\n"
                "    Login verification user not found (<backend>): '<user>'")
        extra = ("- `backend` - the authentication backend that answered (`htpasswd`)\n"
                 "- `auth_method` - backend, password encryption and method (`htpasswd/plain/PLAIN`)\n"
                 "- a refused login logs the backend's reason first (wrong password, or unknown user), then the\n"
                 "  `Failed login attempt` line with the client address")
    else:
        msgs = ("    Successful login: '<user>'\n"
                "    Failed login attempt from <client_ip>: '<user>'")
        extra = ""
    return f"""
# Radicale {version} - server log on stderr, level info

Source: Radicale documentation ("Logging" and "Authentication" settings), Debian package, htpasswd authentication.
One line per event:

    [<timestamp>] [<pid>/<thread>] [<level>] <message>

`timestamp` is local time with its UTC offset; `thread` names the request thread (`Thread-N (process_request_thread)`).

## The messages kept

{msgs}

- `level` - INFO for a success, WARNING for a refusal
- `user` - the username the client sent; `client_ip` - the client address (only on the refusal line)
{extra}
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("user", "user.name", "keyword", "account", "easy"),
    _f("action", "event.action", "keyword", "event_type", "medium"),
    _f("level", "log.level", "keyword", "severity", "easy"),
    _f("pid", "process.pid", "long", "process_id", "easy"),
    _f("thread", "process.thread.name", "keyword", "thread", "medium"),
    _f("backend", None, "keyword", "auth_backend", "hard", "No ECS field for the authentication backend.", abstain=True),
    _f("auth_method", None, "keyword", "auth_method", "hard", "No ECS field.", abstain=True),
    _f("timestamp", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r7_radicale_318", family="radicale",
    software="Radicale 3.1.8 (Debian 12)", category="authentication",
    contamination="high", split="train_r7",
    notes="ROUND 10 (pool r7), OLD VERSION: Radicale 3.1.8, htpasswd authentication, log level info.",
    documentation=_doc("3.1.8", False), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r7_radicale_353", family="radicale",
    software="Radicale 3.5.3 (Debian 13)", category="authentication",
    contamination="high", split="test_r7",
    notes="ROUND 10 (pool r7), NEW VERSION of r7_radicale_318: login lines gain the backend; new verification lines.",
    documentation=_doc("3.5.3", True), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

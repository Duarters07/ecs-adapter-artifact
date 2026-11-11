"""r7_mumble: Mumble server log on stderr (foreground), Debian 12 1.3.4 -> Debian 13 1.5.735."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_HEAD = re.compile(r"^<(?P<level>[A-Z])>(?P<timestamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}) (?P<server_id>\d+) => "
                   r"<(?P<session>\d+):(?P<user>[^(]*)\((?P<user_id>-?\d+)\)> (?P<msg>.*)$")
_MSGS = (
    re.compile(r"^(?P<action>New connection): (?P<client_ip>[0-9.]+):(?P<client_port>\d+)$"),
    re.compile(r"^(?P<action>Client version) (?P<client_version>\S+) \((?P<client_os>[^:]+): (?P<client_release>[^)]+)\)$"),
    re.compile(r"^(?P<action>Authenticated)$"),
    re.compile(r"^(?P<action>Rejected connection) from (?P<client_ip>[0-9.]+):(?P<client_port>\d+): (?P<reason>.+)$"),
    re.compile(r"^(?P<action>Connection closed): (?P<close_reason>.*) \[(?P<close_code>-?\d+)\]$"),
)


def _extract(line: str) -> dict[str, str]:
    m = _HEAD.match(line.strip())
    if not m:
        return {}
    for rx in _MSGS:
        mm = rx.match(m.group("msg"))
        if mm:
            out = {k: v for k, v in m.groupdict().items() if k != "msg" and v}
            out.update({k: v for k, v in mm.groupdict().items() if v is not None})
            if not out.get("close_reason", "x").strip():
                del out["close_reason"]   # a refused login closes with an empty reason
            return out
    return {}


def _doc(version: str, new: bool) -> str:
    pre = ("The session number before authentication is always 0; the real one appears from `Authenticated` or "
           "`Rejected connection` on." if new else "The session number is the client's from its first line.")
    osv = " and, from 1.4 on, its version (`Win 10.0.19045`)" if new else " (`Win`)"
    return f"""
# Mumble server {version} - log on stderr (foreground)

Source: Mumble server documentation (mumble-server.ini: "serverpassword", "logfile"), Debian package. One line per
event, tagged with the virtual server and the client session:

    <<level>><yyyy-mm-dd hh:mm:ss.mmm> <server_id> => <<session>:<user>(<user_id>)> <message>

{pre} `user` is empty until the client has sent its name; `user_id` is -1 for an unregistered user.

## The messages kept

    New connection: <client_ip>:<client_port>
    Client version <client_version> (<client_os>: <client_release>)
    Authenticated
    Rejected connection from <client_ip>:<client_port>: <reason>
    Connection closed: <close_reason> [<close_code>]

- `level` - W (warning) for these lines; `server_id` - the virtual server
- `client_ip`, `client_port` - the client; `client_release` - the client's release; `client_os` - its operating
  system{osv}
- `reason` - why the login was refused (Invalid server password; Wrong certificate or password for existing user)
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("client_port", "source.port", "long", "client_port", "easy", "client.port is equivalent."),
    _f("user", "user.name", "keyword", "account", "easy"),
    _f("reason", "event.reason", "keyword", "refusal_reason", "medium"),
    _f("client_release", "user_agent.version", "keyword", "client_version", "medium"),
    _f("client_os", "user_agent.os.full", "keyword", "client_os", "hard", "user_agent.os.name is close."),
    _f("level", "log.level", "keyword", "severity", "easy"),
    _f("action", "event.action", "keyword", "event_type", "medium"),
    _f("session", None, "long", "session_id", "hard", "No ECS field for a Mumble session number.", abstain=True),
    _f("user_id", None, "long", "registration_id", "hard", "-1 for unregistered users; user.id would mislead.", abstain=True),
    _f("server_id", None, "long", "virtual_server", "hard", "No ECS field.", abstain=True),
    _f("client_version", None, "keyword", "protocol_version", "hard", "The protocol version; client_release is the release.", abstain=True),
    _f("close_reason", None, "keyword", "close_reason", "hard", "event.reason holds the refusal reason.", abstain=True),
    _f("close_code", None, "long", "close_code", "hard", "No ECS field.", abstain=True),
    _f("timestamp", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r7_mumble_134", family="mumble",
    software="Mumble server 1.3.4 (Debian 12)", category="authentication",
    contamination="high", split="train_r7",
    notes="ROUND 10 (pool r7), OLD VERSION: Mumble server 1.3.4 (murmurd), server password, log on stderr.",
    documentation=_doc("1.3.4", False), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r7_mumble_15", family="mumble",
    software="Mumble server 1.5.735 (Debian 13)", category="authentication",
    contamination="high", split="test_r7",
    notes="ROUND 10 (pool r7), NEW VERSION of r7_mumble_134: client OS version logged; pre-auth session number 0.",
    documentation=_doc("1.5.735", True), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

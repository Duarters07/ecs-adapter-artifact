"""r7_ocserv: ocserv (OpenConnect VPN server) via syslog, Debian 12 (1.1.6) -> Debian 13 (1.3.0): VPN logins."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_HEAD = re.compile(r"^(?P<timestamp>\d{4}-\d\d-\d\dT[\d:.]+[+-]\d\d:\d\d) (?P<host>\S+) (?P<program>ocserv)\[(?P<pid>\d+)\]: (?P<msg>.*)$")
_MSGS = (
    re.compile(r"^(?P<component>sec-mod): (?P<action>initiating session|invalidating session) (?:for|of) user "
               r"'(?P<user>[^']*)' \(session: (?P<session>[^)]+)\)$"),
    re.compile(r"^(?P<component>plain-auth): (?P<action>error authenticating) user '(?P<user>[^']*)'$"),
    re.compile(r"^(?P<component>worker)\[(?P<user>[^\]]*)\]: (?P<client_ip>[0-9.]+) (?P<src_location>\S+): "
               r"(?P<action>failed authentication) for '[^']*'$"),
    re.compile(r"^(?P<component>main)\[(?P<user>[^\]]*)\]:(?P<client_ip>[0-9.]+):(?P<client_port>\d+) "
               r"(?P<action>new user session|user logged in)$"),
    re.compile(r"^(?P<component>main)\[(?P<user>[^\]]*)\]:(?P<client_ip>[0-9.]+):(?P<client_port>\d+) "
               r"(?P<action>user disconnected) \(reason: (?P<reason>[^,]+), rx: (?P<rx>\d+), tx: (?P<tx>\d+)\)$"),
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
    main = """
    main[<user>]:<client_ip>:<client_port> new user session
    main[<user>]:<client_ip>:<client_port> user logged in
    main[<user>]:<client_ip>:<client_port> user disconnected (reason: <reason>, rx: <rx>, tx: <tx>)""" if new else ""
    return f"""
# ocserv {version} - OpenConnect VPN server, syslog (default level), via rsyslog

Source: ocserv(8) manual (vendor documentation), Debian package. Password authentication against a plain password
file. rsyslog writes one line per message:

    <timestamp> <host> ocserv[<pid>]: <component>: <message>

## The messages kept

    sec-mod: initiating session for user '<user>' (session: <session>)
    sec-mod: invalidating session of user '<user>' (session: <session>)
    plain-auth: error authenticating user '<user>'
    worker[<user>]: <client_ip> <src_location>: failed authentication for '<user>'{main}

- `component` - the ocserv process that logs: sec-mod (security module), plain-auth, worker (one per client), main
- `user` - the username submitted; `session` - the session id sec-mod assigns
- `client_ip`{", `client_port`" if new else ""} - the VPN client
- `src_location` - the source file and line that logged the failure
{"- `reason`, `rx`, `tx` - why the session ended and the bytes received from and sent to the client" if new else "- A successful login is logged only by sec-mod, without the client address."}
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("client_port", "source.port", "long", "client_port", "easy", "client.port is equivalent."),
    _f("user", "user.name", "keyword", "account", "easy"),
    _f("action", "event.action", "keyword", "event_type", "medium"),
    _f("reason", "event.reason", "keyword", "end_reason", "medium"),
    _f("host", "host.hostname", "keyword", "host", "easy", "host.name is equivalent."),
    _f("program", "process.name", "keyword", "program", "easy"),
    _f("pid", "process.pid", "long", "process_id", "easy"),
    _f("rx", "source.bytes", "long", "bytes_received", "medium", "client.bytes is equivalent."),
    _f("tx", "destination.bytes", "long", "bytes_sent", "medium", "server.bytes is equivalent."),
    _f("component", None, "keyword", "component", "hard", "No ECS field for the ocserv sub-process.", abstain=True),
    _f("session", None, "keyword", "session_id", "hard", "event.id is acceptable; declining accepted.", abstain=True),
    _f("src_location", None, "keyword", "source_location", "hard", "No ECS field.", abstain=True),
    _f("timestamp", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r7_ocserv_116", family="ocserv",
    software="ocserv 1.1.6 (Debian 12)", category="authentication",
    contamination="high", split="train_r7",
    notes="ROUND 10 (pool r7), OLD VERSION: ocserv 1.1.6, plain password auth, rsyslog.",
    documentation=_doc("1.1.6", False), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r7_ocserv_130", family="ocserv",
    software="ocserv 1.3.0 (Debian 13)", category="authentication",
    contamination="high", split="test_r7",
    notes="ROUND 10 (pool r7), NEW VERSION of r7_ocserv_116: main[user]:ip:port session lines added; failure line's source location moves.",
    documentation=_doc("1.3.0", True), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

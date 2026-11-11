"""r5_mosquitto: Eclipse Mosquitto broker log, 1.6.15 -> 2.0.22 (official images, same configuration)."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_ADDR = r"(?P<client_ip>[0-9a-fA-F.:]+?)(?::(?P<client_port>\d+))?"
_MSGS = (
    re.compile(r"^(?P<timestamp>\d+): New connection from " + _ADDR + r" on port (?P<listener_port>\d+)\.$"),
    re.compile(r"^(?P<timestamp>\d+): New client connected from " + _ADDR + r" as (?P<client_id>\S+) "
               r"\(p(?P<protocol_version>\d+), c(?P<clean_session>\d), k(?P<keepalive>\d+), u'(?P<user>[^']*)'\)\.$"),
    re.compile(r"^(?P<timestamp>\d+): Client (?P<client_id>\S+) disconnected(?:, (?P<reason>[^.]+))?\.$"),
    re.compile(r"^(?P<timestamp>\d+): Socket error on client (?P<client_id>\S+), disconnecting\.$"),
)


def _extract(line: str) -> dict[str, str]:
    for rx in _MSGS:
        m = rx.match(line.strip())
        if m:
            return {k: v for k, v in m.groupdict().items() if v is not None}
    return {}


def _doc(version: str, addr: str, failed: str) -> str:
    return f"""
# Eclipse Mosquitto {version} - broker log

Source: mosquitto.conf(5) (`log_dest`, `log_type`, `connection_messages`), Mosquitto {version}
documentation, https://mosquitto.org/man/mosquitto-conf-5.html

With `log_dest stdout` and the default log types, every line is `<timestamp>: <message>`, where the
timestamp is in seconds since the Unix epoch.

## The messages kept

    New connection from {addr} on port <listener_port>.
    New client connected from {addr} as <client_id> (p<protocol_version>, c<clean_session>, k<keepalive>, u'<user>').
    Client <client_id> disconnected.
    {failed}

- `client_ip`{", `client_port`" if "port" in addr else ""} - the address{" and port" if "port" in addr else ""} the client connected from
- `listener_port` - the broker's listener port the connection arrived on
- `client_id` - the MQTT client identifier the client chose
- `protocol_version` - the MQTT protocol level (`2` here, MQTT 3.1.1 on the wire is reported as 2 by this version)
- `clean_session`, `keepalive` - the session flag and the keep-alive interval, seconds
- `user` - the user name the client authenticated with
{"- `reason` - why the client was disconnected (`not authorised`: the user name or password was refused)" if "reason" in failed else "- a connection refused for a wrong user name or password is logged as a socket error on a client whose identifier is still `<unknown>`"}
"""


_COMMON = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("listener_port", "destination.port", "long", "server_port", "medium", "server.port is equivalent."),
    _f("user", "user.name", "keyword", "account", "easy"),
    _f("client_id", None, "keyword", "client_identifier", "hard",
       "An MQTT client id names a session, not a host or an account. Declining accepted.", abstain=True),
    _f("protocol_version", None, "keyword", "protocol_level", "hard", "No ECS field.", abstain=True),
    _f("clean_session", None, "keyword", "session_flag", "hard", "No ECS field.", abstain=True),
    _f("keepalive", None, "long", "keepalive", "hard", "No ECS field.", abstain=True),
]

OLD = Spec(
    source_id="r5_mosquitto_16", family="mosquitto",
    software="Eclipse Mosquitto 1.6.15 (image eclipse-mosquitto:1.6)", category="authentication",
    contamination="high", split="train_r5",
    notes="ROUND 6 (pool r5), OLD VERSION: Mosquitto 1.6 with password authentication.",
    documentation=_doc("1.6", "<client_ip>", "Socket error on client <client_id>, disconnecting."),
    keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_COMMON,
)

NEW = Spec(
    source_id="r5_mosquitto_20", family="mosquitto",
    software="Eclipse Mosquitto 2.0.22 (image eclipse-mosquitto:2.0)", category="authentication",
    contamination="high", split="test_r5",
    notes=("ROUND 6 (pool r5), NEW VERSION of r5_mosquitto_16. Measured: addresses gain the client port "
           "(`ip:port`), and a refused login becomes `Client <id> disconnected, not authorised.`"),
    documentation=_doc("2.0", "<client_ip>:<client_port>", "Client <client_id> disconnected, <reason>."),
    keep=lambda ln: bool(_extract(ln)), extract=_extract,
    fields=_COMMON + [
        _f("client_port", "source.port", "long", "client_port", "easy"),
        _f("reason", "event.reason", "keyword", "disconnect_reason", "medium"),
    ],
)

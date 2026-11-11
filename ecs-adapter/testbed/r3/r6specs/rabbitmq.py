"""r6_rabbitmq: RabbitMQ 3.13.7 connection log, console text -> the JSON console formatter (same version)."""
from __future__ import annotations

import json
import re

from testbed.heldout_r2.specs import Spec, _f

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_TEXT = re.compile(r"^(?P<timestamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+\+\d\d:\d\d) \[(?P<level>\w+)\] (?P<pid><[\d.]+>) (?P<msg>.*)$")
_PEER = r"\((?P<src_ip>[0-9.]+):(?P<src_port>\d+) -> (?P<dst_ip>[0-9.]+):(?P<dst_port>\d+)"
_MSGS = (
    re.compile(r"^accepting AMQP connection (?P<conn><[\d.]+>) " + _PEER + r"\)$"),
    re.compile(r"^connection (?P<conn><[\d.]+>) " + _PEER + r"\): user '(?P<user>[^']*)' (?P<result>authenticated and granted access) to vhost '(?P<vhost>[^']*)'$"),
    re.compile(r"^closing AMQP connection (?P<conn><[\d.]+>) " + _PEER + r"(?:, vhost: '(?P<vhost>[^']*)', user: '(?P<user>[^']*)')?\)$"),
    re.compile(r"^Error on AMQP connection (?P<conn><[\d.]+>) " + _PEER + r"(?:, user: '(?P<user>[^']*)')?, state: (?P<state>\w+)\):"
               r"(?:\n(?:PLAIN login refused: user '(?P<refused_user>[^']*)' - (?P<reason>invalid credentials)"
               r"|access to vhost '(?P<denied_vhost>[^']*)' (?P<reason2>refused) for user '(?P<denied_user>[^']*)'))?$"),
    re.compile(r"^PLAIN login refused: user '(?P<user>[^']*)' - (?P<reason>invalid credentials)$"),
    re.compile(r"^access to vhost '(?P<vhost>[^']*)' (?P<reason>refused) for user '(?P<user>[^']*)'$"),
)


def _msg_fields(msg: str) -> dict[str, str]:
    for rx in _MSGS:
        m = rx.match(msg)
        if m:
            d = {k: v for k, v in m.groupdict().items() if v is not None}
            if "refused_user" in d:
                d["user"] = d.pop("refused_user")
            if "denied_user" in d:
                d["user"] = d.pop("denied_user"); d["vhost"] = d.pop("denied_vhost"); d["reason"] = d.pop("reason2")
            return d
    return {}


def _extract(line: str) -> dict[str, str]:
    s = line.strip()
    if s.startswith("{"):
        try:
            o = json.loads(s)
        except ValueError:
            return {}
        if not isinstance(o, dict) or "msg" not in o:
            return {}
        d = _msg_fields(o["msg"])
        if not d:
            return {}
        return {"timestamp": o.get("time", ""), "level": o.get("level", ""), "pid": o.get("pid", ""),
                "domain": o.get("domain", ""), **d}
    m = _TEXT.match(_ANSI.sub("", s))
    if not m:
        return {}
    d = _msg_fields(m.group("msg"))
    if not d:
        return {}
    return {k: v for k, v in m.groupdict().items() if k != "msg"} | d


def _doc_text() -> str:
    return """
# RabbitMQ 3.13 - console log (default text format)

Source: RabbitMQ documentation, "Logging" (https://www.rabbitmq.com/docs/logging). The official image logs
to standard output, one event per line, coloured with terminal escape codes:

    <timestamp> [<level>] <pid> <message>

A connection error is written as two lines with the same timestamp and pid: the error header, then the
reason.

## The messages kept

    accepting AMQP connection <conn> (<client_ip>:<client_port> -> <server_ip>:<server_port>)
    connection <conn> (<client>... -> <server>...): user '<user>' authenticated and granted access to vhost '<vhost>'
    closing AMQP connection <conn> (<client> -> <server>[, vhost: '<vhost>', user: '<user>'])
    Error on AMQP connection <conn> (<client> -> <server>[, user: '<user>'], state: <state>):
    PLAIN login refused: user '<user>' - invalid credentials
    access to vhost '<vhost>' refused for user '<user>'

- `timestamp` - UTC with microseconds and offset; `level` - info, warning, error
- `pid` - the Erlang process handling the connection; `conn` repeats it
- client and server address and port of the AMQP connection
- `user` - the account presented; `vhost` - the virtual host asked for
- `state` - the connection's state when it failed (starting: authentication, opening: vhost access)
- `reason` - `invalid credentials`, or `refused` for a vhost the account may not use
"""


def _doc_json() -> str:
    return """
# RabbitMQ 3.13 - console log, JSON formatter

Source: RabbitMQ documentation, "Logging", JSON output (https://www.rabbitmq.com/docs/logging#json),
enabled with `log.console.formatter = json`. One JSON object per line:

    {"time": "<timestamp>", "level": "<level>", "msg": "<message>", "pid": "<pid>", "domain": "<domain>"}

`msg` is the same text as in the default format; a connection error and its reason are one event, the
reason after a newline inside `msg`. `domain` is the logging domain (`rabbitmq.connection`).

## The messages kept (inside msg)

    accepting AMQP connection <conn> (<client_ip>:<client_port> -> <server_ip>:<server_port>)
    connection <conn> (...): user '<user>' authenticated and granted access to vhost '<vhost>'
    closing AMQP connection <conn> (...[, vhost: '<vhost>', user: '<user>'])
    Error on AMQP connection <conn> (...[, user: '<user>'], state: <state>):\\nPLAIN login refused: user '<user>' - invalid credentials
    Error on AMQP connection <conn> (...):\\naccess to vhost '<vhost>' refused for user '<user>'
"""


_FIELDS = [
    _f("src_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("src_port", "source.port", "long", "client_port", "easy", "client.port is equivalent."),
    _f("dst_ip", "destination.ip", "ip", "server_ip", "medium", "server.ip is equivalent."),
    _f("dst_port", "destination.port", "long", "server_port", "medium", "server.port is equivalent."),
    _f("user", "user.name", "keyword", "account", "easy"),
    _f("reason", "event.reason", "keyword", "refusal_reason", "medium"),
    _f("level", "log.level", "keyword", "severity", "easy"),
    _f("vhost", None, "keyword", "virtual_host", "hard", "No ECS field for an AMQP vhost.", abstain=True),
    _f("pid", None, "keyword", "erlang_process", "hard", "An Erlang process id, not an OS pid.", abstain=True),
    _f("conn", None, "keyword", "connection_id", "hard", "Same as pid.", abstain=True),
    _f("state", None, "keyword", "connection_state", "hard", "No ECS field.", abstain=True),
    _f("result", None, "keyword", "auth_outcome", "hard", "event.outcome needs a value map; declining accepted.", abstain=True),
    _f("domain", None, "keyword", "log_domain", "hard", "Logging domain, constant.", abstain=True),
]

OLD = Spec(
    source_id="r6_rabbitmq_text", family="rabbitmq",
    software="RabbitMQ 3.13.7 (official image), console text", category="authentication",
    contamination="high", split="train_r6",
    notes="ROUND 8 (pool r6), OLD VERSION: RabbitMQ 3.13.7, default console text format.",
    documentation=_doc_text(), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r6_rabbitmq_json", family="rabbitmq",
    software="RabbitMQ 3.13.7 (official image), JSON console formatter", category="authentication",
    contamination="high", split="test_r6",
    notes="ROUND 8 (pool r6), NEW VERSION of r6_rabbitmq_text: log.console.formatter = json.",
    documentation=_doc_json(), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

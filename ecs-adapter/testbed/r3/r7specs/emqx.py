"""r7_emqx: EMQX console log (level info), official image 4.4.19 -> 5.8.6 (text -> structured key: value lines)."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_HEAD = re.compile(r"^(?P<timestamp>\d{4}-\d\d-\d\dT[\d:.]+[+-]\d\d:\d\d) \[(?P<level>[a-z]+)\] (?P<msg>.*)$")
_PEER = r"(?P<client_id>[^@\s]+)@(?P<client_ip>[0-9.]+):(?P<client_port>\d+) "
_OLD = (
    re.compile(r"^" + _PEER + r"(?P<action>PUBLISH) to (?P<topic>[^:]+): <<(?P<payload>.*)>>$"),
    re.compile(r"^" + _PEER + r"file: (?P<file>[^,]+), line: (?P<line>\d+), mfa: (?P<mfa>.+?), msg: (?P<action>terminate), "
               r"pid: (?P<erlang_pid>[^,]+), reason: (?P<reason>.+)$"),
    re.compile(r"^" + _PEER + r"\S+ (?P<action>SUBSCRIBE) (?P<topic>\S+): Options: (?P<options>.+)$"),
    re.compile(r"^" + _PEER + r"\[Channel\] (?P<action>Cannot subscribe) (?P<topic>\S+) with options (?P<options>.+?) "
               r"due to (?P<reason>.+?)\.$"),
)
_NEW = (
    re.compile(r"^tag: (?P<tag>\w+), clientid: (?P<client_id>[^,]+), msg: (?P<action>\w+), "
               r"peername: (?P<client_ip>[0-9.]+):(?P<client_port>\d+), (?:username: (?P<user>[^,]+), )?"
               r"topic: (?P<topic>[^,]+), source: (?P<authz_source>[^,]+), action: (?P<operation>.+)$"),
    re.compile(r"^clientid: (?P<client_id>[^,]+), msg: (?P<action>terminate), peername: (?P<client_ip>[0-9.]+):(?P<client_port>\d+), "
               r"(?:username: (?P<user>[^,]+), )?reason: (?P<reason>.+)$"),
)


def _extract(line: str) -> dict[str, str]:
    m = _HEAD.match(line.strip())
    if not m:
        return {}
    for rx in _OLD + _NEW:
        mm = rx.match(m.group("msg"))
        if mm:
            out = {k: v for k, v in m.groupdict().items() if k != "msg"}
            out.update({k: v for k, v in mm.groupdict().items() if v is not None})
            return out
    return {}


def _doc(version: str, new: bool) -> str:
    if new:
        body = """    <timestamp> [<level>] tag: <tag>, clientid: <client_id>, msg: <action>, peername: <client_ip>:<client_port>, [username: <user>, ]topic: <topic>, source: <authz_source>, action: <operation>
    <timestamp> [<level>] clientid: <client_id>, msg: terminate, peername: <client_ip>:<client_port>, [username: <user>, ]reason: <reason>

EMQX 5 writes structured log events as `key: value` pairs separated by `, `. The authorization check of every publish
and subscribe is logged (`tag: AUTHZ`): `msg` is `authorization_permission_allowed` or
`authorization_permission_denied`, `source` the authorizer that decided (`file`, the default ACL), `action` the MQTT
operation with its QoS and retain flags (`PUBLISH(Q0,R0)`, `SUBSCRIBE(Q0)`). `username` is present only when the
client sent one."""
    else:
        body = """    <timestamp> [<level>] <client_id>@<client_ip>:<client_port> PUBLISH to <topic>: <<<payload>>>
    <timestamp> [<level>] <client_id>@<client_ip>:<client_port> <client_id> SUBSCRIBE <topic>: Options: <options>
    <timestamp> [<level>] <client_id>@<client_ip>:<client_port> [Channel] Cannot subscribe <topic> with options <options> due to <reason>.
    <timestamp> [<level>] <client_id>@<client_ip>:<client_port> file: <file>, line: <line>, mfa: <mfa>, msg: terminate, pid: <erlang_pid>, reason: <reason>

EMQX 4 prefixes each client's lines with `clientid@address:port`. A publish logs the payload as an Erlang binary
(`<<"...">>`); a refused subscription logs the reason (`Not authorized`); the username is not logged."""
    return f"""
# EMQX {version} - console log, level info

Source: EMQX documentation ("Logs" configuration), official Docker image, default listener on 1883, default file ACL.

## The messages kept

{body}

- `level` - info, warning...; `client_id` - the MQTT client id; `client_ip`, `client_port` - the client
- `topic` - the MQTT topic (or filter) published or subscribed to
- `reason` - why a subscription was refused, or how the connection ended (`{{shutdown,normal}}`)
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("client_port", "source.port", "long", "client_port", "easy", "client.port is equivalent."),
    _f("user", "user.name", "keyword", "account", "easy"),
    _f("action", "event.action", "keyword", "event_type", "medium"),
    _f("reason", "event.reason", "keyword", "refusal_reason", "medium"),
    _f("level", "log.level", "keyword", "severity", "easy"),
    _f("file", "log.origin.file.name", "keyword", "source_file", "medium"),
    _f("line", "log.origin.file.line", "long", "source_line", "medium"),
    _f("mfa", "log.origin.function", "keyword", "source_function", "hard", "Erlang module, function and arity; leaving it unmapped is acceptable.", abstain=True),
    _f("client_id", None, "keyword", "client_identifier", "hard",
       "An MQTT client id names a session, not a host or an account. Declining accepted.", abstain=True),
    _f("topic", None, "keyword", "mqtt_topic", "hard", "No ECS field for an MQTT topic.", abstain=True),
    _f("operation", None, "keyword", "mqtt_operation", "hard", "The MQTT operation with QoS and retain flags; event.action holds the outcome.", abstain=True),
    _f("tag", None, "keyword", "log_tag", "hard", "No ECS field.", abstain=True),
    _f("authz_source", None, "keyword", "authorizer", "hard", "No ECS field for the authorizer.", abstain=True),
    _f("payload", None, "keyword", "payload", "hard", "Message payload; not mapped.", abstain=True),
    _f("options", None, "keyword", "subscribe_options", "hard", "No ECS field.", abstain=True),
    _f("erlang_pid", None, "keyword", "erlang_pid", "hard", "An Erlang process id, not an OS pid.", abstain=True),
    _f("timestamp", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r7_emqx_44", family="emqx",
    software="EMQX 4.4.19 (official image)", category="network",
    contamination="high", split="train_r7",
    notes="ROUND 10 (pool r7), OLD VERSION: EMQX 4.4.19, console log at info, default listener and ACL.",
    documentation=_doc("4.4.19", False), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r7_emqx_58", family="emqx",
    software="EMQX 5.8.6 (official image)", category="network",
    contamination="high", split="test_r7",
    notes="ROUND 10 (pool r7), NEW VERSION of r7_emqx_44: structured key: value log lines, authorization events, usernames.",
    documentation=_doc("5.8.6", True), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

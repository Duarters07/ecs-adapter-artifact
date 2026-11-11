"""r7_389ds: 389 Directory Server access log, 2.5.0 (text) -> 3.1.2 (JSON access log, nsslapd-accesslog-log-format)."""
from __future__ import annotations

import json
import re

from testbed.heldout_r2.specs import Spec, _f

_TS = r"^\[(?P<timestamp>\d\d/[A-Z][a-z]{2}/\d{4}:\d\d:\d\d:\d\d\.\d+ [+-]\d{4})\] conn=(?P<conn>\d+) "
_TEXT = (
    re.compile(_TS + r"fd=(?P<fd>\d+) slot=(?P<slot>\d+) (?P<action>connection) from (?P<client_ip>[0-9.]+) to (?P<server_ip>[0-9.]+)$"),
    re.compile(_TS + r'op=(?P<op>\d+) (?P<action>BIND) dn="(?P<bind_dn>[^"]*)" method=(?P<method>\S+) version=(?P<version>\d+)$'),
    re.compile(_TS + r"op=(?P<op>\d+) (?P<action>RESULT) err=(?P<err>\d+) tag=(?P<tag>\d+) nentries=(?P<nentries>\d+) "
               r'wtime=(?P<wtime>[\d.]+) optime=(?P<optime>[\d.]+) etime=(?P<etime>[\d.]+)'
               r'(?: dn="(?P<bind_dn>[^"]*)"| - (?P<reason>.+))?$'),
    re.compile(_TS + r"op=(?P<op>-?\d+) fd=(?P<fd>\d+) (?P<action>Disconnect) - (?P<close_reason>.+)$"),
)
_JSON_KEYS = {  # JSON key -> the name the text format's captures use
    "local_time": "timestamp", "operation": "action", "conn_id": "conn", "op_id": "op", "fd": "fd", "slot": "slot",
    "tls": "tls", "client_ip": "client_ip", "server_ip": "server_ip", "bind_dn": "bind_dn", "version": "version",
    "method": "method", "msg": "reason", "tag": "tag", "err": "err", "nentries": "nentries", "wtime": "wtime",
    "optime": "optime", "etime": "etime", "close_reason": "close_reason", "key": "key",
}
_JSON_KEPT = {"CONNECTION", "BIND", "RESULT", "DISCONNECT"}


def _extract(line: str) -> dict[str, str]:
    s = line.strip()
    if s.startswith("{"):
        try:
            o = json.loads(s)
        except ValueError:
            return {}
        if not isinstance(o, dict) or o.get("operation") not in _JSON_KEPT:
            return {}
        out = {}
        for k, v in o.items():
            if k in _JSON_KEYS and v != "":
                out[_JSON_KEYS[k]] = str(v).lower() if isinstance(v, bool) else str(v)
        return out
    for rx in _TEXT:
        m = rx.match(s)
        if m:
            return {k: v for k, v in m.groupdict().items() if v is not None}
    return {}


def _doc(version: str, new: bool) -> str:
    if new:
        body = """One JSON object per line (`nsslapd-accesslog-log-format: json`, new in 3.1.2), its `operation` naming the event:

    {"local_time": "<timestamp>", "operation": "CONNECTION", "key": "<key>", "conn_id": <conn>, "fd": <fd>, "slot": <slot>, "tls": <tls>, "client_ip": "<client_ip>", "server_ip": "<server_ip>"}
    {"local_time": ..., "operation": "BIND", "key": ..., "conn_id": ..., "op_id": <op>, "bind_dn": "<bind_dn>", "version": <version>, "method": "<method>"}
    {"local_time": ..., "operation": "RESULT", "key": ..., "conn_id": ..., "op_id": ..., "msg": "<reason>", "tag": <tag>, "err": <err>, "nentries": <nentries>, "wtime": "<wtime>", "optime": "<optime>", "etime": "<etime>", "client_ip": "<client_ip>"[, "bind_dn": "<bind_dn>"]}
    {"local_time": ..., "operation": "DISCONNECT", "key": ..., "conn_id": ..., "op_id": ..., "fd": ..., "close_reason": "<close_reason>"}

- `key` - a key unique to the connection (`<epoch>-<conn>`); `tls` - whether the connection uses TLS
- `msg` - the result's text: the refusal reason (` - Invalid credentials`, ` - No such entry`), or a status"""
    else:
        body = """One line per operation:

    [<timestamp>] conn=<conn> fd=<fd> slot=<slot> connection from <client_ip> to <server_ip>
    [<timestamp>] conn=<conn> op=<op> BIND dn="<bind_dn>" method=<method> version=<version>
    [<timestamp>] conn=<conn> op=<op> RESULT err=<err> tag=<tag> nentries=<nentries> wtime=<wtime> optime=<optime> etime=<etime>[ dn="<bind_dn>"| - <reason>]
    [<timestamp>] conn=<conn> op=<op> fd=<fd> Disconnect - <close_reason>

- a successful bind's RESULT repeats the bound DN; a refused one ends with the reason (`Invalid credentials`,
  `No such entry`)"""
    return f"""
# 389 Directory Server {version} - access log

Source: Red Hat Directory Server / 389 Directory Server documentation ("Access log reference"), official container
image. The access log records every client connection and operation; lines of one connection share `conn`.

{body}

- `conn`, `op` - connection and operation numbers; `fd`, `slot` - the file descriptor and connection slot
- `client_ip` - the client; `server_ip` - the server address it connected to
- `bind_dn` - the DN a client binds as; `method` - 128 is a simple (password) bind; `version` - the LDAP version
- `err` - the LDAP result code (0 success, 49 invalid credentials); `tag` - the response type (97 bind, 120 extended)
- `nentries` - entries returned; `wtime`, `optime`, `etime` - wait, operation and elapsed times in seconds
- `close_reason` - why the connection closed (`Cleanly Closed Connection - U1`)
- the lines kept are connections, binds, results and disconnections; unbinds and extended operations are left out
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("server_ip", "destination.ip", "ip", "server_ip", "medium", "server.ip is equivalent."),
    _f("bind_dn", "user.name", "keyword", "account", "medium",
       "A distinguished name; ECS has no DN field, and user.name is where the authenticated identity goes."),
    _f("err", "event.code", "keyword", "result_code", "hard",
       "The LDAP result code (49: invalid credentials); error.code is not offered for authentication."),
    _f("reason", "event.reason", "keyword", "refusal_reason", "medium"),
    _f("action", "event.action", "keyword", "event_type", "medium"),
    _f("tls", "tls.established", "boolean", "tls_flag", "hard", "Leaving it unmapped is acceptable.", abstain=True),
    _f("close_reason", None, "keyword", "close_reason", "hard", "event.reason holds the bind result; declining accepted.", abstain=True),
    _f("conn", None, "keyword", "connection_id", "hard", "No ECS field for a connection number.", abstain=True),
    _f("op", None, "keyword", "operation_id", "hard", "No ECS field.", abstain=True),
    _f("key", None, "keyword", "connection_key", "hard", "No ECS field.", abstain=True),
    _f("fd", None, "long", "file_descriptor", "hard", "No ECS field.", abstain=True),
    _f("slot", None, "long", "connection_slot", "hard", "No ECS field.", abstain=True),
    _f("method", None, "keyword", "bind_method", "hard", "No ECS field.", abstain=True),
    _f("version", None, "keyword", "protocol_version", "hard", "No ECS field for the LDAP version.", abstain=True),
    _f("tag", None, "keyword", "response_type", "hard", "No ECS field.", abstain=True),
    _f("nentries", None, "long", "result_count", "hard", "No ECS field.", abstain=True),
    _f("wtime", None, "float", "wait_time", "hard", "No ECS field.", abstain=True),
    _f("optime", None, "float", "operation_time", "hard", "No ECS field.", abstain=True),
    _f("etime", None, "float", "elapsed_time", "hard", "event.duration is in nanoseconds; declining accepted.", abstain=True),
    _f("timestamp", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r7_389ds_25", family="389ds",
    software="389 Directory Server 2.5.0 (official image 389ds/dirsrv:2.4)", category="authentication",
    contamination="high", split="train_r7",
    notes="ROUND 10 (pool r7), OLD VERSION: 389-DS 2.5.0 access log (text). The candidate pin was 2.3.1; the official "
          ":2.3 image cannot start, so the oldest working 2.x image is used (ROUND3_VERSION_DRIFT.md, r7 captures).",
    documentation=_doc("2.5.0", False), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r7_389ds_31", family="389ds",
    software="389 Directory Server 3.1.2 (official image 389ds/dirsrv:3.1)", category="authentication",
    contamination="high", split="test_r7",
    notes="ROUND 10 (pool r7), NEW VERSION of r7_389ds_25: the JSON access log (option added in 3.1.2) enabled.",
    documentation=_doc("3.1.2", True), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

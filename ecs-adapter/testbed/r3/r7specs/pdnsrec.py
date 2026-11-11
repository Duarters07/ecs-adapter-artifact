"""r7_pdnsrec: PowerDNS Recursor console log (quiet=no, key="value"), Debian 12 4.8.8 -> Debian 13 5.2.13."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_HEAD = re.compile(r"^(?P<timestamp>[A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d) (?P<rest>msg=.*)$")
_KV = re.compile(r'([\w-]+)="((?:[^"\\]|\\.)*)"')
_KEEP = {"Question", "Answer", "Question answered from packet cache", "Dropping UDP query, address not matched by allow-from"}


def _extract(line: str) -> dict[str, str]:
    m = _HEAD.match(line.strip())
    if not m:
        return {}
    kv = dict(_KV.findall(m.group("rest")))
    if kv.get("msg") not in _KEEP:
        return {}
    out = {"timestamp": m.group("timestamp"), "action": kv["msg"]}
    for k in ("subsystem", "prio", "tid", "proto", "qname", "qtype", "rcode", "answers"):
        if k in kv:
            out[k] = kv[k]
    peer = kv.get("remote") or kv.get("source")
    if peer:
        out["client_ip"], out["client_port"] = peer.rsplit(":", 1)
    return out


def _doc(version: str, new: bool) -> str:
    extra = ('answer-is-variable="<0|1>" ' if new else "")
    tail = ('into-packetcache="<0|1>" maxdepth="<n>" ' if new else "")
    recv = ('received="<n>" ' if new else "")
    return f"""
# PowerDNS Recursor {version} - console log, quiet=no (every question and answer)

Source: PowerDNS Recursor documentation, "Logging" (structured logging, key="value" pairs) and the settings
"quiet" and "allow-from", Debian package. One line per event: a syslog-style time, then key="value" pairs:

    <Mon dd hh:mm:ss> msg="<message>" subsystem="<subsystem>" level="<n>" prio="<prio>" tid="<tid>" ts="<epoch>" ...

## The messages kept

    msg="Question" ... proto="<proto>" qname="<qname>" qtype="<qtype>" remote="<client_ip>:<client_port>"
    msg="Answer" ... additional="<n>" {extra}answers="<answers>" dotout="<n>" ecs="" {tail}mtid="<n>" netms="<ms>"
        outqueries="<n>" proto="<proto>" qname="<qname>" qtype="<qtype>" rcode="<rcode>" rd="<0|1>" {recv}remote="<client_ip>:<client_port>"
        tcpout="<n>" throttled="<n>" timeouts="<n>" totms="<ms>" validationState="<state>"
    msg="Question answered from packet cache" ... qname="<qname>" qtype="<qtype>" remote="<client_ip>:<client_port>" source="..." tag="<n>"
    msg="Dropping UDP query, address not matched by allow-from" ... proto="<proto>" source="<client_ip>:<client_port>"

- `client_ip`, `client_port` - the client (`remote`, or `source` for a dropped query)
- `qname`, `qtype` - the question; `rcode` - the numeric DNS response code (0 NOERROR, 3 NXDOMAIN)
- `answers` - number of answer records; `proto` - udp or tcp
- `subsystem` - the logging subsystem (syncres, in); `prio` - Info, Notice, Error; `tid` - the worker thread
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("client_port", "source.port", "long", "client_port", "easy", "client.port is equivalent."),
    _f("qname", "dns.question.name", "keyword", "query_name", "easy"),
    _f("qtype", "dns.question.type", "keyword", "query_type", "easy"),
    _f("rcode", "dns.response_code", "keyword", "response_code", "medium", "Numeric here; ECS expects the name."),
    _f("proto", "network.transport", "keyword", "transport", "easy"),
    _f("prio", "log.level", "keyword", "severity", "easy"),
    _f("subsystem", "log.logger", "keyword", "subsystem", "medium"),
    _f("tid", "process.thread.id", "long", "thread_id", "medium"),
    _f("action", "event.action", "keyword", "event_type", "medium"),
    _f("answers", None, "long", "answer_count", "hard", "No ECS field for a count of answers.", abstain=True),
    _f("timestamp", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r7_pdnsrec_48", family="pdns-recursor",
    software="PowerDNS Recursor 4.8.8 (Debian 12)", category="network",
    contamination="high", split="train_r7",
    notes="ROUND 10 (pool r7), OLD VERSION: PowerDNS Recursor 4.8.8, quiet=no, allow-from restricted.",
    documentation=_doc("4.8.8", False), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r7_pdnsrec_52", family="pdns-recursor",
    software="PowerDNS Recursor 5.2.13 (Debian 13)", category="network",
    contamination="high", split="test_r7",
    notes="ROUND 10 (pool r7), NEW VERSION of r7_pdnsrec_48: the Answer line gains keys (answer-is-variable, into-packetcache, maxdepth, received).",
    documentation=_doc("5.2.13", True), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

"""r7_unbound: Unbound log on stderr (verbosity 1, log-queries, log-replies), Debian 12 1.17.1 -> Debian 13 1.26.2."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_LINE = re.compile(r"^\[(?P<timestamp>\d+)\] unbound\[(?P<pid>\d+):(?P<thread>\d+)\] (?P<level>[a-z]+): "
                   r"(?P<client_ip>[0-9.]+) (?P<qname>\S+) (?P<qtype>\S+) (?P<qclass>\S+)"
                   r"(?: (?P<rcode>[A-Z]+) (?P<response_time>[\d.]+) (?P<cached>\d) (?P<size>\d+))?$")


def _extract(line: str) -> dict[str, str]:
    m = _LINE.match(line.strip())
    return {k: v for k, v in m.groupdict().items() if v is not None} if m else {}


def _doc(version: str) -> str:
    return f"""
# Unbound {version} - log on stderr, verbosity 1, log-queries and log-replies

Source: unbound.conf(5) ("log-queries", "log-replies", "verbosity", "access-control"), Debian package. One line per
query and one per reply:

    [<timestamp>] unbound[<pid>:<thread>] <level>: <client_ip> <qname> <qtype> <qclass>
    [<timestamp>] unbound[<pid>:<thread>] <level>: <client_ip> <qname> <qtype> <qclass> <rcode> <response_time> <cached> <size>

`timestamp` is seconds since the epoch. A query refused by access-control is logged as a reply only, with the
question unread: `<client_ip> null TYPE0 CLASS0 REFUSED ...`.

- `client_ip` - the client; `qname`, `qtype`, `qclass` - the question
- `rcode` - the reply's response code (NOERROR, NXDOMAIN, REFUSED...)
- `response_time` - seconds taken; `cached` - 1 if answered from the cache; `size` - reply size in bytes
- `pid`, `thread` - the server process and its thread; `level` - info for these lines
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("qname", "dns.question.name", "keyword", "query_name", "easy"),
    _f("qtype", "dns.question.type", "keyword", "query_type", "easy"),
    _f("qclass", "dns.question.class", "keyword", "query_class", "medium"),
    _f("rcode", "dns.response_code", "keyword", "response_code", "medium"),
    _f("pid", "process.pid", "long", "process_id", "easy"),
    _f("thread", "process.thread.id", "long", "thread_id", "medium"),
    _f("level", "log.level", "keyword", "severity", "easy"),
    _f("response_time", None, "float", "duration_seconds", "hard", "event.duration is nanoseconds; declined.", abstain=True),
    _f("cached", None, "long", "cache_flag", "hard", "No ECS field.", abstain=True),
    _f("size", None, "long", "reply_bytes", "hard", "No ECS field for a DNS reply's size.", abstain=True),
    _f("timestamp", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r7_unbound_117", family="unbound",
    software="Unbound 1.17.1 (Debian 12)", category="network",
    contamination="high", split="train_r7",
    notes="ROUND 10 (pool r7), OLD VERSION: Unbound 1.17.1, verbosity 1, log-queries and log-replies on stderr.",
    documentation=_doc("1.17.1"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r7_unbound_126", family="unbound",
    software="Unbound 1.26.2 (Debian 13)", category="network",
    contamination="high", split="test_r7",
    notes="ROUND 10 (pool r7), NEW VERSION of r7_unbound_117. CONTROL: the query and reply lines did not change.",
    documentation=_doc("1.26.2"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

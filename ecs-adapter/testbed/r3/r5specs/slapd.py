"""r5_slapd: OpenLDAP slapd stats log, Debian 11 (2.4.57) -> Debian 12 (2.5.13)."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_HEAD = re.compile(r"^(?P<timestamp>[0-9a-f]+(?:\.[0-9a-f]+)?) (?:(?P<thread>0x[0-9a-f]+) )?"
                   r"conn=(?P<conn>\d+) (?P<rest>.*)$")
_TIMES = r"(?: qtime=(?P<qtime>[\d.]+) etime=(?P<etime>[\d.]+))?"
_MSGS = (
    re.compile(r"^fd=(?P<fd>\d+) ACCEPT from IP=(?P<client_ip>[0-9.]+):(?P<client_port>\d+) "
               r"\(IP=(?P<listener_ip>[0-9.]+):(?P<listener_port>\d+)\)$"),
    re.compile(r'^op=(?P<op>\d+) BIND dn="(?P<bind_dn>[^"]*)" method=(?P<method>\d+)$'),
    re.compile(r'^op=(?P<op>\d+) BIND dn="(?P<bind_dn>[^"]*)" mech=(?P<mech>\S+)(?: bind_ssf=(?P<bind_ssf>\d+))? ssf=(?P<ssf>\d+)$'),
    re.compile(r"^op=(?P<op>\d+) RESULT tag=(?P<tag>\d+) err=(?P<err>\d+)" + _TIMES + r" text=(?P<text>.*)$"),
    re.compile(r"^op=(?P<op>\d+) RESULT oid=(?P<oid>\S*) err=(?P<err>\d+)" + _TIMES + r" text=(?P<text>.*)$"),
    re.compile(r'^op=(?P<op>\d+) SRCH base="(?P<base>[^"]*)" scope=(?P<scope>\d+) deref=(?P<deref>\d+) filter="(?P<filter>[^"]*)"$'),
    re.compile(r"^op=(?P<op>\d+) SEARCH RESULT tag=(?P<tag>\d+) err=(?P<err>\d+)" + _TIMES +
               r" nentries=(?P<nentries>\d+) text=(?P<text>.*)$"),
)


def _extract(line: str) -> dict[str, str]:
    m = _HEAD.match(line.strip())
    if not m:
        return {}
    for rx in _MSGS:
        mm = rx.match(m.group("rest"))
        if mm:
            out = {k: v for k, v in m.groupdict().items() if v is not None and k != "rest"}
            out.update({k: v for k, v in mm.groupdict().items() if v is not None and v != ""})
            return out
    return {}


def _doc(version: str, prefix: str, prefix_doc: str, times: str, times_doc: str, ssf: str) -> str:
    return f"""
# OpenLDAP {version} - slapd, `stats` log level

Source: slapd.conf(5) / slapd-config(5), "olcLogLevel" (`stats`: connections, operations and
results), OpenLDAP {version} Administrator's Guide, https://www.openldap.org/doc/admin{version.replace('.', '')}/

Run with `-d 256`, slapd writes one line per event to standard error:

    {prefix}conn=<conn> <event>

{prefix_doc}

## The events kept

    fd=<fd> ACCEPT from IP=<client_ip>:<client_port> (IP=<listener_ip>:<listener_port>)
    op=<op> BIND dn="<bind_dn>" method=<method>
    op=<op> BIND dn="<bind_dn>" mech=<mech> {ssf}
    op=<op> RESULT tag=<tag> err=<err> {times}text=<text>
    op=<op> RESULT oid=<oid> err=<err> {times}text=<text>
    op=<op> SRCH base="<base>" scope=<scope> deref=<deref> filter="<filter>"
    op=<op> SEARCH RESULT tag=<tag> err=<err> {times}nentries=<nentries> text=<text>

- `conn`, `op`, `fd` - the connection number, the operation number within it, and the socket
- `client_ip`, `client_port` - the address and port of the client that connected
- `listener_ip`, `listener_port` - the address and port slapd accepted the connection on
- `bind_dn` - the distinguished name the client authenticated as (empty for an anonymous bind)
- `method`, `mech` - the bind method (128: simple) and the SASL mechanism name (`SIMPLE`)
- `tag` - the LDAP response type (97: bind response, 101: search result done)
- `err` - the LDAP result code: 0 success, 49 invalid credentials, 32 no such object, ...
- `text` - the diagnostic text of the result, often empty
- `oid` - the OID of an extended operation's response, often empty
- `base`, `scope`, `deref`, `filter` - the search request
- `nentries` - how many entries the search returned
{times_doc}"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("client_port", "source.port", "long", "client_port", "easy"),
    _f("listener_port", "destination.port", "long", "server_port", "medium", "server.port is equivalent."),
    _f("bind_dn", "user.name", "keyword", "account", "medium",
       "A distinguished name; ECS has no DN field, and user.name is where the authenticated identity goes."),
    _f("err", "event.code", "keyword", "result_code", "hard",
       "The LDAP result code (49: invalid credentials); error.code is not offered for authentication."),
    _f("listener_ip", None, "ip", "listen_address", "hard", "The wildcard 0.0.0.0, not the server's address.", abstain=True),
    _f("conn", None, "keyword", "connection_id", "hard", "No ECS field for a connection number.", abstain=True),
    _f("op", None, "keyword", "operation_id", "hard", "No ECS field.", abstain=True),
    _f("method", None, "keyword", "bind_method", "hard", "No ECS field.", abstain=True),
    _f("mech", None, "keyword", "auth_mechanism", "hard", "No ECS field.", abstain=True),
    _f("tag", None, "keyword", "response_type", "hard", "No ECS field.", abstain=True),
    _f("base", None, "keyword", "search_base", "hard", "No ECS field for an LDAP search.", abstain=True),
    _f("filter", None, "keyword", "search_filter", "hard", "No ECS field for an LDAP search.", abstain=True),
    _f("nentries", None, "long", "result_count", "hard", "No ECS field.", abstain=True),
]

OLD = Spec(
    source_id="r5_slapd_24", family="openldap",
    software="OpenLDAP slapd 2.4.57 (Debian 11)", category="authentication",
    contamination="high", split="train_r5",
    notes="ROUND 6 (pool r5), OLD VERSION: slapd 2.4 stats log on stderr.",
    documentation=_doc("2.4", "<timestamp> ", "- `timestamp` - the time, seconds since the Unix epoch in hexadecimal",
                       "", "", "ssf=<ssf>"),
    keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r5_slapd_25", family="openldap",
    software="OpenLDAP slapd 2.5.13 (Debian 12)", category="authentication",
    contamination="high", split="test_r5",
    notes=("ROUND 6 (pool r5), NEW VERSION of r5_slapd_24. Measured: the prefix gains nanoseconds and the "
           "thread id, results gain qtime and etime, and the second BIND line gains bind_ssf."),
    documentation=_doc("2.5", "<timestamp> <thread> ",
                       "- `timestamp` - the time, `<seconds>.<nanoseconds>` since the Unix epoch, both in hexadecimal\n"
                       "- `thread` - the id of the thread that logged the line",
                       "qtime=<qtime> etime=<etime> ",
                       "- `qtime`, `etime` - seconds the operation waited in the queue, and seconds it took\n",
                       "bind_ssf=<bind_ssf> ssf=<ssf>"),
    keep=lambda ln: bool(_extract(ln)), extract=_extract,
    fields=_FIELDS + [
        _f("thread", None, "keyword", "thread_id", "hard", "No ECS 8.11 field for a thread id in these roots.", abstain=True),
        _f("qtime", None, "float", "queue_time", "hard", "No ECS field.", abstain=True),
        _f("etime", None, "float", "elapsed_time", "hard", "event.duration is in nanoseconds; declining accepted.", abstain=True),
    ],
)

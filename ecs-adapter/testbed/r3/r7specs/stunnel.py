"""r7_stunnel: stunnel log on stderr (debug 5), Debian 12 5.68 (OpenSSL 3.0) -> Debian 13 5.74 (OpenSSL 3.5)."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_HEAD = re.compile(r"^(?P<timestamp>\d{4}\.\d\d\.\d\d \d\d:\d\d:\d\d) LOG(?P<level>\d)\[(?P<thread>\d+)\]: (?P<msg>.*)$")
_MSGS = (
    re.compile(r"^Service \[(?P<service>[^\]]+)\] (?P<action>accepted connection) from (?P<client_ip>[0-9.]+):(?P<client_port>\d+)$"),
    re.compile(r"^(?P<action>Certificate accepted) at depth=(?P<depth>\d+): (?P<subject>.+)$"),
    re.compile(r"^CERT: (?P<action>Pre-verification error): (?P<verify_error>.+)$"),
    re.compile(r"^(?P<action>Rejected by CERT) at depth=(?P<depth>\d+): (?P<subject>.+)$"),
    re.compile(r"^(?P<action>SSL_accept): (?P<ssl_location>\S+): (?P<ssl_error>error:.+)$"),
    re.compile(r"^(?P<action>Connection (?:closed|reset/closed)): (?P<bytes_tls>\d+) byte\(s\) sent to TLS, "
               r"(?P<bytes_socket>\d+) byte\(s\) sent to socket$"),
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


def _doc(version: str, openssl: str) -> str:
    return f"""
# stunnel {version} ({openssl}) - log, debug level 5 (notice), foreground on stderr

Source: stunnel(8) manual ("debug", "foreground", "verifyChain", "requireCert") (https://www.stunnel.org/static/stunnel.html),
Debian package. A TLS front end that requires a client certificate from the lab CA. One line per event:

    <yyyy.mm.dd hh:mm:ss> LOG<level>[<thread>]: <message>

## The messages kept

    Service [<service>] accepted connection from <client_ip>:<client_port>
    Certificate accepted at depth=<depth>: <subject>
    CERT: Pre-verification error: <verify_error>
    Rejected by CERT at depth=<depth>: <subject>
    SSL_accept: <ssl_location>: <ssl_error>
    Connection closed: <bytes_tls> byte(s) sent to TLS, <bytes_socket> byte(s) sent to socket
    Connection reset/closed: <bytes_tls> byte(s) sent to TLS, <bytes_socket> byte(s) sent to socket

- `level` - syslog severity number (5 notice, 4 warning, 3 error); `thread` - the connection's thread id, which ties
  the lines of one client connection together (only the first names the client)
- `service` - the stunnel service section; `client_ip`, `client_port` - the TLS client
- `subject` - the client certificate's subject; `depth` - its position in the chain
- `verify_error` - why OpenSSL's pre-verification refused the certificate; `ssl_error` - the OpenSSL error of the
  refused handshake, `ssl_location` - where in OpenSSL it was raised
- `bytes_tls`, `bytes_socket` - bytes sent each way when the connection ends
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("client_port", "source.port", "long", "client_port", "easy", "client.port is equivalent."),
    _f("subject", "tls.client.subject", "keyword", "certificate_subject", "medium", "tls.client.x509.subject.distinguished_name is equivalent."),
    _f("verify_error", "event.reason", "keyword", "refusal_reason", "medium"),
    _f("ssl_error", "error.message", "keyword", "error", "medium"),
    _f("service", "service.name", "keyword", "service", "medium"),
    _f("thread", "process.thread.id", "long", "thread_id", "medium"),
    _f("level", "log.syslog.severity.code", "long", "severity", "medium", "log.level is equivalent."),
    _f("action", "event.action", "keyword", "event_type", "medium"),
    _f("depth", None, "long", "chain_depth", "hard", "No ECS field.", abstain=True),
    _f("ssl_location", None, "keyword", "source_location", "hard", "OpenSSL's source location; no ECS field.", abstain=True),
    _f("bytes_tls", None, "long", "bytes_out", "hard", "Direction is relative to stunnel; source/destination.bytes would be a guess.", abstain=True),
    _f("bytes_socket", None, "long", "bytes_in", "hard", "As bytes_tls.", abstain=True),
    _f("timestamp", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r7_stunnel_568", family="stunnel",
    software="stunnel 5.68 (Debian 12, OpenSSL 3.0)", category="network",
    contamination="high", split="train_r7",
    notes="ROUND 10 (pool r7), OLD VERSION: stunnel 5.68, client certificate required, debug 5 on stderr.",
    documentation=_doc("5.68", "OpenSSL 3.0"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r7_stunnel_574", family="stunnel",
    software="stunnel 5.74 (Debian 13, OpenSSL 3.5)", category="network",
    contamination="high", split="test_r7",
    notes="ROUND 10 (pool r7), NEW VERSION of r7_stunnel_568. Part of the change is OpenSSL's error text (3.0 -> 3.5).",
    documentation=_doc("5.74", "OpenSSL 3.5"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

"""Round-3 sources: one OLD and one NEW version per pair (ROUND3_VERSION_DRIFT.md).

The new version is evaluated (split "test_r3"); the old version is training
material only (split "train_r3") and is also the "parser the organisation
already had" for test T3. Ground truth follows testbed/heldout_r2/specs.py and
is a DRAFT until the author reviews it.
"""
from __future__ import annotations

from dataclasses import replace
import json
import re

from testbed.heldout_r2.specs import APACHE, Spec, _f, _HTTPD_MSG

# ------------------------------------------------------------- Apache httpd

# 2.2's default error-log line: no module, no pid/tid, no client port, no AH code.
#   [Mon Oct 19 09:17:57 2026] [error] [client 172.21.0.3] user ana not found: /members/q3.html
_HTTPD22 = re.compile(
    r"^\[(?P<timestamp>[^\]]+)\] \[(?P<level>\w+)\] "
    r"\[client (?P<client_ip>[0-9a-fA-F.:]+)\] "
    r"(?P<rest>.*?)(?:, referer: (?P<referer>\S+))?$")


def _httpd22(line: str) -> dict[str, str]:
    m = _HTTPD22.match(line)
    if not m:
        return {}
    out = {k: v for k, v in m.groupdict().items() if v is not None and k != "rest"}
    for rx in _HTTPD_MSG:
        mm = rx.match(m.group("rest"))
        if mm:
            out.update(mm.groupdict())
            break
    return out


R3_APACHE_OLD = Spec(
    source_id="r3_apache_v22",
    family="apache-httpd",
    software="Apache httpd 2.2.34 (image httpd:2.2)",
    category="web",
    contamination="high",
    split="train_r3",
    notes=("ROUND 3, OLD VERSION - training material only. Apache 2.2's error log: the "
           "same three events as the 2.4 capture, in 2.2's format, which has no module, "
           "no worker pid/tid, no client port and no AH message code."),
    documentation="""
# Apache httpd 2.2 — error log

Source: Apache HTTP Server 2.2 documentation, "Log Files",
https://httpd.apache.org/docs/2.2/logs.html#errorlog

A line of the error log reads

    [<timestamp>] [<level>] [client <client_ip>] <message>[, referer: <referer>]

- `timestamp` — `Www Mmm dd HH:MM:SS yyyy`
- `level` — the severity of the message: `error`, `warn`, `info`, ...
- `client_ip` — the address of the client that sent the request
- `referer` — the Referer header of the request, when the client sent one

## The three messages captured, and the names of their parts

    user <user>: authentication failure for "<url_path>": <reason>
    user <user> <reason>: <url_path>          (reason is "not found")
    <reason>: <file_path>                      (reason is "client denied by server configuration")

- `user` — the account in the request's credentials
- `url_path` — the path of the requested URL
- `file_path` — the file system path the request was resolved to
- `reason` — why the request was refused
""",
    keep=lambda ln: bool(_httpd22(ln)),
    extract=_httpd22,
    fields=[
        _f("level", "log.level", "keyword", "severity", "easy"),
        _f("client_ip", "source.ip", "ip", "client_ip", "easy",
           "client.ip is equivalent for scoring."),
        _f("user", "user.name", "keyword", "account", "easy"),
        _f("url_path", "url.path", "keyword", "request_path", "medium"),
        _f("file_path", None, "keyword", "filesystem_path", "hard",
           "As in apache_error: file.path is unreachable from `web`.", abstain=True),
        _f("reason", "event.reason", "keyword", "refusal_reason", "medium"),
        _f("referer", "http.request.referrer", "keyword", "referrer", "medium"),
    ],
)

R3_APACHE_NEW = replace(
    APACHE,
    source_id="r3_apache_v24",
    software="Apache httpd 2.4.62 (image httpd:2.4.62)",
    split="test_r3",
    notes=("ROUND 3, NEW VERSION of r3_apache_v22 - evaluated. " + APACHE.notes),
)

# ------------------------------------------------------------------ OpenSSH
#
# sshd -D -e: messages on stderr with no syslog header, as round 2's sshd_auth.
# The capture names are a scoring convention, stated in documentation.md.
_SSH_MSGS = (
    re.compile(r"^(?P<outcome>Failed|Accepted) (?P<method>password|publickey) for "
               r"(?:invalid user )?(?P<user>\S+) from (?P<src_ip>[0-9a-fA-F.:]+) "
               r"port (?P<src_port>\d+) ssh2$"),
    re.compile(r"^Invalid user (?P<user>\S*) from (?P<src_ip>[0-9a-fA-F.:]+) port (?P<src_port>\d+)$"),
    re.compile(r"^Connection closed by (?:authenticating|invalid) user (?P<user>\S+) "
               r"(?P<src_ip>[0-9a-fA-F.:]+) port (?P<src_port>\d+) \[preauth\]$"),
    re.compile(r"^Did not receive identification string from (?P<src_ip>[0-9a-fA-F.:]+) "
               r"port (?P<src_port>\d+)$"),
    re.compile(r"^Connection closed by (?P<src_ip>[0-9a-fA-F.:]+) port (?P<src_port>\d+)$"),
    re.compile(r"^kex_exchange_identification: (?P<reason>.+)$"),
)


def _sshd(line: str) -> dict[str, str]:
    for rx in _SSH_MSGS:
        m = rx.match(line.strip())
        if m:
            return {k: v for k, v in m.groupdict().items() if v is not None}
    return {}


def _ssh_doc(version: str, extra: str) -> str:
    return f"""
# OpenSSH {version} — sshd authentication messages

Source: OpenSSH sshd(8) and the messages of auth.c / sshd.c in OpenSSH {version}.
`sshd` writes one line per event to its log target; collected here from its
standard error (`sshd -D -e`), so a line carries no syslog header.

    Failed password for <user> from <src_ip> port <src_port> ssh2
    Failed password for invalid user <user> from <src_ip> port <src_port> ssh2
    Accepted password for <user> from <src_ip> port <src_port> ssh2
    Invalid user <user> from <src_ip> port <src_port>
    Connection closed by authenticating user <user> <src_ip> port <src_port> [preauth]
    Connection closed by invalid user <user> <src_ip> port <src_port> [preauth]
{extra}
- `outcome` — `Failed` or `Accepted`: whether the authentication attempt succeeded
- `method` — the authentication method (`password`)
- `user` — the account the client tried to log in as
- `src_ip`, `src_port` — the address and port the client connected from
"""


_SSH_FIELDS = [
    _f("outcome", "event.outcome", "keyword", "auth_outcome", "medium",
       "Failed -> failure, Accepted -> success (value map), as round 2's sshd_auth."),
    _f("user", "user.name", "keyword", "account", "easy"),
    _f("src_ip", "source.ip", "ip", "client_ip", "easy"),
    _f("src_port", "source.port", "long", "client_port", "easy"),
]
_SSH_VMAP = {"outcome": {"Failed": "failure", "Accepted": "success"}}

R3_SSHD_OLD = Spec(
    source_id="r3_sshd_deb10",
    family="openssh",
    software="OpenSSH 7.9p1 (Debian 10, openssh-server 1:7.9p1-10+deb10u4)",
    category="authentication",
    contamination="high",
    split="train_r3",
    notes=("ROUND 3, OLD VERSION - training material only. FREE TEXT; capture names are "
           "a scoring convention fixed in documentation.md, as in sshd_auth."),
    documentation=_ssh_doc("7.9", """    Did not receive identification string from <src_ip> port <src_port>
"""),
    keep=lambda ln: bool(_sshd(ln)),
    extract=_sshd,
    fields=_SSH_FIELDS,
    value_maps=_SSH_VMAP,
)

R3_SSHD_NEW = Spec(
    source_id="r3_sshd_deb12",
    family="openssh",
    software="OpenSSH 9.2p1 (Debian 12, openssh-server 1:9.2p1-2+deb12u10)",
    category="authentication",
    contamination="high",
    split="test_r3",
    notes=("ROUND 3, NEW VERSION of r3_sshd_deb10 - evaluated. The pre-authentication "
           "drop that 7.9 wrote as 'Did not receive identification string' is written by "
           "9.2 as two lines: 'kex_exchange_identification: <reason>' and 'Connection "
           "closed by <ip> port <port>'."),
    documentation=_ssh_doc("9.2", """    kex_exchange_identification: <reason>
    Connection closed by <src_ip> port <src_port>
"""),
    keep=lambda ln: bool(_sshd(ln)),
    extract=_sshd,
    fields=_SSH_FIELDS,
    value_maps=_SSH_VMAP,
)


# -------------------------------------------------------------------- nginx
#
# Same nginx 1.27 binary and server block; the administrator replaces the stock
# `combined` access log with a JSON log_format (testbed/r3/conf/nginx-*.conf).
# The capture names are the JSON keys the administrator chose; the combined
# reading uses the same names for the same parts.
_COMBINED = re.compile(
    r'^(?P<client>\S+) - (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<uri>\S+) (?P<protocol>[^"]+)" (?P<status>\d{3}) (?P<bytes_sent>\d+) '
    r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)"$')


def _combined(line: str) -> dict[str, str]:
    m = _COMBINED.match(line)
    return {k: v for k, v in m.groupdict().items() if v is not None} if m else {}


def _nginx_json(line: str) -> dict[str, str]:
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return {}
    if not isinstance(obj, dict) or "uri" not in obj:
        return {}
    return {k: str(v) for k, v in obj.items() if not isinstance(v, (dict, list))}


_NGINX_PARTS = """
- `client` — the address of the client that connected to nginx
- `user` — the user name the client authenticated as with HTTP basic
  authentication; `-` (or empty) when it sent none
- `method` — the request method
- `uri` — the request URI as sent, path and query string
- `protocol` — the request protocol, `HTTP/1.1`
- `status` — the response status code
- `bytes_sent` — the bytes of the response body sent to the client
- `referer` — the Referer header of the request
- `agent` — the User-Agent header of the request
"""

_NGINX_FIELDS = [
    _f("client", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent for scoring."),
    _f("user", "user.name", "keyword", "account", "easy"),
    _f("method", "http.request.method", "keyword", "request_method", "easy"),
    _f("uri", "url.original", "keyword", "request_uri", "medium",
       "The URI as sent, path and query; url.path would drop the query."),
    _f("protocol", "http.version", "keyword", "protocol_version", "medium",
       "Value convention: HTTP/1.1 on the wire, 1.1 in ECS - no rule filters on it."),
    _f("status", "http.response.status_code", "long", "status_code", "easy"),
    _f("bytes_sent", "http.response.body.bytes", "long", "response_body_size", "medium"),
    _f("referer", "http.request.referrer", "keyword", "referrer", "medium"),
    _f("agent", "user_agent.original", "keyword", "user_agent", "easy"),
]

R3_NGINX_OLD = Spec(
    source_id="r3_nginx_combined",
    family="nginx",
    software="nginx 1.27.5 (image nginx:1.27-alpine), log_format combined",
    category="web",
    contamination="high",
    split="train_r3",
    notes=("ROUND 3, OLD CONFIGURATION - training material only. The stock combined access "
           "log. Contamination is HIGH: the format is everywhere, and SIEMgen generates an "
           "nginx family (in other layouts)."),
    documentation="""
# nginx — access log, `combined` format

Source: nginx documentation, ngx_http_log_module,
https://nginx.org/en/docs/http/ngx_http_log_module.html#log_format

The predefined `combined` format writes

    <client> - <user> [<time>] "<method> <uri> <protocol>" <status> <bytes_sent> "<referer>" "<agent>"

- `time` — local time in the Common Log Format, `dd/Mmm/yyyy:HH:MM:SS +zzzz`
""" + _NGINX_PARTS,
    keep=lambda ln: bool(_combined(ln)),
    extract=_combined,
    fields=_NGINX_FIELDS,
    unqueryable={"http.version": "value convention: HTTP/1.1 on the wire, 1.1 in ECS"},
)

R3_NGINX_NEW = Spec(
    source_id="r3_nginx_json",
    family="nginx",
    software="nginx 1.27.5 (image nginx:1.27-alpine), administrator's JSON log_format",
    category="web",
    contamination="high",
    split="test_r3",
    notes=("ROUND 3, NEW CONFIGURATION of r3_nginx_combined - evaluated. The same server "
           "after the administrator switched the access log to JSON and added the Host, "
           "X-Forwarded-For, request time and request id. A configuration change, not a "
           "version change: the documentation is the administrator's own log_format."),
    documentation="""
# nginx — access log, the site's JSON format

Source: the site's nginx.conf (ngx_http_log_module, `log_format ... escape=json`),
https://nginx.org/en/docs/http/ngx_http_log_module.html#log_format

    log_format r3json escape=json '{"time":"$time_iso8601","client":"$remote_addr",'
        '"user":"$remote_user","host":"$host","method":"$request_method",'
        '"uri":"$request_uri","protocol":"$server_protocol","status":$status,'
        '"bytes_sent":$body_bytes_sent,"referer":"$http_referer",'
        '"agent":"$http_user_agent","forwarded_for":"$http_x_forwarded_for",'
        '"duration":$request_time,"request_id":"$request_id"}';

One JSON object per request. With `escape=json` a variable with no value is
written as an empty string.

- `time` — local time in ISO 8601
- `host` — the host name the request was addressed to (Host header or server name)
- `forwarded_for` — the X-Forwarded-For header: the original client when a proxy
  forwarded the request
- `duration` — request processing time in seconds, millisecond resolution
- `request_id` — a unique identifier nginx generated for the request (32 hex digits)
""" + _NGINX_PARTS,
    keep=lambda ln: bool(_nginx_json(ln)),
    extract=_nginx_json,
    fields=_NGINX_FIELDS + [
        _f("host", "url.domain", "keyword", "requested_host", "medium"),
        _f("forwarded_for", "network.forwarded_ip", "ip", "forwarded_client", "hard",
           "The original client behind a proxy; source.ip would be WRONG (that is `client`)."),
        _f("duration", None, "float", "request_duration", "hard",
           "ECS event.duration is in nanoseconds; seconds need a conversion the IR cannot "
           "express, so declining is accepted.", abstain=True),
        _f("request_id", "http.request.id", "keyword", "request_identifier", "medium"),
    ],
    unqueryable={"http.version": "value convention: HTTP/1.1 on the wire, 1.1 in ECS"},
)


# ----------------------------------------------------------------- Suricata
#
# The same rule file (testbed/r3/conf/suricata-r3.rules) under 6.0.20 and
# 7.0.17, image default suricata.yaml. Only `alert` and `dns` events are kept:
# the source's category is `network`, which offers no http/url/user_agent
# root, so the http object of an alert is declared unreachable rather than
# scored. Measured on the capture: 7.0 only ADDS keys (pkt_src, direction,
# dns.version, flow.src_ip/dest_ip/src_port/dest_port); no 6.0 key moved.
_SURI_KEEP = {"alert", "dns"}


def _suricata(line: str) -> dict[str, str]:
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return {}
    if not isinstance(obj, dict) or obj.get("event_type") not in _SURI_KEEP:
        return {}
    out: dict[str, str] = {}

    def walk(o, pre: str) -> None:
        for k, v in o.items():
            if isinstance(v, dict):
                walk(v, f"{pre}{k}.")
            elif not isinstance(v, list):
                out[pre + k] = str(v)
    walk(obj, "")
    return out


def _suri_doc(version: str, extra: str) -> str:
    return f"""
# Suricata {version} — EVE JSON output, alert and dns events

Source: Suricata {version} user guide, "Eve JSON Format",
https://docs.suricata.io/en/suricata-{version}/output/eve/eve-json-format.html

One JSON object per event. Nested objects are addressed here with dots
(`alert.signature` is the `signature` key of the `alert` object).

## Keys of every event

- `timestamp` — when the packet was seen, ISO 8601 with microseconds
- `flow_id` — the identifier Suricata gives the flow, the same on every event of it
- `in_iface` — the network interface the packet was captured on
- `event_type` — the kind of event: `alert`, `dns`, ...
- `src_ip`, `src_port` — the address and port the packet came from
- `dest_ip`, `dest_port` — the address and port the packet went to
- `proto` — the transport protocol: `TCP`, `UDP`, `ICMP`
{extra}
## alert events

- `alert.action` — what the engine did: `allowed` (IDS mode) or `blocked`
- `alert.gid`, `alert.signature_id`, `alert.rev` — the rule's group id, its id (sid)
  and its revision
- `alert.signature` — the rule's name, its message text (`msg`)
- `alert.category` — the rule's classification (`classtype`), as text
- `alert.severity` — the priority of that classification, 1 (highest) to 4
- `app_proto` — the application protocol detected on the flow: `http`, `dns`, ...
- `tx_id` — the transaction the alert belongs to, within the flow
- `http.*` — the HTTP transaction that triggered the alert, when there is one
- `flow.*` — counters of the flow so far: `pkts_toserver`, `bytes_toclient`, `start`, ...

## dns events

- `dns.type` — `query` for a request
- `dns.id` — the DNS transaction id of the message
- `dns.rrname` — the name queried
- `dns.rrtype` — the record type queried: `A`, `AAAA`, `TXT`, ...
- `dns.opcode` — the DNS opcode, 0 for a standard query
- `dns.tx_id` — the transaction within the flow
"""


_SURI_UNREACH = ("unreachable from `network`: the category offers no http/url/user_agent root")
_SURI_FIELDS = [
    _f("src_ip", "source.ip", "ip", "client_ip", "easy"),
    _f("src_port", "source.port", "long", "client_port", "easy"),
    _f("dest_ip", "destination.ip", "ip", "server_ip", "easy"),
    _f("dest_port", "destination.port", "long", "server_port", "easy"),
    _f("proto", "network.transport", "keyword", "transport_protocol", "easy",
       "Value convention: TCP on the wire, tcp in ECS - no rule filters on it."),
    _f("app_proto", "network.protocol", "keyword", "application_protocol", "medium"),
    _f("in_iface", "observer.ingress.interface.name", "keyword", "capture_interface", "hard"),
    _f("event_type", None, "keyword", "event_kind", "ambiguous",
       "ECS event.kind takes `alert` but not `dns`; a value map would be needed. Declining "
       "is accepted. (Round 2's suricata_eve truth mapped it to event.kind - DRAFT, author "
       "to reconcile.)", abstain=True),
    _f("flow_id", None, "long", "flow_identifier", "hard",
       "No ECS field holds Suricata's flow id (network.community_id is a different hash).",
       abstain=True),
    _f("alert.signature", "rule.name", "keyword", "rule_message", "easy"),
    _f("alert.signature_id", "rule.id", "keyword", "rule_identifier", "medium"),
    _f("alert.category", "rule.category", "keyword", "rule_classification", "medium"),
    _f("alert.severity", "event.severity", "long", "priority", "medium"),
    _f("alert.action", "event.action", "keyword", "engine_action", "medium"),
    _f("alert.rev", "rule.version", "keyword", "rule_revision", "medium"),
    _f("alert.gid", None, "long", "rule_group", "hard", "No ECS field.", abstain=True),
    _f("dns.rrname", "dns.question.name", "keyword", "query_name", "easy"),
    _f("dns.rrtype", "dns.question.type", "keyword", "query_type", "easy"),
    _f("dns.type", "dns.type", "keyword", "message_type", "medium"),
    _f("dns.id", "dns.id", "keyword", "transaction_id", "medium"),
    _f("dns.opcode", "dns.op_code", "keyword", "opcode", "hard"),
    _f("http.hostname", None, "keyword", "http_host", "hard", _SURI_UNREACH, abstain=True),
    _f("http.url", None, "keyword", "http_url", "hard", _SURI_UNREACH, abstain=True),
    _f("http.http_user_agent", None, "keyword", "user_agent", "hard", _SURI_UNREACH, abstain=True),
    _f("http.http_method", None, "keyword", "http_method", "hard", _SURI_UNREACH, abstain=True),
    _f("http.status", None, "long", "http_status", "hard", _SURI_UNREACH, abstain=True),
]
_SURI_UNQ = {"network.transport": "value convention: TCP on the wire, tcp in ECS"}

R3_SURICATA_OLD = Spec(
    source_id="r3_suricata_v6",
    family="suricata",
    software="Suricata 6.0.20 (image jasonish/suricata:6.0)",
    category="network",
    contamination="high",
    split="train_r3",
    notes=("ROUND 3, OLD VERSION - training material only. EVE alert and dns events. "
           "Contamination is HIGH: EVE is widely reproduced, round 2 has suricata_eve and "
           "SIEMgen a suricata family."),
    documentation=_suri_doc("6.0.20", ""),
    keep=lambda ln: bool(_suricata(ln)),
    extract=_suricata,
    fields=_SURI_FIELDS,
    unqueryable=_SURI_UNQ,
)

R3_SURICATA_NEW = Spec(
    source_id="r3_suricata_v7",
    family="suricata",
    software="Suricata 7.0.17 (image jasonish/suricata:7.0)",
    category="network",
    contamination="high",
    split="test_r3",
    notes=("ROUND 3, NEW VERSION of r3_suricata_v6 - evaluated. Measured: 7.0 only adds keys "
           "(pkt_src, direction, dns.version and the flow's endpoints inside `flow`); every 6.0 "
           "key is where it was. The pre-registration expected renamed fields; this pair is "
           "the CONTROL case where a real upgrade does not break the parser."),
    documentation=_suri_doc("7.0.17", """- `pkt_src` — where the packet came from: `wire/pcap`, `stream (flow timeout)`, ...
- `direction` — `to_server` or `to_client`, the direction of the packet in its flow
- `dns.version` — the version of the EVE DNS format (2)
- `flow.src_ip`, `flow.dest_ip`, `flow.src_port`, `flow.dest_port` — the flow's own
  endpoints, as the flow was first seen
"""),
    keep=lambda ln: bool(_suricata(ln)),
    extract=_suricata,
    fields=[dict(f, retrieval_unreachable=True, note=(
                "MEASURED 2026-10-20: the ECS retrieval never offers rule.name for this source - "
                "7.0's new generic keys (version, direction) promote ~dozens of *.version and "
                "*.direction fields and fill the 320-field budget (6.0 offers it). Still scored "
                "as a miss for every arm alike; no detection rule filters on it (unqueryable), "
                "so no arm is refused for a field it was never shown. Author's decision (b)."))
            if f["source_key"] == "alert.signature" else f for f in _SURI_FIELDS] + [
        _f("pkt_src", None, "keyword", "packet_origin", "hard", "No ECS field.", abstain=True),
        _f("direction", None, "keyword", "flow_direction", "ambiguous",
           "ECS network.direction is relative to the monitored network (inbound/outbound), "
           "not to the flow, so to_server has no ECS home; declining is accepted.", abstain=True),
    ],
    unqueryable={**_SURI_UNQ, "rule.name": "retrieval never offers it for this source (measured; see the field's note)"},
)


# ------------------------------------------------------------------- syslog
#
# Debian 12's sshd and sudo behind rsyslog; only the collector's template
# changes. The header is read first, then the message by the same per-program
# readers in both versions. Session bookkeeping (pam_unix session opened/
# closed) and the container's own noise (pam_systemd: no system bus,
# pam_limits: Operation not permitted, pam_env) are not kept: they carry no
# authentication event, and the last three exist only because the programs run
# in a container.
_SYSLOG_TRAD = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (?P<host>\S+) "
    r"(?P<program>[\w.-]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$")
_SYSLOG_5424 = re.compile(
    r"^<(?P<pri>\d+)>1 (?P<timestamp>\S+) (?P<host>\S+) (?P<program>\S+) (?P<pid>\S+) "
    r"(?P<msgid>\S+) (?P<sd>-|\[.*?\]) (?P<msg>.*)$")
_SYSLOG_MSGS = _SSH_MSGS[:-1] + (
    re.compile(r"^error: kex_exchange_identification: (?P<reason>.+)$"),
    re.compile(r"^(?P<user>\S+) : (?:(?P<sudo_result>\d+ incorrect password attempts?|user NOT in sudoers) ; )?"
               r"PWD=(?P<cwd>\S+) ; USER=(?P<target_user>\S+) ; COMMAND=(?P<command>.+)$"),
)


def _syslog(header: re.Pattern[str]):
    def read(line: str) -> dict[str, str]:
        m = header.match(line)
        if not m:
            return {}
        out = {k: v for k, v in m.groupdict().items() if v is not None and k not in ("msg", "sd", "msgid")}
        if out.get("pid") == "-":
            del out["pid"]
        msg = m.group("msg").strip()
        for rx in _SYSLOG_MSGS:
            mm = rx.match(msg)
            if mm:
                out.update({k: v for k, v in mm.groupdict().items() if v is not None})
                return out
        return {}
    return read


_syslog_trad, _syslog_5424 = _syslog(_SYSLOG_TRAD), _syslog(_SYSLOG_5424)

_SYSLOG_MSG_DOC = """
## The messages kept, and the names of their parts

sshd (OpenSSH 9.2):

    Failed password for [invalid user ]<user> from <src_ip> port <src_port> ssh2
    Accepted password for <user> from <src_ip> port <src_port> ssh2
    Invalid user <user> from <src_ip> port <src_port>
    Connection closed by authenticating user <user> <src_ip> port <src_port> [preauth]
    Connection closed by invalid user <user> <src_ip> port <src_port> [preauth]
    Connection closed by <src_ip> port <src_port>
    error: kex_exchange_identification: <reason>

sudo (1.9):

    <user> : PWD=<cwd> ; USER=<target_user> ; COMMAND=<command>
    <user> : <sudo_result> ; PWD=<cwd> ; USER=<target_user> ; COMMAND=<command>

- `outcome` — the word `Failed` or `Accepted`
- `user` — the account that tried to log in, or that ran sudo
- `src_ip`, `src_port` — the address and port the ssh client connected from
- `reason` — why the ssh key exchange did not start
- `sudo_result` — why sudo refused: `1 incorrect password attempt`, `user NOT in sudoers`
- `cwd` — the directory sudo was run in
- `target_user` — the account the command was to run as
- `command` — the command line sudo was asked to run
"""

_SYSLOG_FIELDS = [
    _f("host", "host.hostname", "keyword", "host_name", "easy", "host.name is equivalent."),
    _f("program", "process.name", "keyword", "program_name", "easy"),
    _f("pid", "process.pid", "long", "process_id", "easy"),
    _f("outcome", "event.outcome", "keyword", "auth_outcome", "medium",
       "Failed -> failure, Accepted -> success (value map)."),
    _f("user", "user.name", "keyword", "account", "easy"),
    _f("src_ip", "source.ip", "ip", "client_ip", "easy"),
    _f("src_port", "source.port", "long", "client_port", "easy"),
    _f("reason", None, "keyword", "kex_failure", "hard",
       "event.reason is taken by sudo_result; the IR maps one key per field.", abstain=True),
    _f("sudo_result", "event.reason", "keyword", "refusal_reason", "medium"),
    _f("cwd", "process.working_directory", "keyword", "working_directory", "medium"),
    _f("target_user", "user.target.name", "keyword", "target_account", "hard",
       "The account sudo runs the command AS; user.name would be WRONG (that is `user`)."),
    _f("command", "process.command_line", "keyword", "command_line", "medium"),
]

R3_SYSLOG_OLD = Spec(
    source_id="r3_syslog_trad",
    family="linux-auth-syslog",
    software="Debian 12 OpenSSH 9.2p1 + sudo 1.9.13p3, rsyslog 8.2302.0 RSYSLOG_TraditionalFileFormat",
    category="authentication",
    contamination="high",
    split="train_r3",
    notes=("ROUND 3, OLD COLLECTOR - training material only. /var/log/auth.log in the "
           "traditional format. Contamination HIGH: SIEMgen's linux_auth family and round 4 "
           "phase 2's header-edit pairs are this kind of line. The sshd messages are the same "
           "program as r3_sshd_deb12 (declared)."),
    documentation="""
# Linux authentication log — rsyslog, traditional file format

Source: rsyslog documentation, "Templates" (RSYSLOG_TraditionalFileFormat),
https://www.rsyslog.com/doc/configuration/templates.html

    <timestamp> <host> <program>[<pid>]: <message>

- `timestamp` — `Mmm dd HH:MM:SS`, local time, no year
- `host` — the host name of the machine that logged the message
- `program` — the program that logged it (`sshd`, `sudo`)
- `pid` — that program's process id; sudo writes none
""" + _SYSLOG_MSG_DOC,
    keep=lambda ln: bool(_syslog_trad(ln)),
    extract=_syslog_trad,
    fields=_SYSLOG_FIELDS,
    value_maps=_SSH_VMAP,
)

R3_SYSLOG_NEW = Spec(
    source_id="r3_syslog_5424",
    family="linux-auth-syslog",
    software="Debian 12 OpenSSH 9.2p1 + sudo 1.9.13p3, rsyslog 8.2302.0 RSYSLOG_SyslogProtocol23Format",
    category="authentication",
    contamination="high",
    split="test_r3",
    notes=("ROUND 3, NEW COLLECTOR of r3_syslog_trad - evaluated. The same programs; the "
           "header becomes RFC 5424: priority, version, ISO 8601 time with microseconds, the "
           "process id as its own field (`-` when absent), MSGID and STRUCTURED-DATA `-`, and "
           "a message that rsyslog writes after TWO spaces."),
    documentation="""
# Linux authentication log — rsyslog, RFC 5424 format

Source: RFC 5424 section 6, and rsyslog documentation, "Templates"
(RSYSLOG_SyslogProtocol23Format), https://www.rsyslog.com/doc/configuration/templates.html

    <<pri>>1 <timestamp> <host> <program> <pid> <msgid> <structured_data> <message>

- `pri` — the priority: facility * 8 + severity (`<38>` is auth.info, `<85>` authpriv.notice)
- `1` — the syslog protocol version
- `timestamp` — ISO 8601 with microseconds and the UTC offset
- `host` — the host name of the machine that logged the message
- `program` — the program that logged it (`sshd`, `sudo`)
- `pid` — that program's process id, `-` when it gave none (sudo)
- `msgid`, `structured_data` — both `-` here
""" + _SYSLOG_MSG_DOC,
    keep=lambda ln: bool(_syslog_5424(ln)),
    extract=_syslog_5424,
    fields=_SYSLOG_FIELDS + [
        _f("pri", "log.syslog.priority", "long", "syslog_priority", "medium"),
    ],
    value_maps=_SSH_VMAP,
)


# ----------------------------------------------------------------- firewall
#
# netfilter -> NFLOG -> ulogd2 (Debian 12), one rule set, one traffic plan;
# the collector's output plugin changes from LOGEMU (the iptables LOG text) to
# JSON. Every rule logs with a prefix naming it (R3-DROP-SSH, R3-ACCEPT-WEB).
_LOGEMU = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (?P<host>\S+) (?P<prefix>R3-\S+) (?P<rest>IN=.*)$")
_KV = re.compile(r"(?:^| )([A-Z]+)=(\S*)")


def _logemu(line: str) -> dict[str, str]:
    m = _LOGEMU.match(line.rstrip())
    if not m:
        return {}
    out = {k: m.group(k) for k in ("timestamp", "host", "prefix")}
    for k, v in _KV.findall(m.group("rest")):
        out.setdefault(k, v)  # LEN appears twice on UDP lines: the IP length comes first
    return out


def _ulogd_json(line: str) -> dict[str, str]:
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return {}
    if not isinstance(obj, dict) or "oob.prefix" not in obj:
        return {}
    return {k: str(v) for k, v in obj.items() if not isinstance(v, (dict, list))}


_FW_UNQ = {"network.transport": "value convention: TCP on the wire, tcp in ECS",
           "source.mac": "value convention: aa:bb:... on the wire, AA-BB-... in ECS",
           "destination.mac": "value convention: aa:bb:... on the wire, AA-BB-... in ECS"}

R3_FIREWALL_OLD = Spec(
    source_id="r3_firewall_logemu",
    family="netfilter-ulogd",
    software="Debian 12 iptables 1.8.9 (nft) NFLOG -> ulogd2 2.0.8 LOGEMU",
    category="firewall",
    contamination="high",
    split="train_r3",
    notes=("ROUND 3, OLD COLLECTOR - training material only. The iptables LOG text format, "
           "positional KEY=value after a syslog-style header and the rule's prefix. "
           "Contamination HIGH: the format is everywhere, and SIEMgen generates pfSense filterlog."),
    documentation="""
# netfilter packet log — ulogd2 LOGEMU (iptables LOG format)

Source: ulogd2 documentation (output plugin LOGEMU) and the iptables-extensions(8)
LOG target, https://www.netfilter.org/projects/ulogd/ and
https://ipset.netfilter.org/iptables-extensions.man.html

    <timestamp> <host> <prefix> IN=<in> OUT=<out> MAC=<mac> SRC=<src> DST=<dst> LEN=<len> TOS=.. PREC=.. TTL=<ttl> ID=<id> [DF] PROTO=<proto> ...

then, by protocol: `SPT=<sport> DPT=<dport>` and TCP's `SEQ= ACK= WINDOW=` and flag
words (`SYN`) for TCP; `SPT= DPT= LEN=` for UDP; `TYPE= CODE= ID= SEQ=` for ICMP.

- `timestamp` — `Mmm dd HH:MM:SS`, local time, no year
- `host` — the firewall's host name
- `prefix` — the log prefix of the rule that matched, naming the rule
- `IN`, `OUT` — the interface the packet came in on, and went out on (empty for input)
- `MAC` — destination MAC, source MAC and EtherType, joined with colons
- `SRC`, `DST` — source and destination addresses
- `LEN` — the length of the IP packet in bytes
- `TTL`, `ID` — the IP time to live and identification
- `PROTO` — the transport protocol: `TCP`, `UDP`, `ICMP`
- `SPT`, `DPT` — source and destination ports
""",
    keep=lambda ln: bool(_logemu(ln)),
    extract=_logemu,
    fields=[
        _f("host", "observer.hostname", "keyword", "firewall_name", "medium"),
        _f("prefix", "rule.name", "keyword", "rule_label", "medium"),
        _f("IN", "observer.ingress.interface.name", "keyword", "ingress_interface", "hard"),
        _f("SRC", "source.ip", "ip", "packet_source", "easy"),
        _f("DST", "destination.ip", "ip", "packet_destination", "easy"),
        _f("SPT", "source.port", "long", "source_port", "easy"),
        _f("DPT", "destination.port", "long", "destination_port", "easy"),
        _f("PROTO", "network.transport", "keyword", "transport_protocol", "easy",
           "Value convention: TCP on the wire, tcp in ECS - no rule filters on it."),
        _f("LEN", None, "long", "packet_length", "hard",
           "network.bytes counts a whole flow, not one packet; declining is accepted.", abstain=True),
        _f("MAC", None, "keyword", "mac_header", "hard",
           "Two MACs and an EtherType in one string; no single ECS field holds it.", abstain=True),
    ],
    unqueryable=_FW_UNQ,
)

R3_FIREWALL_NEW = Spec(
    source_id="r3_firewall_json",
    family="netfilter-ulogd",
    software="Debian 12 iptables 1.8.9 (nft) NFLOG -> ulogd2 2.0.8 JSON",
    category="firewall",
    contamination="medium",
    split="test_r3",
    notes=("ROUND 3, NEW COLLECTOR of r3_firewall_logemu - evaluated. ulogd's JSON output: "
           "the same packets under different names (SRC -> src_ip, DPT -> dest_port, the prefix "
           "-> oob.prefix), the protocol as its IANA number, and ~40 keys the text format never "
           "had (oob.*, raw.*, tcp.*, mac.*). Dotted names are literal top-level keys, not nesting."),
    documentation="""
# netfilter packet log — ulogd2 JSON output

Source: ulogd2 documentation, output plugin JSON (ulogd2-json),
https://www.netfilter.org/projects/ulogd/

One flat JSON object per logged packet. The dots are part of the key names
(`oob.prefix` is one key), not nesting.

- `timestamp` — ISO 8601 with microseconds
- `dvc` — the device name configured for the output: the firewall's name
- `oob.prefix` — the log prefix of the rule that matched, naming the rule
- `oob.in`, `oob.out` — the interface the packet came in on, and went out on
- `oob.hook`, `oob.family`, `oob.protocol`, `oob.mark`, `oob.ifindex_in` — netfilter
  hook number, address family, EtherType, packet mark, interface index
- `raw.pktlen` — the length of the packet in bytes
- `src_ip`, `dest_ip` — source and destination addresses
- `src_port`, `dest_port` — source and destination ports (TCP, UDP)
- `ip.protocol` — the IP protocol number: 6 TCP, 17 UDP, 1 ICMP
- `ip.ttl`, `ip.id`, `ip.tos`, `ip.totlen` — IP header fields
- `tcp.*` — TCP header fields and flags (`tcp.syn` is 1 on a SYN)
- `udp.len` — the UDP length
- `icmp.type`, `icmp.code` — the ICMP type and code
- `mac.saddr.str`, `mac.daddr.str` — source and destination MAC addresses
""",
    keep=lambda ln: bool(_ulogd_json(ln)),
    extract=_ulogd_json,
    fields=[
        _f("dvc", "observer.hostname", "keyword", "firewall_name", "medium"),
        _f("oob.prefix", "rule.name", "keyword", "rule_label", "medium"),
        _f("oob.in", "observer.ingress.interface.name", "keyword", "ingress_interface", "hard"),
        _f("src_ip", "source.ip", "ip", "packet_source", "easy"),
        _f("dest_ip", "destination.ip", "ip", "packet_destination", "easy"),
        _f("src_port", "source.port", "long", "source_port", "easy"),
        _f("dest_port", "destination.port", "long", "destination_port", "easy"),
        _f("ip.protocol", "network.iana_number", "keyword", "protocol_number", "hard",
           "The IANA number; network.transport would need a value map (6 -> tcp)."),
        _f("mac.saddr.str", "source.mac", "keyword", "source_mac", "medium"),
        _f("mac.daddr.str", "destination.mac", "keyword", "destination_mac", "medium"),
        _f("raw.pktlen", None, "long", "packet_length", "hard",
           "network.bytes counts a whole flow, not one packet; declining is accepted.", abstain=True),
    ],
    unqueryable=_FW_UNQ,
)


# ===========================================================================
# ROUND 4 - fresh held-out changes (captured 2026-10-22, after the configuration
# was frozen; never used in any development step). Split train_r4 / test_r4.
# ===========================================================================

def _json_dotted(line: str, need: str) -> dict[str, str]:
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return {}
    if not isinstance(obj, dict):
        return {}
    out: dict[str, str] = {}

    def walk(o, pre: str) -> None:
        for k, v in o.items():
            if isinstance(v, dict):
                walk(v, f"{pre}{k}.")
            elif not isinstance(v, list):
                out[pre + k] = str(v)
    walk(obj, "")
    return out if need in out else {}


# ------------------------------------------------------------------ HAProxy
_HAP = re.compile(
    r'^(?P<client_ip>[0-9a-fA-F.:]+):(?P<client_port>\d+) \[(?P<accept_date>[^\]]+)\] (?P<frontend>\S+) '
    r'(?P<backend>[^/\s]+)/(?P<server>\S+) (?P<timers>\S+) (?P<status>\d{3}) (?P<bytes_read>\d+) '
    r'(?P<req_cookie>\S+) (?P<res_cookie>\S+) (?P<term_state>\S+) (?P<conns>\S+) (?P<queues>\S+) '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<http_version>[^"]+)"$')


def _hap_text(line: str) -> dict[str, str]:
    m = _HAP.match(line.strip())
    return {k: v for k, v in m.groupdict().items() if v is not None} if m else {}


_HAP_PARTS = """
- `client_ip`, `client_port` - the address and port of the client that connected
- `accept_date` - when the connection was accepted, `dd/Mmm/yyyy:HH:MM:SS.mmm`
- `frontend` - the frontend (listener) that received the request
- `backend`, `server` - the backend and server the request was sent to; `<NOSRV>` when
  the request was answered by the proxy itself (for example a deny rule)
- `status` - the HTTP status code returned to the client
- `bytes_read` - the bytes sent to the client, headers included
- `method`, `path`, `http_version` - the request line
"""
_HAP_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("client_port", "source.port", "long", "client_port", "easy"),
    _f("status", "http.response.status_code", "long", "status_code", "easy"),
    _f("bytes_read", "http.response.bytes", "long", "response_size", "medium"),
    _f("method", "http.request.method", "keyword", "request_method", "easy"),
    _f("path", "url.original", "keyword", "request_uri", "medium", "The request URI as sent; url.path acceptable if no query."),
    _f("http_version", "http.version", "keyword", "protocol_version", "medium",
       "Value convention: HTTP/1.1 on the wire, 1.1 in ECS - no rule filters on it."),
    _f("frontend", None, "keyword", "listener", "hard", "No ECS field for a proxy listener name.", abstain=True),
    _f("backend", None, "keyword", "backend_pool", "hard", "No ECS field for a backend pool.", abstain=True),
    _f("server", None, "keyword", "upstream_server", "hard", "destination.address is arguable; declining accepted.", abstain=True),
]
_HAP_UNQ = {"http.version": "value convention: HTTP/1.1 on the wire, 1.1 in ECS"}

R4_HAPROXY_OLD = Spec(
    source_id="r4_haproxy_httplog", family="haproxy",
    software="HAProxy 2.8 (image haproxy:2.8-alpine), option httplog", category="web",
    contamination="high", split="train_r4",
    notes="ROUND 4 (fresh held-out), OLD CONFIGURATION: HAProxy's stock HTTP log.",
    documentation="""
# HAProxy 2.8 - HTTP log (option httplog)

Source: HAProxy 2.8 Configuration Manual, section 8.2.3 "HTTP log format",
https://docs.haproxy.org/2.8/configuration.html#8.2.3

    <client_ip>:<client_port> [<accept_date>] <frontend> <backend>/<server> <timers> <status> <bytes_read> <req_cookie> <res_cookie> <term_state> <conns> <queues> "<method> <path> <http_version>"

- `timers` - Tq/Tw/Tc/Tr/Ta, milliseconds
- `term_state` - the session termination state, four characters
- `conns` - actconn/feconn/beconn/srv_conn/retries
- `queues` - srv_queue/backend_queue
""" + _HAP_PARTS,
    keep=lambda ln: bool(_hap_text(ln)), extract=_hap_text, fields=_HAP_FIELDS, unqueryable=_HAP_UNQ,
)

R4_HAPROXY_NEW = Spec(
    source_id="r4_haproxy_json", family="haproxy",
    software="HAProxy 2.8 (image haproxy:2.8-alpine), administrator's JSON log-format", category="web",
    contamination="high", split="test_r4",
    notes="ROUND 4 (fresh held-out), NEW CONFIGURATION of r4_haproxy_httplog: the same proxy with a JSON log-format.",
    documentation="""
# HAProxy 2.8 - the site's JSON log format

Source: the site's haproxy.cfg (log-format, HAProxy 2.8 Configuration Manual section 8.2.4).

    log-format '{"client_ip":"%ci","client_port":%cp,"accept_date":"%tr","frontend":"%ft","backend":"%b","server":"%s","status":%ST,"bytes_read":%B,"method":"%HM","path":"%HU","http_version":"%HV","total_ms":%Ta,"user_agent":"%[capture.req.hdr(0)]"}'

One JSON object per request.

- `total_ms` - the total time to serve the request, milliseconds
- `user_agent` - the User-Agent header of the request
""" + _HAP_PARTS,
    keep=lambda ln: bool(_json_dotted(ln, "status")), extract=lambda ln: _json_dotted(ln, "status"),
    fields=_HAP_FIELDS + [
        _f("user_agent", "user_agent.original", "keyword", "user_agent", "easy"),
        _f("total_ms", None, "long", "duration", "hard", "event.duration is in nanoseconds; declining accepted.", abstain=True),
    ],
    unqueryable=_HAP_UNQ,
)

# -------------------------------------------------------------------- Caddy
_CADDY_CONSOLE = re.compile(r"^(?P<ts>\S+ \S+)\t(?:\x1b\[[0-9;]*m)?(?P<level>[A-Z]+)(?:\x1b\[[0-9;]*m)?\t(?P<logger>\S+)\t(?P<msg>[^\t]+)\t(?P<rest>\{.*\})$")


def _caddy_console(line: str) -> dict[str, str]:
    m = _CADDY_CONSOLE.match(line.rstrip("\n"))
    if not m:
        return {}
    out = _json_dotted(m.group("rest"), "status")
    if not out:
        return {}
    out.update({"level": m.group("level"), "logger": m.group("logger"), "msg": m.group("msg")})
    return out


_CADDY_PARTS = """
- `level` - the log level (`info`)
- `logger` - the logger that wrote the line (`http.log.access.log0`)
- `request.remote_ip`, `request.remote_port` - the address and port the connection came from
- `request.client_ip` - the client address after trusted-proxy processing (here the same)
- `request.proto`, `request.method`, `request.host`, `request.uri` - the request
- `request.headers.*` - the request headers, each a list of values
- `bytes_read` - the request body bytes read
- `user_id` - the authenticated user, empty when none
- `duration` - the time to serve the request, seconds
- `size` - the response body size, bytes
- `status` - the HTTP status code
- `resp_headers.*` - the response headers
"""
_CADDY_FIELDS = [
    _f("request.remote_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("request.remote_port", "source.port", "long", "client_port", "easy"),
    _f("request.method", "http.request.method", "keyword", "request_method", "easy"),
    _f("request.uri", "url.original", "keyword", "request_uri", "medium"),
    _f("request.host", "url.domain", "keyword", "requested_host", "medium"),
    _f("request.proto", "http.version", "keyword", "protocol_version", "medium",
       "Value convention: HTTP/1.1 on the wire, 1.1 in ECS - no rule filters on it."),
    _f("status", "http.response.status_code", "long", "status_code", "easy"),
    _f("size", "http.response.body.bytes", "long", "response_body_size", "medium"),
    _f("bytes_read", "http.request.body.bytes", "long", "request_body_size", "medium"),
    _f("level", "log.level", "keyword", "severity", "easy"),
    _f("logger", "log.logger", "keyword", "logger", "medium"),
    _f("request.client_ip", None, "ip", "client_ip_resolved", "hard", "Same value as remote_ip here; one key per field.", abstain=True),
    _f("duration", None, "float", "duration", "hard", "event.duration is in nanoseconds; declining accepted.", abstain=True),
]
_CADDY_UNQ = {"http.version": "value convention: HTTP/1.1 on the wire, 1.1 in ECS"}

R4_CADDY_OLD = Spec(
    source_id="r4_caddy_console", family="caddy",
    software="Caddy 2.8 (image caddy:2.8-alpine), log format console", category="web",
    contamination="high", split="train_r4",
    notes="ROUND 4 (fresh held-out), OLD CONFIGURATION: Caddy's console log encoder (tab-separated, ANSI colour codes, JSON fields).",
    documentation="""
# Caddy 2.8 - access log, console encoder

Source: Caddy documentation, "log" directive, `format console`,
https://caddyserver.com/docs/caddyfile/directives/log

    <ts>\\t<level>\\t<logger>\\t<msg>\\t{<fields as JSON>}

The level is wrapped in terminal colour codes. The JSON object carries:
""" + _CADDY_PARTS,
    keep=lambda ln: bool(_caddy_console(ln)), extract=_caddy_console, fields=_CADDY_FIELDS, unqueryable=_CADDY_UNQ,
)

R4_CADDY_NEW = Spec(
    source_id="r4_caddy_json", family="caddy",
    software="Caddy 2.8 (image caddy:2.8-alpine), log format json", category="web",
    contamination="high", split="test_r4",
    notes="ROUND 4 (fresh held-out), NEW CONFIGURATION of r4_caddy_console: the access log as JSON.",
    documentation="""
# Caddy 2.8 - access log, JSON encoder

Source: Caddy documentation, "log" directive, `format json`,
https://caddyserver.com/docs/caddyfile/directives/log

One JSON object per request: `level`, `ts` (Unix time), `logger`, `msg` and:
""" + _CADDY_PARTS,
    keep=lambda ln: bool(_json_dotted(ln, "status")), extract=lambda ln: _json_dotted(ln, "status"),
    fields=_CADDY_FIELDS, unqueryable=_CADDY_UNQ,
)

# ------------------------------------------------------------------ Postfix
_PF_HEAD = re.compile(r"^(?P<timestamp>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (?P<host>\S+) postfix/(?P<process>[a-z]+)\[(?P<pid>\d+)\]: (?P<msg>.*)$")
_PF_MSGS = (
    re.compile(r"^NOQUEUE: reject: RCPT from (?P<client_name>[^\[\s]+)\[(?P<client_ip>[^\]]+)\]: (?P<smtp_code>\d{3}) (?P<dsn>\d\.\d\.\d) <(?P<rcpt>[^>]*)>: (?P<reason>[^;]+); from=<(?P<from>[^>]*)> to=<(?P<to>[^>]*)> proto=(?P<proto>\S+) helo=<(?P<helo>[^>]*)>$"),
    re.compile(r"^(?P<queue_id>[0-9A-F]+): from=<(?P<from>[^>]*)>, size=(?P<size>\d+), nrcpt=(?P<nrcpt>\d+) \(queue active\)$"),
    re.compile(r"^(?P<queue_id>[0-9A-F]+): to=<(?P<to>[^>]*)>, relay=(?P<relay>\S+), delay=(?P<delay>[\d.]+), delays=\S+, dsn=(?P<dsn>\S+), status=(?P<status>\w+) \((?P<status_text>[^)]*)\)$"),
    re.compile(r"^connect from (?P<client_name>[^\[\s]+)\[(?P<client_ip>[^\]]+)\]$"),
    re.compile(r"^(?P<queue_id>[0-9A-F]+): client=(?P<client_name>[^\[\s]+)\[(?P<client_ip>[^\]]+)\]$"),
)


def _postfix(line: str) -> dict[str, str]:
    m = _PF_HEAD.match(line.strip())
    if not m:
        return {}
    for rx in _PF_MSGS:
        mm = rx.match(m.group("msg"))
        if mm:
            out = {k: v for k, v in m.groupdict().items() if v is not None and k != "msg"}
            out.update({k: v for k, v in mm.groupdict().items() if v is not None})
            return out
    return {}


def _pf_doc(version: str) -> str:
    return f"""
# Postfix {version} - mail log (maillog_file)

Source: Postfix documentation, MAILLOG_README and the smtpd, qmgr and local manual pages,
https://www.postfix.org/MAILLOG_README.html

    <timestamp> <host> postfix/<process>[<pid>]: <message>

## The messages kept

    connect from <client_name>[<client_ip>]
    <queue_id>: client=<client_name>[<client_ip>]
    <queue_id>: from=<<from>>, size=<size>, nrcpt=<nrcpt> (queue active)
    <queue_id>: to=<<to>>, relay=<relay>, delay=<delay>, delays=..., dsn=<dsn>, status=<status> (<status_text>)
    NOQUEUE: reject: RCPT from <client_name>[<client_ip>]: <smtp_code> <dsn> <<rcpt>>: <reason>; from=<<from>> to=<<to>> proto=<proto> helo=<<helo>>

- `process`, `pid` - the Postfix daemon (smtpd, qmgr, local, cleanup) and its process id
- `queue_id` - the queue identifier of the message
- `client_name`, `client_ip` - the connecting client's reverse name and address
- `from`, `to` - envelope sender and recipient
- `relay` - where the message was delivered (`local`, or a next hop)
- `dsn`, `status` - the delivery status code and outcome (`sent`, `bounced`, `deferred`)
- `smtp_code`, `reason` - the SMTP reply code and text of a rejection
- `helo` - the name the client gave in HELO/EHLO
"""


_PF_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy"),
    _f("client_name", "source.domain", "keyword", "client_name", "medium"),
    _f("from", "email.from.address", "keyword", "sender", "medium"),
    _f("to", "email.to.address", "keyword", "recipient", "medium"),
    _f("queue_id", "email.local_id", "keyword", "message_id", "hard"),
    _f("process", "process.name", "keyword", "program", "easy"),
    _f("pid", "process.pid", "long", "process_id", "easy"),
    _f("reason", "event.reason", "keyword", "refusal_reason", "medium"),
    _f("host", "host.hostname", "keyword", "host", "easy"),
    _f("status", None, "keyword", "delivery_status", "hard", "event.outcome needs a value map (sent->success); declining accepted.", abstain=True),
    _f("helo", None, "keyword", "helo_name", "hard", "No ECS field for a HELO name.", abstain=True),
]

R4_POSTFIX_OLD = Spec(
    source_id="r4_postfix_35", family="postfix",
    software="Postfix 3.5.25 (Debian 11)", category="email",
    contamination="high", split="train_r4",
    notes="ROUND 4 (fresh held-out), OLD VERSION. Same software as round 2's postfix_smtpd (dev), declared.",
    documentation=_pf_doc("3.5"),
    keep=lambda ln: bool(_postfix(ln)), extract=_postfix, fields=_PF_FIELDS,
)
R4_POSTFIX_NEW = Spec(
    source_id="r4_postfix_37", family="postfix",
    software="Postfix 3.7.11 (Debian 12)", category="email",
    contamination="high", split="test_r4",
    notes=("ROUND 4 (fresh held-out), NEW VERSION of r4_postfix_35. Measured: the format is unchanged; "
           "the relay refusal moves from 554 5.7.1 to 454 4.7.1. A control pair."),
    documentation=_pf_doc("3.7"),
    keep=lambda ln: bool(_postfix(ln)), extract=_postfix, fields=_PF_FIELDS,
)

# ------------------------------------------------------------------ Dovecot
_DV_HEAD = re.compile(r"^(?P<timestamp>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (?P<process>[a-z-]+)(?P<ctx>\S*): (?:request \[\d+\]: )?Info: (?P<msg>.*)$")
_DV_MSGS = (
    re.compile(r"^(?P<result>Login|Logged in): user=<(?P<user>[^>]*)>, method=(?P<method>\w+), rip=(?P<rip>[^,]+), lip=(?P<lip>[^,]+), mpid=(?P<mpid>\d+), session=<(?P<session>[^>]+)>$"),
    re.compile(r"^(?P<result>Disconnected|Login aborted: Connection closed) \(auth failed, \d+ attempts in \d+ secs\)(?: \(auth_failed\))?: user=<(?P<user>[^>]*)>, method=(?P<method>\w+), rip=(?P<rip>[^,]+), lip=(?P<lip>[^,]+), session=<(?P<session>[^>]+)>$"),
)
_DV_VMAP = {"result": {"Login": "success", "Logged in": "success", "Disconnected": "failure",
                       "Login aborted: Connection closed": "failure"}}


def _dovecot(line: str) -> dict[str, str]:
    m = _DV_HEAD.match(line.strip())
    if not m:
        return {}
    for rx in _DV_MSGS:
        mm = rx.match(m.group("msg"))
        if mm:
            out = {"timestamp": m.group("timestamp"), "process": m.group("process")}
            out.update({k: v for k, v in mm.groupdict().items() if v is not None})
            return out
    return {}


def _dv_doc(version: str, login: str, failed: str) -> str:
    return f"""
# Dovecot {version} - IMAP login log

Source: Dovecot {version} documentation, "Logging" and the imap-login messages.

    <timestamp> <process>: Info: <message>

## The messages kept

    {login}: user=<<user>>, method=<method>, rip=<rip>, lip=<lip>, mpid=<mpid>, session=<<session>>
    {failed}: user=<<user>>, method=<method>, rip=<rip>, lip=<lip>, session=<<session>>

- `result` - the event: a successful login, or a connection closed after failed authentication
- `user` - the account the client tried to log in as
- `method` - the SASL mechanism (PLAIN)
- `rip`, `lip` - the remote (client) and local (server) addresses
- `mpid` - the process id of the mail process started for a successful login
- `session` - the session identifier
"""


_DV_FIELDS = [
    _f("user", "user.name", "keyword", "account", "easy"),
    _f("rip", "source.ip", "ip", "client_ip", "easy"),
    _f("lip", "destination.ip", "ip", "server_ip", "medium"),
    _f("result", "event.outcome", "keyword", "auth_outcome", "medium", "value map: login -> success, auth failed -> failure"),
    _f("process", "process.name", "keyword", "program", "easy"),
    _f("method", None, "keyword", "auth_mechanism", "hard", "No ECS field for a SASL mechanism.", abstain=True),
    _f("session", None, "keyword", "session_id", "hard", "No ECS field fits a mail session id cleanly.", abstain=True),
    _f("mpid", None, "long", "mail_pid", "hard", "process.pid would be the login process; declining accepted.", abstain=True),
]

R4_DOVECOT_OLD = Spec(
    source_id="r4_dovecot_23", family="dovecot",
    software="Dovecot 2.3.13 (Debian 11)", category="authentication",
    contamination="high", split="train_r4",
    notes="ROUND 4 (fresh held-out), OLD VERSION. Same software as round 2's dovecot_auth (ood), declared.",
    documentation=_dv_doc("2.3", "Login", "Disconnected (auth failed, N attempts in S secs)"),
    keep=lambda ln: bool(_dovecot(ln)), extract=_dovecot, fields=_DV_FIELDS, value_maps=_DV_VMAP,
)
R4_DOVECOT_NEW = Spec(
    source_id="r4_dovecot_24", family="dovecot",
    software="Dovecot 2.4.1 (Debian 13)", category="authentication",
    contamination="high", split="test_r4",
    notes=("ROUND 4 (fresh held-out), NEW VERSION of r4_dovecot_23. Measured: `Login:` becomes `Logged in:`, "
           "a failed login `Login aborted: Connection closed (...) (auth_failed)`, a logout `Disconnected: Logged out`."),
    documentation=_dv_doc("2.4", "Logged in", "Login aborted: Connection closed (auth failed, N attempts in S secs) (auth_failed)"),
    keep=lambda ln: bool(_dovecot(ln)), extract=_dovecot, fields=_DV_FIELDS, value_maps=_DV_VMAP,
)


# (old, new) per pair, in ROUND3_VERSION_DRIFT.md's order.
PAIRS: dict[str, tuple[Spec, Spec]] = {
    "r3_apache": (R3_APACHE_OLD, R3_APACHE_NEW),
    "r3_sshd": (R3_SSHD_OLD, R3_SSHD_NEW),
    "r3_suricata": (R3_SURICATA_OLD, R3_SURICATA_NEW),
    "r3_nginx": (R3_NGINX_OLD, R3_NGINX_NEW),
    "r3_syslog": (R3_SYSLOG_OLD, R3_SYSLOG_NEW),
    "r3_firewall": (R3_FIREWALL_OLD, R3_FIREWALL_NEW),
    "r4_haproxy": (R4_HAPROXY_OLD, R4_HAPROXY_NEW),
    "r4_caddy": (R4_CADDY_OLD, R4_CADDY_NEW),
    "r4_postfix": (R4_POSTFIX_OLD, R4_POSTFIX_NEW),
    "r4_dovecot": (R4_DOVECOT_OLD, R4_DOVECOT_NEW),
}

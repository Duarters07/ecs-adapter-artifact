"""The round-2 held-out sources: how each is read, and its DRAFT ground truth.

One `Spec` per source. `extract` reads a line the way the source's
documentation.md says it is written - it is the oracle's reading, used to count
expected hits, so it must agree with that prose exactly. `fields` is the DRAFT
truth: every mapping is the fork's proposal from the vendor documentation and
awaits the author's review (`review_status`), and a field whose correct ECS
home is genuinely ambiguous is an acceptable abstention rather than a guess.

Families here are chosen to be in no training pool and in nothing SIEMgen
generates (bench/HELDOUT.md criteria V, P, A, E).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable
import json
import re


@dataclass(frozen=True)
class Spec:
    source_id: str
    family: str
    software: str
    category: str
    contamination: str
    notes: str
    documentation: str
    keep: Callable[[str], bool]
    extract: Callable[[str], dict[str, str]]
    fields: list[dict[str, Any]]
    value_maps: dict[str, dict[str, str]] = field(default_factory=dict)
    unqueryable: dict[str, str] = field(default_factory=dict)
    # "test" unless a property of the artefact - not of any model - would make
    # its numbers unfair; then "dev", with the reason in `notes`.
    split: str = "test"
    # Captured and specified, but NOT written to bench/sources: a defect in the
    # apparatus would charge every arm for it. The reason is the string itself.
    deferred: str = ""


def _f(key: str, ecs: str | None, typ: str, role: str, difficulty: str,
       note: str = "", abstain: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {"source_key": key, "ecs_field": ecs, "type": typ,
                           "role": role, "difficulty": difficulty}
    if note:
        out["note"] = note
    if abstain or ecs is None:
        out["acceptable_abstention"] = True
    return out


def _flat_json_dotted(line: str) -> dict[str, str]:
    """Every scalar of a JSON line, nested keys joined with dots."""
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return {}
    out: dict[str, str] = {}

    def walk(o: Any, pre: str) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                walk(v, f"{pre}{k}.")
        elif not isinstance(o, list):
            out[pre[:-1]] = str(o)
    walk(obj, "")
    return out


# ------------------------------------------------------------------ MongoDB

_MONGO_KEEP = {"Successfully authenticated", "Failed to authenticate",
               "Connection accepted", "Connection ended", "Checking authorization failed"}


def _mongo_keep(line: str) -> bool:
    try:
        return json.loads(line).get("msg") in _MONGO_KEEP
    except (json.JSONDecodeError, ValueError):
        return False


MONGODB = Spec(
    source_id="mongodb_log",
    family="mongodb",
    software="MongoDB 7.0 (image mongo:7)",
    category="database",
    contamination="medium",
    notes=("NESTED JSON, AND ONE CONCEPT UNDER TWO KEYS. The client endpoint is "
           "`attr.client` on authentication lines and `attr.remote` on connection "
           "lines, as `ip:port` in one string; the IR cannot split a json value, so "
           "source.address is the only home that holds it whole. The IR also allows "
           "one key per ECS field, so a parser can claim only one of the two keys - "
           "the author must decide whether truth keeps both. Capture limited to the "
           "ACCESS and NETWORK messages an authentication monitor reads."),
    documentation="""
# MongoDB 7.0 — structured server log (JSON)

Source: MongoDB manual, "Log Messages",
https://www.mongodb.com/docs/manual/reference/log-messages/

Since 4.4 every log line is one JSON object. The lines here are the ACCESS and
NETWORK messages an authentication monitor reads: successful and failed
authentications, authorization failures, connections opened and closed.

## Top-level keys

- `t` — timestamp, an object `{"$date": "<ISO 8601>"}`
- `s` — severity: `F` fatal, `E` error, `W` warning, `I` informational, `D1`-`D5` debug
- `c` — the component that logged the message: `ACCESS`, `NETWORK`, `COMMAND`, ...
- `id` — a unique numeric identifier of the log statement in the server source
- `ctx` — the name of the thread that logged it: `conn12`, `listener`
- `msg` — the human-readable text of the log statement
- `attr` — an object of attributes, different per message

## attr, on the messages captured

- `attr.client` — the client's network address and port, `ip:port` (authentication messages)
- `attr.remote` — the remote (client) address and port, `ip:port` (connection messages)
- `attr.user` — the account the client authenticated as, or tried to
- `attr.db` — the database the account is defined in (the authentication database)
- `attr.mechanism` — the SASL mechanism: `SCRAM-SHA-256`, `SCRAM-SHA-1`
- `attr.error` — the error message of a failed authentication
- `attr.result` — the server error code of the attempt; `0` on success,
  `18` (AuthenticationFailed), `11` (UserNotFound)
- `attr.connectionId` — the server's number for the connection
- `attr.connectionCount` — how many connections were open after this one
- `attr.doc` — client metadata the driver sends: application, driver, os, platform
""",
    keep=_mongo_keep,
    extract=_flat_json_dotted,
    fields=[
        _f("s", "log.level", "keyword", "severity", "medium",
           "A one-letter severity code (I, W, E, F). ECS log.level holds the source's own "
           "level vocabulary, so the code itself is correct."),
        _f("c", "log.logger", "keyword", "logging_component", "hard",
           "The server component that wrote the line; the closest ECS notion is the name "
           "of the logger inside the application."),
        _f("id", "event.code", "keyword", "message_identifier", "medium",
           "Identifies the log statement, not the event instance."),
        _f("ctx", "process.thread.name", "keyword", "thread_name", "hard"),
        _f("msg", "message", "text", "message_text", "easy"),
        _f("attr.client", "source.address", "keyword", "client_endpoint", "hard",
           "ip:port in one string. source.ip would hold a value that is not an IP."),
        _f("attr.remote", None, "keyword", "client_endpoint", "hard",
           "The same endpoint as attr.client (source.address), on connection lines. The IR "
           "gives a field to ONE key (corpus/validate.py one_key_per_field), so declining "
           "here is accepted; DRAFT - author to decide which of the two keys owns it.",
           abstain=True),
        _f("attr.user", "user.name", "keyword", "account", "easy"),
        _f("attr.db", None, "keyword", "authentication_database", "ambiguous",
           "The database the account is defined in. user.domain is plausible and "
           "debatable; declining is correct.", abstain=True),
        _f("attr.mechanism", None, "keyword", "authentication_mechanism", "ambiguous",
           "ECS 8.11 has no field for the authentication method.", abstain=True),
        _f("attr.error", "error.message", "text", "error_text", "medium"),
        _f("attr.result", "error.code", "keyword", "error_code", "medium",
           "0 on success; 18 and 11 are failure codes. A code, not a count."),
        _f("attr.connectionId", None, "long", "connection_number", "ambiguous",
           "Correlates lines of one connection; no ECS field describes it.", abstain=True),
        _f("attr.connectionCount", None, "long", "open_connections", "ambiguous",
           "A gauge of the server, not a property of the event.", abstain=True),
    ],
    unqueryable={
        "message": "match_only_text is analysed, so a term query would measure the analyser",
        "error.message": "match_only_text is analysed",
    },
    # DEV, NOT TEST, AND THE REASON IS THE RETRIEVAL, NOT THE SOURCE.
    # The authentication lines carry the driver's metadata (attr.doc.os.name,
    # attr.doc.driver.version, ...). Observed keys are harvested as LEAF names
    # (adapter/types.py `_json_keys`), so `name`, `id` and `version` rank every
    # ECS field ending in those words first, the 320-field budget is spent, and
    # source.address, error.code and error.message are never offered
    # (tests/test_retrieval.py). Any arm would then be charged for a retrieval
    # miss. Promote to "test" once retrieval reads nested json by dotted path.
    split="dev",
    deferred=("retrieval cannot offer source.address, error.code, error.message for "
              "nested json with driver metadata (tests/test_retrieval.py)"),
)


# ------------------------------------------------------------------ Dovecot

_DOVECOT_LOGIN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2} +\d+ [\d:]+) (?P<process>[\w-]+-login): (?P<level>\w+): "
    r"(?P<event>.+?): user=<(?P<user>[^>]*)>, method=(?P<method>[\w-]+), "
    r"rip=(?P<rip>[0-9a-fA-F.:]+), lip=(?P<lip>[0-9a-fA-F.:]+)"
    r"(?:, mpid=(?P<mpid>\d+))?, session=<(?P<session>[^>]+)>")
_DOVECOT_AUTH = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2} +\d+ [\d:]+) (?P<process>auth): (?P<level>\w+): "
    r"(?P<backend>[\w-]+)\((?P<user>[^,]*),(?P<rip>[^,]*),<(?P<session>[^>]+)>\): "
    r"(?P<reason>.+)$")


def _dovecot(line: str) -> dict[str, str]:
    for rx in (_DOVECOT_LOGIN, _DOVECOT_AUTH):
        m = rx.match(line)
        if m:
            return {k: v for k, v in m.groupdict().items() if v is not None}
    return {}


DOVECOT = Spec(
    source_id="dovecot_auth",
    family="dovecot",
    software="Dovecot 2.3.21 (image dovecot/dovecot:2.3.21)",
    category="email",
    contamination="medium",
    notes=("FREE TEXT WITH KEY=VALUE INSIDE, AND THE REPORTER IS ONE OF THE ENDPOINTS. "
           "`rip` is the client and `lip` is the server's own address: the destination "
           "of the connection AND the device writing the line. destination.ip is drafted "
           "because rules about a flow read the destination; observer.ip is defensible and "
           "the author must decide. Two line shapes - the login processes and the auth "
           "process - carry the client address under different syntax. The capture names "
           "are fixed in documentation.md, as for every free-text source."),
    documentation="""
# Dovecot 2.3 — login and authentication log

Source: Dovecot documentation, "Logging" and the login_log_format settings,
https://doc.dovecot.org/2.3/configuration_manual/logging/ and
https://doc.dovecot.org/2.3/settings/core/#core_setting-login_log_format_elements

Dovecot's default log line is a timestamp, the process that wrote it, a level,
and the message. Two processes are captured here.

## Login processes: `imap-login`, `pop3-login`

    <timestamp> <process>: <level>: <event>: user=<<user>>, method=<method>, rip=<rip>, lip=<lip>[, mpid=<mpid>], session=<<session>>

- `event` — what happened: `Login`, or `Disconnected: Connection closed (auth failed, N attempts in M secs)`
- `user` — the account the client logged in as, or tried to
- `method` — the SASL mechanism: `PLAIN`, `LOGIN`
- `rip` — the REMOTE IP: the client's address
- `lip` — the LOCAL IP: the address of this server the client connected to
- `mpid` — the pid of the mail process started for the session (successful logins only)
- `session` — Dovecot's session identifier, the same on every line of one session

## Authentication process: `auth`

    <timestamp> auth: <level>: <backend>(<user>,<rip>,<<session>>): <reason>

- `backend` — the password database that answered: `passwd-file`
- `user`, `rip`, `session` — as above
- `reason` — why authentication failed: `Password mismatch`, `unknown user`

## Fields common to both

- `timestamp` — `Mmm dd HH:MM:SS`, local time, no year
- `process` — the Dovecot process that wrote the line
- `level` — `Info`, `Warning`, `Error`, `Fatal`
""",
    keep=lambda ln: bool(_dovecot(ln)),
    extract=_dovecot,
    fields=[
        _f("process", "process.name", "keyword", "logging_process", "medium"),
        _f("level", "log.level", "keyword", "severity", "easy"),
        _f("event", "event.action", "keyword", "event_description", "hard",
           "`Login` or a disconnection with its cause. event.action takes the source's own "
           "vocabulary; an outcome would need a value map over a free-text phrase."),
        _f("user", "user.name", "keyword", "account", "easy"),
        _f("method", None, "keyword", "authentication_mechanism", "ambiguous",
           "ECS 8.11 has no field for the SASL mechanism.", abstain=True),
        _f("rip", "source.ip", "ip", "client_ip", "medium",
           "The REMOTE address, i.e. where the connection came from."),
        _f("lip", "destination.ip", "ip", "server_local_ip", "hard",
           "This server's own address. destination.ip (flow) and observer.ip (reporter) "
           "are both defensible - DRAFT, author to decide; source.ip is wrong."),
        _f("mpid", None, "long", "mail_process_pid", "ambiguous",
           "The pid of a DIFFERENT process from the one that wrote the line, so process.pid "
           "would describe the wrong process.", abstain=True),
        _f("session", None, "keyword", "session_identifier", "ambiguous",
           "Correlates the lines of one session; ECS 8.11 has no session identifier.",
           abstain=True),
        _f("backend", None, "keyword", "password_database", "ambiguous",
           "The authentication backend; no ECS field describes it.", abstain=True),
        _f("reason", "event.reason", "keyword", "failure_reason", "medium"),
    ],
)


# ------------------------------------------------------------- Apache httpd

_HTTPD = re.compile(
    r"^\[(?P<timestamp>[^\]]+)\] \[(?P<module>[\w-]+):(?P<level>\w+)\] "
    r"\[pid (?P<pid>\d+):tid (?P<tid>\d+)\] "
    r"\[client (?P<client_ip>[0-9a-fA-F.:]+?):(?P<client_port>\d+)\] "
    r"(?P<code>AH\d+): (?P<rest>.*?)(?:, referer: (?P<referer>\S+))?$")
_HTTPD_MSG = (
    re.compile(r'^user (?P<user>\S+): authentication failure for "(?P<url_path>[^"]+)": '
               r"(?P<reason>.+)$"),
    re.compile(r"^user (?P<user>\S+) (?P<reason>not found): (?P<url_path>\S+)$"),
    re.compile(r"^(?P<reason>client denied by server configuration): (?P<file_path>\S+)$"),
)


def _httpd(line: str) -> dict[str, str]:
    m = _HTTPD.match(line)
    if not m:
        return {}
    out = {k: v for k, v in m.groupdict().items() if v is not None and k != "rest"}
    for rx in _HTTPD_MSG:
        mm = rx.match(m.group("rest"))
        if mm:
            out.update(mm.groupdict())
            break
    return out


APACHE = Spec(
    source_id="apache_error",
    family="apache-httpd",
    software="Apache httpd 2.4.62 (image httpd:2.4.62)",
    category="web",
    contamination="high",
    notes=("FREE TEXT, BRACKETED FIELDS, AND TWO KINDS OF PATH. The request path of an "
           "authentication failure is a URL path; the path of a denied request is a "
           "FILESYSTEM path the server resolved it to - url.path versus file.path is the "
           "URL-granularity confusion of bench/HELDOUT.md. Contamination is HIGH: the "
           "Apache error-log format is widely reproduced. Capture names fixed in "
           "documentation.md; only error-log lines are kept (the access log shares stdout)."),
    documentation="""
# Apache httpd 2.4 — error log

Source: Apache HTTP Server documentation, "ErrorLogFormat" and "Log Files",
https://httpd.apache.org/docs/2.4/mod/core.html#errorlogformat and
https://httpd.apache.org/docs/2.4/logs.html#errorlog

With the default ErrorLogFormat a line reads

    [<timestamp>] [<module>:<level>] [pid <pid>:tid <tid>] [client <client_ip>:<client_port>] <code>: <message>[, referer: <referer>]

- `timestamp` — `Www Mmm dd HH:MM:SS.uuuuuu yyyy`
- `module` — the module that logged the message: `auth_basic`, `authz_core`
- `level` — the log level: `error`, `warn`, `info`, ...
- `pid`, `tid` — the process and thread of the server worker
- `client_ip`, `client_port` — the address and port of the client that sent the request
- `code` — Apache's message identifier, `AH` and five digits
- `referer` — the Referer header of the request, when the client sent one

## The three messages captured, and the names of their parts

    AH01617: user <user>: authentication failure for "<url_path>": <reason>
    AH01618: user <user> <reason>: <url_path>          (reason is "not found")
    AH01630: <reason>: <file_path>                      (reason is "client denied by server configuration")

- `user` — the account in the request's credentials
- `url_path` — the path of the requested URL
- `file_path` — the file system path the request was resolved to
- `reason` — why the request was refused
""",
    keep=lambda ln: bool(_httpd(ln)),
    extract=_httpd,
    fields=[
        _f("module", "log.logger", "keyword", "logging_module", "hard",
           "The server module that wrote the line."),
        _f("level", "log.level", "keyword", "severity", "easy"),
        _f("pid", None, "long", "worker_pid", "ambiguous",
           "Correct ECS home: process.pid. Declining is accepted ONLY because the `web` "
           "fieldset this benchmark offers cannot reach process.* "
           "(tests/test_corpus.py); DRAFT - author to decide whether to widen `web`.",
           abstain=True),
        _f("tid", None, "long", "worker_thread_id", "ambiguous",
           "Correct ECS home: process.thread.id; unreachable from `web`, as pid.",
           abstain=True),
        _f("client_ip", "source.ip", "ip", "client_ip", "easy",
           "client.ip is equivalent for scoring."),
        _f("client_port", "source.port", "long", "client_port", "easy"),
        _f("code", "event.code", "keyword", "message_identifier", "medium"),
        _f("user", "user.name", "keyword", "account", "easy"),
        _f("url_path", "url.path", "keyword", "request_path", "medium"),
        _f("file_path", None, "keyword", "filesystem_path", "hard",
           "Correct ECS home: file.path - where the URL resolved to on disk; url.path would "
           "be WRONG. Declining is accepted only because `web` cannot reach file.*; DRAFT - "
           "author to decide (widening `web` restores the URL-granularity test).",
           abstain=True),
        _f("reason", "event.reason", "keyword", "refusal_reason", "medium"),
        _f("referer", "http.request.referrer", "keyword", "referrer", "medium"),
    ],
)


# ------------------------------------------------------------------- BIND 9

_BIND = re.compile(
    r"^(?P<timestamp>\d{2}-[A-Z][a-z]{2}-\d{4} [\d:.]+) client @(?P<client_object>0x[0-9a-f]+) "
    r"(?P<client_ip>[0-9a-fA-F.:]+)#(?P<client_port>\d+) \((?P<query_name>[^)]+)\): (?P<rest>.*)$")
_BIND_REST = (
    re.compile(r"^query: \S+ (?P<query_class>[A-Z]+) (?P<query_type>[A-Z0-9]+) (?P<flags>\S+) "
               r"\((?P<server_ip>[0-9a-fA-F.:]+)\)$"),
    re.compile(r"^(?P<action>query \(cache\)|zone transfer) '(?P<question>[^']+)' denied"
               r"(?: \((?P<reason>[^)]+)\))?$"),
    re.compile(r"^query failed \((?P<response_code>[A-Z]+)\) for (?P<question>\S+) at "
               r"(?P<code_location>\S+)$"),
)


def _bind(line: str) -> dict[str, str]:
    m = _BIND.match(line)
    if not m:
        return {}
    out = {k: v for k, v in m.groupdict().items() if k != "rest"}
    for rx in _BIND_REST:
        mm = rx.match(m.group("rest"))
        if mm:
            out.update({k: v for k, v in mm.groupdict().items() if v is not None})
            break
    return out


BIND = Spec(
    source_id="bind_query",
    family="bind9",
    software="BIND 9.18.50 (image internetsystemsconsortium/bind9:9.18)",
    category="network",
    contamination="medium",
    notes=("FREE TEXT; THE CLIENT AND THE SERVER ARE ON THE SAME LINE. The client is "
           "`ip#port` after the client object; the address the query was SENT TO - this "
           "server, also the reporter - closes the line in parentheses. destination.ip is "
           "drafted (observer.ip defensible, author to decide). Three message shapes: the "
           "query itself, a refusal (cache query or zone transfer), and a failure with its "
           "DNS response code. Capture names fixed in documentation.md."),
    documentation="""
# BIND 9.18 — query and security log

Source: BIND 9 Administrator Reference Manual, "logging" statement and the
`queries`, `security` and `xfer-out` categories,
https://bind9.readthedocs.io/en/v9.18.50/reference.html#logging-block

Every line starts with the time and the client that sent the request:

    <timestamp> client @<client_object> <client_ip>#<client_port> (<query_name>): <message>

- `timestamp` — `dd-Mmm-yyyy HH:MM:SS.mmm`
- `client_object` — the memory address of the server's client object, for debugging
- `client_ip`, `client_port` — where the query came from
- `query_name` — the name the query is about

## The three messages captured

    query: <query_name> <query_class> <query_type> <flags> (<server_ip>)
    <action> '<question>' denied[ (<reason>)]
    query failed (<response_code>) for <question> at <code_location>

- `query_class` — the DNS class, `IN`
- `query_type` — the record type asked for: `A`, `AAAA`, `MX`, `TXT`, `AXFR`, ...
- `flags` — `+` recursion requested, `-` not; `E(0)` EDNS version 0, `T` TCP, `K` cookie
- `server_ip` — the address of this server the query was sent to
- `action` — what was refused: `query (cache)` or `zone transfer`
- `question` — `name/type/class` of the refused request
- `reason` — which access-control list refused it
- `response_code` — the DNS response code sent back: `REFUSED`, `SERVFAIL`, ...
- `code_location` — the source file and line in BIND that logged the failure
""",
    keep=lambda ln: bool(_bind(ln)),
    extract=_bind,
    fields=[
        _f("client_object", None, "keyword", "debug_handle", "ambiguous",
           "A memory address; no ECS field describes it.", abstain=True),
        _f("client_ip", "source.ip", "ip", "client_ip", "easy"),
        _f("client_port", "source.port", "long", "client_port", "easy"),
        _f("query_name", "dns.question.name", "keyword", "queried_name", "easy"),
        _f("query_class", "dns.question.class", "keyword", "query_class", "medium"),
        _f("query_type", "dns.question.type", "keyword", "query_type", "medium"),
        _f("flags", None, "keyword", "query_flags", "ambiguous",
           "BIND's own flag notation; dns.header_flags holds header flag NAMES (RD, AA), "
           "not this string.", abstain=True),
        _f("server_ip", "destination.ip", "ip", "server_ip", "hard",
           "The server the query was sent to, which also wrote the line. destination.ip "
           "drafted; observer.ip defensible - author to decide. source.ip is wrong."),
        _f("action", "event.action", "keyword", "refused_operation", "medium"),
        _f("question", None, "keyword", "refused_question", "ambiguous",
           "name/type/class in one string; no single ECS field holds the triple.",
           abstain=True),
        _f("reason", "event.reason", "keyword", "refusal_reason", "medium"),
        _f("response_code", "dns.response_code", "keyword", "dns_response_code", "medium"),
        _f("code_location", None, "keyword", "source_code_location", "ambiguous",
           "Where in BIND's source the line was logged; log.origin.file.name/line split it "
           "and the IR cannot split one capture.", abstain=True),
    ],
)


# ----------------------------------------------------------------- Keycloak

_KC_HEAD = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} [\d:,]+) (?P<level>[A-Z]+) +\[(?P<logger>[\w.]+)\] "
    r"\((?P<thread>[^)]+)\) (?P<rest>type=\".*)$")
_KC_PAIR = re.compile(r'(\w+)="([^"]*)"')


def _keycloak(line: str) -> dict[str, str]:
    m = _KC_HEAD.match(line)
    if not m:
        return {}
    out = {k: v for k, v in m.groupdict().items() if k != "rest"}
    out.update(dict(_KC_PAIR.findall(m.group("rest"))))
    return out


_KC_ABSTAIN = [
    ("realmId", "tenant_identifier", "The realm (tenant) the event belongs to, as a UUID; ECS "
     "8.11 has no tenant field."),
    ("sessionId", "session_identifier", "No ECS session identifier."),
    ("auth_method", "authentication_protocol", "The protocol (openid-connect); no ECS field."),
    ("grant_type", "oauth_grant_type", "The OAuth grant used; no ECS field."),
    ("client_auth_method", "client_authentication_method", "No ECS field."),
    ("token_id", "token_identifier", "Correlates tokens; no ECS field."),
    ("refresh_token_id", "token_identifier", "As token_id."),
    ("refresh_token_type", "token_type", "No ECS field."),
    ("scope", "oauth_scope", "Granted OAuth scopes; no ECS field."),
    ("authSessionParentId", "session_identifier", "As sessionId."),
    ("authSessionTabId", "session_identifier", "A browser-tab discriminator; no ECS field."),
]

KEYCLOAK = Spec(
    source_id="keycloak_events",
    family="keycloak",
    software="Keycloak 24.0.5 (image quay.io/keycloak/keycloak:24.0.5), jboss-logging events listener",
    category="authentication",
    contamination="medium",
    notes=("JAVA LOG PREAMBLE, THEN QUOTED KEY=VALUE PAIRS SEPARATED BY COMMA AND SPACE - and "
           "the timestamp itself contains a comma. WHICH ENTITY: `clientId` is the OAuth "
           "client, an APPLICATION registered in Keycloak, not the network client - client.* "
           "would be wrong; `userId` is Keycloak's internal UUID and `username` the login "
           "name, so user.id and user.name are not interchangeable. `userId` is the literal "
           "string `null` when the account does not exist. Most keys have no ECS home and are "
           "acceptable abstentions."),
    documentation="""
# Keycloak 24 — login events (jboss-logging event listener)

Source: Keycloak Server Administration Guide, "Auditing and events",
https://www.keycloak.org/docs/24.0.5/server_admin/#auditing-and-events and the
event type reference https://www.keycloak.org/docs-api/24.0.5/javadocs/org/keycloak/events/EventType.html

The listener writes one line per event through the server's Java logging:

    <timestamp> <level> [<logger>] (<thread>) type="<type>", realmId="...", clientId="...", ...

- `timestamp` — `yyyy-MM-dd HH:mm:ss,SSS`
- `level` — `INFO` for successful events, `WARN` for errors (as configured here)
- `logger` — the Java logger, `org.keycloak.events`
- `thread` — the server thread that handled the request

## The event attributes, as key="value" pairs

- `type` — the event type: `LOGIN`, `LOGIN_ERROR`, ...
- `realmId` — the realm (tenant) the event happened in, as a UUID
- `clientId` — the OAuth client - the APPLICATION - the login was for
- `userId` — Keycloak's id of the user, a UUID; `null` if the user does not exist
- `username` — the login name that was submitted
- `ipAddress` — the address the request came from
- `error` — on an error event, its code: `invalid_user_credentials`, `user_not_found`, `client_not_found`
- `sessionId`, `authSessionParentId`, `authSessionTabId` — session identifiers
- `auth_method` — the protocol, `openid-connect`
- `grant_type` — the OAuth grant, `password` here
- `client_auth_method` — how the client authenticated
- `token_id`, `refresh_token_id`, `refresh_token_type`, `scope` — the tokens issued on success
""",
    keep=lambda ln: "[org.keycloak.events]" in ln and bool(_keycloak(ln)),
    extract=_keycloak,
    fields=[
        _f("level", "log.level", "keyword", "severity", "easy"),
        _f("logger", "log.logger", "keyword", "java_logger", "medium"),
        _f("thread", "process.thread.name", "keyword", "worker_thread", "medium"),
        _f("type", "event.action", "keyword", "event_type", "medium"),
        _f("clientId", None, "keyword", "oauth_application", "hard",
           "The APPLICATION the login was for. client.* describes the network client and "
           "would be WRONG; ECS 8.11 has no field for an OAuth client id.", abstain=True),
        _f("userId", "user.id", "keyword", "user_uuid", "medium",
           "Keycloak's UUID for the account; `null` when it does not exist."),
        _f("username", "user.name", "keyword", "login_name", "easy"),
        _f("ipAddress", "source.ip", "ip", "client_ip", "easy"),
        _f("error", "event.reason", "keyword", "error_code", "medium",
           "A short error code. error.code is defensible but outside the authentication "
           "fieldset this benchmark offers; DRAFT - author to decide."),
    ] + [_f(k, None, "keyword", role, "ambiguous", note, abstain=True)
         for k, role, note in _KC_ABSTAIN],
)


# ----------------------------------------------------------- MariaDB audit

_MARIADB_COLUMNS = ["timestamp", "serverhost", "username", "host", "connectionid",
                    "queryid", "operation", "database", "object", "retcode"]


def _mariadb(line: str) -> dict[str, str]:
    import csv
    import io

    row = next(csv.reader(io.StringIO(line), quotechar="'"), [])
    if len(row) != len(_MARIADB_COLUMNS):
        return {}
    return dict(zip(_MARIADB_COLUMNS, row))


MARIADB = Spec(
    source_id="mariadb_audit",
    family="mariadb",
    software="MariaDB 11.4.4 (image mariadb:11.4.4), server_audit plugin",
    category="database",
    contamination="medium",
    notes=("CSV WITHOUT A HEADER, AND A COLUMN NAMED FOR THE WRONG ENTITY. `host` is the "
           "CLIENT's address - source.ip; host.* would describe the database server, which "
           "is `serverhost`. The query text in `object` is single-quoted. ECS 8.11 has no "
           "database fieldset, so the database name, the statement and the connection id "
           "are acceptable abstentions."),
    documentation="""
# MariaDB 11.4 — server_audit plugin log (CSV)

Source: MariaDB Knowledge Base, "MariaDB Audit Plugin - Log Format",
https://mariadb.com/kb/en/mariadb-audit-plugin-log-format/

One event per line, comma-separated, no header, in this column order:

    timestamp,serverhost,username,host,connectionid,queryid,operation,database,object,retcode

- `timestamp` — `yyyyMMdd HH:mm:ss`, server local time
- `serverhost` — the host name of the MariaDB server writing the log
- `username` — the account the client connected as
- `host` — the host the CLIENT connected FROM (its address)
- `connectionid` — the server's connection number
- `queryid` — the query number within the connection; 0 for connection events
- `operation` — `CONNECT`, `FAILED_CONNECT`, `DISCONNECT`, `QUERY`, ...
- `database` — the default database of the connection, empty when none
- `object` — for QUERY, the statement text in single quotes; empty otherwise
- `retcode` — the server's return code: 0 on success, 1045 access denied, ...
""",
    keep=lambda ln: bool(_mariadb(ln)),
    extract=_mariadb,
    fields=[
        _f("serverhost", "host.hostname", "keyword", "server_hostname", "hard",
           "The database SERVER that wrote the line - also the reporter; observer.hostname "
           "defensible, DRAFT."),
        _f("username", "user.name", "keyword", "account", "easy"),
        _f("host", "source.ip", "ip", "client_address", "hard",
           "Named `host` but it is the CLIENT: host.ip would put the client in the server's "
           "place."),
        _f("connectionid", None, "long", "connection_number", "ambiguous",
           "Correlates a connection's lines; no ECS field.", abstain=True),
        _f("queryid", None, "long", "query_number", "ambiguous", "No ECS field.", abstain=True),
        _f("operation", "event.action", "keyword", "audit_operation", "medium"),
        _f("database", None, "keyword", "database_name", "ambiguous",
           "ECS 8.11 has no database fieldset.", abstain=True),
        _f("object", None, "keyword", "sql_statement", "ambiguous",
           "The SQL statement; ECS 8.11 has no field for it.", abstain=True),
        _f("retcode", "error.code", "keyword", "return_code", "medium",
           "0 is success; 1045 is access denied. A code, not a count."),
    ],
)


# ------------------------------------------------------------------- Exim

_EXIM_TS = r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
_EXIM_ID = r"(?P<msgid>[0-9A-Za-z]{6}-[0-9A-Za-z]{6}-[0-9A-Za-z]{2})"
_EXIM_HOST = (r"H=(?P<host_name>\S+) \((?P<helo>[^)]+)\) "
              r"\[(?P<host_ip>[0-9a-fA-F.:]+)\]")
_EXIM = (
    re.compile(rf"^{_EXIM_TS} {_EXIM_ID} (?P<flag><=) (?P<sender>\S+) {_EXIM_HOST} "
               r"P=(?P<protocol>\S+) S=(?P<size>\d+)"),
    re.compile(rf"^{_EXIM_TS} {_EXIM_ID} (?P<flag>=>) (?P<local_part>\S+)(?: \([^)]*\))? "
               r"<(?P<recipient>[^>]+)> R=(?P<router>\S+) T=(?P<transport>\S+)"),
    re.compile(rf"^{_EXIM_TS} {_EXIM_ID} (?P<flag>Completed)$"),
    re.compile(rf"^{_EXIM_TS} {_EXIM_HOST} F=<(?P<sender>[^>]*)> (?P<flag>rejected RCPT) "
               r"<(?P<recipient>[^>]+)>: (?P<reason>.+)$"),
)


def _exim(line: str) -> dict[str, str]:
    for rx in _EXIM:
        m = rx.match(line)
        if m:
            return {k: v for k, v in m.groupdict().items() if v is not None}
    return {}


EXIM = Spec(
    source_id="exim_main",
    family="exim",
    software="Exim 4.96 (Debian 12 package exim4-daemon-light, image debian:12.8-slim)",
    category="email",
    contamination="medium",
    notes=("FREE TEXT WITH LETTER=VALUE TAGS AND SYMBOLIC FLAGS. Four line shapes share a "
           "timestamp; three carry Exim's queue id. WHICH IDENTIFIER: the queue id is "
           "email.local_id - email.message_id is the RFC 5322 Message-ID header, which this "
           "log does not carry. The client is named three ways on one line: reverse-DNS name "
           "(H=), the name it gave in HELO (in parentheses), and its address (in brackets). "
           "The reverse-DNS names here are the Docker client containers' names, as a real "
           "MTA would resolve them."),
    documentation="""
# Exim 4.96 — main log

Source: Exim Specification, chapter 52 "Log files", sections "Logging message
reception", "Logging deliveries" and "Log line flags",
https://www.exim.org/exim-html-4.96/doc/html/spec_html/ch-log_files.html

Every line starts with a timestamp; lines about one message carry its queue id.

    <timestamp> <msgid> <= <sender> H=<host_name> (<helo>) [<host_ip>] P=<protocol> S=<size>
    <timestamp> <msgid> => <local_part> [(<address>)] <<recipient>> R=<router> T=<transport>
    <timestamp> <msgid> Completed
    <timestamp> H=<host_name> (<helo>) [<host_ip>] F=<<sender>> rejected RCPT <<recipient>>: <reason>

- `timestamp` — `yyyy-mm-dd HH:MM:SS`
- `msgid` — Exim's own id for the message in its queue
- `flag` — `<=` message arrival, `=>` normal delivery, `Completed`, or `rejected RCPT`
- `sender` — the envelope sender address
- `recipient` — the envelope recipient address
- `host_name` — the sending host's name, from reverse DNS
- `helo` — the name the sending host gave in its HELO/EHLO command
- `host_ip` — the sending host's IP address
- `protocol` — the protocol the message was received with: `esmtp`, `smtp`, `local`
- `size` — the message size in bytes
- `local_part` — the local mailbox the message was delivered to
- `router`, `transport` — the Exim router and transport that delivered it
- `reason` — why the recipient was refused
""",
    keep=lambda ln: bool(_exim(ln)),
    extract=_exim,
    fields=[
        _f("msgid", "email.local_id", "keyword", "queue_id", "hard",
           "Exim's queue id. email.message_id is the Message-ID header and would be wrong."),
        _f("flag", "event.action", "keyword", "log_line_flag", "hard",
           "Symbolic: <= arrival, => delivery. event.action takes the source's own vocabulary."),
        _f("sender", "email.from.address", "keyword", "envelope_sender", "medium"),
        _f("recipient", "email.to.address", "keyword", "envelope_recipient", "medium"),
        _f("host_name", "source.domain", "keyword", "sender_rdns_name", "hard",
           "The sending host's name from reverse DNS; not the HELO name."),
        _f("helo", None, "keyword", "helo_name", "ambiguous",
           "The name the client CLAIMED in HELO. ECS 8.11 has no field for it; source.domain "
           "belongs to the reverse-DNS name.", abstain=True),
        _f("host_ip", "source.ip", "ip", "sender_ip", "easy"),
        _f("protocol", "network.protocol", "keyword", "reception_protocol", "medium"),
        _f("size", None, "long", "message_size", "ambiguous",
           "Message size in bytes; ECS 8.11 has no email size field.", abstain=True),
        _f("local_part", "user.name", "keyword", "local_mailbox", "hard",
           "The local account the message was delivered to. DRAFT - author to decide."),
        _f("router", None, "keyword", "exim_router", "ambiguous", "No ECS field.", abstain=True),
        _f("transport", None, "keyword", "exim_transport", "ambiguous", "No ECS field.",
           abstain=True),
        _f("reason", "event.reason", "keyword", "rejection_reason", "medium"),
    ],
)


SPECS: dict[str, Spec] = {s.source_id: s for s in (MONGODB, DOVECOT, APACHE, BIND, KEYCLOAK, MARIADB, EXIM)}

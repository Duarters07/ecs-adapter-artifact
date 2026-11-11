"""Plain-language roles for generated training targets, and what documentation may say.

Two defects of the first gold corpus (R5, 2026-10-15), both found on 2026-10-16
before any student was trained on it:

THE ANSWER WAS IN THE QUESTION
------------------------------
`siemgen_gold.documentation()` listed every key with `role_text(ecs_field)`, and
`roles_for()` gave stage 1 the same `role_text(ecs_field)` as its target. Stage
1's input therefore carried its own answer verbatim: it would have learned to
copy a line of the documentation, a skill no real vendor document rewards.
Documentation now draws from DOC_TEXT, a separate vocabulary in a vendor's
terse register, and `leaks()` is the check the dataset builder applies to every
interpret example (training/build_dataset.py).

ONE PHRASE PER FIELD IS A LABEL, NOT A ROLE
-------------------------------------------
56 distinct phrasings over 16,289 role instances: stage 1 was being taught to
pick one of 56 strings, an ECS field in disguise, and stage 2 to look the string
up. The blindness between the stages held in form and not in substance. The UEBA
paper this design borrows from varied its grounded targets across several
templates per verdict for the same reason (uebaslmjournal, Sec. 5.2). Each field
now has several phrasings; which one a target gets is a stable function of the
source and the key, so a rebuild is byte-identical and two keys of one source
can read differently.

No phrasing names an ECS field (tests/test_blindness.py, tests/test_roles.py).
"""
from __future__ import annotations

import hashlib
import re

ROLE_VARIANTS: dict[str, tuple[str, ...]] = {
    # The key the IR's `timestamp` block reads. Stage 1 must name it like any
    # other key: until 2026-10-17 the gold answers left it out in 1,301 of
    # 1,301 cases, and the student learned that a key may go unmentioned.
    "@timestamp": (
        "moment the record was written",
        "time at which the event happened",
        "date and time the line refers to",
    ),
    "source.ip": (
        "address the connection or request came from",
        "IP address of the client that initiated it",
        "network address of the originating side",
        "where the traffic or request originated, as an IP",
    ),
    "source.port": (
        "port on the side that opened the connection",
        "originating port number",
        "client-side port of the connection",
    ),
    "source.domain": (
        "host name of the originating side",
        "name of the machine the request came from",
        "domain of the client that initiated it",
    ),
    "source.bytes": (
        "bytes sent by the originating side",
        "volume the client transmitted, in bytes",
        "byte count from the initiator",
    ),
    "source.packets": (
        "packets sent by the originating side",
        "number of packets the initiator transmitted",
        "client-to-server packet count",
    ),
    "destination.ip": (
        "address the connection was made to",
        "IP address of the receiving side",
        "network address the traffic was sent to",
    ),
    "destination.port": (
        "port on the receiving side",
        "port number the connection targeted",
        "server-side port of the connection",
    ),
    "destination.address": (
        "address or name of the receiving side, as written",
        "target the connection went to, IP or host name",
        "the remote end the request was forwarded to",
    ),
    "destination.bytes": (
        "bytes sent back by the receiving side",
        "volume the server returned, in bytes",
        "byte count from the responder",
    ),
    "destination.packets": (
        "packets sent back by the receiving side",
        "number of packets the responder transmitted",
        "server-to-client packet count",
    ),
    "observer.ip": (
        "address of the appliance that reported the event",
        "IP of the device that saw and logged the traffic",
        "network address of the reporting sensor",
    ),
    "observer.name": (
        "name of the appliance that reported the event",
        "label of the device that logged it",
        "identifier of the reporting sensor or proxy",
    ),
    "observer.hostname": (
        "name of the device that reported the event",
        "host name of the reporting appliance",
        "machine name of the sensor that logged it",
    ),
    "observer.ingress.interface.name": (
        "interface the device saw the traffic on",
        "network interface the packet arrived on",
        "inbound interface label",
    ),
    "user.name": (
        "account that performed the action",
        "user name the activity is attributed to",
        "login of the person or service acting",
        "the account involved",
    ),
    "user.id": (
        "numeric identifier of the account that performed the action",
        "user id number of the actor",
        "numeric uid of the acting account",
    ),
    "user.domain": (
        "domain or realm the acting account belongs to",
        "authentication domain of the user",
        "directory or workgroup of the account",
    ),
    "user.email": (
        "mail address of the acting account",
        "user's e-mail address",
        "email identity of the person acting",
    ),
    "user.full_name": (
        "display name of the acting person",
        "the user's full human-readable name",
        "first and last name of the account holder",
    ),
    "user.effective.name": (
        "account the action ran as",
        "user the command was executed as",
        "identity assumed for the action",
    ),
    "user.effective.id": (
        "numeric identifier of the account the action ran as",
        "effective uid of the action",
        "numeric id of the identity assumed",
    ),
    "user.audit.id": (
        "login identity the kernel attributes the action to",
        "original login uid kept across privilege changes",
        "audit uid of the session",
    ),
    "process.pid": (
        "identifier of the process that wrote the line",
        "process id of the emitting program",
        "numeric pid of the writer",
    ),
    "process.parent.pid": (
        "identifier of the parent process",
        "pid of the process that spawned it",
        "parent's process number",
    ),
    "process.name": (
        "short name of the program that ran",
        "program name without its path",
        "executable's base name",
    ),
    "process.executable": (
        "absolute path of the program that ran",
        "full path to the executable",
        "location of the binary on disk",
    ),
    "process.command_line": (
        "full command that was run",
        "command line with its arguments",
        "exact invocation, arguments included",
    ),
    "process.working_directory": (
        "directory the program ran in",
        "current directory of the process",
        "path the command was executed from",
    ),
    "event.outcome": (
        "whether the attempt succeeded or failed",
        "result of the attempt, success or failure",
        "if the operation worked or not",
    ),
    "event.action": (
        "what the device did with the event",
        "the action taken or performed",
        "verb naming what happened",
    ),
    "event.id": (
        "identifier the source gives this event",
        "unique id of this record",
        "the event's own reference number",
    ),
    "event.code": (
        "numeric or short code identifying the event type",
        "event type number assigned by the source",
        "code the vendor uses for this kind of event",
    ),
    "event.sequence": (
        "sequence number ordering the records",
        "running counter of the event",
        "position of the record in the source's sequence",
    ),
    "event.duration": (
        "how long the operation took",
        "elapsed time of the request or session",
        "duration of the activity",
    ),
    "event.start": (
        "time the activity began",
        "start timestamp of the flow or session",
        "when it started",
    ),
    "event.end": (
        "time the activity finished",
        "end timestamp of the flow or session",
        "when it ended",
    ),
    "event.kind": (
        "broad kind of record: event, alert or metric",
        "whether the record is an alert or a plain event",
        "class of the record at the highest level",
    ),
    "event.provider": (
        "subsystem or service that produced the record",
        "component that emitted the event",
        "name of the producing service",
    ),
    "log.level": (
        "severity of the message",
        "log level such as info, warn or error",
        "how serious the entry is",
    ),
    "log.logger": (
        "name of the logger or module that wrote it",
        "component name of the emitting logger",
        "logging channel the line came from",
    ),
    "message": (
        "free-text message of the entry",
        "the human-readable description in the line",
        "message body as written",
    ),
    "error.message": (
        "description of the error that occurred",
        "error text reported by the source",
        "what went wrong, in words",
    ),
    "host.name": (
        "name of the machine the event concerns",
        "host the activity happened on",
        "name of the server or workstation involved",
    ),
    "host.hostname": (
        "short name of the machine that wrote the line",
        "host name of the emitting computer",
        "machine name in the line's header",
    ),
    "rule.id": (
        "number of the rule that matched",
        "identifier of the matching rule",
        "id of the policy entry that fired",
    ),
    "rule.uuid": (
        "stable tracking identifier of the rule that matched",
        "persistent tracker id of the rule",
        "long-lived unique id of the rule",
    ),
    "rule.name": (
        "name of the rule that matched",
        "label of the policy entry that fired",
        "title of the matching rule",
    ),
    "network.iana_number": (
        "protocol number of the transport",
        "numeric transport protocol code",
        "proto (numeric)",
    ),
    "network.transport": (
        "name of the transport protocol",
        "transport layer protocol, like tcp or udp",
        "layer-4 protocol name",
    ),
    "network.direction": (
        "whether traffic left or entered the network",
        "direction of the flow, in or out",
        "inbound or outbound",
    ),
    "network.protocol": (
        "application protocol",
        "application-layer protocol name",
        "protocol spoken above the transport",
    ),
    "network.community_id": (
        "flow hash shared across sensors",
        "community flow identifier",
        "hash that names the flow consistently between tools",
    ),
    "email.from.address": (
        "mailbox the message was sent from",
        "sender's mail address",
        "envelope or header sender",
    ),
    "email.to.address": (
        "mailbox the message was delivered to",
        "recipient's mail address",
        "address the mail was destined for",
    ),
    "email.message_id": (
        "identifier of the message itself",
        "unique message id of the mail",
        "the mail's own reference id",
    ),
    "dns.id": (
        "transaction number of the lookup",
        "query id pairing the question with its answer",
        "numeric id of the DNS exchange",
    ),
    "dns.question.name": (
        "name that was looked up",
        "domain name queried",
        "the host or domain being resolved",
    ),
    "dns.question.type": (
        "record type that was asked for",
        "kind of record requested, such as A or MX",
        "query type",
    ),
    "dns.question.class": (
        "class of the lookup, usually IN",
        "query class",
        "DNS class the question was asked in",
    ),
    "dns.response_code": (
        "result code of the lookup",
        "status the resolver answered with",
        "outcome code such as NOERROR or NXDOMAIN",
    ),
    "dns.resolved_ip": (
        "address the name resolved to",
        "IP returned in the answer",
        "resolution result as an address",
    ),
    "http.request.method": (
        "request method",
        "HTTP verb of the request",
        "method used, such as GET or POST",
    ),
    "http.request.referrer": (
        "page that linked to the request",
        "referring URL",
        "where the visitor came from",
    ),
    "http.version": (
        "protocol version of the request",
        "HTTP version number",
        "version of the web protocol used",
    ),
    "http.response.status_code": (
        "response status code",
        "numeric HTTP status returned",
        "result code the server answered with",
    ),
    "http.response.body.bytes": (
        "size of the response body",
        "bytes of content returned",
        "response payload length",
    ),
    "http.response.bytes": (
        "total size of the response",
        "bytes sent back, headers included",
        "full response length",
    ),
    "http.response.mime_type": (
        "media type of the returned content",
        "content type of the response",
        "MIME type served",
    ),
    "url.original": (
        "requested path and query as sent",
        "the URL as it appeared in the request",
        "resource requested, unparsed",
    ),
    "url.path": (
        "path part of the requested address",
        "requested path without the query",
        "resource path",
    ),
    "url.domain": (
        "domain part of the requested address",
        "host name in the requested URL",
        "site the request was for",
    ),
    "user_agent.original": (
        "client software identification string",
        "browser or client signature",
        "user agent header as sent",
    ),
    "file.name": (
        "name of the file involved",
        "file name without its directory",
        "base name of the file",
    ),
    "file.path": (
        "full path of the file involved",
        "location of the file on disk",
        "file's absolute path",
    ),
    "file.size": (
        "size of the file",
        "file length in bytes",
        "how large the file is",
    ),
}

# What a documentation page says about a capture. Terse, the register of a
# vendor's field reference, and deliberately not any phrasing in ROLE_VARIANTS:
# documentation is evidence stage 1 reasons from, never its answer.
DOC_TEXT: dict[str, str] = {
    "source.ip": "client IP",
    "source.port": "client port",
    "source.domain": "client host",
    "destination.ip": "server IP",
    "destination.port": "server port",
    "destination.address": "upstream",
    "observer.ip": "appliance IP",
    "observer.name": "appliance",
    "observer.hostname": "reporting host",
    "observer.ingress.interface.name": "interface",
    "user.name": "user",
    "user.id": "uid",
    "user.effective.name": "run-as user",
    "user.effective.id": "euid",
    "user.audit.id": "auid",
    "process.pid": "pid",
    "process.parent.pid": "ppid",
    "process.name": "program",
    "process.executable": "exe",
    "process.command_line": "command",
    "process.working_directory": "cwd",
    "event.outcome": "result word",
    "event.action": "action",
    "event.id": "record id",
    "event.sequence": "serial",
    "host.hostname": "host",
    "host.name": "host",
    "rule.id": "rule number",
    "rule.uuid": "tracker",
    "network.iana_number": "proto number",
    "network.transport": "proto",
    "network.direction": "dir",
    "email.from.address": "from",
    "email.to.address": "to",
    "email.message_id": "message-id",
    "dns.id": "query id",
    "dns.question.name": "qname",
    "dns.question.type": "qtype",
    "dns.response_code": "rcode",
    "dns.resolved_ip": "answer",
    "http.request.method": "method",
    "http.request.referrer": "referer",
    "http.version": "protocol",
    "http.response.status_code": "status",
    "http.response.body.bytes": "body bytes",
    "url.original": "request URI",
    "url.domain": "vhost",
    "user_agent.original": "user agent",
}

# WHAT A VENDOR'S FIELD REFERENCE SAYS, 2026-10-17.
#
# DOC_TEXT is two or three words per field, and the documentation it built was
# a list of capture names with a label: 299 characters at the median, against
# 1,526 for the hand-written documentation of the real sources the students are
# evaluated on (a product title, a sentence, a schematic of the line, example
# lines, a bullet per field). The students were trained on one register and
# tested on another. These are the descriptions that documentation now uses -
# the register of a vendor's field table - several per field, chosen by a
# stable salt like the roles. They must share no run of four words with any
# phrasing in ROLE_VARIANTS (tests/test_roles.py checks every pair), because
# documentation is evidence stage 1 reasons from, never its answer.
DOC_VARIANTS: dict[str, tuple[str, ...]] = {
    "@timestamp": ("event time", "timestamp as written", "when the entry was logged"),
    "source.ip": ("client IP", "remote peer IP", "IP of the requesting host"),
    "source.port": ("client port", "remote peer's TCP/UDP port", "ephemeral port on the client"),
    "source.domain": ("client hostname", "remote peer's DNS name", "requesting host, by name"),
    "source.bytes": ("client bytes", "client-to-server byte counter", "upstream byte count"),
    "source.packets": ("client packets", "pkts from client",
                       "upstream packet count"),
    "destination.ip": ("server IP", "target IP", "IP the session was opened to"),
    "destination.port": ("server port", "target port", "listening port on the target"),
    "destination.address": ("upstream server", "backend the request was relayed to", "next hop"),
    "destination.bytes": ("bytes returned by the server", "server-to-client byte counter",
                          "downstream byte count"),
    "destination.packets": ("packets returned by the server", "pkts to client",
                            "downstream packet count"),
    "observer.ip": ("appliance IP", "sensor management IP", "IP of the logging device"),
    "observer.name": ("appliance name", "sensor label", "logging device"),
    "observer.hostname": ("reporting host", "hostname of the firewall or sensor", "logging appliance name"),
    "observer.ingress.interface.name": ("interface", "NIC the packet came in on", "ingress port name"),
    "user.name": ("user", "login name", "account"),
    "user.id": ("uid", "numeric user ID", "account number"),
    "user.domain": ("domain", "realm", "NetBIOS domain"),
    "user.email": ("e-mail", "user's SMTP address", "UPN or mailbox"),
    "user.full_name": ("display name", "full name", "person's name as shown in the directory"),
    "user.effective.name": ("run-as user", "target account", "user switched to"),
    "user.effective.id": ("euid", "run-as UID", "effective UID"),
    "user.audit.id": ("auid", "audit UID", "loginuid"),
    "process.pid": ("pid", "process ID", "PID of the daemon"),
    "process.parent.pid": ("ppid", "parent PID", "PID of the spawning process"),
    "process.name": ("program", "daemon name", "comm"),
    "process.executable": ("exe", "binary path", "image path"),
    "process.command_line": ("command", "argv as typed", "full invocation"),
    "process.working_directory": ("cwd", "working dir", "directory at exec time"),
    "event.outcome": ("result word", "status keyword", "verdict"),
    "event.action": ("action", "verb logged by the device", "operation"),
    "event.id": ("record id", "queue ID", "entry identifier"),
    "event.code": ("event ID", "message number", "numeric type code"),
    "event.sequence": ("serial", "sequence counter", "audit serial number"),
    "event.duration": ("elapsed", "duration field", "time taken"),
    "event.start": ("start time", "flow start", "session opened at"),
    "event.end": ("end time", "flow end", "session closed at"),
    "event.kind": ("record class", "entry type", "class of the line"),
    "event.provider": ("subsystem", "producing service", "source component"),
    "log.level": ("severity", "level", "priority keyword"),
    "log.logger": ("logger", "module", "channel"),
    "message": ("free text", "message body", "text of the entry"),
    "error.message": ("error text", "failure detail", "diagnostic"),
    "host.name": ("host", "machine", "endpoint name"),
    "host.hostname": ("host", "hostname in the header", "machine name"),
    "rule.id": ("rule number", "rule ID", "policy line number"),
    "rule.uuid": ("tracker", "tracker ID", "rule tracking number"),
    "rule.name": ("rule", "signature name", "policy name"),
    "network.iana_number": ("proto number", "IP protocol number", "protocol ID"),
    "network.transport": ("proto", "L4 protocol", "transport name"),
    "network.direction": ("dir", "direction flag", "in/out flag"),
    "network.protocol": ("app protocol", "L7 protocol", "service protocol"),
    "network.community_id": ("community ID", "flow hash", "Community-ID string"),
    "email.from.address": ("from", "envelope sender", "MAIL FROM"),
    "email.to.address": ("to", "envelope recipient", "RCPT TO"),
    "email.message_id": ("message-id", "Message-ID header", "msgid"),
    "dns.id": ("query id", "transaction ID", "DNS ID"),
    "dns.question.name": ("qname", "queried name", "lookup target"),
    "dns.question.type": ("qtype", "record type", "RR type"),
    "dns.question.class": ("qclass", "query class", "RR class"),
    "dns.response_code": ("rcode", "response code", "DNS status"),
    "dns.resolved_ip": ("answer", "resolved address", "A/AAAA record"),
    "http.request.method": ("method", "HTTP verb", "request verb"),
    "http.request.referrer": ("referer", "Referer header", "referring page"),
    "http.version": ("protocol", "HTTP version", "protocol version"),
    "http.response.status_code": ("status", "HTTP status", "response status"),
    "http.response.body.bytes": ("body bytes", "bytes sent", "response size"),
    "http.response.bytes": ("total bytes", "response bytes incl. headers", "wire size"),
    "http.response.mime_type": ("content type", "Content-Type", "MIME type"),
    "url.original": ("request URI", "request line target", "URL as received"),
    "url.path": ("path", "URI path", "request path"),
    "url.domain": ("vhost", "Host header", "site"),
    "user_agent.original": ("user agent", "User-Agent header", "UA string"),
    "file.name": ("file", "filename", "object name"),
    "file.path": ("path", "file path", "absolute filename"),
    "file.size": ("size", "file size", "byte length"),
}

# A key the source writes and the schema has no use for still gets a line in a
# field reference; what that line says must not hint at a mapping.
NEUTRAL_DOC: tuple[str, ...] = ("recorded by the source", "vendor-specific value",
                                "kept as written", "internal to the product")

_DOTTED = re.compile(r"\b[a-z_@]+(?:\.[a-z_]+)+\b")


def _pick(options: tuple[str, ...], salt: str) -> str:
    h = int(hashlib.sha256(salt.encode("utf-8")).hexdigest()[:8], 16)
    return options[h % len(options)]


def role_text(ecs_field: str, salt: str = "") -> str:
    """A plain-language role for the field; `salt` (source and key) picks the phrasing.

    A field with no entry falls back to the first sentence of its ECS
    description - which is also what stage 2 is shown beside the candidate, so
    a fallback is a lookup and not a role. `uncovered()` lists them so the
    corpus builder can refuse to rely on one.
    """
    if ecs_field in ROLE_VARIANTS:
        return _pick(ROLE_VARIANTS[ecs_field], salt or ecs_field)
    from corpus.siemgen_gold import ecs_index

    desc = ""
    try:
        desc = ecs_index().fields[ecs_field].description
    except (KeyError, AttributeError):
        pass
    first = (desc.split(". ")[0] if desc else "value recorded by the source").strip()
    return _DOTTED.sub("", first).replace("ECS", "").strip(" ,.")[:200] or \
        "value recorded by the source"


def doc_variant(ecs_field: str | None, salt: str = "") -> str:
    """A vendor-style description of a key whose field is `ecs_field`; neutral if none."""
    if ecs_field and ecs_field in DOC_VARIANTS:
        return _pick(DOC_VARIANTS[ecs_field], salt or ecs_field)
    return _pick(NEUTRAL_DOC, salt or "neutral")


def doc_text(ecs_field: str) -> str:
    """What a terse field reference would say about this capture, or "" for nothing."""
    return DOC_TEXT.get(ecs_field, "")


def uncovered(fields: list[str]) -> list[str]:
    return sorted({f for f in fields if f not in ROLE_VARIANTS})


_WORD = re.compile(r"[a-z0-9]+")


def _ngrams(text: str, n: int) -> set[tuple[str, ...]]:
    w = _WORD.findall(text.lower())
    return {tuple(w[i:i + n]) for i in range(len(w) - n + 1)}


def leaks(target_roles: list[str], prompt_input: str, n: int = 4) -> list[str]:
    """The target roles stage 1's input already states.

    A role leaks when the input contains it outright, or shares a run of `n`
    consecutive words with it. Short roles (fewer than `n` words) leak only
    verbatim and as a whole phrase, since three common words in a row prove
    nothing.
    """
    hay = " ".join(_WORD.findall(prompt_input.lower()))
    grams = _ngrams(prompt_input, n)
    out = []
    for role in target_roles:
        words = _WORD.findall(role.lower())
        if not words:
            continue
        phrase = " ".join(words)
        if len(words) >= 3 and f" {phrase} " in f" {hay} ":
            out.append(role)
        elif len(words) >= n and _ngrams(role, n) & grams:
            out.append(role)
    return out

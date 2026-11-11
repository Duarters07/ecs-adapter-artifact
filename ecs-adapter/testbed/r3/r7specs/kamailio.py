"""r7_kamailio: Kamailio 5.8.4 registrar log, stderr text -> core JSON log engine (--log-engine=json:M), same version."""
from __future__ import annotations

import json
import re

from testbed.heldout_r2.specs import Spec, _f

_TEXT = re.compile(r"^\s*(?P<idx>\d+)\((?P<pid>\d+)\) (?P<level>[A-Z]+): (?P<prefix>\{.*?\} )<script>: (?P<msg>.*)$")
_PREFIX = re.compile(r"^\{(?P<msg_type>\d+) (?P<cseq>\d+) (?P<sip_method>[A-Z]+) (?P<call_id>\S+)\} $")
_WHO = r"(?P<user>[^@\s]+)@(?P<domain>\S+) from (?P<client_ip>[0-9.]+):(?P<client_port>\d+)"
_MSGS = (
    re.compile(r"^(?P<action>REGISTER challenge) for " + _WHO + r" ua=\[(?P<user_agent>.*)\]$"),
    re.compile(r"^(?P<action>REGISTER accepted) for " + _WHO + r" contact=<(?P<contact>[^>]*)> expires=(?P<expires>\d+)$"),
    # The script writes "wrong password for <user>@..." but "unknown user <user>@..." (no "for").
    re.compile(r"^(?P<action>REGISTER auth failed): (?P<reason>wrong password|unknown user) (?:for )?" + _WHO + r" ua=\[(?P<user_agent>.*)\]$"),
)


def _parts(prefix: str, msg: str) -> dict[str, str]:
    p = _PREFIX.match(prefix)
    if not p:
        return {}
    for rx in _MSGS:
        m = rx.match(msg)
        if m:
            return p.groupdict() | {k: v for k, v in m.groupdict().items() if v is not None}
    return {}


def _extract(line: str) -> dict[str, str]:
    s = line.strip()
    if s.startswith("{ "):
        try:
            o = json.loads(s)
        except ValueError:
            return {}
        if not isinstance(o, dict):
            return {}
        d = _parts(str(o.get("logprefix", "")), str(o.get("message", "")))
        if not d:
            return {}
        head = {k: str(o[k]) for k in ("idx", "pid", "level", "module", "file", "line", "function") if o.get(k) not in (None, "")}
        return head | d
    m = _TEXT.match(line.rstrip())
    if not m:
        return {}
    d = _parts(m.group("prefix"), m.group("msg"))
    return ({k: m.group(k) for k in ("idx", "pid", "level")} | d) if d else {}


def _doc(fmt: str) -> str:
    if fmt == "text":
        head = """plain lines (log_stderror=yes):

    <process rank>(<pid>) <LEVEL>: <log_prefix><module>: <message>

`<module>` is `<script>` for the routing script's own xlog lines."""
    else:
        head = """the core JSON log engine (`kamailio --log-engine=json:M`), one JSON object per line:

    { "idx": <process rank>, "pid": <pid>, "level": "<LEVEL>", "module": "<module>", "file": "<source file>",
      "line": <source line>, "function": "<function>", "logprefix": "<log_prefix>", "message": "<message>" }"""
    return f"""
# Kamailio 5.8.4 - SIP registrar log, {'stderr text' if fmt == 'text' else 'JSON log engine'}

Source: Kamailio core cookbook ("log_prefix", "log_stderror") and the core's JSON log engine (vendor documentation),
official image. A registrar with digest authentication. Kamailio logs no authentication outcome by itself: the event
messages below are the routing script's own xlog lines, identical in both formats. The server writes {head}

`log_prefix` is set to `{{$mt $hdr(CSeq) $ci}} `: the SIP message type (1 request), the CSeq header (number and
method) and the Call-ID.

## The messages kept (SIP REGISTER with digest authentication)

    REGISTER challenge for <user>@<domain> from <client_ip>:<client_port> ua=[<user_agent>]
    REGISTER accepted for <user>@<domain> from <client_ip>:<client_port> contact=<<contact>> expires=<expires>
    REGISTER auth failed: wrong password for <user>@<domain> from <client_ip>:<client_port> ua=[<user_agent>]
    REGISTER auth failed: unknown user <user>@<domain> from <client_ip>:<client_port> ua=[<user_agent>]

- `reason` - `wrong password` or `unknown user` (the second written without `for`); `user`, `domain` - the account and SIP domain
- `client_ip`, `client_port` - the SIP client (source of the request); `user_agent` - its User-Agent header
- `contact` - the registered contact URI; `expires` - its lifetime in seconds
- `call_id`, `cseq` - tie the challenge to the authenticated request
"""


def _fields(json_: bool) -> list:
    out = [
        _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
        _f("client_port", "source.port", "long", "client_port", "easy"),
        _f("user", "user.name", "keyword", "account", "easy"),
        _f("domain", "user.domain", "keyword", "account_domain", "medium"),
        _f("action", "event.action", "keyword", "event_type", "medium"),
        _f("reason", "event.reason", "keyword", "refusal_reason", "medium"),
        _f("user_agent", "user_agent.original", "keyword", "user_agent", "easy"),
        _f("level", "log.level", "keyword", "severity", "easy"),
        _f("pid", "process.pid", "long", "process_id", "easy"),
        _f("call_id", None, "keyword", "call_id", "hard", "SIP Call-ID; no ECS field.", abstain=True),
        _f("cseq", None, "long", "sequence", "hard", "No ECS field.", abstain=True),
        _f("sip_method", None, "keyword", "sip_method", "hard", "No ECS field for a SIP method.", abstain=True),
        _f("msg_type", None, "long", "message_type", "hard", "No ECS field.", abstain=True),
        _f("contact", None, "keyword", "contact_uri", "hard", "No ECS field.", abstain=True),
        _f("expires", None, "long", "lifetime", "hard", "No ECS field.", abstain=True),
        _f("idx", None, "long", "process_rank", "hard", "Kamailio's process rank, not a pid.", abstain=True),
    ]
    if json_:
        out[9:9] = [_f("module", "log.logger", "keyword", "logger", "medium"),
                    _f("file", "log.origin.file.name", "keyword", "source_file", "medium"),
                    _f("line", "log.origin.file.line", "long", "source_line", "medium")]
        out.append(_f("function", None, "keyword", "function", "hard", "Empty for xlog lines.", abstain=True))
    return out


OLD = Spec(
    source_id="r7_kamailio_text", family="kamailio",
    software="Kamailio 5.8.4 (ghcr.io official image), stderr text log", category="authentication",
    contamination="high", split="train_r7",
    notes="ROUND 10 (pool r7), OLD VERSION: Kamailio 5.8.4 registrar, plain stderr log. Event messages are the routing script's xlog lines.",
    documentation=_doc("text"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_fields(False),
)

NEW = Spec(
    source_id="r7_kamailio_json", family="kamailio",
    software="Kamailio 5.8.4 (ghcr.io official image), --log-engine=json:M", category="authentication",
    contamination="high", split="test_r7",
    notes="ROUND 10 (pool r7), NEW VERSION of r7_kamailio_text: core JSON log engine (same version and config).",
    documentation=_doc("json"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_fields(True),
)

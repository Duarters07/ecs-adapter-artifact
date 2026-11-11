"""r6_opensmtpd: OpenSMTPD session log, Debian 11 -> Debian 12 (both 6.8.0p2; Debian 12 builds it against OpenSSL 3)."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_MSGS = (
    re.compile(r'^(?P<session>[0-9a-f]{16}) smtp (?P<action>connected) address=(?P<client_ip>[0-9.]+) host=(?P<client_host>\S+)$'),
    re.compile(r'^(?P<session>[0-9a-f]{16}) smtp (?P<action>message) msgid=(?P<msgid>[0-9a-f]+) size=(?P<size>\d+) nrcpt=(?P<nrcpt>\d+) proto=(?P<proto>\w+)$'),
    re.compile(r'^(?P<session>[0-9a-f]{16}) smtp (?P<action>failed-command) command="(?P<command>[^"]*)" result="(?P<reason>[^"]*)"$'),
    re.compile(r'^(?P<session>[0-9a-f]{16}) smtp (?P<action>disconnected) reason=(?P<reason>"[^"]*"|\S+)$'),
)


def _extract(line: str) -> dict[str, str]:
    s = line.strip()
    for rx in _MSGS:
        m = rx.match(s)
        if m:
            d = {k: v for k, v in m.groupdict().items() if v is not None}
            if d.get("reason", "").startswith('"'):
                d["reason"] = d["reason"][1:-1]
            return d
    return {}


def _doc(debian: str) -> str:
    return f"""
# OpenSMTPD 6.8 (Debian {debian}) - smtpd log, SMTP sessions

Source: OpenSMTPD manual, smtpd(8) and smtpd.conf(5) (https://man.openbsd.org/smtpd), and the Debian package. In the
foreground (`smtpd -d`) the daemon writes one line per session event to standard error, prefixed by the session id:

    <session> smtp <event> <key>=<value> ...

## The events kept

    <session> smtp connected address=<client_ip> host=<client_host>
    <session> smtp message msgid=<msgid> size=<size> nrcpt=<nrcpt> proto=<proto>
    <session> smtp failed-command command="<command>" result="<reason>"
    <session> smtp disconnected reason=<reason>

- `session` - the SMTP session id (16 hex digits), the same on every line of one session
- `client_ip`, `client_host` - the client's address and its reverse-DNS name
- `msgid`, `size`, `nrcpt`, `proto` - an accepted message: internal id, size in bytes, recipients, ESMTP or SMTP
- `command`, `reason` (the `result` value) - a refused command and the reply, such as an unknown recipient or a relay attempt
  (`550 Invalid recipient: <...>`)
- `reason` - why the session ended (`quit`, `disconnect`, or an I/O error)
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("client_host", "source.domain", "keyword", "client_hostname", "medium", "client.domain is equivalent."),
    _f("reason", "event.reason", "keyword", "refusal_or_end_reason", "medium", "the refused command's reply, or why the session ended."),
    _f("action", "event.action", "keyword", "session_event", "medium"),
    _f("session", None, "keyword", "session_id", "hard", "event.id is acceptable; declining accepted.", abstain=True),
    _f("msgid", None, "keyword", "queue_id", "hard", "internal queue id, not the Message-ID header.", abstain=True),
    _f("size", None, "long", "message_size", "hard", "email has no plain size field in ECS 8.11.", abstain=True),
    _f("nrcpt", None, "long", "recipient_count", "hard", "No ECS field.", abstain=True),
    _f("proto", None, "keyword", "smtp_protocol", "hard", "network.protocol expects lowercase names; declining accepted.", abstain=True),
    _f("command", None, "keyword", "smtp_command", "hard", "No ECS field for the refused command.", abstain=True),
]

OLD = Spec(
    source_id="r6_opensmtpd_d11", family="opensmtpd",
    software="OpenSMTPD 6.8.0p2 (Debian 11)", category="network",
    contamination="high", split="train_r6",
    notes="ROUND 8 (pool r6), OLD VERSION: OpenSMTPD 6.8.0p2 on Debian 11; port-25 sessions only (see capture.json).",
    documentation=_doc("11"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r6_opensmtpd_d12", family="opensmtpd",
    software="OpenSMTPD 6.8.0p2 (Debian 12)", category="network",
    contamination="high", split="test_r6",
    notes="ROUND 8 (pool r6), NEW VERSION of r6_opensmtpd_d11: the same upstream version rebuilt for Debian 12.",
    documentation=_doc("12"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

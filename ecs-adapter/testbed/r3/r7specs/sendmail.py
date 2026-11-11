"""r7_sendmail: Sendmail via syslog (mail.log), Debian 12 (8.17.1.9) -> Debian 13 (8.18.1): SMTP transactions."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_HEAD = re.compile(r"^(?P<timestamp>\d{4}-\d\d-\d\dT[\d:.]+[+-]\d\d:\d\d) (?P<host>\S+) (?P<program>sendmail)\[(?P<pid>\d+)\]: "
                   r"(?P<queue_id>[0-9A-Za-z]{14}): (?P<msg>.*)$")
_RELAY = r"relay=(?P<relay_host>\S+) \[(?P<client_ip>[0-9.]+)\]"
_MSGS = (
    re.compile(r"^from=<(?P<sender>[^>]*)>, size=(?P<size>\d+), class=(?P<class>-?\d+), nrcpts=(?P<nrcpts>\d+), "
               r"(?:msgid=<(?P<msgid>[^>]*)>, )?proto=(?P<proto>\w+), daemon=(?P<daemon>[^,]+), " + _RELAY + r"$"),
    re.compile(r"^to=<(?P<rcpt>[^>]*)>, delay=(?P<delay>[\d:+]+), xdelay=(?P<xdelay>[\d:+]+), mailer=(?P<mailer>[^,]+), "
               r"pri=(?P<pri>\d+), dsn=(?P<dsn>[\d.]+), stat=(?P<stat>.+)$"),
    re.compile(r"^<(?P<rcpt>[^>]*)>\.\.\. (?P<reason>User unknown)$"),
    re.compile(r"^ruleset=(?P<ruleset>[^,]+), arg1=<(?P<rcpt>[^>]*)>, " + _RELAY + r", reject=(?P<reason>.+)$"),
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


def _doc(version: str) -> str:
    return f"""
# Sendmail {version} - mail log (syslog facility mail, via rsyslog)

Source: Sendmail Installation and Operation Guide, logging section (vendor documentation), Debian package. Listens on
port 25 for lab.example, local delivery through procmail. rsyslog writes one line per message:

    <timestamp> <host> sendmail[<pid>]: <queue_id>: <message>

## The messages kept

    from=<<sender>>, size=<size>, class=<class>, nrcpts=<nrcpts>, [msgid=<<msgid>>, ]proto=<proto>, daemon=<daemon>, relay=<relay_host> [<client_ip>]
    to=<<rcpt>>, delay=<delay>, xdelay=<xdelay>, mailer=<mailer>, pri=<pri>, dsn=<dsn>, stat=<stat>
    <<rcpt>>... User unknown
    ruleset=<ruleset>, arg1=<<rcpt>>, relay=<relay_host> [<client_ip>], reject=<reason>

- `queue_id` - the queue id, the same on every line of one transaction
- `client_ip`, `relay_host` - the SMTP client's address and its reverse name
- `sender` - the envelope sender; `rcpt` - a recipient (delivered, unknown, or refused)
- `msgid` - the Message-ID header (absent when no recipient was accepted)
- `stat` - the delivery status (Sent); `dsn` - its enhanced status code
- `reason` - why a recipient was refused (`User unknown`, or the reply of a refused relay attempt);
  `ruleset` - the ruleset that refused it
- `size`, `class`, `nrcpts`, `proto`, `daemon`, `delay`, `xdelay`, `mailer`, `pri` - message and queue details
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("relay_host", "source.domain", "keyword", "client_hostname", "medium", "client.domain is equivalent."),
    _f("sender", "email.from.address", "keyword", "sender", "medium"),
    _f("rcpt", "email.to.address", "keyword", "recipient", "medium"),
    _f("queue_id", "email.local_id", "keyword", "queue_id", "hard", "The queue id is the id the MTA gives the message (ECS email.local_id)."),
    _f("msgid", "email.message_id", "keyword", "message_id", "medium"),
    _f("reason", "event.reason", "keyword", "refusal_reason", "medium"),
    _f("stat", None, "keyword", "delivery_status", "hard", "event.outcome would need a value map (Sent -> success); declining accepted.", abstain=True),
    _f("ruleset", "rule.name", "keyword", "ruleset", "medium", "The ruleset that refused the recipient."),
    _f("host", "host.hostname", "keyword", "host", "easy", "host.name is equivalent."),
    _f("program", "process.name", "keyword", "program", "easy"),
    _f("pid", "process.pid", "long", "process_id", "easy"),
    _f("dsn", None, "keyword", "status_code", "hard", "No ECS field.", abstain=True),
    _f("size", None, "long", "message_size", "hard", "email has no plain size field in ECS 8.11.", abstain=True),
    _f("class", None, "long", "message_class", "hard", "No ECS field.", abstain=True),
    _f("nrcpts", None, "long", "recipient_count", "hard", "No ECS field.", abstain=True),
    _f("proto", None, "keyword", "smtp_protocol", "hard", "network.protocol expects lowercase names; declining accepted.", abstain=True),
    _f("daemon", None, "keyword", "daemon", "hard", "No ECS field.", abstain=True),
    _f("delay", None, "keyword", "delay", "hard", "event.duration is in nanoseconds; declining accepted.", abstain=True),
    _f("xdelay", None, "keyword", "xdelay", "hard", "As delay.", abstain=True),
    _f("mailer", None, "keyword", "mailer", "hard", "No ECS field.", abstain=True),
    _f("pri", None, "long", "priority", "hard", "No ECS field.", abstain=True),
    _f("timestamp", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r7_sendmail_8179", family="sendmail",
    software="Sendmail 8.17.1.9 (Debian 12)", category="email",
    contamination="high", split="train_r7",
    notes="ROUND 10 (pool r7), OLD VERSION: Sendmail 8.17.1.9, port 25, local delivery, rsyslog mail.log.",
    documentation=_doc("8.17.1.9"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r7_sendmail_8181", family="sendmail",
    software="Sendmail 8.18.1 (Debian 13)", category="email",
    contamination="high", split="test_r7",
    notes="ROUND 10 (pool r7), NEW VERSION of r7_sendmail_8179. CONTROL: the transaction lines are unchanged.",
    documentation=_doc("8.18.1"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

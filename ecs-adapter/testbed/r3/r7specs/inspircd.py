"""r7_inspircd: InspIRCd log file, Debian 12 (3.15.0) -> Debian 13 (4.7.0)."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_FMT = re.compile(r"[\x02\x03\x0f\x16\x1d\x1f]")   # IRC formatting codes (bold, colour, reset...)
_HEAD = re.compile(r"^(?P<timestamp>[A-Z][a-z]{2} (?:[A-Z][a-z]{2} \d\d?|\d\d? [A-Z][a-z]{2}) \d{4} \d\d:\d\d:\d\d) "
                   r"(?P<type>[A-Z]+): (?P<msg>.*)$")
_WHO = r"(?P<nick>[^!\s]+)!(?P<ident>[^@\s]+)@(?P<client_ip>[0-9.]+) \([0-9.]+\)"
_OPWHO = r"(?P<nick>\S+) \((?P<ident>[^@\s]+)@(?P<client_ip>[0-9.]+)\)(?: \[[0-9.]+\])?"
_MSGS = (
    re.compile(r"^(?P<action>Client connecting) on port (?P<port>\d+) \(class (?P<conn_class>[^)]+)\): " + _WHO
               + r" \[(?P<realname>[^\]]*)\]$"),
    re.compile(r"^(?P<action>Client exiting): " + _WHO + r" \[(?P<reason>[^\]]*)\]$"),
    re.compile(r"^" + _OPWHO + r" (?P<action>is now a server operator) of type (?P<oper_type>[^\s(]+) "
               r"\(using (?:oper '(?P<oper_name>[^']+)'|account (?P<oper_name2>[^)]+))\)\.?$"),
    re.compile(r"^WARNING! (?P<action>Failed oper attempt) by (?P<nick>[^!\s]+)!(?P<ident>[^@\s]+)@(?P<client_ip>[0-9.]+) "
               r"using login '(?P<oper_name>[^']+)': The following fields do not match: (?P<reason>.+)$"),
    re.compile(r"^" + _OPWHO + r" (?P<action>failed to log into) the (?P<oper_name>\S+) oper account because "
               r"(?P<reason>.+?)\.$"),
)


def _extract(line: str) -> dict[str, str]:
    m = _HEAD.match(line.strip())
    if not m:
        return {}
    for rx in _MSGS:
        mm = rx.match(m.group("msg"))
        if mm:
            out = {k: v for k, v in m.groupdict().items() if k != "msg"}
            d = {k: v for k, v in mm.groupdict().items() if v is not None}
            if "oper_name2" in d:
                d["oper_name"] = d.pop("oper_name2")
            out.update(d)
            # A value wrapped in formatting codes is the same value: `\x02admin\x02` is the account admin.
            out = {k: _FMT.sub("", v) for k, v in out.items()}
            return out
    return {}


def _doc(version: str, new: bool) -> str:
    bold = ", and the operator account and type are wrapped in bold (`\\x02admin\\x02`)" if new else ""
    if new:
        ts = "Fri 30 Oct 2026 19:12:52 (weekday, day, month, year, time)"
        oper = ("    OPER: <nick> (<ident>@<client_ip>) [<client_ip>] is now a server operator of type <oper_type> (using account <oper_name>).\n"
                "    OPER: <nick> (<ident>@<client_ip>) [<client_ip>] failed to log into the <oper_name> oper account because <reason>.")
    else:
        ts = "Fri Oct 30 2026 19:12:13 (weekday, month, day, year, time)"
        oper = ("    OPER: <nick> (<ident>@<client_ip>) is now a server operator of type <oper_type> (using oper '<oper_name>')\n"
                "    OPER: WARNING! Failed oper attempt by <nick>!<ident>@<client_ip> using login '<oper_name>': The following fields do not match: <reason>")
    return f"""
# InspIRCd {version} - log file (`<log method="file" type="* -USERINPUT -USEROUTPUT">`)

Source: InspIRCd documentation (configuration, `<log>` tag), Debian package; one IRC operator block. One line per event:

    <timestamp> <type>: <message>

`timestamp` is local time, {ts}; `type` is the log type that wrote the line (CONNECT, QUIT, OPER).

## The messages kept

    CONNECT: Client connecting on port <port> (class <conn_class>): <nick>!<ident>@<client_ip> (<client_ip>) [<realname>]
    QUIT: Client exiting: <nick>!<ident>@<client_ip> (<client_ip>) [<reason>]
{oper}

- `port` - the server port the client connected to; `conn_class` - the connect class that admitted it
- `nick`, `ident` - the client's nickname and user name; `client_ip` - its address; `realname` - the real name it sent
- `reason` - the quit message, or why an OPER attempt failed
- `oper_name` - the operator account asked for; `oper_type` - the operator type it grants

Values may carry IRC formatting codes, which are not part of the value: the real name is followed by a reset
(`\\x0f`){bold}.
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("port", "destination.port", "long", "server_port", "medium", "server.port is equivalent."),
    _f("nick", "user.name", "keyword", "account", "medium"),
    _f("realname", "user.full_name", "keyword", "real_name", "medium"),
    _f("oper_name", "user.effective.name", "keyword", "privileged_account", "hard",
       "The operator account the user takes on; leaving it unmapped is acceptable.", abstain=True),
    _f("reason", "event.reason", "keyword", "refusal_reason", "medium"),
    _f("action", "event.action", "keyword", "event_type", "medium"),
    _f("type", "log.logger", "keyword", "log_type", "medium"),
    _f("oper_type", None, "keyword", "oper_type", "hard", "user.roles is an array of roles; leaving it unmapped is acceptable.", abstain=True),
    _f("ident", None, "keyword", "ident", "hard", "The IRC user name; user.name holds the nick.", abstain=True),
    _f("conn_class", None, "keyword", "connect_class", "hard", "No ECS field.", abstain=True),
    _f("timestamp", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r7_inspircd_315", family="inspircd",
    software="InspIRCd 3.15.0 (Debian 12)", category="network",
    contamination="high", split="train_r7",
    notes="ROUND 10 (pool r7), OLD VERSION: InspIRCd 3.15.0, log file, one OPER block.",
    documentation=_doc("3.15.0", False), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r7_inspircd_47", family="inspircd",
    software="InspIRCd 4.7.0 (Debian 13)", category="network",
    contamination="high", split="test_r7",
    notes="ROUND 10 (pool r7), NEW VERSION of r7_inspircd_315: date order changed, OPER lines reworded.",
    documentation=_doc("4.7.0", True), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

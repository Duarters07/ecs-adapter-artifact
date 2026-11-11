"""r5_samba: Samba 4.17 (Debian 12) authentication audit, text (auth_audit) -> JSON (auth_json_audit)."""
from __future__ import annotations

import json
import re

from testbed.heldout_r2.specs import Spec, _f

_TEXT = re.compile(
    r"^\[(?P<timestamp>[^\]]+), +(?P<level>\d+)\] +Auth: \[(?P<service>[^,\]]+),(?P<auth_description>[^\]]*)\] "
    r"user \[(?P<client_domain>[^\]]*)\]\\\[(?P<client_account>[^\]]*)\] at \[(?P<event_time>[^\]]+)\] "
    r"with \[(?P<password_type>[^\]]*)\] status \[(?P<status>[^\]]+)\] workstation \[(?P<workstation>[^\]]*)\] "
    r"remote host \[ipv4:(?P<remote_ip>[0-9.]+):(?P<remote_port>\d+)\] "
    r"(?:became \[(?P<became_domain>[^\]]*)\]\\\[(?P<became_account>[^\]]*)\] \[(?P<became_sid>[^\]]*)\]"
    r"|mapped to \[(?P<mapped_domain>[^\]]*)\]\\\[(?P<mapped_account>[^\]]*)\])\. "
    r"local host \[ipv4:(?P<local_ip>[0-9.]+):(?P<local_port>\d+)\]\s*$")
_ADDR = re.compile(r"^ipv4:(?P<ip>[0-9.]+):(?P<port>\d+)$")


def _text(line: str) -> dict[str, str]:
    m = _TEXT.match(line)
    return {k: v for k, v in m.groupdict().items() if v is not None} if m else {}


def _json(line: str) -> dict[str, str]:
    try:
        obj = json.loads(line)
    except ValueError:
        return {}
    if not isinstance(obj, dict) or obj.get("type") != "Authentication":
        return {}
    out: dict[str, str] = {}

    def walk(o: dict, pre: str) -> None:
        for k, v in o.items():
            if isinstance(v, dict):
                walk(v, f"{pre}{k}.")
            elif v is not None and not isinstance(v, list):
                out[pre + k] = str(v)
    walk(obj, "")
    for key, part in (("Authentication.remoteAddress", "remote"), ("Authentication.localAddress", "local")):
        m = _ADDR.match(out.get(key, ""))
        if m:
            out[f"{part}_ip"], out[f"{part}_port"] = m.group("ip"), m.group("port")
    return out


def _alias(field: dict, *names: str) -> dict:
    return {**field, "source_key_aliases": list(names)}


_ADDR_FIELDS = [
    _f("remote_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("remote_port", "source.port", "long", "client_port", "easy"),
    _f("local_ip", "destination.ip", "ip", "server_ip", "medium", "server.ip is equivalent."),
    _f("local_port", "destination.port", "long", "server_port", "medium"),
]

OLD = Spec(
    source_id="r5_samba_text", family="samba",
    software="Samba 4.17.12 (Debian 12), log level 1 auth_audit:3", category="authentication",
    contamination="high", split="train_r5",
    notes="ROUND 6 (pool r5), OLD CONFIGURATION: Samba's authentication audit, human-readable.",
    documentation=r"""
# Samba 4.17 - authentication audit, human-readable (`auth_audit`)

Source: smb.conf(5), "log level" (debug classes `auth_audit` and `auth_json_audit`), and the Samba
wiki, "Setting up Audit Logging", https://wiki.samba.org/index.php/Setting_up_Audit_Logging

With `log level = 1 auth_audit:3` and `debug prefix timestamp = yes`, every authentication attempt
writes one line to the log file. A successful attempt:

    [<timestamp>, <level>]   Auth: [<service>,<auth_description>] user [<client_domain>]\[<client_account>] at [<event_time>] with [<password_type>] status [<status>] workstation [<workstation>] remote host [ipv4:<remote_ip>:<remote_port>] became [<became_domain>]\[<became_account>] [<became_sid>]. local host [ipv4:<local_ip>:<local_port>]

A failed attempt ends `mapped to [<mapped_domain>]\[<mapped_account>]. local host [...]` instead
of `became ...`.

- `timestamp`, `level` - the debug header: the time, and the debug level of the message (3 for a
  success, 2 for a failure)
- `service` - the service that asked for authentication (`SMB2`)
- `auth_description` - a further description of the authentication, `(null)` when none
- `client_domain`, `client_account` - the domain and account the client presented
- `event_time` - the time of the attempt, as a date string
- `password_type` - how the password was presented (`NTLMv2`)
- `status` - the NT status of the result: `NT_STATUS_OK`, `NT_STATUS_WRONG_PASSWORD`,
  `NT_STATUS_NO_SUCH_USER`, ...
- `workstation` - the NetBIOS name the client gave for its machine
- `remote_ip`, `remote_port` - the client's address and port
- `local_ip`, `local_port` - the server's address and port
- `became_domain`, `became_account`, `became_sid` - the local account the session runs as, and its SID
- `mapped_domain`, `mapped_account` - the account the attempt was mapped to
""",
    keep=lambda ln: bool(_text(ln)), extract=_text,
    fields=[
        _f("client_account", "user.name", "keyword", "account", "easy"),
        _f("client_domain", "user.domain", "keyword", "account_domain", "medium"),
        _f("status", "event.reason", "keyword", "auth_result", "medium",
           "The NT status names the reason; event.outcome would need a value map."),
        _f("became_sid", "user.id", "keyword", "account_sid", "medium"),
        *_ADDR_FIELDS,
        _f("level", "log.level", "keyword", "severity", "medium", "The debug level of the message."),
        _f("workstation", None, "keyword", "client_hostname", "hard",
           "A NetBIOS name, not a DNS name; source.domain is arguable. Declining accepted.", abstain=True),
        _f("password_type", None, "keyword", "auth_mechanism", "hard", "No ECS field.", abstain=True),
        _f("service", None, "keyword", "protocol", "hard", "network.protocol is not offered for authentication.", abstain=True),
        _f("became_account", None, "keyword", "local_account", "hard", "Same value as client_account here.", abstain=True),
        _f("mapped_account", None, "keyword", "mapped_account", "hard", "Same value as client_account here.", abstain=True),
    ],
)

NEW = Spec(
    source_id="r5_samba_json", family="samba",
    software="Samba 4.17.12 (Debian 12), log level 1 auth_json_audit:3", category="authentication",
    contamination="high", split="test_r5",
    notes=("ROUND 6 (pool r5), NEW CONFIGURATION of r5_samba_text: the authentication audit as JSON. "
           "Addresses stay `ipv4:ip:port` strings, so a parser that only decodes the JSON cannot fill "
           "source.ip. Key aliases cover a grok parser of the same line."),
    documentation=r"""
# Samba 4.17 - authentication audit as JSON (`auth_json_audit`)

Source: smb.conf(5), "log level" (debug class `auth_json_audit`), and the Samba wiki, "Setting up
Audit Logging", https://wiki.samba.org/index.php/Setting_up_Audit_Logging

With `log level = 1 auth_json_audit:3`, every authentication attempt writes one JSON object on a
line of its own, indented by two spaces, always with the keys in this order:

    {"timestamp": "<timestamp>", "type": "Authentication", "Authentication": {"version": {"major": 1, "minor": 2}, "eventId": <eventId>, "logonId": "<logonId>", "logonType": <logonType>, "status": "<status>", "localAddress": "ipv4:<local_ip>:<local_port>", "remoteAddress": "ipv4:<remote_ip>:<remote_port>", "serviceDescription": "<..>", "authDescription": <..>, "clientDomain": "<..>", "clientAccount": "<..>", "workstation": "<..>", "becameAccount": <..>, "becameDomain": <..>, "becameSid": <..>, "mappedAccount": "<..>", "mappedDomain": "<..>", "netlogonComputer": null, "netlogonTrustAccount": null, "netlogonNegotiateFlags": "0x00000000", "netlogonSecureChannelType": 0, "netlogonTrustAccountSid": null, "passwordType": "<..>", "duration": <duration>}}

A value that does not apply is `null` (the `became*` keys of a failed attempt).

- `timestamp` - the time of the attempt
- `Authentication.eventId` - the Windows event id of the result: 4624 logon succeeded, 4625 logon failed
- `Authentication.logonId`, `Authentication.logonType` - the logon session id and type (3: network)
- `Authentication.status` - the NT status of the result: `NT_STATUS_OK`, `NT_STATUS_WRONG_PASSWORD`, ...
- `Authentication.localAddress`, `Authentication.remoteAddress` - the server's and the client's
  address, `ipv4:<ip>:<port>`
- `Authentication.serviceDescription` - the service that asked for authentication (`SMB2`)
- `Authentication.clientDomain`, `Authentication.clientAccount` - the domain and account the client presented
- `Authentication.workstation` - the NetBIOS name the client gave for its machine
- `Authentication.becameAccount`, `becameDomain`, `becameSid` - the local account the session runs as
- `Authentication.mappedAccount`, `mappedDomain` - the account the attempt was mapped to
- `Authentication.passwordType` - how the password was presented (`NTLMv2`)
- `Authentication.duration` - the time the authentication took, microseconds
""",
    keep=lambda ln: bool(_json(ln)), extract=_json,
    fields=[
        _alias(_f("Authentication.clientAccount", "user.name", "keyword", "account", "easy"), "clientAccount"),
        _alias(_f("Authentication.clientDomain", "user.domain", "keyword", "account_domain", "medium"), "clientDomain"),
        _alias(_f("Authentication.status", "event.reason", "keyword", "auth_result", "medium",
                  "The NT status names the reason; event.outcome would need a value map."), "status"),
        _alias(_f("Authentication.eventId", "event.code", "keyword", "event_id", "medium"), "eventId"),
        _alias(_f("Authentication.becameSid", "user.id", "keyword", "account_sid", "medium"), "becameSid"),
        *_ADDR_FIELDS,
        _alias(_f("Authentication.remoteAddress", None, "keyword", "client_address", "hard",
                  "ipv4:ip:port in one string; split it, or decline.", abstain=True), "remoteAddress"),
        _alias(_f("Authentication.localAddress", None, "keyword", "server_address", "hard",
                  "ipv4:ip:port in one string; split it, or decline.", abstain=True), "localAddress"),
        _alias(_f("Authentication.workstation", None, "keyword", "client_hostname", "hard",
                  "A NetBIOS name, not a DNS name; source.domain is arguable. Declining accepted.", abstain=True), "workstation"),
        _alias(_f("Authentication.logonType", None, "long", "logon_type", "hard", "No ECS field.", abstain=True), "logonType"),
        _alias(_f("Authentication.passwordType", None, "keyword", "auth_mechanism", "hard", "No ECS field.", abstain=True), "passwordType"),
        _alias(_f("Authentication.duration", None, "long", "duration", "hard", "Microseconds; declining accepted.", abstain=True), "duration"),
    ],
)

"""r5_freeradius: FreeRADIUS authentication log, Debian 11 (3.0.21) -> Debian 13 (3.2.7)."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_AUTH = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d \d{4}) : Auth: \((?P<request_id>\d+)\) "
    r"(?P<result>Login OK|Login incorrect)(?: \((?P<reason>.*)\))?: \[(?P<user>[^\]]*)\] "
    r"\(from client (?P<nas>\S+) port (?P<nas_port>\d+)\)$")


def _extract(line: str) -> dict[str, str]:
    m = _AUTH.match(line.strip())
    return {k: v for k, v in m.groupdict().items() if v is not None} if m else {}


def _doc(version: str) -> str:
    return f"""
# FreeRADIUS {version} - authentication log

Source: radiusd.conf(5) and the packaged radiusd.conf, section `log` (`auth = yes` logs every
authentication request and its result), FreeRADIUS {version} documentation, https://freeradius.org/documentation/

Run with `-l stdout`, every request writes one line:

    <timestamp> : Auth: (<request_id>) <result>: [<user>] (from client <nas> port <nas_port>)
    <timestamp> : Auth: (<request_id>) <result> (<reason>): [<user>] (from client <nas> port <nas_port>)

- `timestamp` - local time, `Www Mmm dd HH:MM:SS yyyy`
- `request_id` - the server's number for the request
- `result` - `Login OK` (Access-Accept) or `Login incorrect` (Access-Reject)
- `reason` - why the request was rejected, as the module reports it: a wrong password
  (`pap: Cleartext password does not match "known good" password`), or an unknown user
  (`No Auth-Type found: rejecting the user via Post-Auth-Type = Reject`)
- `user` - the User-Name of the request
- `nas` - the short name of the RADIUS client (the network access server) that sent the request:
  `ap-floor1` (a Wi-Fi access point) or `vpn-gw` (a VPN gateway)
- `nas_port` - the NAS-Port of the request
"""


_FIELDS = [
    _f("user", "user.name", "keyword", "account", "easy"),
    _f("reason", "event.reason", "keyword", "refusal_reason", "medium"),
    _f("result", None, "keyword", "auth_outcome", "hard",
       "event.outcome needs a value map (Login OK -> success); declining accepted.", abstain=True),
    _f("nas", None, "keyword", "access_server", "hard",
       "observer.name is the home, but `observer` is not offered for authentication.", abstain=True),
    _f("nas_port", None, "long", "access_server_port", "hard", "A NAS port number, not a network port.", abstain=True),
    _f("request_id", None, "keyword", "request_number", "hard", "No ECS field.", abstain=True),
]

OLD = Spec(
    source_id="r5_freeradius_30", family="freeradius",
    software="FreeRADIUS 3.0.21 (Debian 11)", category="authentication",
    contamination="high", split="train_r5",
    notes="ROUND 6 (pool r5), OLD VERSION: FreeRADIUS 3.0.21, authentication log on.",
    documentation=_doc("3.0"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r5_freeradius_32", family="freeradius",
    software="FreeRADIUS 3.2.7 (Debian 13)", category="authentication",
    contamination="high", split="test_r5",
    notes="ROUND 6 (pool r5), NEW VERSION of r5_freeradius_30. Captured as an upgrade; see T3 for whether the format changed.",
    documentation=_doc("3.2"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

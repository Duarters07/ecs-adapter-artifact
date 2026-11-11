"""r5_openvpn: OpenVPN server log (verb 3), Debian 11 (2.5.1) -> Debian 12 (2.6.14)."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_HEAD = re.compile(r"^(?P<timestamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) "
                   r"(?:(?:(?P<peer_name>[^/\s\[]+)/)?(?P<client_ip>[0-9.]+):(?P<client_port>\d+) )?(?P<msg>.*)$")
_MSGS = (
    re.compile(r"^TLS: Initial packet from \[AF_INET\][0-9.]+:\d+, sid=(?P<sid>.+)$"),
    re.compile(r"^VERIFY OK: depth=(?P<depth>\d+), CN=(?P<cert_cn>.+)$"),
    re.compile(r"^VERIFY ERROR: depth=(?P<depth>\d+), error=(?P<error>[^:]+): CN=(?P<cert_cn>[^,]+), serial=(?P<serial>\d+)$"),
    re.compile(r"^TLS Auth Error: (?P<error>.+)$"),
    re.compile(r"^\[(?P<common_name>[^\]]+)\] Peer Connection Initiated with \[AF_INET\][0-9.]+:\d+$"),
    re.compile(r"^SENT CONTROL \[(?P<common_name>[^\]]+)\]: '(?P<control>[^']+)' \(status=(?P<status>\d+)\)$"),
    re.compile(r"^TLS Error: (?P<error>.+)$"),
    re.compile(r"^MULTI_sva: pool returned IPv4=(?P<vpn_ip>[0-9.]+), IPv6=(?P<vpn_ipv6>.+)$"),
)


def _extract(line: str) -> dict[str, str]:
    m = _HEAD.match(line.strip())
    if not m:
        return {}
    for rx in _MSGS:
        mm = rx.match(m.group("msg"))
        if mm:
            out = {k: v for k, v in m.groupdict().items() if v is not None and k != "msg"}
            out.update({k: v for k, v in mm.groupdict().items() if v is not None})
            if "peer_name" in out:
                out.setdefault("common_name", out.pop("peer_name"))
            return out
    return {}


def _doc(version: str, initial: bool, sva: str, extra: str) -> str:
    return f"""
# OpenVPN {version} - server log, verb 3

Source: openvpn(8), "--verb", and the OpenVPN {version} reference manual,
https://openvpn.net/community-resources/reference-manual-for-openvpn-2-{version[2]}/

Every line is `<timestamp> <peer> <message>`. The peer is the client's `<client_ip>:<client_port>`;
once the client's certificate has been accepted and the session set up it becomes
`<common_name>/<client_ip>:<client_port>`; some messages have no peer.

## The messages kept (authentication and certificate verification)

{"    TLS: Initial packet from [AF_INET]<client_ip>:<client_port>, sid=<sid>" + chr(10) if initial else ""}    VERIFY OK: depth=<depth>, CN=<cert_cn>
    VERIFY ERROR: depth=<depth>, error=<error>: CN=<cert_cn>, serial=<serial>
    TLS Auth Error: <error>
    [<common_name>] Peer Connection Initiated with [AF_INET]<client_ip>:<client_port>
    SENT CONTROL [<common_name>]: '<control>' (status=<status>)
    TLS Error: <error>
    {sva}MULTI_sva: pool returned IPv4=<vpn_ip>, IPv6=<vpn_ipv6>

- `timestamp` - local time
- `client_ip`, `client_port` - the client's address and port
- `common_name` - the common name of the client's certificate, the identity the session runs as
- `depth`, `cert_cn` - the position of a certificate in the chain (0 the client, 1 its CA) and its
  common name
- `error` - why verification or authentication failed: an untrusted certificate
  (`unable to get local issuer certificate`), a rejected username or password
  (`Auth Username/Password verification failed for peer`), a failed TLS handshake
- `serial` - the serial number of the refused certificate
- `control`, `status` - a control message sent to the client (`AUTH_FAILED`) and its status
- `vpn_ip`, `vpn_ipv6` - the tunnel address given to the client
- `sid` - the TLS session id
{extra}"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("client_port", "source.port", "long", "client_port", "easy"),
    _f("common_name", "user.name", "keyword", "account", "medium",
       "The certificate's common name is the identity of the VPN session."),
    _f("error", "event.reason", "keyword", "refusal_reason", "medium"),
    _f("cert_cn", None, "keyword", "certificate_cn", "hard",
       "The CA's or the client's certificate name by depth; tls.* is not offered for authentication.", abstain=True),
    _f("serial", None, "keyword", "certificate_serial", "hard", "tls.* is not offered for authentication.", abstain=True),
    _f("vpn_ip", None, "ip", "tunnel_address", "hard", "No ECS field for an address assigned inside a tunnel.", abstain=True),
    _f("control", None, "keyword", "control_message", "hard", "No ECS field.", abstain=True),
    _f("depth", None, "long", "chain_depth", "hard", "No ECS field in the offered roots.", abstain=True),
    _f("status", None, "keyword", "control_status", "hard", "No ECS field.", abstain=True),
]

OLD = Spec(
    source_id="r5_openvpn_25", family="openvpn",
    software="OpenVPN 2.5.1 (Debian 11)", category="authentication",
    contamination="high", split="train_r5",
    notes="ROUND 6 (pool r5), OLD VERSION: OpenVPN 2.5.1 server, certificate plus username/password.",
    documentation=_doc("2.5", True, "<common_name>/<client_ip>:<client_port> ", ""),
    keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r5_openvpn_26", family="openvpn",
    software="OpenVPN 2.6.14 (Debian 12)", category="authentication",
    contamination="high", split="test_r5",
    notes=("ROUND 6 (pool r5), NEW VERSION of r5_openvpn_25. Measured: the initial-packet line is no longer "
           "logged at verb 3, the tunnel-address line loses its peer, and a refused password also sends "
           "AUTH_FAILED to an `UNDEF` peer."),
    documentation=_doc("2.6", False, "",
                       "\nA refused password is answered twice, once to the session before its name is known (`[UNDEF]`).\n"),
    keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

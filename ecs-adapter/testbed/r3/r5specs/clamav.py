"""r5_clamav: ClamAV clamd log, Debian 11 package (1.4.3) -> Debian 12 package (1.4.6)."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_FOUND = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d \d{4}) -> "
    r"(?P<scan>instream)\((?P<client_ip>[0-9.]+)@(?P<client_port>\d+)\): "
    r"(?P<signature>\S+?)\((?P<md5>[0-9a-f]{32}):(?P<size>\d+)\) (?P<result>FOUND)$")


def _extract(line: str) -> dict[str, str]:
    m = _FOUND.match(line.strip())
    return {k: v for k, v in m.groupdict().items() if v is not None} if m else {}


def _doc(version: str) -> str:
    return f"""
# ClamAV {version} - clamd log

Source: clamd.conf(5) (`LogFile`, `LogTime`, `LogClean`, `ExtendedDetectionInfo`), ClamAV
documentation, https://docs.clamav.net/manual/Usage/Configuration.html, and the Debian package's
clamd.conf.

clamd writes to its log file, with `LogTime` on, one line per detection. Files submitted over the
network with the INSTREAM command are named after the client that sent them:

    <timestamp> -> instream(<client_ip>@<client_port>): <signature>(<md5>:<size>) FOUND

Clean scans are not logged (`LogClean` is off, as packaged).

- `timestamp` - local time, `Www Mmm dd HH:MM:SS yyyy`
- `client_ip`, `client_port` - the address and port of the client that submitted the data
- `signature` - the name of the signature that matched; `.UNOFFICIAL` marks a signature from a
  local database rather than the official ones
- `md5`, `size` - the MD5 hash and the size in bytes of the data that matched
  (`ExtendedDetectionInfo`)
- `result` - `FOUND`
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("client_port", "source.port", "long", "client_port", "easy"),
    _f("signature", "rule.name", "keyword", "detection_name", "medium",
       "The signature that matched, as an IDS rule name is mapped; threat.* is not offered for network."),
    _f("md5", None, "keyword", "content_hash", "hard",
       "file.hash.md5 is the home, but `file` is not offered for category network. Declining accepted.", abstain=True),
    _f("size", None, "long", "content_size", "hard",
       "file.size is the home, but `file` is not offered for category network. Declining accepted.", abstain=True),
    _f("result", None, "keyword", "verdict", "hard", "Always FOUND; event.outcome would need a value map.", abstain=True),
    _f("scan", None, "keyword", "scan_command", "hard", "No ECS field.", abstain=True),
]

OLD = Spec(
    source_id="r5_clamav_d11", family="clamav",
    software="ClamAV 1.4.3 (Debian 11 package)", category="network",
    contamination="high", split="train_r5",
    notes="ROUND 6 (pool r5), OLD VERSION: clamd from Debian 11, a local signature database.",
    documentation=_doc("1.4.3"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r5_clamav_d12", family="clamav",
    software="ClamAV 1.4.6 (Debian 12 package)", category="network",
    contamination="high", split="test_r5",
    notes=("ROUND 6 (pool r5), NEW VERSION of r5_clamav_d11. Debian ships the current upstream ClamAV to "
           "every stable release, so the two versions differ only in the patch level; see T3."),
    documentation=_doc("1.4.6"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

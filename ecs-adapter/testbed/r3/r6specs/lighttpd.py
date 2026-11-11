"""r6_lighttpd: lighttpd error log (mod_auth), Debian 11 (1.4.59) -> Debian 12 (1.4.69)."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_LINE = re.compile(r"^(?P<timestamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d): \(?(?P<module>[a-z_]+)\.c\.(?P<src_line>\d+)\) "
                   r"(?P<reason>password doesn't match) for (?P<path>\S+) username: (?P<user>\S+) IP: (?P<client_ip>[0-9.]+)$")


def _extract(line: str) -> dict[str, str]:
    m = _LINE.match(line.strip())
    return {k: v for k, v in m.groupdict().items() if v is not None} if m else {}


def _doc(version: str, paren: bool) -> str:
    src = "(<module>.c.<line>)" if paren else "<module>.c.<line>)"
    return f"""
# lighttpd {version} - error log, authentication

Source: lighttpd documentation, "server.errorlog" and mod_auth (https://redmine.lighttpd.net/projects/lighttpd/wiki/Mod_auth),
and the Debian package's configuration (/var/log/lighttpd/error.log). One line per event:

    <timestamp>: {src} <message>

## The message kept

    password doesn't match for <path> username: <user> IP: <client_ip>

Logged by mod_auth when a basic-auth login to a protected path is refused: a wrong password, or a user the
user file does not hold (the two are not told apart). A request without credentials is not logged here.

- `timestamp` - local time, seconds
- `module`, `line` - the source file and line that logged the event
- `path` - the requested protected path
- `user` - the username sent; `client_ip` - the client address
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("user", "user.name", "keyword", "account", "easy"),
    _f("path", "url.path", "keyword", "url_path", "easy", "url.original is equivalent."),
    _f("reason", "event.reason", "keyword", "refusal_reason", "medium"),
    _f("module", None, "keyword", "source_module", "hard", "log.origin.file.name would need the .c suffix; declining accepted.", abstain=True),
    _f("src_line", None, "long", "source_line", "hard", "log.origin.file.line is acceptable; declining accepted.", abstain=True),
]

OLD = Spec(
    source_id="r6_lighttpd_1459", family="lighttpd",
    software="lighttpd 1.4.59 (Debian 11)", category="authentication",
    contamination="high", split="train_r6",
    notes="ROUND 8 (pool r6), OLD VERSION: lighttpd 1.4.59, packaged error log, mod_auth basic auth on /admin/.",
    documentation=_doc("1.4.59", False), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r6_lighttpd_1469", family="lighttpd",
    software="lighttpd 1.4.69 (Debian 12)", category="authentication",
    contamination="high", split="test_r6",
    notes="ROUND 8 (pool r6), NEW VERSION of r6_lighttpd_1459. Captured as an upgrade; see T3 for whether the format changed.",
    documentation=_doc("1.4.69", True), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

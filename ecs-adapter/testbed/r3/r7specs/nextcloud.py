"""r7_nextcloud: Nextcloud 30.0.17 admin_audit log, log_type_audit=file (JSON) -> syslog (same version)."""
from __future__ import annotations

import json
import re

from testbed.heldout_r2.specs import Spec, _f

_SYSLOG = re.compile(r"^(?P<syslog_time>\d{4}-\d\d-\d\dT[\d:.]+[+-]\d\d:\d\d) (?P<host>\S+) (?P<program>[^\[\s]+)\[(?P<pid>\d+)\]: (?P<json>\{.*\})$")
_MSG = re.compile(r'^(?P<action>Login (?:attempt|successful|failed)): "(?P<login_user>[^"]*)"$')
_KEYS = {"reqId": "req_id", "level": "level", "time": "time", "remoteAddr": "remote_addr", "user": "user", "app": "app",
         "method": "method", "url": "url", "userAgent": "user_agent", "version": "version"}


def _extract(line: str) -> dict[str, str]:
    s, out = line.strip(), {}
    m = _SYSLOG.match(s)
    if m:
        out = {k: v for k, v in m.groupdict().items() if k != "json"}
        s = m.group("json")
    if not s.startswith("{"):
        return {}
    try:
        o = json.loads(s)
    except ValueError:
        return {}
    mm = _MSG.match(str(o.get("message", ""))) if isinstance(o, dict) else None
    if not mm:
        return {}
    out.update({new: str(o[k]) for k, new in _KEYS.items() if o.get(k) is not None})
    out.update(mm.groupdict())
    return out


def _doc(kind: str) -> str:
    obj = ('{"reqId": "<req_id>", "level": <level>, "time": "<ISO 8601>", "remoteAddr": "<client address>", "user": "<user>",\n'
           '     "app": "admin_audit", "method": "<method>", "url": "<url>", "message": "<message>", "userAgent": "<agent>",\n'
           '     "version": "<server version>", "data": {"app": "admin_audit"}}')
    head = (f"one JSON object per line in the audit file (`logfile_audit`):\n\n    {obj}" if kind == "file" else
            "through syslog (`syslog_tag_audit` = Nextcloud-audit), rsyslog's line with the same JSON object as its "
            f"message:\n\n    <ISO 8601 time> <host> Nextcloud-audit[<pid>]: {obj}")
    return f"""
# Nextcloud 30.0.17 - admin_audit log, log_type_audit = {kind}

Source: Nextcloud administration manual, "Logging" (log_type, log_type_audit, logfile_audit, syslog_tag_audit) and the
admin_audit app (vendor documentation), official image. The audit app logs at level 1 (info). The server writes
{head}

## The messages kept (WebDAV logins)

    Login attempt: "<login_user>"
    Login successful: "<login_user>"
    Login failed: "<login_user>"

- `login_user` - the account named in the attempt (an unknown account is named too)
- `user` - the session's user: `--` until the login succeeds
- `remoteAddr` - the client address; `reqId` - ties the attempt to its outcome
- `level` - Nextcloud's numeric level (0 debug, 1 info, 2 warning, 3 error, 4 fatal)
"""


def _fields(syslog: bool) -> list:
    out = [
        _f("remote_addr", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
        _f("login_user", "user.name", "keyword", "account", "easy"),
        _f("action", "event.action", "keyword", "event_type", "medium"),
        _f("method", "http.request.method", "keyword", "http_method", "easy"),
        _f("url", "url.path", "keyword", "url_path", "easy", "url.original is equivalent."),
        _f("user_agent", "user_agent.original", "keyword", "user_agent", "easy"),
        _f("req_id", "http.request.id", "keyword", "request_id", "medium", "trace.id is equivalent."),
        _f("version", "service.version", "keyword", "server_version", "medium"),
        _f("level", "log.level", "keyword", "severity", "medium", "Nextcloud's numeric level."),
        _f("user", None, "keyword", "session_user", "hard", "'--' before login; user.name is the account the message names.", abstain=True),
        _f("app", None, "keyword", "app", "hard", "Constant admin_audit.", abstain=True),
        _f("time", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
    ]
    if syslog:
        out += [_f("host", "host.name", "keyword", "hostname", "easy"),
                _f("program", "process.name", "keyword", "program", "easy", "The syslog tag."),
                _f("pid", "process.pid", "long", "process_id", "easy"),
                _f("syslog_time", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True)]
    return out


OLD = Spec(
    source_id="r7_nextcloud_file", family="nextcloud",
    software="Nextcloud 30.0.17 (official image), admin_audit, log_type_audit=file", category="authentication",
    contamination="high", split="train_r7",
    notes="ROUND 10 (pool r7), OLD VERSION: Nextcloud 30.0.17 admin_audit to its JSON file.",
    documentation=_doc("file"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_fields(False),
)

NEW = Spec(
    source_id="r7_nextcloud_syslog", family="nextcloud",
    software="Nextcloud 30.0.17 (official image), admin_audit, log_type_audit=syslog", category="authentication",
    contamination="high", split="test_r7",
    notes="ROUND 10 (pool r7), NEW VERSION of r7_nextcloud_file: log_type_audit=syslog (same version).",
    documentation=_doc("syslog"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_fields(True),
)

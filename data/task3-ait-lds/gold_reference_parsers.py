"""Reference parsers (DRAFT, the author must review) for the six AIT-LDS Task 3 sources."""
import json, sys
from pathlib import Path
T = Path(sys.argv[1])
SYSHDR = r"^%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:host} %{DATA:program}(?:\[%{POSINT:pid}\])?: "

def ir(sid, extraction, fields, constants, unresolved):
    return {"source_id": sid, "ecs_version": "8.11", "extraction": extraction,
            "fields": [{"source_key": k, "ecs_field": e, "confidence": 1.0, **({"type": t} if t else {})} for k, e, t in fields],
            "constants": constants,
            "unresolved": [{"source_key": k, "reason": r} for k, r in unresolved]}

G = {}
G["t3_ait_apache_access"] = ir("t3_ait_apache_access",
    {"kind": "grok", "pattern": r'^%{IPORHOST:client_ip} %{NOTSPACE:ident} %{NOTSPACE:auth_user} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:method} %{NOTSPACE:url} HTTP/%{NUMBER:http_version}|-)" %{INT:status} (?:%{INT:bytes}|-) "%{DATA:referrer}" "%{DATA:user_agent}"$'},
    [("client_ip", "source.ip", "ip"), ("method", "http.request.method", None), ("url", "url.original", None),
     ("http_version", "http.version", None), ("status", "http.response.status_code", "long"),
     ("bytes", "http.response.body.bytes", "long"), ("referrer", "http.request.referrer", None),
     ("user_agent", "user_agent.original", None)],
    {"event.category": ["web"], "event.kind": "event", "event.dataset": "apache.access"},
    [("timestamp", "@timestamp is set at ingest"), ("ident", "identd field, always -"),
     ("auth_user", "HTTP user, always - in the samples")])
G["t3_ait_apache_error"] = ir("t3_ait_apache_error",
    {"kind": "grok", "pattern": r"^\[%{HTTPDERROR_DATE:timestamp}\] \[%{WORD:module}:%{LOGLEVEL:level}\] \[pid %{POSINT:pid}\] \[client %{IP:client_ip}:%{POSINT:client_port}\] (?:%{WORD:error_code}: )?%{GREEDYDATA:text}$"},
    [("client_ip", "source.ip", "ip"), ("client_port", "source.port", "long"), ("pid", "process.pid", "long"),
     ("level", "log.level", None), ("module", "log.logger", None), ("error_code", "error.code", None),
     ("text", "message", None)],
    {"event.category": ["web"], "event.kind": "event", "event.dataset": "apache.error"},
    [("timestamp", "@timestamp is set at ingest")])
auth_msgs = [
    r"pam_unix\(%{DATA:pam_service}:session\): session %{WORD:action} for user %{USERNAME:user}(?: by \(uid=%{INT:by_uid}\))?$",
    r"Accepted %{WORD:auth_method} for %{USERNAME:user} from %{IP:src_ip} port %{INT:src_port} ssh2(?:: %{GREEDYDATA:key_info})?$",
    r"Did not receive identification string from %{IP:src_ip} port %{INT:src_port}$",
    r"Successful su for %{USERNAME:target_user} by %{USERNAME:user}$",
    r"\+ %{NOTSPACE:tty} %{USERNAME:user}:%{USERNAME:target_user}$",
    r"New session %{NOTSPACE:session} of user %{USERNAME:user}\.$",
    r"Removed session %{NOTSPACE:session}\.$",
    r" +%{USERNAME:user} : TTY=%{NOTSPACE:tty} ; PWD=%{DATA:pwd} ; USER=%{USERNAME:target_user} ; COMMAND=%{GREEDYDATA:command}$",
]
G["t3_ait_auth"] = ir("t3_ait_auth",
    {"kind": "grok", "pattern": SYSHDR + auth_msgs[0], "alternatives": [SYSHDR + m for m in auth_msgs[1:]]},
    [("host", "host.hostname", None), ("program", "process.name", None), ("pid", "process.pid", "long"),
     ("user", "user.name", None), ("target_user", "user.target.name", None), ("src_ip", "source.ip", "ip"),
     ("src_port", "source.port", "long"), ("command", "process.command_line", None),
     ("pwd", "process.working_directory", None), ("action", "event.action", None)],
    {"event.category": ["authentication"], "event.kind": "event", "event.dataset": "system.auth"},
    [("timestamp", "@timestamp is set at ingest"), ("pam_service", "PAM service name, no ECS field"),
     ("by_uid", "uid of the opening process"), ("auth_method", "ssh method, no ECS field in this subset"),
     ("key_info", "key fingerprint"), ("tty", "terminal"), ("session", "logind session id")])
AUD = r"^type=%{WORD:audit_type} msg=audit\(%{NUMBER:audit_epoch}:%{INT:audit_seq}\): "
aud_msgs = [
    r"pid=%{INT:pid} uid=%{INT:uid} auid=%{INT:auid} ses=%{INT:ses} msg=\x27op=%{NOTSPACE:op} acct=\"%{DATA:acct}\" exe=\"%{DATA:exe}\" hostname=%{NOTSPACE:hostname} addr=%{NOTSPACE:addr} terminal=%{NOTSPACE:terminal} res=%{WORD:result}\x27$",
    r"pid=%{INT:pid} uid=%{INT:uid} old-auid=%{INT:old_auid} auid=%{INT:auid} tty=%{NOTSPACE:tty} old-ses=%{INT:old_ses} ses=%{INT:ses} res=%{INT:result}$",
    r"pid=%{INT:pid} uid=%{INT:uid} auid=%{INT:auid} ses=%{INT:ses} msg=\x27unit=%{NOTSPACE:unit} comm=\"%{DATA:comm}\" exe=\"%{DATA:exe}\" hostname=%{NOTSPACE:hostname} addr=%{NOTSPACE:addr} terminal=%{NOTSPACE:terminal} res=%{WORD:result}\x27$",
]
G["t3_ait_audit"] = ir("t3_ait_audit",
    {"kind": "grok", "pattern": AUD + aud_msgs[0], "alternatives": [AUD + m for m in aud_msgs[1:]]},
    [("audit_type", "event.action", None), ("pid", "process.pid", "long"), ("uid", "user.id", None),
     ("acct", "user.name", None), ("exe", "process.executable", None),
     ("comm", "process.name", None), ("result", "event.outcome", None)],
    {"event.category": ["authentication"], "event.kind": "event", "event.dataset": "auditd.log"},
    [("audit_epoch", "@timestamp is set at ingest"), ("audit_seq", "audit record sequence"), ("ses", "audit session"),
     ("auid", "audit login uid; ECS 8.11 has no field for it"),
     ("op", "PAM operation"), ("hostname", "'?' in every sample"), ("addr", "'?' in every sample"),
     ("terminal", "terminal"), ("old_auid", "previous auid"), ("tty", "tty"), ("old_ses", "previous session"),
     ("unit", "systemd unit")])
DNS = r"^%{SYSLOGTIMESTAMP:timestamp} %{WORD:program}\[%{POSINT:pid}\]: "
G["t3_ait_dnsmasq"] = ir("t3_ait_dnsmasq",
    {"kind": "grok", "pattern": DNS + r"query\[%{WORD:query_type}\] %{NOTSPACE:query_name} from %{IP:client_ip}$",
     "alternatives": [DNS + r"forwarded %{NOTSPACE:query_name} to %{IP:upstream_ip}$",
                      DNS + r"reply %{NOTSPACE:query_name} is %{NOTSPACE:answer}$"]},
    [("query_type", "dns.question.type", None), ("query_name", "dns.question.name", None),
     ("client_ip", "source.ip", "ip"), ("upstream_ip", "destination.ip", "ip"),
     ("answer", "dns.answers.data", None), ("program", "process.name", None), ("pid", "process.pid", "long")],
    {"event.category": ["network"], "event.kind": "event", "event.dataset": "dnsmasq.log"},
    [("timestamp", "@timestamp is set at ingest")])
G["t3_ait_openvpn"] = ir("t3_ait_openvpn",
    {"kind": "grok", "pattern": r"^%{TIMESTAMP_ISO8601:timestamp} %{USERNAME:user}/%{IP:client_ip}:%{INT:client_port} %{GREEDYDATA:text}$"},
    [("user", "user.name", None), ("client_ip", "source.ip", "ip"), ("client_port", "source.port", "long"),
     ("text", "message", None)],
    {"event.category": ["network"], "event.kind": "event", "event.dataset": "openvpn.log"},
    [("timestamp", "@timestamp is set at ingest")])
for sid, g in G.items():
    (T / sid / "reference.ir.json").write_text(json.dumps(g, indent=1) + "\n")
    truth = {"source_id": sid, "review_status": "DRAFT - every field below awaits the author's review",
             "fields": [{**f, "review_status": "DRAFT"} for f in g["fields"]]}
    (T / sid / "truth.json").write_text(json.dumps(truth, indent=1) + "\n")
print("written", len(G))

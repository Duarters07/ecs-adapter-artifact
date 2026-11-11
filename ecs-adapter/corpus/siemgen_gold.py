"""R5 - gold IRs for SIEMgen's native formats, checked against per-line truth.

WHY GOLD, AND WHY BY HAND
-------------------------
Round 1 trained the students on 645 examples, and the teacher wrote every one
of them. What the teacher does not do, the student never sees: one completion
in 645 uses grok `alternatives`, 23 use an optional segment, and arm C then
failed `sshd_auth` at V2 with every field it mapped correct - it had never been
shown a source whose lines come in more than one shape. A local 32B cannot
teach what it does not write.

So the native formats SIEMgen emits are mapped here once, by hand, one grok
alternative per message type, with the optional segments made optional and the
computed values (`event.outcome` from `Accepted`/`Failed`) expressed as value
maps. Structured sources (JSON) are mapped by value matching, which is exact
for them (see `auto_ir`). Every gold IR is compiled, run in the V3 sandbox over
SIEMgen lines it was not written from, and checked by VT against SIEMgen's own
ECS rendering of the same events: a gold IR may leave a field unchecked, never
contradict one.

WHAT THE TRUTH IS, LINE BY LINE
-------------------------------
`render_ecs` describes an EVENT, and a native event can be several lines (an
sshd login writes the accept, the PAM session and the logind session). A line
is held only to the ECS values it literally carries (`line_truth`): a field is
demanded of a line when its value occurs in that line as a whole token, or as
a whole JSON value. A field whose value the source COMPUTED (`event.outcome`,
`network.direction`) is demanded only where a per-source rule says which lines
it can be read from (`COMPUTED`). Nothing else is claimed.

This is training material only (PLAN_R2.md): SIEMgen's ECS is one generator's
opinion, good enough to teach from and never used to grade a held-out source.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
import argparse
import json
import os
import random
import re
import sys
import time

from adapter.wiring import ROOT

# In-distribution held-out families (PLAN_R2.md): no training record, ever.
# corpus/siemgen_corpus.py owns the split; its test families and exclusions are
# taken from there so that the two halves of the corpus cannot disagree.
try:
    from corpus.siemgen_corpus import EXCLUDED as _SC_EXCLUDED, TEST_ID as _SC_TEST_ID
except ImportError:  # pragma: no cover - the other half not built yet
    _SC_EXCLUDED, _SC_TEST_ID = (), ()
HELD_OUT = frozenset({"dhcp", "vpn", "sysmon", *_SC_TEST_ID, *_SC_EXCLUDED})
GOLD_OUT = ROOT / "teacher" / "out" / "gold.ndjson"
SOURCES_DIR = ROOT / "bench" / "sources"

_NOT_TRUTH = ("@timestamp", "@version", "ecs.", "data_stream.", "message", "labels.",
              "related.", "event.kind", "event.dataset", "event.module", "event.category",
              "event.type", "host.os.")


# ------------------------------------------------------------------ SIEMgen

def siemgen_dir() -> Path:
    d = Path(os.environ.get("SIEMGEN_DIR", "").strip()
             or Path.home() / ".cache" / "ecs-p4" / "SIEMgen-classroom")
    if not (d / "siemgen").is_dir():
        sys.exit(f"SIEMGEN_DIR ({d}) is not an export of SIEMgen's classroom branch.")
    if str(d) not in sys.path:
        sys.path.insert(0, str(d))
    return d


def siemgen_commit() -> str:
    f = siemgen_dir() / "COMMIT"
    return f.read_text().strip() if f.is_file() else "unknown"


@dataclass
class Ev:
    """One SIEMgen event: its structured fields, its native lines, its ECS."""

    fields: dict[str, Any]
    ts: datetime
    lines: list[str]
    ecs: dict[str, Any]


def events(source: str, n: int, seed: int, org_seed: int = 7) -> list[Ev]:
    """`n` events of one SIEMgen source, deterministic in (seed, org_seed)."""
    d = siemgen_dir()
    import yaml
    from siemgen.org.generate import generate_org
    from siemgen.sources import SOURCES

    cfg = yaml.safe_load((d / "config" / "classroom.yaml").read_text())
    org = generate_org(cfg, seed=org_seed)
    src = SOURCES[source]()
    src.bind(org)
    rng = random.Random(seed)
    t = datetime(2026, 10, 14, 8, 0, tzinfo=timezone.utc)
    out: list[Ev] = []
    guard = 0
    while len(out) < n and guard < n * 60:
        guard += 1
        u = rng.choice(org.users)
        h = org.host_for(u)
        if not src.applies_to(u, h):
            continue
        t = t + timedelta(seconds=rng.randint(3, 90))
        made = src.make_event(u, h, t, org, rng)
        for ev in (made if isinstance(made, list) else [made]):
            if ev is not None:
                out.append(Ev(dict(ev.fields), ev.timestamp,
                              src.render_native(ev).split("\n"), src.render_ecs(ev)))
    return out[:n]


# -------------------------------------------------------------------- truth

def flatten(doc: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in doc.items():
        if isinstance(v, dict):
            out.update(flatten(v, f"{prefix}{k}."))
        else:
            out[f"{prefix}{k}"] = v
    return out


def _is_truth_field(name: str) -> bool:
    return not any(name == p or (p.endswith(".") and name.startswith(p)) for p in _NOT_TRUTH)


def _json_scalars(obj: Any) -> list[str]:
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _json_scalars(v)]
    if isinstance(obj, list):
        return [s for v in obj for s in _json_scalars(v)]
    return [] if obj is None or isinstance(obj, bool) else [str(obj)]


def carries(line: str, value: str) -> bool:
    """Whether `line` carries `value` as a whole token (or a whole JSON value)."""
    if not value or value in ("-", ""):
        return False
    s = line.lstrip()
    if s.startswith("{"):
        try:
            return value in _json_scalars(json.loads(s))
        except ValueError:
            pass
    rx = re.compile(r"(?<![\w.:/@-])" + re.escape(value) + r"(?![\w.:/@-])")
    return bool(rx.search(line))


def _scalar_list(v: Any) -> list[str] | None:
    items = v if isinstance(v, list) else [v]
    if any(isinstance(x, (dict, list)) or isinstance(x, bool) for x in items):
        return None
    return [str(x) for x in items if x is not None]


# Values the source COMPUTED rather than copied, and the lines that carry the
# word they were computed from. Only these lines are held to them.
COMPUTED: dict[str, Callable[[str], Iterable[str]]] = {
    "linux_auth": lambda ln: (["event.outcome"]
                              if re.search(r"sshd\[\d+\]: (Accepted|Failed) ", ln) else []),
    "mail": lambda ln: ["event.outcome"] if " status=" in ln else [],
    "pfsense": lambda ln: ["network.direction"] if "filterlog" in ln else [],
    "auditd": lambda ln: ["event.outcome"] if ln.startswith("type=SYSCALL") else [],
}


def line_truth(source: str, line: str, ecs: dict[str, Any]) -> dict[str, Any]:
    """The ECS values this line carries, plus the computed ones its rule allows."""
    flat = flatten(ecs)
    out: dict[str, Any] = {}
    for name, v in flat.items():
        if not _is_truth_field(name):
            continue
        vals = _scalar_list(v)
        if not vals:
            continue
        if all(carries(line, x) for x in vals):
            out[name] = v
    for name in COMPUTED.get(source, lambda _l: [])(line):
        if name in flat and _scalar_list(flat[name]):
            out[name] = flat[name]
    return out


def truth_rows(source: str, evs: list[Ev], render: Callable[[Ev], list[str]] | None = None
               ) -> tuple[list[str], list[dict[str, Any]]]:
    """(lines, line-truth rows) for events rendered natively or by `render`."""
    lines: list[str] = []
    rows: list[dict[str, Any]] = []
    for ev in evs:
        for ln in (render(ev) if render else ev.lines):
            lines.append(ln)
            t = line_truth(source, ln, ev.ecs)
            if t:
                rows.append({"raw": ln, "ecs": t})
    return lines, rows


# ---------------------------------------------------------------- gold IRs

def _f(key: str, ecs: str, typ: str = "keyword") -> dict[str, Any]:
    return {"source_key": key, "ecs_field": ecs, "type": typ, "confidence": 1.0}


def _u(*keys: str) -> list[dict[str, Any]]:
    return [{"source_key": k, "reason": "carries no ECS field this source maps"} for k in keys]


# The syslog prefix every native SIEMgen syslog line starts with (RFC 3164 as
# rsyslog writes it). `augment` swaps it for other framings.
SYSLOG_PREFIX = r"%{SYSLOGTIMESTAMP:ts} %{SYSLOGHOST:hostname} "
SYSLOG_TS = {"source_key": "ts", "formats": ["MMM  d HH:mm:ss", "MMM dd HH:mm:ss"]}

# Each grok gold is a prefix plus one BODY per message type; the IR's pattern
# is prefix + first body and its alternatives are prefix + the rest. Kept apart
# so that a framing variant changes the prefix and nothing else.
GROK_BODIES: dict[str, list[tuple[str, str]]] = {
    # Eight shapes: the schema allows a pattern and seven alternatives, so
    # message types that share their captures share a pattern, with the words
    # that differ written as an alternation that captures nothing.
    "linux_auth": [
        ("ssh_auth", r"sshd\[%{POSINT:pid}\]: %{WORD:verb} %{WORD:method} for (?:invalid user )?"
                     r"%{USERNAME:user} from %{IP:src_ip} port %{POSINT:src_port} ssh2"
                     r"(?:: %{GREEDYDATA:key_info})?"),
        ("ssh_invalid_or_preauth",
         r"sshd\[%{POSINT:pid}\]: (?:Invalid user|Connection closed by (?:invalid|authenticating) "
         r"user) %{USERNAME:user}(?: from)? %{IP:src_ip} port %{POSINT:src_port}(?: \[preauth\])?"),
        ("ssh_disconnect",
         r"sshd\[%{POSINT:pid}\]: (?:Received disconnect from|Disconnected from user "
         r"%{USERNAME:user}) %{IP:src_ip} port %{POSINT:src_port}"
         r"(?::%{INT:reason_code}: %{GREEDYDATA:reason})?"),
        ("session_pam", r"(?:sshd|CRON)\[%{POSINT:pid}\]: pam_unix\((?:sshd|cron):session\): session "
                        r"%{WORD:session_state} for user %{USERNAME:user}"
                        r"(?:\(uid=%{INT:uid}\) by \(uid=%{INT:by_uid}\))?"),
        ("su_sudo_pam", r"(?:sudo|su\[%{POSINT:pid}\]): pam_unix\((?:sudo|su):session\): session "
                        r"%{WORD:session_state} for user %{USERNAME:target_user}"
                        r"(?:\(uid=%{INT:target_uid}\) by %{USERNAME:user}\(uid=%{INT:uid}\))?"),
        ("sudo", r"sudo: %{USERNAME:user} : TTY=%{DATA:tty} ; PWD=%{DATA:pwd} ; "
                 r"USER=%{USERNAME:target_user} ; COMMAND=%{GREEDYDATA:command}"),
        ("su", r"su\[%{POSINT:pid}\]: \(to %{USERNAME:target_user}\) %{USERNAME:user} on %{NOTSPACE:tty}"),
        ("logind", r"systemd-logind\[%{POSINT:logind_pid}\]: (?:New|Removed) session %{INT:session_id}"
                   r"(?: of user %{USERNAME:user})?\."),
    ],
    "mail": [
        ("connect", r"postfix/%{WORD:proc}\[%{POSINT:pid}\]: (?:connect|disconnect) from "
                    r"%{HOSTNAME:client_host}\[%{IP:client_ip}\](?: %{GREEDYDATA:stats})?"),
        ("client", r"postfix/%{WORD:proc}\[%{POSINT:pid}\]: %{WORD:qid}: client=%{HOSTNAME:client_host}"
                   r"\[%{IP:client_ip}\](?:, sasl_method=%{WORD:sasl_method}, "
                   r"sasl_username=%{NOTSPACE:sender})?"),
        ("cleanup", r"postfix/%{WORD:proc}\[%{POSINT:pid}\]: %{WORD:qid}: message-id=<%{DATA:message_id}>"),
        ("qmgr_from", r"postfix/%{WORD:proc}\[%{POSINT:pid}\]: %{WORD:qid}: from=<%{DATA:sender}>, "
                      r"size=%{INT:size}, nrcpt=%{INT:nrcpt} \(queue active\)"),
        ("delivery", r"postfix/%{WORD:proc}\[%{POSINT:pid}\]: %{WORD:qid}: to=<%{DATA:recipient}>, "
                     r"relay=%{DATA:relay}, delay=%{NUMBER:delay}, delays=%{NOTSPACE:delays}, "
                     r"dsn=%{NOTSPACE:dsn}, status=%{WORD:status} \(%{GREEDYDATA:response}\)"),
        ("removed", r"postfix/%{WORD:proc}\[%{POSINT:pid}\]: %{WORD:qid}: removed"),
    ],
    "dns": [
        ("query", r"dnsmasq\[%{POSINT:pid}\]: query\[%{WORD:qtype}\] %{HOSTNAME:qname} from %{IP:client_ip}"),
        ("nxdomain", r"dnsmasq\[%{POSINT:pid}\]: reply %{HOSTNAME:qname} is %{WORD:rcode}$"),
        ("answer", r"dnsmasq\[%{POSINT:pid}\]: (?:reply|cached|config) %{HOSTNAME:qname} is %{NOTSPACE:answer}"),
        ("forwarded", r"dnsmasq\[%{POSINT:pid}\]: forwarded %{HOSTNAME:qname} to %{IP:upstream}"),
    ],
    "pfsense": [
        ("filterlog", r"filterlog\[%{POSINT:pid}\]: %{INT:rule},%{DATA:subrule},%{DATA:anchor},"
                      r"%{INT:tracker},%{DATA:iface},%{WORD:reason},%{WORD:action},%{WORD:direction},"
                      r"%{INT:ipver},%{DATA:tos},%{DATA:ecn},%{INT:ttl},%{INT:ipid},%{INT:offset},"
                      r"%{WORD:flags},%{INT:protonum},%{WORD:transport},%{INT:length},%{IP:src_ip},"
                      r"%{IP:dst_ip}(?:,%{INT:src_port},%{INT:dst_port},%{INT:datalen})?"
                      r"(?:,%{GREEDYDATA:tcp_rest})?"),
    ],
}

GROK_GOLD: dict[str, dict[str, Any]] = {
    "linux_auth": {
        "fields": [_f("user", "user.name"), _f("src_ip", "source.ip", "ip"),
                   _f("src_port", "source.port", "long"), _f("pid", "process.pid", "long"),
                   _f("uid", "user.id"), _f("target_user", "user.effective.name"),
                   _f("target_uid", "user.effective.id"),
                   _f("command", "process.command_line"), _f("hostname", "host.hostname")],
        "value_maps": [{"ecs_field": "event.outcome", "from_source_key": "verb",
                        "map": {"Accepted": "success", "Failed": "failure"}}],
        "unresolved": _u("method", "key_info", "reason_code", "reason", "session_state",
                         "by_uid", "tty", "pwd", "logind_pid", "session_id"),
        "constants": {"event.dataset": "system.auth", "event.kind": "event",
                      "event.category": ["authentication"]},
    },
    "mail": {
        "fields": [_f("client_ip", "source.ip", "ip"), _f("qid", "event.id"),
                   _f("sender", "email.from.address"), _f("recipient", "email.to.address"),
                   _f("message_id", "email.message_id"), _f("status", "event.action"),
                   _f("pid", "process.pid", "long"), _f("hostname", "host.hostname")],
        "value_maps": [{"ecs_field": "event.outcome", "from_source_key": "outcome_word",
                        "map": {"sent": "success", "deferred": "failure", "bounced": "failure"}}],
        "unresolved": _u("proc", "client_host", "stats", "sasl_method", "size", "nrcpt",
                         "relay", "delay", "delays", "dsn", "response"),
        "constants": {"event.dataset": "postfix.log", "event.kind": "event",
                      "event.category": ["email"]},
    },
    "dns": {
        "fields": [_f("qtype", "dns.question.type"), _f("qname", "dns.question.name"),
                   _f("client_ip", "source.ip", "ip"), _f("rcode", "dns.response_code"),
                   _f("answer", "dns.resolved_ip", "ip"), _f("hostname", "host.hostname")],
        "unresolved": _u("pid", "upstream"),
        "constants": {"event.dataset": "dns", "event.kind": "event",
                      "event.category": ["network"]},
    },
    "pfsense": {
        "fields": [_f("rule", "rule.id"), _f("tracker", "rule.uuid"),
                   _f("iface", "observer.ingress.interface.name"), _f("action", "event.action"),
                   _f("protonum", "network.iana_number"), _f("transport", "network.transport"),
                   _f("src_ip", "source.ip", "ip"), _f("dst_ip", "destination.ip", "ip"),
                   _f("src_port", "source.port", "long"), _f("dst_port", "destination.port", "long"),
                   _f("hostname", "observer.hostname")],
        "value_maps": [{"ecs_field": "network.direction", "from_source_key": "direction",
                        "map": {"out": "egress", "in": "ingress"}}],
        "unresolved": _u("pid", "subrule", "anchor", "reason", "ipver", "tos", "ecn", "ttl",
                         "ipid", "offset", "flags", "length", "datalen", "tcp_rest"),
        "constants": {"event.dataset": "pfsense.firewall", "event.kind": "event",
                      "event.category": ["network"]},
    },
}

# auditd is key=value, one record type per line.
AUDITD_GOLD: dict[str, Any] = {
    "extraction": {"kind": "kv", "field_split": " ", "value_split": "="},
    "fields": [_f("pid", "process.pid", "long"), _f("ppid", "process.parent.pid", "long"),
               _f("uid", "user.id"), _f("euid", "user.effective.id"),
               _f("exe", "process.executable"), _f("comm", "process.name"),
               _f("cwd", "process.working_directory")],
    "value_maps": [{"ecs_field": "event.outcome", "from_source_key": "success",
                    "map": {"yes": "success", "no": "failure"}}],
    # auid is the login identity; ECS 8.11 has no field for it (user.audit.*
    # arrived later), so it is declared rather than forced into user.id.
    "unresolved": _u("auid", "type", "msg", "arch", "syscall", "exit", "items", "gid", "suid", "fsuid",
                     "egid", "sgid", "fsgid", "tty", "ses", "subj", "key", "argc", "item",
                     "name", "inode", "dev", "mode", "ouid", "ogid", "rdev", "nametype",
                     "cap_fp", "cap_fi", "cap_fe", "cap_fver", "cap_frootid", "proctitle",
                     *[f"a{i}" for i in range(16)]),
    "constants": {"event.dataset": "linux.audit", "event.kind": "event",
                  "event.category": ["process"]},
}

NATIVE_GROK = tuple(GROK_BODIES)          # linux_auth, mail, dns, pfsense
NATIVE_KV = ("auditd",)
NATIVE_JSON = ("suricata", "windows", "azuread", "cloud_audit")
NATIVE_TEXT = ("nginx",)
GOLD_SOURCES = NATIVE_GROK + NATIVE_KV + NATIVE_JSON + NATIVE_TEXT

NGINX_GOLD = {
    "extraction": {"kind": "grok", "pattern":
                   r'%{IPORHOST:src_ip} - %{DATA:remote_user} \[%{HTTPDATE:ts}\] '
                   r'"%{WORD:method} %{DATA:uri} HTTP/%{NUMBER:http_version}" %{INT:status} '
                   r'%{INT:bytes} "%{DATA:referrer}" "%{DATA:agent}"'},
    "fields": [_f("src_ip", "source.ip", "ip"), _f("method", "http.request.method"),
               _f("uri", "url.original"), _f("http_version", "http.version"),
               _f("status", "http.response.status_code", "long"),
               _f("bytes", "http.response.body.bytes", "long"),
               _f("referrer", "http.request.referrer"), _f("agent", "user_agent.original")],
    "timestamp": {"source_key": "ts", "formats": ["dd/MMM/yyyy:HH:mm:ss Z"]},
    "unresolved": _u("remote_user"),
    "constants": {"event.dataset": "nginx.access", "event.kind": "event",
                  "event.category": ["web"]},
}


def grok_ir(source: str, source_id: str, prefix: str = SYSLOG_PREFIX,
            bodies: list[str] | None = None, ts: dict[str, Any] | None = SYSLOG_TS) -> dict[str, Any]:
    """The gold grok IR for a native syslog source under a given framing."""
    g = GROK_GOLD[source]
    names = bodies or [n for n, _ in GROK_BODIES[source]]
    pats = [prefix + dict(GROK_BODIES[source])[n] for n in names]
    if source == "mail":
        # The delivery status is read twice: as the action it names, and as the
        # word the outcome is computed from. One capture cannot feed both a
        # rename and a translate, so the delivery line captures it twice.
        pats = [p.replace(r"status=%{WORD:status} \(",
                          r"status=(?=%{WORD:outcome_word})%{WORD:status} \(") for p in pats]
    ir = {
        "source_id": source_id, "ecs_version": "8.11",
        "extraction": {"kind": "grok", "pattern": pats[0], "alternatives": pats[1:]},
        "fields": [dict(f) for f in g["fields"]],
        "value_maps": [dict(v) for v in g.get("value_maps", [])],
        "constants": dict(g["constants"]),
        "unresolved": list(g["unresolved"]),
    }
    if ts:
        ir["timestamp"] = dict(ts)
    if not ir["extraction"]["alternatives"]:
        ir["extraction"].pop("alternatives")
    return _prune(ir)


def _captures(ir: dict[str, Any]) -> set[str]:
    ex = ir.get("extraction") or {}
    pats = [ex.get("pattern") or ""] + list(ex.get("alternatives") or [])
    return {m for p in pats for m in re.findall(r"%\{[A-Z0-9_]+:([A-Za-z0-9_]+)", p)}


def _prune(ir: dict[str, Any]) -> dict[str, Any]:
    """Drop mappings and declarations for keys the chosen patterns never capture."""
    if (ir.get("extraction") or {}).get("kind") != "grok":
        return ir
    caps = _captures(ir)
    ir["fields"] = [f for f in ir["fields"] if f["source_key"] in caps]
    ir["value_maps"] = [v for v in ir.get("value_maps", []) if v.get("from_source_key") in caps]
    if not ir["value_maps"]:
        ir.pop("value_maps")
    mapped = {f["source_key"] for f in ir["fields"]} | {v["from_source_key"] for v in ir.get("value_maps", [])}
    ts_key = (ir.get("timestamp") or {}).get("source_key")
    ir["unresolved"] = [u for u in ir.get("unresolved", []) if u["source_key"] in caps]
    have = {u["source_key"] for u in ir["unresolved"]} | mapped | ({ts_key} if ts_key else set())
    ir["unresolved"] += _u(*sorted(caps - have))
    return ir


def native_gold(source: str, source_id: str, evs: list[Ev] | None = None) -> dict[str, Any]:
    if source in GROK_GOLD:
        return grok_ir(source, source_id)
    if source == "auditd":
        return {"source_id": source_id, "ecs_version": "8.11", **json.loads(json.dumps(AUDITD_GOLD))}
    if source == "nginx":
        return {"source_id": source_id, "ecs_version": "8.11", **json.loads(json.dumps(NGINX_GOLD))}
    if source in NATIVE_JSON:
        assert evs, "a JSON gold is derived from events"
        return auto_ir(source, source_id, [json.loads(e.lines[0]) for e in evs],
                       [e.ecs for e in evs], {"kind": "json"})
    raise KeyError(source)


# --------------------------------------------------- value-matching auto IR

_IR_TYPE = {"keyword": "keyword", "constant_keyword": "keyword", "wildcard": "keyword",
            "match_only_text": "text", "text": "text", "ip": "ip", "long": "long",
            "integer": "long", "short": "long", "byte": "long", "unsigned_long": "long",
            "float": "float", "double": "float", "scaled_float": "float",
            "half_float": "float", "boolean": "boolean", "date": "date"}
_NOT_TARGET = _NOT_TRUTH + ("host.name", "event.created", "event.ingested", "user_agent.name",
                            "user_agent.os.", "user_agent.device.", "user_agent.version")


def _leaves(obj: Any, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(_leaves(v, f"{prefix}{k}."))
    else:
        out[prefix.rstrip(".")] = obj
    return out


_ECS = None


def ecs_index():
    global _ECS
    if _ECS is None:
        from adapter.wiring import _ecs_index
        _ECS = _ecs_index()
    return _ECS


def auto_mapping(records: list[dict[str, Any]], ecs_docs: list[dict[str, Any]],
                 min_share: float = 0.9) -> tuple[dict[str, str], list[str]]:
    """key -> ECS field, by value equality across events; plus the keys left out.

    A key maps to the field whose value equals the key's value on at least
    `min_share` of the events carrying the key. A key that matches two fields
    that often, or none, is left out (`unresolved`). When two keys win the same
    field the one that matches more often keeps it; ties go to the shorter key,
    and the loser is left out - one key per field is the IR's rule.
    """
    idx = ecs_index()
    hits: dict[str, Counter[str]] = defaultdict(Counter)
    seen: Counter[str] = Counter()
    for rec, doc in zip(records, ecs_docs):
        flat_doc = {k: v for k, v in flatten(doc).items()
                    if not any(k == p or (p.endswith(".") and k.startswith(p)) for p in _NOT_TARGET)}
        by_value: dict[str, set[str]] = defaultdict(set)
        for f, v in flat_doc.items():
            vals = _scalar_list(v)
            if vals and len(vals) == 1:
                by_value[vals[0]].add(f)
        for key, v in _leaves(rec).items():
            if isinstance(v, (dict, list, bool)) or v is None or str(v) in ("", "-"):
                continue
            seen[key] += 1
            for f in by_value.get(str(v), ()):
                hits[key][f] += 1
    chosen: dict[str, tuple[str, float]] = {}
    left: list[str] = []
    for key, n in seen.items():
        good = [(f, c / n) for f, c in hits[key].items() if c / n >= min_share]
        good = [(f, s) for f, s in good if idx.exists(f)]
        if len(good) == 1:
            chosen[key] = good[0]
        else:
            left.append(key)
    owner: dict[str, str] = {}
    for key, (f, share) in sorted(chosen.items(), key=lambda kv: (-kv[1][1], len(kv[0]), kv[0])):
        if f in owner:
            left.append(key)
        else:
            owner[f] = key
    mapping = {k: f for f, k in owner.items()}
    return mapping, sorted(set(left))


# Fields whose value is a closed vocabulary the source spells in its own words.
VALUE_MAP_FIELDS = ("event.outcome", "network.direction")


def auto_value_maps(records: list[dict[str, Any]], ecs_docs: list[dict[str, Any]],
                    candidates: list[str], min_share: float = 0.95) -> list[dict[str, Any]]:
    """Value maps for keys whose words determine a closed-vocabulary field.

    Value matching cannot see `Accepted` in `event.outcome: success`, so until
    2026-10-17 every re-rendered layout lost the outcome its native gold
    translated, and 53 of 740 training answers carried a value map at all. A
    key earns a map when its value decides the field's value - each word always
    the same target, on at least `min_share` of the events carrying both - with
    at least two words, so a constant is never mistaken for a translation,
    and at most eight, each seen at least twice, so an identifier is not either.
    """
    out: list[dict[str, Any]] = []
    taken: set[str] = set()
    for field in VALUE_MAP_FIELDS:
        best = None
        for key in candidates:
            pairs: dict[str, Counter[str]] = defaultdict(Counter)
            for rec, doc in zip(records, ecs_docs):
                v = _leaves(rec).get(key)
                t = flatten(doc).get(field)
                if v in (None, "", "-") or t in (None, "") or isinstance(v, (dict, list)):
                    continue
                pairs[str(v)][str(t)] += 1
            n = sum(sum(c.values()) for c in pairs.values())
            # A vocabulary, not an identifier: few words, each seen repeatedly.
            # Without this a unique value per event (a URL) "determines" the
            # outcome trivially, one event per word.
            if not 2 <= len(pairs) <= 8 or not n or min(sum(c.values()) for c in pairs.values()) < 2:
                continue
            agree = sum(c.most_common(1)[0][1] for c in pairs.values())
            if agree / n >= min_share and len({c.most_common(1)[0][0] for c in pairs.values()}) >= 2:
                if best is None or agree / n > best[0]:
                    best = (agree / n, key, {w: c.most_common(1)[0][0] for w, c in pairs.items()})
        if best and best[1] not in taken:
            taken.add(best[1])
            out.append({"from_source_key": best[1], "ecs_field": field, "map": best[2]})
    return out


def auto_ir(source: str, source_id: str, records: list[dict[str, Any]],
            ecs_docs: list[dict[str, Any]], extraction: dict[str, Any],
            rename: dict[str, str] | None = None) -> dict[str, Any]:
    """An IR for a structured layout, derived from value matching.

    `rename` maps the generator's key names to the names the layout actually
    writes (a key-naming scheme); the mapping is computed on the original keys
    and carried across.
    """
    idx = ecs_index()
    mapping, left = auto_mapping(records, ecs_docs)
    rename = rename or {}
    fields = []
    for key, f in sorted(mapping.items()):
        typ = _IR_TYPE.get(idx.type_of(f) or "keyword", "keyword")
        fields.append(_f(rename.get(key, key), f, typ))
    present = {k for r in records for k, v in _leaves(r).items()}
    owned = set(mapping.values())
    vmaps = [v for v in auto_value_maps(records, ecs_docs, sorted(present - set(mapping)))
             if v["ecs_field"] not in owned]
    vm_keys = {v["from_source_key"] for v in vmaps}
    unresolved = _u(*sorted(rename.get(k, k) for k in present if k not in mapping and k not in vm_keys))
    const = {"event.dataset": f"siemgen.{source}", "event.kind": "event",
             "event.category": [_CATEGORY.get(source, "network")]}
    ir = {"source_id": source_id, "ecs_version": "8.11", "extraction": dict(extraction),
          "fields": fields, "constants": const, "unresolved": unresolved}
    if vmaps:
        ir["value_maps"] = [{**v, "from_source_key": rename.get(v["from_source_key"], v["from_source_key"])}
                            for v in vmaps]
    return ir


_CATEGORY = {"nginx": "web", "linux_auth": "authentication", "pfsense": "network",
             "auditd": "process", "dns": "network", "mail": "email", "suricata": "network",
             "windows": "process", "azuread": "authentication", "cloud_audit": "file"}


# ------------------------------------------------------- batched verification

def _inner(filter_block: str) -> str:
    s = filter_block.strip()
    i = s.index("filter {")
    return s[i + len("filter {"): s.rstrip().rfind("}")]


@dataclass
class Candidate:
    source_id: str
    source: str                  # SIEMgen source
    ir: dict[str, Any]
    lines: list[str]             # every line, for VT
    truth: list[dict[str, Any]]
    transform: str
    provenance: dict[str, Any] = field(default_factory=dict)
    documentation: str = ""
    report: dict[str, Any] = field(default_factory=dict)
    category: str | None = None
    holdback: frozenset[str] = frozenset()

    def sample_lines(self) -> list[str]:
        return [ln for ln in self.lines if ln not in self.holdback]


def choose_holdback(c: "Candidate") -> frozenset[str]:
    """Lines of one shape kept out of the samples, to become detection scenarios.

    A scenario may not replay a line that equals a sample once its numbers and
    addresses are masked (tests/test_pools.py). A firewall log is one shape
    under that masking, so with every shape represented in the samples no
    scenario could ever be written and V4 could not run. One shape - the most
    frequent that still leaves most lines - is therefore never shown; it is read
    by the same extraction, so nothing about the task changes except that the
    rule is tested on lines the model did not see.
    """
    shapes = Counter(_norm(ln) for ln in c.lines)
    if len(shapes) < 2:
        return frozenset()
    cap = 0.4 * len(c.lines)
    fits = sorted(((n, sh) for sh, n in shapes.items() if 3 <= n <= cap), reverse=True)
    ex = c.ir.get("extraction") or {}
    pats: list[Any] = []
    if ex.get("kind") == "grok":
        from validators.v2_consistency import _grok_to_regex

        pats = [re.compile(_grok_to_regex(x)[0])
                for x in [ex.get("pattern") or ""] + list(ex.get("alternatives") or [])]
    for _n, shape in fits:
        held = frozenset(ln for ln in c.lines if _norm(ln) == shape)
        rest = [ln for ln in c.lines if ln not in held]
        # Every message shape the answer needs must still be shown: an
        # alternative for lines the model never saw would be taught blind.
        if all(any(rx.match(ln) for ln in rest) for rx in pats):
            return held
    return frozenset()


def fit_category(ir: dict[str, Any], preferred: str | None) -> tuple[str | None, dict[str, Any]]:
    """The category hint retrieval will use, and the IR cut to what it can offer.

    `category_hint` decides which ECS roots the mapping stage is shown
    (tests/test_corpus.py). A training example that maps a field retrieval
    never offers teaches the student to name a field it will not be given, so
    the hint is chosen to cover the most mapped roots - the source's natural
    category when it covers as many as any other - and any field still out of
    reach is declared `unresolved` rather than taught.
    """
    from adapter.ecs_index import ALWAYS, CATEGORY_FIELDSETS, CONFUSABLE

    targets = [f["ecs_field"] for f in ir.get("fields", [])] + \
              [v["ecs_field"] for v in ir.get("value_maps", [])]

    def covered(hint: str) -> int:
        reach = CATEGORY_FIELDSETS[hint] | CONFUSABLE | ALWAYS
        return sum(t.partition(".")[0] in reach for t in targets)

    hints = sorted(CATEGORY_FIELDSETS, key=lambda h: (-covered(h), h != preferred, h))
    hint = hints[0] if hints else preferred
    reach = CATEGORY_FIELDSETS.get(hint, set()) | CONFUSABLE | ALWAYS
    out = json.loads(json.dumps(ir))
    gone = [f for f in out.get("fields", []) if f["ecs_field"].partition(".")[0] not in reach]
    out["fields"] = [f for f in out.get("fields", []) if f not in gone]
    out["unresolved"] = list(out.get("unresolved", [])) + [
        {"source_key": f["source_key"], "reason": "no field this category offers fits it"}
        for f in gone]
    if out.get("value_maps"):
        out["value_maps"] = [v for v in out["value_maps"]
                             if v["ecs_field"].partition(".")[0] in reach]
        if not out["value_maps"]:
            out.pop("value_maps")
    return hint, out


# The product each SIEMgen source imitates, for the title of its documentation.
_PRODUCT = {
    "linux_auth": "OpenSSH, sudo and PAM authentication log",
    "mail": "Postfix MTA log",
    "dns": "dnsmasq resolver log",
    "pfsense": "pfSense filterlog",
    "nginx": "nginx access log",
    "auditd": "Linux audit daemon records",
    "suricata": "Suricata EVE events",
    "windows": "Windows Security event log",
    "azuread": "Azure AD sign-in log",
    "cloud_audit": "Nextcloud audit log",
}
_TS_DOC = ("event time", "timestamp as written", "when the entry was logged")


def _pattern_schematic(pattern: str) -> str:
    """A grok pattern as a vendor would print the line: literals, and UPPERCASE placeholders.

    `%{IP:src_ip}` becomes SRC_IP, an optional group `(?:...)?` becomes
    `[...]`, a lookahead disappears, and grok's escapes are dropped.
    """
    p = re.sub(r"\(\?=[^()]*\)", "", pattern)
    p = re.sub(r"%\{([A-Z0-9_]+)(?::([A-Za-z0-9_.\[\]]+))?\}",
               lambda m: (m.group(2) or m.group(1)).split("][")[-1].strip("[]").upper(), p)
    # Optional groups: walk the parentheses so nested ones resolve correctly.
    out, stack, i = [], [], 0
    while i < len(p):
        if p.startswith("(?:", i):
            stack.append(len(out))
            out.append("(")
            i += 3
            continue
        if p[i] == ")" and stack and (i == 0 or p[i - 1] != "\\"):
            j = stack.pop()
            if i + 1 < len(p) and p[i + 1] == "?":
                out[j] = "["
                out.append("]")
                i += 2
            else:
                out.append(")")
                i += 1
            continue
        out.append(p[i])
        i += 1
    text = "".join(out)
    return re.sub(r"\\(.)", r"\1", text).replace("$", "")


def _keys_in_order(c: "Candidate") -> list[str]:
    """Every key the source writes, in the order the lines show them."""
    ir, ex = c.ir, c.ir["extraction"]
    kind = ex.get("kind")
    keys: list[str] = []

    def add(k: str) -> None:
        if k and k not in keys:
            keys.append(k)

    if kind == "grok":
        for pat in [ex.get("pattern") or ""] + list(ex.get("alternatives") or []):
            for m in re.finditer(r"%\{[A-Z0-9_]+:([A-Za-z_][A-Za-z0-9_]*)", pat):
                add(m.group(1))
    elif kind == "csv":
        for k in ex.get("columns") or []:
            add(k)
    else:
        for ln in c.sample_lines():
            if kind == "json":
                try:
                    for k in _leaves(json.loads(ln)):
                        add(k)
                except ValueError:
                    pass
            else:
                vs = re.escape(ex.get("value_split") or "=")
                for m in re.finditer(r"(?:^|[\s,;|])([A-Za-z_@][A-Za-z0-9_.@-]*)" + vs, ln):
                    add(m.group(1))
    named = [f["source_key"] for f in ir.get("fields", [])] + \
            [v["from_source_key"] for v in ir.get("value_maps", [])] + \
            [u["source_key"] for u in ir.get("unresolved", [])]
    for k in named:
        add(k)
    return keys


def _line_schematic(c: "Candidate", keys: list[str]) -> list[str]:
    ex = c.ir["extraction"]
    kind = ex.get("kind")
    if kind == "grok":
        pats = [ex.get("pattern") or ""] + list(ex.get("alternatives") or [])
        return [_pattern_schematic(p) for p in pats[:8]]
    if kind == "csv":
        sep = ex.get("field_split") or ","
        return [("\t" if sep == "\t" else sep).join(k.upper() for k in keys)]
    if kind == "json":
        return ["{" + ", ".join(f'"{k}": {k.upper().replace(".", "_")}' for k in keys[:14])
                + (", ..." if len(keys) > 14 else "") + "}"]
    fs, vs = ex.get("field_split") or " ", ex.get("value_split") or "="
    return [fs.join(f"{k}{vs}{k.upper()}" for k in keys[:14]) + (" ..." if len(keys) > 14 else "")]


def documentation(c: "Candidate") -> str:
    """A vendor-style field reference for the source - and never its answer.

    THE REGISTER OF THE REAL SOURCES (2026-10-17). The hand-written
    documentation of the sources the students are evaluated on has a product
    title, a sentence on what the log is, a schematic of the line with
    UPPERCASE placeholders, a couple of real lines, and a bullet per field
    saying in a few words what it holds (bench/sources/vsftpd_xfer). The gold
    documentation had a format line and, at most, capture names with a
    two-word label: 299 characters at the median against 1,526. Students
    trained on the one were evaluated on the other.

    THE ANSWER IS STILL NOT IN IT. Descriptions come from DOC_VARIANTS
    (corpus/roles.py), a vocabulary that shares no run of four words with any
    role phrasing, and training.build_dataset refuses any example whose roles
    its documentation states. A key the IR leaves unresolved gets a neutral
    line. A key whose words a value map translates lists those words, as a
    vendor's reference does ("RESULT is OK or FAIL") - that is evidence about
    the line, and stage 2 needs it.

    Every key gets a bullet in the `- `key` — text` form Source.observed_keys
    reads, so retrieval sees the same keys it saw before.
    """
    from corpus.roles import _pick, doc_variant

    ir = c.ir
    ex = ir["extraction"]
    target = {f["source_key"]: f["ecs_field"] for f in ir.get("fields", [])}
    vmaps = {v["from_source_key"]: v for v in ir.get("value_maps", [])}
    ts = (ir.get("timestamp") or {}).get("source_key")
    keys = _keys_in_order(c)
    product = _PRODUCT.get(c.source, c.source)
    framing = (c.provenance or {}).get("framing")
    lines = [f"# {product}", ""]
    lines.append(f"{format_summary(ex)[0].upper()}{format_summary(ex)[1:]}, one entry per line"
                 + (f", behind a {framing} header" if framing else "") + ".")
    lines += ["", "```", *_line_schematic(c, keys), "```", ""]
    shown = c.sample_lines()
    ex_lines: list[str] = []
    for ln in shown:
        if not ex_lines or _norm(ln) not in {_norm(x) for x in ex_lines}:
            ex_lines.append(ln)
        if len(ex_lines) == 2:
            break
    if ex_lines:
        lines += ["Example lines:", "", "```", *ex_lines, "```", ""]
    for k in keys:
        salt = f"{c.source_id}:{k}:doc"
        if k == ts:
            desc = _pick(_TS_DOC, salt)
        elif k in vmaps:
            words = ", ".join(f"`{w}`" for w in sorted(vmaps[k].get("map") or {}))
            desc = doc_variant(vmaps[k]["ecs_field"], salt) + (f"; one of {words}" if words else "")
        else:
            desc = doc_variant(target.get(k), salt)
        lines.append(f"- `{k}` \u2014 {desc}")
    return "\n".join(lines) + "\n"


def fit_retrieval(c: "Candidate") -> dict[str, Any]:
    """The IR cut to the ECS fields retrieval will actually offer for this source.

    training/build_dataset.py renders the map prompt with
    `relevant_subset(observed_keys, documentation, category_hint, ...)`. A field
    outside that subset is one the student is taught to name without having
    been shown it, so it is declared `unresolved` instead.
    """
    from adapter.ecs_index import DEFAULT_MAX_FIELDS
    from adapter.types import Source

    src = Source(source_id=c.source_id, samples=tuple(_samples(c.sample_lines())),
                 documentation=c.documentation, category_hint=c.category)
    # Retrieval is called three ways in this codebase - the dataset builder
    # (embeddings, no documentation hints), the arms at inference (embeddings
    # and hints), the retrieval tests (hints, no embeddings) - and a field must
    # be offered by all three to be taught.
    idx = ecs_index()
    keys, doc, hint = src.observed_keys(), src.documentation, src.category_hint
    offered = None
    for emb, hints in ((True, None), (True, src.documentation_hints()),
                       (False, src.documentation_hints())):
        try:
            got = {f.name for f in idx.relevant_subset(keys, doc, hint, DEFAULT_MAX_FIELDS,
                                                       use_embeddings=emb, doc_hints=hints)}
        except ImportError:   # no sentence-transformers on this host
            continue
        offered = got if offered is None else offered & got
    ir = json.loads(json.dumps(c.ir))
    gone = [f for f in ir.get("fields", []) if f["ecs_field"] not in offered]
    ir["fields"] = [f for f in ir.get("fields", []) if f not in gone]
    ir["unresolved"] = list(ir.get("unresolved", [])) + [
        {"source_key": f["source_key"], "reason": "not among the fields offered for this source"}
        for f in gone]
    if ir.get("value_maps"):
        keep = [v for v in ir["value_maps"] if v["ecs_field"] in offered]
        for v in ir["value_maps"]:
            if v not in keep:
                ir["unresolved"].append({"source_key": v["from_source_key"],
                                         "reason": "not among the fields offered for this source"})
        ir["value_maps"] = keep
        if not keep:
            ir.pop("value_maps")
    return ir


def _samples(lines: list[str]):
    from adapter.sampler import deduplicate

    return deduplicate(lines)


def verify(cands: list[Candidate], stack_version: str = "8.19.7") -> None:
    """V1, V2, then ONE Logstash run for the whole batch, then VT. In place.

    Each candidate's compiled filter is fenced by its inputs' @metadata tags, so
    a batch of twenty candidates costs one start-up instead of forty. A batch
    whose combined pipeline Logstash refuses is re-run one candidate at a time,
    so one bad candidate cannot sink the others.
    """
    from adapter.compiler import CompileError, compile_ir
    from adapter.types import Source
    from validators import v1_schema, v2_consistency, v3_sandbox, vt_truth

    idx = ecs_index()
    live: list[tuple[Candidate, str]] = []
    for c in cands:
        c.holdback = choose_holdback(c)
        c.category, c.ir = fit_category(c.ir, _CATEGORY.get(c.source))
        c.documentation = documentation(c)
        c.ir = fit_retrieval(c)
        r1 = v1_schema.validate(c.ir, idx)
        if not r1.passed:
            c.report = _report(r1, "V1")
            continue
        src = Source(source_id=c.source_id, samples=tuple(_samples(c.sample_lines())),
                     documentation=c.documentation)
        r2 = v2_consistency.validate(c.ir, src)
        if not r2.passed:
            c.report = _report(r2, "V2")
            continue
        try:
            live.append((c, compile_ir(c.ir, idx.all_names())))
        except CompileError as exc:
            c.report = {"passed": False, "rung_reached": "V1", "metrics": {},
                        "findings": [{"rung": "V1", "code": "compile_error", "message": str(exc)}]}
    if not live:
        return

    def run(batch: list[tuple[Candidate, str]]) -> bool:
        sources, fences = [], []
        for i, (c, fb) in enumerate(batch):
            sources.append(Source(source_id=c.source_id, samples=tuple(_samples(c.sample_lines()))))
            sources.append(Source(source_id=c.source_id,
                                  samples=tuple(_sample_of(ln) for ln in c.lines)))
            fences.append(f'  if [@metadata][sbx] in ["{2 * i}", "{2 * i + 1}"] {{\n'
                          f'{_inner(fb)}\n  }}')
        combined = "filter {\n" + "\n".join(fences) + "\n}\n"
        if len(sources) == 2:
            combined = batch[0][1]
        reps = v3_sandbox.validate_many(combined, sources, stack_version,
                                        timeout_s=240 + 20 * len(batch))
        if len(batch) > 1 and all(any(f.code in ("logstash_failed", "logstash_timeout")
                                      for f in r.findings) for r in reps):
            return False
        for i, (c, _fb) in enumerate(batch):
            r3, full = reps[2 * i], reps[2 * i + 1]
            if not r3.passed:
                c.report = _report(r3, "V3")
                continue
            vt = vt_truth.validate(full.metrics.get("documents", []), c.truth)
            assigned = {f["ecs_field"] for f in c.ir.get("fields", [])} | \
                       {v["ecs_field"] for v in c.ir.get("value_maps", [])}
            verified = sorted(set(vt.metrics["verified_fields"]) & assigned)
            c.report = {
                "passed": bool(verified) and not vt.metrics["contradicted_fields"],
                "rung_reached": "VT",
                "findings": [_finding(f) for f in vt.findings],
                "metrics": {"oracle": "VT", "verified_fields": verified,
                            "contradicted_fields": vt.metrics["contradicted_fields"],
                            "unchecked_fields": vt.metrics["unchecked_fields"],
                            "extra_fields": vt.metrics["extra_fields"],
                            "vt_per_field": vt.metrics["per_field"],
                            "v3_documents": len(r3.metrics.get("documents", [])),
                            "truth_lines": len(c.truth)},
            }
        return True

    if not run(live):
        for one in live:
            run([one])


def _sample_of(line: str):
    from adapter.types import Sample

    return Sample.of(line, "vt")


def _finding(f) -> dict[str, Any]:
    return {"rung": f.rung, "code": f.code, "message": f.message, "stage": f.stage,
            "source_key": f.source_key}


def _report(rep, rung: str) -> dict[str, Any]:
    return {"passed": False, "rung_reached": rung, "metrics": {},
            "findings": [_finding(f) for f in rep.findings]}


# ------------------------------------------------------------ roles, records

# Plain-language roles, never naming an ECS field: stage 1's answer must stay
# free of ECS vocabulary (schema/roles.schema.json, tests/test_blindness.py).
# Several phrasings per field since 2026-10-16; see corpus/roles.py.
from corpus.roles import ROLE_VARIANTS, role_text  # noqa: E402

ROLE = {k: v[0] for k, v in ROLE_VARIANTS.items()}
VALUE_SEMANTICS = {
    "event.outcome": "words such as Accepted/Failed, yes/no or sent/deferred say whether it succeeded",
    "network.direction": "out means traffic leaving, in means traffic arriving",
}
# What a target value means, in words stage 1 may use (no ECS vocabulary).
_MEANS = {"success": "it succeeded", "failure": "it failed", "unknown": "the result is unknown",
          "ingress": "the traffic was arriving", "egress": "the traffic was leaving",
          "inbound": "the traffic was arriving", "outbound": "the traffic was leaving"}


def value_semantics(vmap: dict[str, str], target: str) -> str:
    """The source's own words and what each one means, as the prompt asks.

    Stage 2 never sees a line, so the words a value map translates reach it only
    through this text (prompts/s1_interpret.md rule 6, prompts/s2_map.md rule 9).
    Until 2026-10-17 it was one fixed sentence per field ("words such as
    Accepted/Failed, yes/no ..."), never the words of the source at hand; the
    first gold-trained student then wrote sshd's map backwards and with words
    the log does not contain (`succeeded`), and left vsftpd's OK/FAIL unmapped.
    """
    parts = [f"`{word}` indicates {_MEANS.get(val, 'the value ' + repr(val))}"
             for word, val in vmap.items()]
    return "; ".join(parts) or VALUE_SEMANTICS.get(target, "a word that names the result")


UNIT = {"http.response.body.bytes": "bytes", "source.bytes": "bytes", "destination.bytes": "bytes"}

def format_summary(extraction: dict[str, Any]) -> str:
    kind = extraction.get("kind")
    if kind == "json":
        return "one JSON object per line"
    if kind == "kv":
        return (f'key=value pairs separated by "{extraction.get("field_split", " ")}", '
                f'key and value joined by "{extraction.get("value_split", "=")}"')
    if kind == "csv":
        sep = extraction.get("field_split") or ","
        return f'positional columns separated by "{"tab" if sep == chr(9) else sep}"'
    n = 1 + len(extraction.get("alternatives") or [])
    return (f"free text in {n} distinct message shape(s), read with a grok pattern"
            + (" per shape" if n > 1 else ""))


def roles_for(ir: dict[str, Any]) -> dict[str, Any]:
    """Stage 1's answer for this IR: extraction, plain roles, no ECS names."""
    roles = []
    vm_src = {v["from_source_key"]: v["ecs_field"] for v in ir.get("value_maps", [])}
    vm_map = {v["from_source_key"]: v.get("map") or {} for v in ir.get("value_maps", [])}
    for f in ir.get("fields", []):
        r = {"source_key": f["source_key"],
             "role": role_text(f["ecs_field"], f"{ir['source_id']}:{f['source_key']}"),
             "evidence": "sample:1", "confidence": 1.0}
        if f["ecs_field"] in UNIT:
            r["unit"] = UNIT[f["ecs_field"]]
        roles.append(r)
    for key, target in vm_src.items():
        roles.append({"source_key": key, "role": role_text(target, f"{ir['source_id']}:{key}"),
                      "evidence": "sample:1",
                      "confidence": 1.0,
                      "value_semantics": value_semantics(vm_map.get(key, {}), target)})
    ts = (ir.get("timestamp") or {}).get("source_key")
    if ts and ts not in {r["source_key"] for r in roles}:
        roles.append({"source_key": ts, "role": role_text("@timestamp", f"{ir['source_id']}:{ts}"),
                      "evidence": "sample:1", "confidence": 1.0})
    out = {"source_id": ir["source_id"], "format_summary": format_summary(ir["extraction"]),
           "extraction": dict(ir["extraction"]), "roles": roles}
    # EVERY KEY IS ACCOUNTED FOR, the mapped ones and the rest. Stage 2 never
    # sees a line: a key stage 1 does not name is a key the IR cannot list, and
    # V2 then rejects the source (`key_not_accounted_for`). Until 2026-10-17 the
    # gold answer named only the keys it mapped, and the first gold-trained
    # student dropped `dest_ip`/`flow` (suricata) and `RequestAddr` (traefik).
    # The reason is neutral: why a key maps nowhere is a schema question.
    named = {r["source_key"] for r in roles}
    rest = [u["source_key"] for u in ir.get("unresolved") or [] if u["source_key"] not in named]
    if rest:
        out["unresolved"] = [{"source_key": k, "reason": "carries nothing a field here needs"}
                             for k in rest]
    if ir["extraction"].get("kind") == "csv":
        out["column_order"] = list(ir["extraction"].get("columns") or [])
    return out


def write_source(c: Candidate, root: Path = SOURCES_DIR) -> Path | None:
    """The source directory, in the format every other source has (PLAN_R2.md).

    None, and nothing written, when no detection scenario can be built from
    lines the model is not shown: a source V4 can never replay is not added to
    a corpus whose sources all carry one.
    """
    shown = {s.raw for s in _samples(c.sample_lines())}
    if not _scenarios_for(c, shown):
        return None
    d = root / c.source_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "samples.ndjson").write_text(
        "".join(json.dumps({"raw": s.raw}) + "\n" for s in _samples(c.sample_lines())), encoding="utf-8")
    # Truth on disk only for the lines the ladder parses (the samples); the
    # rest of the truth becomes detection scenarios, never shown to a model.
    (d / "line_truth.ndjson").write_text(
        "".join(json.dumps(r, sort_keys=True, default=str) + "\n"
                for r in c.truth if r["raw"] in shown), encoding="utf-8")
    (d / "documentation.md").write_text(
        c.documentation or f"# {c.source_id}\n\nGenerated from SIEMgen source `{c.source}`.\n",
        encoding="utf-8")
    write_scenarios(c, shown)
    truth = {"source_id": c.source_id, "split": "train", "family": f"sg_{c.source}",
             "origin": f"siemgen {siemgen_commit()}",
             "category_hint": c.category or _CATEGORY.get(c.source),
             "contamination_risk": "none", "transform": c.transform,
             "extraction": c.ir["extraction"],
             "fields": [{"source_key": f["source_key"], "ecs_field": f["ecs_field"],
                         "type": f["type"]} for f in c.ir.get("fields", [])]}
    (d / "truth.json").write_text(json.dumps(truth, indent=2, sort_keys=True) + "\n",
                                  encoding="utf-8")
    return d


def _norm(raw: str) -> str:
    """tests/test_pools.py's normalisation: lines equal under it are one line."""
    s = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>", raw)
    s = re.sub(r"\b\d{4}-\d{2}-\d{2}[T ][\d:.+Z-]+", "<ts>", s)
    return re.sub(r"\b\d+\b", "<n>", s)


def scenarios_from_truth(rows: list[dict[str, Any]], shown: set[str], targets: list[str],
                         n: int = 2) -> list[dict[str, Any]]:
    """Term-query scenarios counted over the per-line truth, from unseen lines.

    The same construction as corpus/siemgen_corpus.build_scenarios, over this
    candidate's own lines: for a mapped field and a value it takes, the events
    are the lines that carry it plus some that carry another value, and
    expected_hits is the count of the first group. No line the model is shown
    is used, under the pools test's normalisation.
    """
    forbidden = {_norm(x) for x in shown}
    rows = [r for r in rows if _norm(r["raw"]) not in forbidden]
    out: list[dict[str, Any]] = []
    used: set[str] = set()
    for fld in targets:
        if len(out) >= n:
            break
        vals = Counter(json.dumps(r["ecs"][fld]) for r in rows if fld in r["ecs"])
        for vj, cnt in vals.most_common():
            v = json.loads(vj)
            if cnt < 3 or isinstance(v, list):
                continue
            pos = [r["raw"] for r in rows if r["ecs"].get(fld) == v and r["raw"] not in used][:8]
            # Lines with another value first; lines without the field if
            # those run short - either way the rule must not match them.
            neg = ([r["raw"] for r in rows if fld in r["ecs"] and r["ecs"][fld] != v
                    and r["raw"] not in used]
                   + [r["raw"] for r in rows if fld not in r["ecs"] and r["raw"] not in used])[:6]
            if len(pos) < 3 or len(neg) < 2:
                continue
            used.update(pos + neg)
            out.append({"targets": [fld], "value": v, "events": pos + neg,
                        "expected_hits": len(pos), "split": "repair"})
            break
    return out


def _scenarios_for(c: "Candidate", shown: set[str]) -> list[dict[str, Any]]:
    # Verified fields first; then every other field the IR claims, so that a
    # source whose verified fields all take unique values (pids) still gets a
    # rule V4 can replay.
    verified = (c.report.get("metrics") or {}).get("verified_fields", [])
    mapped = [f["ecs_field"] for f in c.ir.get("fields", [])] + \
             [v["ecs_field"] for v in c.ir.get("value_maps", [])]
    targets = [t for t in mapped if t in verified] + [t for t in mapped if t not in verified]
    return scenarios_from_truth(c.truth, shown, targets)


def write_scenarios(c: "Candidate", shown: set[str]) -> int:
    from corpus.siemgen_corpus import _write_scenario

    scen = _scenarios_for(c, shown)
    for i, sc in enumerate(scen, 1):
        _write_scenario(c.source_id, i, sc, siemgen_commit())
    return len(scen)


def to_record(c: Candidate, seed: int = 0) -> dict[str, Any]:
    """A record in the shape of teacher/out/verified.ndjson, credited by VT."""
    from adapter.architectures import schema_digest
    from adapter.ecs_index import retrieval_digest
    from adapter.prompts import Prompts
    from teacher.revalidate import APPARATUS

    verified = c.report.get("metrics", {}).get("verified_fields", [])
    return {
        "source_id": c.source_id, "family": f"sg_{c.source}", "seed": seed,
        "ecs_version": "8.11", "error": None, "ir": c.ir, "roles": roles_for(c.ir),
        "report": c.report, "normalisations": [],
        "teacher": "gold" if c.transform == "gold" else f"augment:{c.transform}",
        "temperature": 0.0, "usage": {}, "wall_seconds": 0.0,
        "prompt_digest": Prompts(ROOT / "prompts").digest,
        "schema_digest": schema_digest(), "retrieval_digest": retrieval_digest(),
        "validation": {"apparatus": APPARATUS, "oracle": "VT", "scenario_split": "repair",
                       "at": datetime.now(timezone.utc).isoformat(timespec="seconds")},
        # Consumable by training/build_dataset as a verified record: the fields
        # VT proved, never the whole IR (V4 did not run), extraction proved by V3.
        "credit": {"fields": verified, "whole": False, "extraction": True},
        "provenance": {"generator": "siemgen", "commit": siemgen_commit(),
                       "source": c.source, "transform": c.transform, **c.provenance},
    }


def append_records(records: list[dict[str, Any]], out: Path = GOLD_OUT) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, sort_keys=True, default=str) + "\n")


# ----------------------------------------------------------------------- CLI

def gold_candidates(n_events: int = 60, seed: int = 11) -> list[Candidate]:
    out = []
    for source in GOLD_SOURCES:
        if source in HELD_OUT:
            continue
        evs = events(source, n_events, seed)
        sid = f"sg_{source}_native_gold"
        ir = native_gold(source, sid, evs)
        lines, rows = truth_rows(source, evs)
        out.append(Candidate(sid, source, ir, lines, rows, "gold",
                             {"events": len(evs), "seed": seed}))
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="corpus.siemgen_gold", description=__doc__.splitlines()[0])
    p.add_argument("--only", nargs="*")
    p.add_argument("--events", type=int, default=60)
    p.add_argument("--write", action="store_true", help="write source dirs and gold.ndjson")
    a = p.parse_args(argv)
    cands = [c for c in gold_candidates(a.events) if not a.only or c.source in a.only]
    t0 = time.time()
    verify(cands)
    print(f"{'source':<14} {'rung':<4} {'pass':<5} verified / contradicted / unchecked")
    for c in cands:
        m = c.report.get("metrics", {})
        print(f"{c.source:<14} {c.report.get('rung_reached', '-'):<4} "
              f"{str(c.report.get('passed')):<5} {len(m.get('verified_fields', []))} / "
              f"{m.get('contradicted_fields', [])} / {len(m.get('unchecked_fields', []))}")
        if not c.report.get("passed"):
            for f in c.report.get("findings", [])[:3]:
                print(f"    {f['rung']}/{f['code']}: {f['message'][:200]}")
    print(f"{time.time() - t0:.0f}s")
    if a.write:
        good = [c for c in cands if c.report.get("passed") and write_source(c)]
        append_records([to_record(c) for c in good])
        print(f"wrote {len(good)} gold records -> {GOLD_OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

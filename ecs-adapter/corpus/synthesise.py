"""Step 2 - turn recovered mappings into corpus sources, with ground truth by construction.

WHY THIS IS LEGITIMATE
----------------------
Format drift is the phenomenon this subsystem exists to survive: the same
information, written differently after an endpoint updates. So the corpus should
contain the same semantics under many surface forms - which is exactly what a
generator produces, and what hand-collection struggles to.

Ground truth is not annotated here, it is KNOWN: this script chooses the key
name and the layout, so the mapping from key to ECS field is a fact about what
it just did, not a judgement about what someone meant.

WHAT THIS DOES NOT GIVE YOU
---------------------------
Generated sources are easier than real ones: the vocabulary is drawn from a
fixed list, the values are well-formed, and nothing is truncated, interleaved or
corrupted the way a real appliance does it. They are TRAINING material.

**Never generate the test split.** The numbers in the dissertation must come from
sources collected and annotated by hand, or they measure the generator rather
than the model. This script refuses `--split test` for that reason.
"""
from __future__ import annotations

import functools

from pathlib import Path
from typing import Any
import argparse
import json
import random
import re

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "bench" / "sources"

# Alternative key names for the same meaning. The point of the corpus: a model
# must reason from evidence, not recognise a spelling.
#
# THIS TABLE IS A GATE, NOT A CONVENIENCE.
# `build_source` keeps only the fields that appear here, so an ECS field with no
# entry is dropped from every generated source in silence. That was measured: of
# the 23 fields the hand-written pipelines map, 13 reached the corpus. HAProxy
# lost `observer.name` and `destination.address`, which are the two fields that
# source exists to test, so the three-way origin/reporter/destination confusion
# the paper is about was never once presented to a model. `main` now reports
# every drop by name; add an entry rather than let a mapping disappear.
ALIASES: dict[str, list[str]] = {
    # -- network endpoints: the confusion this corpus exists to measure --------
    "source.ip":                    ["src_ip", "client", "client_ip", "remote_addr", "c_ip", "srcaddr", "from"],
    "source.port":                  ["src_port", "sport", "client_port"],
    "source.domain":                ["src_domain", "client_domain", "workgroup", "from_domain"],
    "destination.ip":               ["dst_ip", "dest", "target_ip", "dstaddr", "server_ip", "to"],
    "destination.port":             ["dst_port", "dport", "server_port"],
    "destination.address":          ["upstream", "backend", "peer", "svc", "endpoint"],
    "observer.ip":                  ["device_ip", "appliance", "reporter_ip", "sensor"],
    "observer.name":                ["sensor_name", "appliance_name", "gw", "frontend", "listener"],
    "observer.hostname":            ["device_host", "reporter", "collector", "fw_host"],
    "observer.ingress.interface.name": ["iface", "in_if", "ingress_if", "nic"],
    "network.protocol":             ["proto", "protocol", "l4proto"],
    # `proto` and `l4proto` are deliberately shared with network.protocol.
    # Vendors write `proto=tcp` and `proto=http` with equal frequency, so the
    # key settles nothing and the value has to. Without them the only spellings
    # left were `transport` and `ip_proto`, which name their own answer.
    "network.transport":            ["transport", "ip_proto", "proto", "l4proto"],
    # -- identity --------------------------------------------------------------
    "user.name":                    ["user", "usr", "account", "username", "login", "uid_name"],
    "user.id":                      ["uid", "user_id", "userid", "subject_id"],
    "user.domain":                  ["domain", "user_domain", "nt_domain", "realm"],
    "host.name":                    ["host", "hostname", "machine", "node"],
    # -- process ---------------------------------------------------------------
    "process.name":                 ["proc", "process", "image", "exe"],
    "process.executable":           ["exe_path", "binary", "cmd_path", "program"],
    "process.pid":                  ["pid", "proc_id", "process_id"],
    # -- files -----------------------------------------------------------------
    "file.path":                    ["filepath", "fpath", "object", "target_path"],
    "file.name":                    ["filename", "fname", "basename", "file"],
    "file.size":                    ["fsize", "file_bytes", "obj_size"],
    # -- http and url ----------------------------------------------------------
    "url.original":                 ["url", "uri", "request", "resource", "full_url"],
    "url.path":                     ["path", "uri_path", "page", "req_path"],
    "url.domain":                   ["vhost", "site", "host_header", "fqdn"],
    # -- APPLICATION LOGGING, absent from the corpus until 2026-10-11 ---------
    #
    # None of the eight recovered families emits a severity or a logger name,
    # so the corpus taught neither. Three of the eight evaluation sources ask
    # for them, and the model answered `event.severity` for a textual level -
    # a field ECS types as `long`, so `FATAL` does not even index. It was not
    # guessing badly; it had never seen the mapping once.
    "log.level":                    ["level", "severity", "loglevel", "lvl", "prio"],
    "log.logger":                   ["logger", "component", "module", "facility"],
    "message":                      ["msg", "text", "detail", "description"],
    "error.message":                ["error", "err", "errmsg", "failure_reason"],
    "rule.name":                    ["rule", "jail", "signature", "policy"],
    "event.kind":                   ["kind", "record_type", "entry_type"],
    "http.request.method":          ["method", "verb", "http_method", "m"],
    "http.request.referrer":        ["referrer", "ref", "referer"],
    "http.response.status_code":    ["status", "code", "status_code", "rc", "http_status"],
    # EVERY SPELLING HERE SAYS "BODY", and that is the point.
    #
    # It used to be ["bytes", "size", "resp_bytes", "sent"], none of which says
    # whether the count includes the headers. ECS has two different fields for
    # the two quantities - http.response.body.bytes is "Size in bytes of the
    # response body", http.response.bytes is "Total size in bytes of the
    # response (body and headers)" - so a key reading `bytes` leaves the
    # question open and the ground truth answers it anyway. Measured: the
    # teacher scored 1 of 30 on this field across the Caddy family, choosing
    # http.response.bytes and server.bytes.
    #
    # That is a defect in the SOURCE, not in the model, and widening the oracle
    # would have hidden it. Real formats name it: nginx writes
    # $body_bytes_sent. So does the corpus now.
    "http.response.body.bytes":     ["body_bytes", "body_bytes_sent",
                                     "resp_body_bytes", "sent_body"],
    "http.response.mime_type":      ["mime", "content_type", "ctype", "mime_type"],
    "http.version":                 ["http_ver", "proto_ver", "httpver"],
    "user_agent.original":          ["agent", "ua", "user_agent", "browser"],
    # -- dns -------------------------------------------------------------------
    "dns.question.name":            ["qname", "query", "question", "dns_name"],
    "dns.question.type":            ["qtype", "rrtype", "record_type"],
    "dns.question.class":           ["qclass", "rrclass", "dns_class"],
    "dns.response_code":            ["rcode", "reply_code", "dns_rc"],
    # -- event -----------------------------------------------------------------
    "event.action":                 ["action", "act", "operation", "evt", "cmd"],
    "event.outcome":                ["result", "status", "outcome", "res", "verdict"],
    "event.code":                   ["event_id", "evtid", "msg_id"],
    "event.duration":               ["duration", "elapsed", "took"],
}

VALUES: dict[str, Any] = {
    "ip":      lambda r: r.choice(["192.0.2.", "198.51.100.", "203.0.113."]) + str(r.randint(2, 250)),
    "long":    lambda r: str(r.randint(1, 9999)),
    "float":   lambda r: f"{r.uniform(0.001, 3.0):.3f}",
    "boolean": lambda r: r.choice(["true", "false"]),
    "date":    lambda r: f"2026-09-{r.randint(10,28):02d}T{r.randint(0,23):02d}:{r.randint(0,59):02d}:{r.randint(0,59):02d}Z",
    "keyword": lambda r: r.choice(["alpha", "bravo", "charlie", "delta", "echo"]),
    "text":    lambda r: r.choice(["ok", "not found", "denied by policy"]),
}
# Realistic values, per ECS field. These are not decoration.
#
# `url.original` and `url.path` share the alias "path", which is correct: a
# vendor writes "path" for both. What makes the pair answerable is the VALUE.
# While both drew from the same list of bare paths, a source keyed "path"
# holding "/admin" had two defensible answers and one recorded ground truth, so
# the corpus was scoring a coin toss. `url.original` now carries absolute URLs
# and `url.path` carries paths, and the evidence settles it.
PER_FIELD: dict[str, list[str]] = {
    "user.name":                 ["alice", "bob", "carol", "dave", "svc_backup"],
    "user.id":                   ["0", "1000", "1001", "48"],
    "user.domain":               ["CORP", "WORKGROUP", "EXAMPLE", "LAB"],
    # FATAL and PANIC are held back for the marker tables; see MARKER_TABLES.
    "log.level":                 ["INFO", "WARNING", "ERROR", "DEBUG", "NOTICE"],
    "log.logger":                ["auth.filter", "core.engine", "net.listener",
                                  "db.session", "sync.worker"],
    "message":                   ["connection established", "session closed",
                                  "quota exceeded", "handshake complete"],
    "error.message":             ["permission denied", "no such file",
                                  "timeout waiting for lock", "invalid credentials"],
    "rule.name":                 ["sshd", "http-flood", "bruteforce", "portscan"],
    "event.kind":                ["event", "alert", "metric", "state"],
    "source.domain":             ["CORP", "GUEST", "PARTNER"],
    "event.action":              ["login", "logout", "read", "write", "delete"],
    "event.code":                ["4624", "4625", "4688", "1102"],
    "http.request.method":       ["GET", "POST", "PUT", "DELETE"],
    "http.response.status_code": ["200", "301", "401", "403", "404", "500"],
    "http.response.mime_type":   ["text/html", "application/json", "image/png", "text/css"],
    # 0.9, 1.0 and 3.0 are held back as markers; see MARKER_TABLES.
    "http.version":              ["1.1", "2.0"],
    "url.original":              ["http://example.com/", "https://intra.local/admin",
                                  "http://cdn.example.net/static/app.js",
                                  "https://api.example.com/v1/users",
                                  "http://example.org/login"],
    "url.path":                  ["/", "/admin", "/api/v1/users", "/login"],
    "url.domain":                ["example.com", "intra.local", "api.example.com",
                                  "cdn.example.net"],
    "dns.question.name":         ["example.com", "www.example.org", "api.internal.lan",
                                  "mail.example.net"],
    "dns.question.type":         ["A", "AAAA", "CNAME", "MX", "TXT"],
    # CS, HS and NONE are held back as markers; see MARKER_TABLES.
    "dns.question.class":        ["IN", "CH"],
    "dns.response_code":         ["NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED"],
    "network.protocol":          ["tcp", "udp", "icmp"],
    "network.transport":         ["tcp", "udp"],
    "process.name":              ["sshd", "nginx", "sudo", "systemd"],
    "process.executable":        ["/usr/sbin/sshd", "/usr/bin/sudo", "/usr/sbin/nginx",
                                  "/usr/bin/curl"],
    "file.path":                 ["/etc/passwd", "/var/www/html/index.php",
                                  "/home/alice/report.pdf", "/srv/data/dump.sql"],
    "file.name":                 ["passwd", "index.php", "report.pdf", "dump.sql"],
    "host.name":                 ["web-01", "db-02", "gw-01"],
    # The reporter is named differently from the host on purpose: a value that
    # could belong to either would make observer/host unanswerable.
    "observer.name":             ["fe_public", "edge-gw", "dmz-fw", "lb-01"],
    "observer.hostname":         ["fw-01.lan", "sensor-a.lan", "collector-02.lan"],
    "observer.ingress.interface.name": ["eth0", "igb1", "wan", "lan"],
    "destination.address":       ["app-01", "backend-pool", "api.internal", "cache-02"],
}
# Outcome vocabularies that need a value map: the source word -> the ECS word.
OUTCOMES = [
    ({"denied": "failure", "allowed": "success"}, "denied/allowed"),
    ({"fail": "failure", "ok": "success"}, "fail/ok"),
    ({"0": "failure", "1": "success"}, "0/1"),
    ({"REJECT": "failure", "ACCEPT": "success"}, "REJECT/ACCEPT"),
]
# Injected on purpose: a key whose meaning the evidence does not settle. Abstaining
# is the correct answer and is scored as one, so the corpus must contain the case.
AMBIGUOUS = [
    ("dev", "device name: could be the host where it happened or the appliance reporting it"),
    ("node", "node identifier: host.name or observer.name, the documentation does not say"),
    ("zone", "zone label: could be network zone or an observer grouping"),
]

# WHY `prose` AND `csv_tab` ARE HERE.
#
# The first five layouts are all delimited, and a delimited layout is fully
# described by naming its separator. That made the corpus unable to express the
# one shape that is NOT - free text with values embedded in it, which needs a
# grok pattern - and the blind spot was therefore invisible by construction:
# nothing the generator could produce would ever have revealed it.
#
# Measured when real vendor logs were finally used: 3 of the 8 evaluation
# sources are free text, 0 of 173 training examples were, and the student fell
# back on the modal class. It declared `key=value` for
#     Failed password for alice from 172.18.0.22 port 42710 ssh2
# which contains no `=` at all.
#
# `csv_tab` exists for the same reason one step down: every generated csv used
# a comma, the IR could not express any other separator, and zeek's conn.log -
# also in the evaluation pool - is tab-separated.
LAYOUTS = ("kv_space", "kv_comma", "json", "csv", "kv_pipe", "csv_tab", "prose",
           "syslog")

# Connectors for the prose layout, CHOSEN BY WHAT THE VALUE IS.
#
# The first version drew them at random and produced lines like
#     1487 against DELETE using http://example.com/ to 3658 from 500
# which forces grok, and teaches nothing. A real daemon's connectors carry
# meaning - `from` precedes the address a connection came from, `port`
# precedes a port, `for` precedes an account - and that structure is the only
# cue a parser has when no key names are present. Training on random
# connectors would teach a signal that does not exist outside this file.
#
# Keyed by ECS field so the cue matches the semantics the ground truth already
# records. Unlisted fields fall back to a neutral preposition; the layout is
# still grok-only, because no key name ever appears in the line.
PROSE_CONNECTORS: dict[str, str] = {
    "source.ip": "from", "source.address": "from", "client.ip": "from",
    "destination.ip": "to", "destination.address": "to", "server.ip": "to",
    "observer.ip": "reported by", "host.name": "on host",
    "source.port": "port", "destination.port": "port",
    "user.name": "for user", "user.target.name": "targeting",
    "process.name": "by process", "process.pid": "pid",
    "url.original": "requesting", "url.path": "requesting", "url.domain": "host",
    "http.request.method": "method", "http.response.status_code": "status",
    "http.response.body.bytes": "bytes", "http.version": "proto",
    "network.protocol": "over", "network.transport": "over",
    "event.action": "", "event.outcome": "",
    "file.path": "file", "file.size": "size",
    "dns.question.name": "query", "dns.response_code": "rcode",
    "user_agent.original": "agent", "event.duration": "in",
    "log.level": "level", "rule.name": "rule", "event.reason": "reason",
}
PROSE_FALLBACK = ("with", "and", "value")

# A line reads better, and like a real one, when a verb leads it.
PROSE_LEADING = ("event.action", "event.outcome", "log.level")


# ----------------------------------------------------------------- syslog
#
# WHY `prose` WAS NOT ENOUGH, WHICH IS M10.
#
# `prose_shape` puts a connector before every value but the first, and the
# connector names the field: `from` before an address, `status` before a
# status. Structurally that is `key=value` with the `=` replaced by a space
# and the key replaced by a semantic word, and exactly ONE field - the first -
# is ever unlabelled. A student trained on it learns one rule: THE WORD BEFORE
# A VALUE IS ITS KEY.
#
# Real daemon output does not obey that rule. RFC 3164 fixes a preamble of
# several consecutive unlabelled fields - timestamp, host, tag[pid] - before
# anything a connector could introduce, the event is free text rather than a
# labelled value, punctuation carries field boundaries, and values run to
# several words. Given such a line the learned rule has no precondition to
# fire on, and the student falls back on describing the template: it emitted
# `TIMESTAMP`, `[JAIL]`, `[PID]`, `from=<SENDER>` for the evaluation sources.
#
# WHERE THIS SHAPE COMES FROM, WHICH MATTERS FOR THE HOLDOUT.
#
# From RFC 3164 and RFC 5424, which are public and predate every source in
# this project. NOT from the evaluation pool, and NOT from the platform's own
# `linux-auth.conf` - that file's two richest patterns parse sshd, and
# `sshd_auth` is an evaluation family, so rendering them here would teach the
# student the exact shape of a held-out source. They are excluded on purpose.
# `HELDOUT.md` already recognises documentation as an acquisition route
# distinct from a pipeline this platform runs; this is that route.

# Values that never contain a space may stand bare, because %{NOTSPACE} is
# bounded by the space that follows it and two adjacent bare fields are still
# read deterministically. Anything else needs a marker to be found again.
SYSLOG_SPACELESS = ("ip", "long", "integer", "float")

# How often a field that COULD stand bare does, and how often a marked field
# takes punctuation rather than a word. Fixed per source by the seed, never
# per line - a shape that varied line to line would not be a log format.
SYSLOG_BARE_RATE = 0.34
SYSLOG_BRACKET_RATE = 0.20
SYSLOG_QUOTE_RATE = 0.15


def syslog_shape(order: list[dict[str, Any]], seed: int) -> list[tuple[str, str]]:
    """How each field appears: bare, after a word, in brackets, or quoted.

    Returns one ``(mode, token)`` per field of ``order``. ``event.action`` is
    always bare and always allowed to run to several words, which is the
    property `prose` lacks; the field after it is therefore forced to carry a
    marker, so that the action has something to stop against and the grok
    pattern stays unambiguous.
    """
    rr = random.Random(seed ^ 0x5157)
    out: list[tuple[str, str]] = []
    force_marker = False
    for f in order:
        ecs = f.get("ecs_field")
        if force_marker:
            force_marker = False
        elif ecs == "event.action":
            out.append(("action", ""))
            force_marker = True
            continue
        elif f.get("type") in SYSLOG_SPACELESS and rr.random() < SYSLOG_BARE_RATE:
            out.append(("bare", ""))
            continue
        pick = rr.random()
        if pick < SYSLOG_BRACKET_RATE:
            out.append(("bracket", ""))
        elif pick < SYSLOG_BRACKET_RATE + SYSLOG_QUOTE_RATE:
            out.append(("quote", ""))
        else:
            out.append(("connector",
                        PROSE_CONNECTORS.get(ecs) or rr.choice(PROSE_FALLBACK)))
    return out


# The preamble is structure, not data: three unlabelled tokens that no field
# claims, consumed by unnamed grok patterns. This is what makes the line open
# on something a connector-based reading cannot explain.
SYSLOG_TAGS = ("authsvc", "appsvc", "filesvc", "netsvc", "edgesvc", "corednsd",
               "haproxyd", "squidd", "auditd", "ngxd")
SYSLOG_PREAMBLE_PATTERN = (
    "%{SYSLOGTIMESTAMP} %{HOSTNAME} %{NOTSPACE}\\[%{NUMBER}\\]")


def _syslog_preamble(seed: int, r: random.Random) -> str:
    """`Oct  2 15:57:38 host-07 authsvc[1116]`.

    The tag is fixed per source, because a daemon does not rename itself. The
    timestamp and the pid move line to line, because a real one does, and a
    preamble that never changed would be a constant the student could memorise
    instead of a field it has to find. Both are consumed by UNNAMED grok
    patterns, so varying them costs the ground truth nothing.
    """
    rr = random.Random(seed ^ 0x3164)
    tag = rr.choice(SYSLOG_TAGS)
    host = f"host-{rr.randrange(1, 40):02d}"
    month = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
             "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")[r.randrange(12)]
    stamp = (f"{month} {r.randrange(1, 29):2d} "
             f"{r.randrange(24):02d}:{r.randrange(60):02d}:{r.randrange(60):02d}")
    return f"{stamp} {host} {tag}[{r.randrange(100, 9999)}]"


def _syslog_segment(mode: str, token: str, value: str) -> str:
    if mode == "bracket":
        return f"[{value}]"
    if mode == "quote":
        return f'"{value}"'
    if mode == "connector" and token:
        return f"{token} {value}"
    return str(value)


def _syslog_capture(mode: str, token: str, key: str, last: bool) -> str:
    """The grok fragment that reads back what `_syslog_segment` wrote.

    THE TOKEN CLASS IS DECIDED BY WHAT FOLLOWS, NOT BY THE FIELD.

    `%{NOTSPACE}` cannot cross a space, so it may only be used where nothing
    anchors the end of the value - a bare field, which is why bare mode is
    restricted to types that never contain one. A field introduced by a
    connector word, or wrapped in brackets or quotes, HAS an anchor: the
    literal that follows it. There `%{DATA}` is correct and `%{NOTSPACE}` is a
    bug, because a multi-word value then fails to parse.

    Found by the module's own correct-by-construction check, 2026-10-13:
    `syn_appsvc_syslog` and `syn_authsvc_syslog` yielded 0.02 against their own
    ground truth, on values like `handshake complete` and `permission denied`.
    The other twelve families passed only because their keyword values happened
    to be single words. `prose_shape`'s own truth has always used `%{DATA}`
    here, for this reason.
    """
    if mode == "bracket":
        return "\\[%{DATA:" + key + "}\\]"
    if mode == "quote":
        return '"%{DATA:' + key + '}"'
    if last:
        body = "%{GREEDYDATA:" + key + "}"
    elif mode == "bare":
        body = "%{NOTSPACE:" + key + "}"
    else:
        body = "%{DATA:" + key + "}"
    return f"{token} {body}" if mode == "connector" and token else body


# --------------------------------------------------------------------- markers
#
# Values that never occur in a generated sample line. Three disjoint namespaces,
# and the disjointness is what makes three separate invariants hold BY
# CONSTRUCTION rather than by inspection:
#
#   probe    goes into one extra sample line, and into known_values.json, so
#            V3.5 can ask "the value I injected - which field is holding it?"
#   repair   the scenario the repair loop is allowed to see
#   holdout  the scenario that measures the finished system
#
# `tests/test_pools.py` compares lines after masking IPs, timestamps and every
# digit. So an IP marker alone proves nothing - `203.0.113.200` and
# `192.0.2.7` both normalise to `<ip>`. Every scenario line therefore also
# carries a namespaced value in the AMBIGUOUS key, which is alphabetic, is
# present in every generated source, and maps to no ECS field, so it cannot
# affect a detection query.
#
# IP markers use the .251-.254 range, outside the randint(2, 250) the sample
# generator draws from, so a noise line cannot collide with an attack line.
MARKER_TABLES: dict[str, dict[str, str]] = {
    "probe": {
        "log.level": "FATAL",
        "log.logger": "probe.logger",
        "message": "probe-message",
        "error.message": "probe-error",
        "rule.name": "probe-rule",
        "event.kind": "pipeline",
        "source.ip": "203.0.113.251", "destination.ip": "198.51.100.251",
        "observer.ip": "192.0.2.251", "user.name": "svc_probe",
        "process.name": "strace", "url.original": "/probe-endpoint",
        "url.path": "/probe-endpoint", "http.request.method": "PROPFIND",
        "event.action": "probe", "host.name": "probe-host",
        "user_agent.original": "probe-agent", "http.request.referrer": "probe-ref",
        "network.protocol": "gre", "network.transport": "gre",
        "source.domain": "CONTRACTOR", "user.domain": "ACME",
        "user.id": "31337", "event.code": "5140",
        "destination.address": "quarantine-01", "observer.name": "fe_lab",
        "observer.hostname": "fw-99.lan", "observer.ingress.interface.name": "eth9",
        "process.executable": "/usr/bin/nc", "process.pid": "99001",
        "file.path": "/tmp/.hidden/payload", "file.name": "payload",
        "file.size": "8000001", "url.domain": "probe.test",
        "http.response.mime_type": "application/x-dosexec",
        "http.response.status_code": "418", "http.response.body.bytes": "7000001",
        "source.port": "61001", "destination.port": "61004",
        "dns.question.name": "probe.invalid", "dns.question.type": "NAPTR",
        "dns.response_code": "NOTIMP", "event.duration": "7700001",
        "http.version": "0.9", "dns.question.class": "CS",
    },
    "repair": {
        "log.level": "PANIC",
        "log.logger": "repair.logger",
        "message": "repair-message",
        "error.message": "repair-error",
        "rule.name": "repair-rule",
        "event.kind": "signal",
        "source.ip": "203.0.113.252", "destination.ip": "198.51.100.252",
        "observer.ip": "192.0.2.252", "user.name": "svc_deploy",
        "process.name": "auditctl", "url.original": "/wp-login.php",
        "url.path": "/wp-login.php", "http.request.method": "PATCH",
        "event.action": "escalate", "host.name": "bastion-edge",
        "user_agent.original": "curl-probe", "http.request.referrer": "deploy-ref",
        "network.protocol": "sctp", "network.transport": "sctp",
        "source.domain": "VENDOR", "user.domain": "GLOBEX",
        "user.id": "31338", "event.code": "5145",
        "destination.address": "sinkhole-02", "observer.name": "edge-test",
        "observer.hostname": "sensor-z.lan", "observer.ingress.interface.name": "igb7",
        "process.executable": "/usr/bin/socat", "process.pid": "99002",
        "file.path": "/var/tmp/stage.bin", "file.name": "stage.bin",
        "file.size": "8000002", "url.domain": "repair-c2.test",
        "http.response.mime_type": "application/octet-stream",
        "http.response.status_code": "451", "http.response.body.bytes": "7000002",
        "source.port": "61002", "destination.port": "61005",
        "dns.question.name": "repair-c2.invalid", "dns.question.type": "SRV",
        "dns.response_code": "FORMERR", "event.duration": "7700002",
        "http.version": "1.0", "dns.question.class": "HS",
    },
    "holdout": {
        "log.level": "EMERG",
        "log.logger": "holdout.logger",
        "message": "holdout-message",
        "error.message": "holdout-error",
        "rule.name": "holdout-rule",
        "event.kind": "enrichment",
        "source.ip": "203.0.113.253", "destination.ip": "198.51.100.253",
        "observer.ip": "192.0.2.253", "user.name": "svc_report",
        "process.name": "tcpdump", "url.original": "/xmlrpc.php",
        "url.path": "/xmlrpc.php", "http.request.method": "TRACE",
        "event.action": "exfiltrate", "host.name": "jump-dmz",
        "user_agent.original": "wget-probe", "http.request.referrer": "report-ref",
        "network.protocol": "dccp", "network.transport": "dccp",
        "source.domain": "LEGACY", "user.domain": "INITECH",
        "user.id": "31339", "event.code": "4719",
        "destination.address": "staging-07", "observer.name": "lb-99",
        "observer.hostname": "collector-99.lan", "observer.ingress.interface.name": "vlan99",
        "process.executable": "/tmp/.x", "process.pid": "99003",
        "file.path": "/dev/shm/drop", "file.name": "drop",
        "file.size": "8000003", "url.domain": "exfil.test",
        "http.response.mime_type": "application/zip",
        "http.response.status_code": "226", "http.response.body.bytes": "7000003",
        "source.port": "61003", "destination.port": "61006",
        "dns.question.name": "exfil.invalid", "dns.question.type": "DNSKEY",
        "dns.response_code": "NOTAUTH", "event.duration": "7700003",
        "http.version": "3.0", "dns.question.class": "NONE",
    },
}

MARKER_IP = {"probe": "203.0.113.251", "repair": "203.0.113.252", "holdout": "203.0.113.253"}

# Types a generated detection query may filter on.
#
# `long` was excluded for a real reason: a `term` query for 401 against a field
# the candidate mapped as a keyword matches or not by coercion, so the expected
# count would turn on an Elasticsearch rule rather than on the mapping. The
# consequence was that the status code, the response size, every port and every
# pid were unreachable by V4, and oracle reach could not pass about a third.
#
# The fix is to remove the coercion rather than the type: `_term` below emits
# the value as a JSON number when the ground truth says long and as a string
# when it says keyword, so the query states which it means. A candidate that
# gets the type wrong is already refused at V1, so nothing rests on the
# ambiguity this used to avoid.
QUERYABLE_TYPES = ("ip", "keyword", "long")



@functools.lru_cache(maxsize=1)
def _ecs_types() -> dict[str, str]:
    from adapter.wiring import _ecs_index

    return {n: f.type for n, f in _ecs_index().fields.items()}


# How many entity roots in ECS offer a field with this leaf name. `name` is
# offered under 27 of them, `method` under one.
CONFUSABLE_THRESHOLD = 5


@functools.lru_cache(maxsize=1)
def _roots_per_leaf() -> dict[str, int]:
    from adapter.wiring import _ecs_index

    counts: dict[str, set[str]] = {}
    for n in _ecs_index().fields:
        counts.setdefault(n.rpartition(".")[2], set()).add(n.split(".")[0])
    return {leaf: len(roots) for leaf, roots in counts.items()}


# Abbreviations a vendor writes for an ECS word. Used only to decide whether a
# KEY names its own answer, never to decide the answer.
_KEY_SYNONYMS = {
    "src": "source", "dst": "destination", "dest": "destination",
    "cli": "client", "c": "client", "resp": "response", "req": "request",
    "ua": "user_agent", "addr": "address", "proto": "protocol",
    "pkts": "packets", "rc": "code", "sc": "code", "usr": "user",
}


def _tokens(name: str) -> set[str]:
    out: set[str] = set()
    for t in re.split(r"[._\-]", name.lower()):
        if t:
            out.add(t)
            out.add(_KEY_SYNONYMS.get(t, t))
    return out


def key_names_the_answer(source_key: str, ecs_field: str) -> bool:
    """Does the generated key spell out the ECS field it maps to?

    WHY THIS IS RECORDED SEPARATELY FROM `difficulty`
    -------------------------------------------------
    `_difficulty` below measures a property of the FIELD: how many ECS entity
    roots offer that leaf name, so how easy it is to attach to the wrong
    entity. It is a fact about the schema and it does not change between
    sources.

    What a model actually faces is the field AND the key it arrives under.
    `source.port` is confusable in the abstract, and `src_port -> source.port`
    is not confusable at all. Measured over the training corpus, 37 of 269
    mapped fields had a key that names its own answer, and 18 of those were
    labelled `hard`. Gate 2 reports yield by difficulty, so its hard column was
    inflated by cases that are trivial in practice.

    The difficulty vocabulary is deliberately left alone - it means what it has
    always meant - and this flag is added beside it, so the yield table can
    report hard fields with and without the giveaways.

    Transparent keys are NOT a defect to remove. Vendors really do write
    `src_port`, and a corpus in which no key was ever transparent would be
    unrealistic in the other direction. The defect was counting them as hard.
    """
    shared = _tokens(source_key) & _tokens(ecs_field)
    return len(shared) >= 2


def _difficulty(ecs_field: str) -> str:
    """Hard when the error mode is "right value, wrong entity".

    The first rule read the ROOT of the correct answer: source, destination and
    observer were hard and everything else easy, because those three are the
    confusion this project exists to catch. The intent was right and the test
    was not. It asks what the answer is, when what makes a field hard is what
    the answer could be MISTAKEN FOR.

    `host.name` scored easy under that rule --- its root is `host` --- and the
    teacher placed it in `observer.hostname`, `destination.address` or
    `destination.ip` on all thirty proposals of the windows-security family,
    which is the three-way confusion exactly. Meanwhile `source.ip` scored hard
    and was answered correctly twenty-two times out of thirty, because a key
    named `src_ip` says the answer. Gate 2 reports yield by difficulty, so it
    was measuring with the labels reversed on the one family that failed.

    The test is now taken from the schema rather than asserted: a leaf name
    offered under many entity roots can be attached to the wrong one, and a leaf
    offered under one cannot. `name` appears under 27 roots; `method` under one.
    The threshold is stated rather than tuned, and no result was consulted in
    choosing it --- only the schema.
    """
    leaf = ecs_field.rpartition(".")[2]
    return "hard" if _roots_per_leaf().get(leaf, 1) >= CONFUSABLE_THRESHOLD else "easy"


def _value(ecs_field: str, typ: str, r: random.Random) -> str:
    """The value a field takes, typed by ECS rather than by the pipeline.

    WHY ECS OVERRULES THE RECOVERED TYPE.

    ``typ`` comes from ``corpus/mappings.json``, which records what the Logstash
    pipeline declared. That is not always what the field IS. The recovered
    windows-security mapping declares ``source.ip`` as ``keyword`` --- the
    pipeline never converts it --- while the nginx mapping declares it as
    ``ip``. Same ECS field, two different declarations, and this function
    believed both.

    The consequence was not cosmetic. Every windows-security source was
    generated with ``src_ip=bravo``, ``from=alpha``: the NATO alphabet as the
    value of a field whose ECS type is ``ip``. Stage 1 read those lines and
    reported, correctly, that the values look like hostnames; Stage 2 followed
    its instructions and chose ``source.address``, which is precisely the field
    ECS prescribes for an address of unknown form; and the probe then injected
    ``203.0.113.251`` as ``source.ip`` and failed the proposal. Thirty of ninety
    proposals were recorded as teacher error on a source where the correct
    answer could not be reached from the evidence.

    A synthetic log whose ``source.ip`` contains ``bravo`` is not a log. The
    generator's own premise --- ground truth is known because this script chose
    it --- only holds if what it writes is consistent with what it claims.
    """
    if ecs_field in PER_FIELD:
        return r.choice(PER_FIELD[ecs_field])
    typ = _ecs_types().get(ecs_field, typ)
    return VALUES.get(typ, VALUES["keyword"])(r)


def prose_shape(pairs: list[tuple[str, str]], order: list[dict[str, Any]],
                seed: int) -> list[str]:
    """The connector before each value, fixed for the source.

    Derived from the ECS field each value carries, never from the value, so
    every line of a source shares one sentence shape and one grok pattern
    matches them all. A shape that varied line to line would not be a log
    format; it would be noise, and no parser could be right about it.
    """
    by_key = {f["source_key"]: f.get("ecs_field") for f in order}
    rr = random.Random(seed)
    out: list[str] = []
    for i, (key, _) in enumerate(pairs):
        ecs = by_key.get(key)
        if i == 0:
            out.append("")           # the line opens on its value
            continue
        if ecs in PROSE_CONNECTORS:
            out.append(PROSE_CONNECTORS[ecs])
        else:
            out.append(rr.choice(PROSE_FALLBACK))
    return out


# ------------------------------------------------------- optional fields
#
# ACTION 3 of the corpus plan, and the one the corpus never had: a field that
# is sometimes simply not there. Every synthetic source written before
# 2026-10-12 carried every field on every line, so nothing in the corpus ever
# showed the teacher that a segment can be absent - and M1 is exactly that
# failure. On `sshd_auth` the teacher writes
#
#     %{WORD:outcome} password for %{USERNAME:user} ...
#
# with no room for the `invalid user ` variant, reproduces it across three
# seeds with the V2 message naming the failing line in front of it, and has
# semantic accuracy 1.00 while doing so. It knows what the fields mean. It has
# never been shown that one of them can be missing.
#
# HOW ABSENCE IS RENDERED, WHICH DIFFERS BY LAYOUT AND MUST.
#
#   kv_*, json   the key is gone. Natural, and what a real daemon does.
#   csv, csv_tab the column STAYS and is empty. Dropping it would shift every
#                later column, which is not a missing field - it is a
#                different file format on that line, and the positional
#                contract the layout rests on would be a lie.
#   prose        the segment and its connector are gone. This is the one that
#                forces `(?:...)?` into the pattern, and the reason the whole
#                change exists.
#
# A field that a scenario overrides is always present: the rule counts hits by
# construction, and a target that vanished from an attack line would make the
# expected count wrong for a reason that has nothing to do with the mapping.
OPTIONAL_PER_SOURCE = 2
OPTIONAL_ABSENCE_RATE = 0.35


def _absent(layout: str) -> str | None:
    """What an absent field renders as, or None to drop it entirely."""
    return "" if layout in ("csv", "csv_tab") else None


def _render(layout: str, pairs: list[tuple[str, str]], r: random.Random,
            seed: int = 0, order: list[dict[str, Any]] | None = None) -> str:
    # A pair whose value is None is an absent optional field; csv keeps the
    # column, every other layout loses the key.
    if layout in ("csv", "csv_tab"):
        pairs = [(k, "" if v is None else v) for k, v in pairs]
    else:
        pairs = [(k, v) for k, v in pairs if v is not None]
    if layout == "json":
        return json.dumps(dict(pairs))
    if layout == "csv":
        return ",".join(v for _, v in pairs)
    if layout == "csv_tab":
        return "\t".join(v for _, v in pairs)
    if layout == "prose":
        # No key appears in the line. That is the whole point: the key names
        # live in the documentation and in the grok pattern, and position plus
        # the surrounding words are the only things that identify a value.
        # prose_shape is derived from the field ORDER, not from the pairs, so
        # that a line missing an optional field still speaks the same sentence.
        present = {k for k, _ in pairs}
        full = [(f["source_key"], None) for f in (order or [])] or pairs
        shape = prose_shape(full, order or [], seed)
        shape = [c for c, (k, _) in zip(shape, full) if k in present]
        out = []
        for connector, (_, value) in zip(shape, pairs):
            out.append(f"{connector} {value}".strip() if connector else str(value))
        return " ".join(out)
    if layout == "syslog":
        # RFC 3164 shape: an unlabelled preamble, then a body in which the
        # event is free text and the rest is found by words or punctuation.
        present = {k for k, _ in pairs}
        full = [f["source_key"] for f in (order or [])] or [k for k, _ in pairs]
        shape = syslog_shape(order or [], seed)
        keep = [(m, t) for (m, t), k in zip(shape, full) if k in present]
        body = [_syslog_segment(m, t, v) for (m, t), (_, v) in zip(keep, pairs)]
        return f"{_syslog_preamble(seed, r)}: " + " ".join(body)
    sep = {"kv_space": " ", "kv_comma": ", ", "kv_pipe": "|"}[layout]
    return sep.join(f"{k}={v}" for k, v in pairs)


def build_source(
    mapping: dict[str, Any], layout: str, seed: int, split: str, n_lines: int = 40,
    optional: bool = False
) -> dict[str, Any] | None:
    r = random.Random(seed)
    fields = [f for f in mapping["fields"] if f["ecs_field"] in ALIASES]
    if len(fields) < 2:
        return None

    chosen: list[dict[str, Any]] = []
    used: set[str] = set()
    for f in fields:
        free = [k for k in ALIASES[f["ecs_field"]] if k not in used]
        if not free:
            # Two ECS fields whose alias lists overlap completely. Dropping the
            # field is better than emitting a duplicate key, which would make the
            # source unparseable and the annotation self-contradictory.
            continue
        key = r.choice(free)
        used.add(key)
        entry = {
            "source_key": key,
            "ecs_field": f["ecs_field"],
            "type": f["type"],
            "role": f["semantic_name"],
            "difficulty": _difficulty(f["ecs_field"]),
            # Beside the difficulty, not instead of it. See key_names_the_answer.
            "key_names_the_answer": key_names_the_answer(key, f["ecs_field"]),
        }
        if f["ecs_field"] == "event.outcome":
            vocab, label = r.choice(OUTCOMES)
            entry.update(difficulty="medium", value_map=vocab,
                         note=f"Needs a value map: {label}.")
        chosen.append(entry)

    # Some ambiguous keys ("node") are also aliases of a real field, so only the
    # ones this source did not already spend are available.
    free_amb = [a for a in AMBIGUOUS if a[0] not in used]
    if not free_amb:
        return None
    amb_key, amb_note = r.choice(free_amb)
    used.add(amb_key)
    chosen.append({
        "source_key": amb_key, "ecs_field": None, "type": "keyword",
        "role": "ambiguous_identifier", "difficulty": "ambiguous",
        "acceptable_abstention": True, "note": amb_note,
    })

    order = list(chosen)
    if layout != "csv":
        r.shuffle(order)

    # The ambiguous key anchors every scenario and must be on every line. A
    # field carrying a value_map is left alone too: its vocabulary is what V4
    # translates through, and thinning it would weaken a different test.
    eligible = [
        f for f in order
        if f["ecs_field"] is not None and "value_map" not in f
    ]
    thin = {f["source_key"] for f in r.sample(
        eligible, min(OPTIONAL_PER_SOURCE, max(0, len(eligible) - 2)))} if optional else set()
    for f in order:
        if f["source_key"] in thin:
            f["optional"] = True
            f["note"] = (f.get("note") or "") + (
                " " if f.get("note") else ""
            ) + "Absent on some lines; a pattern must allow for that."

    lines = []
    for _ in range(n_lines):
        pairs = []
        for f in order:
            if f["source_key"] in thin and r.random() < OPTIONAL_ABSENCE_RATE:
                pairs.append((f["source_key"], None))
                continue
            if "value_map" in f:
                v = r.choice(list(f["value_map"]))
            elif f["ecs_field"] is None:
                v = r.choice(["edge-1", "core-2", "dmz-3"])
            else:
                v = _value(f["ecs_field"], f["type"], r)
            pairs.append((f["source_key"], v))
        lines.append(_render(layout, pairs, r, seed, order))
    # At least one line must carry every field, or the source simply does not
    # have the thin one and the annotation would be describing a key that is
    # nowhere to be seen.
    if thin:
        full = [(f["source_key"],
                 r.choice(list(f["value_map"])) if "value_map" in f
                 else r.choice(["edge-1", "core-2", "dmz-3"]) if f["ecs_field"] is None
                 else _value(f["ecs_field"], f["type"], r))
                for f in order]
        lines[0] = _render(layout, full, r, seed, order)

    return {"fields": chosen, "order": order, "lines": lines, "layout": layout,
            "split": split, "seed": seed}


def _marker_value(f: dict[str, Any], ns: str, r: random.Random) -> str:
    """The value this field takes inside namespace ``ns``."""
    if "value_map" in f:
        # Must stay inside the declared vocabulary or the parser cannot
        # translate it, and V4 would fail on the fixture rather than the model.
        return r.choice(list(f["value_map"]))
    if f["ecs_field"] is None:
        return f"{ns}-zone"
    table = MARKER_TABLES[ns]
    if f["ecs_field"] in table:
        return table[f["ecs_field"]]
    typ = f["type"]
    if typ == "ip":
        return MARKER_IP[ns]
    if typ in ("long", "float", "date"):
        return VALUES[typ](r)
    return f"{ns}kw"


def _line(order: list[dict[str, Any]], layout: str, overrides: dict[str, str],
          r: random.Random, seed: int) -> str:
    """One rendered line: ``overrides`` by source_key, everything else random.

    ``seed`` is the SOURCE's seed, not a per-line one. The prose layout derives
    its sentence shape from it, and a scenario line rendered with a different
    shape would not match the pattern written for the samples - the source
    would be two formats wearing one name.
    """
    pairs = []
    for f in order:
        key = f["source_key"]
        if key in overrides:
            # Always present: the rule counts hits by construction, and a
            # target that vanished would make the expected count wrong for a
            # reason that has nothing to do with the mapping.
            v = overrides[key]
        elif f.get("optional") and r.random() < OPTIONAL_ABSENCE_RATE:
            pairs.append((key, None))
            continue
        elif "value_map" in f:
            v = r.choice(list(f["value_map"]))
        elif f["ecs_field"] is None:
            v = r.choice(["edge-1", "core-2", "dmz-3"])
        else:
            v = _value(f["ecs_field"], f["type"], r)
        pairs.append((key, v))
    return _render(layout, pairs, r, seed, order)


def _ambiguous_key(built: dict[str, Any]) -> str | None:
    for f in built["fields"]:
        if f["ecs_field"] is None:
            return f["source_key"]
    return None


def build_probe(built: dict[str, Any], seed: int) -> tuple[str, dict[str, Any]]:
    """One extra sample line with values we chose, and what they were.

    This is the synthetic stand-in for running a probe against a live source.
    `known_values.json` is an observation - "this value is where the probe put
    it" - not a judgement about meaning, which is why the ladder may read it
    while `truth.json` stays off limits.
    """
    r = random.Random(seed + 9001)
    overrides, values = {}, {}
    for f in built["order"]:
        v = _marker_value(f, "probe", r)
        overrides[f["source_key"]] = v
        # Only fields with an unambiguous ECS home, and only markers - a random
        # numeric would repeat elsewhere in the file and prove nothing.
        if f["ecs_field"] and "value_map" not in f and f["ecs_field"] in MARKER_TABLES["probe"]:
            values[f["ecs_field"]] = v
    return _line(built["order"], built["layout"], overrides, r, built["seed"]), values


LONGISH = ("long", "integer", "float")


def _term(ecs_field: str, typ: str, value: str) -> dict[str, Any]:
    """One clause, matching the field or any ECS field that means the same.

    A rule that names only `source.ip` refuses a parser that wrote `client.ip`,
    and ECS carries both names for one endpoint. V4 exists to catch a value in
    the WRONG ENTITY, not a value under the other name for the right one, so
    the clause is a `should` over the equivalence set declared in
    adapter.ecs_index. Sets never cross an entity boundary: source and
    destination are never in the same set, so a swapped mapping still answers
    zero.
    """
    from adapter.ecs_index import EQUIVALENT_TO

    v: Any = value
    if typ in LONGISH:
        try:
            v = int(value)
        except ValueError:
            try:
                v = float(value)
            except ValueError:
                pass

    names = sorted(EQUIVALENT_TO.get(ecs_field, frozenset({ecs_field})))
    if len(names) == 1:
        return {"term": {ecs_field: v}}
    return {"bool": {"should": [{"term": {n: v}} for n in names],
                     "minimum_should_match": 1}}

def _scenario_targets(built: dict[str, Any], ns: str) -> list[dict[str, Any]]:
    """Every field this namespace can write a distinguishable value into."""
    table = MARKER_TABLES[ns]
    targets = [
        f for f in built["order"]
        if f["ecs_field"] and "value_map" not in f
        and f["type"] in QUERYABLE_TYPES
        and (f["type"] == "ip" or f["ecs_field"] in table)
    ]
    # An IP target first: source/destination/observer confusion is the error
    # this whole subsystem exists to catch, so the first rule written for a
    # source should be the one that can express it.
    targets.sort(key=lambda f: (f["type"] != "ip", f["ecs_field"]))
    return targets


def build_scenarios(built: dict[str, Any], sid: str, ns: str, seed: int,
                    n_attack: int = 5, n_noise: int = 6,
                    per_rule: int = 2) -> list[dict[str, Any]]:
    """A battery of detection scenarios whose expected hit counts are known.

    WHY A BATTERY AND NOT ONE SCENARIO
    ----------------------------------
    V4 is the contribution, and V4 can only contradict a field some rule
    actually filters on. One scenario per source filtered on two fields, so on
    a nine-field source seven mappings were never put to the test and the
    ladder reported `verified` on the strength of two. Measured over the
    corpus, replay exercised 28 per cent of the fields that have ground truth.
    "Not contradicted is not verified" is the project's own sentence, and it
    applies per field.

    The alternative of one rule filtering on all nine fields was rejected: an
    AND over every field in a source is not a detection rule anyone writes,
    and it would make V4's verdict a single bit over the whole mapping. So the
    targets are partitioned into rules of `per_rule` fields, each a plausible
    rule, and V4 already requires every scenario for the split to pass.

    Each scenario is indexed separately by the replay harness, so two rules in
    the same namespace may carry the same marker for a field without either
    one seeing the other's events.
    """
    r = random.Random(seed + (7001 if ns == "repair" else 7002))

    targets = _scenario_targets(built, ns)
    if not targets:
        return []

    amb = _ambiguous_key(built)
    if amb is None:
        return []  # no alphabetic marker slot, so distinctness is unprovable

    out: list[dict[str, Any]] = []
    groups = [targets[i:i + per_rule] for i in range(0, len(targets), per_rule)]
    for idx, group in enumerate(groups, start=1):
        overrides = {f["source_key"]: _marker_value(f, ns, r) for f in group}
        overrides[amb] = f"{ns}-zone"

        events = [_line(built["order"], built["layout"], overrides, r, built["seed"])
                  for _ in range(n_attack)]
        # Noise carries the same alphabetic marker - distinctness is measured
        # against SAMPLES, not within the scenario - but never the target
        # values, which are drawn from a range the sample generator cannot
        # produce.
        events += [_line(built["order"], built["layout"], {amb: f"{ns}-zone"}, r, built["seed"])
                   for _ in range(n_noise)]
        r.shuffle(events)

        out.append({
            "dir": f"{sid}__{ns}_probe_{idx:02d}",
            "events": events,
            "query": {"bool": {"filter": [
                _term(f["ecs_field"], f["type"], overrides[f["source_key"]])
                for f in group
            ]}},
            "expected": {
                "split": "repair" if ns == "repair" else "holdout",
                "expected_hits": n_attack,
                "targets": [f["ecs_field"] for f in group],
                "description": (
                    f"{n_attack} events carrying "
                    + ", ".join(f"{f['ecs_field']}={overrides[f['source_key']]}"
                                for f in group)
                    + f", mixed with {n_noise} events that match neither."
                ),
                "why_this_catches_semantic_errors": (
                    "The query filters on the ECS fields, not on the source keys. A "
                    "mapping that puts the right value in the wrong field is schema-"
                    "valid, indexes cleanly and passes V1, V2 and V3; the count "
                    "comes back 0 and only V4 notices."
                ),
                "origin": "generated by corpus/synthesise.py - expected_hits is known by construction",
            },
        })
    return out


def write_scenario(sc: dict[str, Any], scenarios_dir: Path) -> None:
    d = scenarios_dir / sc["dir"]
    d.mkdir(parents=True, exist_ok=True)
    (d / "events.ndjson").write_text(
        "".join(json.dumps({"raw": ln}) + "\n" for ln in sc["events"]), encoding="utf-8")
    (d / "query.json").write_text(json.dumps(sc["query"], indent=2) + "\n", encoding="utf-8")
    (d / "expected.json").write_text(
        json.dumps(sc["expected"], indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _truth_extraction(built: dict[str, Any]) -> dict[str, Any]:
    """How to read back what `_render` wrote. Correct by construction."""
    layout = built["layout"]
    keys = [f["source_key"] for f in built["order"]]
    if layout == "json":
        return {"kind": "json"}
    if layout == "csv":
        return {"kind": "csv", "columns": keys}
    if layout == "csv_tab":
        return {"kind": "csv", "field_split": "\t", "columns": keys}
    if layout == "prose":
        connectors = prose_shape([(k, "") for k in keys], built["order"],
                                 built.get("seed", 0))
        parts = []
        for i, (connector, key) in enumerate(zip(connectors, keys)):
            # The last capture takes the rest of the line; every other one
            # stops at the next connector word.
            cap = ("%{GREEDYDATA:" + key + "}" if i == len(keys) - 1
                   else "%{DATA:" + key + "}")
            parts.append(f"{connector} {cap}" if connector else cap)
        return {"kind": "grok", "pattern": " ".join(parts)}
    if layout == "syslog":
        shape = syslog_shape(built["order"], built.get("seed", 0))
        parts = [_syslog_capture(m, t, k, i == len(keys) - 1)
                 for i, ((m, t), k) in enumerate(zip(shape, keys))]
        return {"kind": "grok",
                "pattern": SYSLOG_PREAMBLE_PATTERN + ": " + " ".join(parts)}
    return {"kind": "kv",
            "field_split": {"kv_space": " ", "kv_comma": ", ", "kv_pipe": "|"}[layout],
            "value_split": "="}


class CorpusWouldChange(RuntimeError):
    """Re-synthesising would replace a source with different data.

    Raised rather than overwriting, because overwriting is silent and the
    damage is not. Every proposal in teacher/out/proposals.ndjson was made
    against the lines that are on disk now; replace those lines and the
    proposals describe a source that no longer exists, while still looking
    perfectly well-formed.

    Measured on 2026-10-12: a dry re-synthesis at the same seed reproduced 56
    of 98 sources byte for byte and changed the other 42 - every source of the
    six families added during October, whose definitions in mappings.json and
    synthesise.py were edited after they were first written. `make
    ecs-corpus-synth` had quietly become a destructive command.
    """


def write_source(sid: str, built: dict[str, Any], mapping: dict[str, Any], out: Path,
                 seed: int = 0, scenarios: list[str] | None = None,
                 force: bool = False) -> None:
    d = out / sid
    d.mkdir(parents=True, exist_ok=True)

    probe_line, known = build_probe(built, seed)
    lines = list(built["lines"]) + [probe_line]
    samples = "".join(
        json.dumps({"raw": ln, "signature": "synthetic"}) + "\n" for ln in lines
    )
    existing = d / "samples.ndjson"
    if not force and existing.is_file() and existing.read_text(encoding="utf-8") != samples:
        raise CorpusWouldChange(
            f"{sid}: the lines on disk are not the lines this would write.\n"
            f"  Proposals already made against {sid} would survive the rewrite "
            "looking valid while describing a source that no longer exists.\n"
            "  Pass --force to replace it, and expect to regenerate and "
            "revalidate every proposal for this source."
        )
    (d / "samples.ndjson").write_text(
        samples, encoding="utf-8")

    (d / "known_values.json").write_text(json.dumps({
        "source_id": sid,
        "origin": "generated by corpus/synthesise.py",
        "note": "NOT ground truth. An observation of what the synthetic probe injected, "
                "which is why the ladder may read this file and may not read truth.json.",
        "provenance": "The last line of samples.ndjson is the probe line; these are the "
                      "values it carries.",
        "values": known,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # WHAT THE DOCUMENTATION MAY SAY, AND WHY IT SAYS SO LITTLE
    #
    # It used to carry a field table: the generated key on the left and, on the
    # right, the capture name from the Logstash pipeline this mapping was
    # recovered from. Two things were wrong with that, and the second is bad.
    #
    #   THE HINT AND THE ANSWER CAME FROM THE SAME FILE. `gw - fe`,
    #   `upstream - srv`, `reporter_ip - proxy`. Ground truth is recovered from
    #   that pipeline, so the documentation was correlated with the answer by
    #   construction, and how strong the hint was depended on how transparently
    #   whoever wrote the pipeline had named the grok captures. That is
    #   uncontrolled variation across families, not a property of the task.
    #
    #   IT GAVE AWAY THE ABSTENTION. Every source carries one deliberately
    #   ambiguous key whose correct answer is to abstain, and the table
    #   announced it: `- dev - ambiguous identifier`, beside a truth.json
    #   saying `ecs_field: null, acceptable_abstention: true`. The corpus was
    #   telling the model the answer to the one case it exists to test.
    #
    # So the documentation now states only what a real vendor document states
    # about the SHAPE of the format, and never what a field means.
    #
    # The column list stays for `csv`, because there it is not a hint: the
    # format is positional, the names appear nowhere in the data, and without
    # them no parser can be written at all. Everywhere else the keys are in the
    # lines, so the model has the evidence and has to reason from it.
    #
    # The held-out sources are unaffected. Their documentation is hand-written
    # from each vendor's real format and describes meaning in prose, which is
    # what an operator actually has.
    # THE SAME ARGUMENT, EXTENDED TO THE TWO LAYOUTS THAT NEED IT MORE.
    #
    # The column list stays for csv because the names appear nowhere in the
    # data. That is equally true of a tab-separated table, and it is MORE true
    # of prose: there the line is a sentence and not one key is written in it.
    # Withholding the names would not be a harder task, it would be an
    # unanswerable one, and the score would measure whether the model guessed
    # the annotator's vocabulary.
    #
    # This is what the hand-written documentation for the real sources already
    # does - `sshd_auth` has a "Capture names" section listing `outcome`,
    # `user`, `src_ip`, `src_port` - so the synthetic corpus and the evaluation
    # pool now state the same kind of thing in the same way, which is what
    # makes transfer between them a fair question.
    keys = [f["source_key"] for f in built["order"]]
    cols = ", ".join(keys)
    layout = built["layout"]
    if layout in ("csv", "csv_tab"):
        sep = "a comma" if layout == "csv" else "a tab"
        shape = f"Columns separated by {sep}, in order: {cols}"
    elif layout == "prose":
        from corpus.synthesise import prose_shape  # noqa: F401  (same module)
        connectors = prose_shape(
            [(k, "") for k in keys], built["order"], built.get("seed", 0))
        line = " ".join(
            (f"{c} {k.upper()}" if c else k.upper())
            for c, k in zip(connectors, keys)
        )
        shape = (
            "Free text. No key name appears in the line; a value is identified "
            "by its position and by the words around it.\n\n"
            "```\n" + line + "\n```\n\n"
            "## Capture names\n\n"
            "Use these names, in this order:\n\n"
            + "\n".join(f"- `{k}`" for k in keys)
        )
    elif layout == "syslog":
        # The same contract as prose - the names appear nowhere in the line, so
        # withholding them would make the task unanswerable rather than harder.
        # Adding the layout to LAYOUTS without adding this branch sent the
        # teacher the `else` text below, which told it the source was
        # key=value. Found 2026-10-13 after the first 16 proposals over the
        # syslog families failed V2, several by writing a kv extraction for a
        # line that contains no `=`.
        shape_tokens = syslog_shape(built["order"], built.get("seed", 0))
        body = " ".join(
            {"bracket": f"[{k.upper()}]", "quote": f'"{k.upper()}"',
             "action": k.upper(), "bare": k.upper()}.get(
                mode, (f"{tok} {k.upper()}" if tok else k.upper()))
            for (mode, tok), k in zip(shape_tokens, keys)
        )
        # Shown as a concrete shape, the way the hand-written documentation
        # for the real sources does - `sshd_auth` prints three literal message
        # forms and explains which parts are literals. A schematic alone put
        # the synthetic corpus BELOW the evaluation pool in what it tells the
        # reader, and transfer between them is only a fair question when both
        # state the same kind of thing. Measured 2026-10-13: given only
        # `MMM DD HH:MM:SS`, the teacher wrote `%{MONTHDAY} %{MONTH}` against a
        # line reading `May  2`.
        sample = built["lines"][0] if built.get("lines") else ""
        shape = (
            "Free text in RFC 3164 syslog form. The line opens with a preamble "
            "that carries NO field of interest, followed by `: ` and then the "
            "message. No key name appears anywhere in the line; a value is "
            "identified by its position, by the words around it, and by the "
            "brackets or quotes it sits in.\n\n"
            "The preamble is, in this order: the three-letter month, the DAY "
            "OF THE MONTH - a number, space-padded to two characters, never a "
            "weekday name - the time, the host, and the emitting program with "
            "its pid in square brackets. None of those five is a field to "
            "capture.\n\n"
            "```\n" + sample + "\n```\n\n"
            "The same line with the values replaced by their capture names:\n\n"
            "```\nMONTH DAY-OF-MONTH TIME HOST PROGRAM[PID]: " + body + "\n```\n\n"
            "## Capture names\n\n"
            "Use these names, in this order:\n\n"
            + "\n".join(f"- `{k}`" for k in keys)
        )
    else:
        shape = "Key-value pairs; key order varies per line."
    (d / "documentation.md").write_text(
        f"""# {sid}

Synthetic source generated by `corpus/synthesise.py` from the mapping recovered
from `{mapping['pipeline']}`. Layout: `{built['layout']}`.

{shape}

No field descriptions are given. What each key means has to be read from the
values; see the note in `corpus/synthesise.py` for why.
""",
        encoding="utf-8")

    truth = {
        "source_id": sid,
        "split": built["split"],
        "family": mapping["family"],
        "category_hint": mapping["category_hint"],
        "contamination_risk": "none",
        "origin": "synthetic - generated by corpus/synthesise.py",
        "notes": (
            "Ground truth is known by construction: the generator chose the key names. "
            "Easier than a real source - fixed vocabulary, well-formed values, no truncation. "
            "Training material only; never use a generated source in the test split."
        ),
        "fields": [{k: v for k, v in f.items() if k != "value_map"} for f in built["fields"]],
        "scenarios": sorted(scenarios or []),
        # RECORDED BECAUSE A CONTROL CANNOT BE BUILT WITHOUT THEM.
        #
        # `layout` was previously inferred from the source id's suffix, which
        # worked until a REAL source called postgres_csv was read as a
        # generated one and the control reported a ground-truth mapping refused
        # at V4 - a falsifier, fired by a guess. Stating it removes the guess.
        #
        # `column_order` and `seed` are what a positional or prose extraction
        # is rebuilt from: for prose there is no delimiter to fall back on, and
        # the sentence shape is a property of the source that only the seed
        # reproduces.
        "layout": built["layout"],
        "column_order": [f["source_key"] for f in built["order"]],
        "seed": built.get("seed", seed),
        # THE EXTRACTION, RECORDED RATHER THAN RECONSTRUCTED.
        #
        # This generator knows exactly how it rendered the line, so the
        # extraction that reads it back is correct by construction. Writing it
        # down removes two problems at once: a control no longer has to
        # recompute a grok pattern from the connectors, and nothing outside
        # this package has to import this module to do so - bench/mutate.py
        # tried, and failed in the container, where corpus/ is not installed.
        "extraction": _truth_extraction(built),
    }
    (d / "truth.json").write_text(json.dumps(truth, indent=2, sort_keys=True), encoding="utf-8")


def audit(mappings: list[dict[str, Any]]) -> int:
    """Say out loud which mapped fields will not reach the corpus, and why.

    Two ways a hand-written pipeline's ground truth can fail to become training
    material, both of which used to happen in silence:

      no alias   the ECS field has no entry in ALIASES, so `build_source`
                 filters it out. Fixable here, by adding one.

      not ECS    the pipeline renames into a field that does not exist in the
                 indexed ECS version. `linux-auditd.conf` maps `user.audit.id`,
                 which is an auditd convention rather than ECS 8.11. A target
                 outside the index can never be offered to the model and can
                 never be answered, so it is scored as a guaranteed miss and
                 the fault is the pipeline's, not the model's. NOT fixable
                 here: the pipeline has to change, or the field has to go.

    Returns the number of fields that will not reach the corpus.
    """
    known = set(_ecs_types())
    lost = 0
    print("corpus reach - what the generated sources will be able to teach")
    reached: set[str] = set()
    for m in mappings:
        no_alias, not_ecs = [], []
        for f in m["fields"]:
            ecs = f["ecs_field"]
            if ecs not in known:
                not_ecs.append(ecs)
            elif ecs not in ALIASES:
                no_alias.append(ecs)
            else:
                reached.add(ecs)
        n = len(m["fields"])
        kept = n - len(no_alias) - len(not_ecs)
        print(f"  {m['family']:<22} {kept:>2}/{n:<2} fields reach the corpus")
        for e in sorted(set(no_alias)):
            print(f"  {'':<22} DROPPED  {e:<36} no ALIASES entry")
        for e in sorted(set(not_ecs)):
            print(f"  {'':<22} INVALID  {e:<36} not a field in this ECS version")
        lost += len(no_alias) + len(not_ecs)
    print(f"  {'':<22} {len(reached)} distinct ECS fields reachable, {lost} field(s) lost")
    return lost


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--mappings", default=str(Path(__file__).parent / "mappings.json"))
    p.add_argument("--out", default=str(SOURCES))
    p.add_argument("--split", default="train", choices=["train", "dev"],
                   help="test is refused on purpose; see the module docstring")
    p.add_argument("--layouts", default=",".join(LAYOUTS))
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--lines", type=int, default=40)
    p.add_argument("--scenarios", default=str(ROOT / "bench" / "scenarios"))
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--strict", action="store_true",
                   help="fail if any mapped field cannot reach the corpus")
    p.add_argument("--optional", action="store_true",
                   help="ACTION 3: build a PARALLEL set of sources, suffixed "
                        "_opt, in which two fields per source are absent from "
                        "about a third of the lines. The existing sources are "
                        "not touched. Nothing in the corpus has ever shown the "
                        "teacher that a field can be missing, which is M1.")
    p.add_argument("--variant", type=int, default=0, metavar="N",
                   help="emit a PARALLEL family of sources suffixed _vN, drawn "
                        "from a different seed, leaving every existing source "
                        "untouched. The source id carries no seed, so without "
                        "this a second draw collides with the first and A20 "
                        "refuses it. Use with --layouts to deepen one layout: "
                        "the training set is filtered by V3/V4, and prose "
                        "survives that filter at 2.57 credited examples per "
                        "source against 5.50 for kv, so a corpus balanced at "
                        "generation time arrives at training 44%% short on "
                        "grok. Deepening prose is how that is repaid.")
    p.add_argument("--force", action="store_true",
                   help="replace sources whose lines on disk differ from what "
                        "this would write. Every proposal made against them "
                        "becomes a description of a source that no longer "
                        "exists, so expect to regenerate and revalidate.")
    a = p.parse_args(argv)

    mappings = json.loads(Path(a.mappings).read_text(encoding="utf-8"))
    layouts = [l.strip() for l in a.layouts.split(",") if l.strip()]
    bad = [l for l in layouts if l not in LAYOUTS]
    if bad:
        print(f"FAILED: unknown layout(s) {bad}; choose from {list(LAYOUTS)}")
        return 1

    lost = audit(mappings)
    if lost and a.strict:
        print(f"\nFAILED: {lost} mapped field(s) will not reach the corpus, and --strict is set.")
        return 1
    print()

    out = Path(a.out)
    scenarios_dir = Path(a.scenarios)
    made = skipped = 0
    would_change: list[str] = []
    for i, m in enumerate(mappings):
        for j, layout in enumerate(layouts):
            sid = f"syn_{m['family'].replace('-', '_')}_{layout}"
            if a.optional:
                sid += "_opt"
            if a.variant:
                sid += f"_v{a.variant}"
            built = build_source(m, layout, a.seed + i * 100 + j + a.variant * 10_000,
                                 a.split, a.lines, optional=a.optional)
            if built is None:
                skipped += 1
                continue
            hard = sum(f["difficulty"] in ("hard", "medium", "ambiguous") for f in built["fields"])
            print(f"  {sid:<34} {len(built['fields']):>2} fields ({hard} non-easy)")
            if not a.dry_run:
                seed = a.seed + i * 100 + j
                names = []
                for ns in ("repair", "holdout"):
                    for sc in build_scenarios(built, sid, ns, seed):
                        write_scenario(sc, scenarios_dir)
                        names.append(sc["dir"])
                try:
                    write_source(sid, built, m, out, seed=seed, scenarios=names,
                                 force=a.force)
                except CorpusWouldChange as exc:
                    # Collected rather than raised: dying on the first one says
                    # nothing about how much of the corpus would move, and that
                    # is the number the decision turns on.
                    would_change.append(str(exc))
                    continue
                if not names:
                    print(f"  {'':<34} WARNING: no queryable field - no scenario, so "
                          "V4 cannot verify this source and Gate 2 will discard it")
            made += 1

    print(f"\n{made} sources generated" + (f", {skipped} skipped (too few mappable fields)" if skipped else ""))
    if would_change:
        print(f"\nREFUSED: {len(would_change)} source(s) already on disk carry lines "
              "this run would replace.\n")
        for msg in would_change:
            print("  " + msg.replace("\n", "\n  "))
        print(
            "\nNothing was written for those. The sources that reproduce byte for "
            "byte were\nrewritten unchanged, which is a no-op.\n\n"
            "  This happens when a shared table in this file or a family in "
            "mappings.json is\n  edited after its sources were first written. "
            "The seed is positional\n  (`seed + i*100 + j`), so inserting a "
            "family also reseeds the ones after it.\n\n"
            "  Decide deliberately: --force replaces them, and then every "
            "proposal for those\n  sources has to be regenerated and "
            "revalidated.\n"
        )
        return 1
    if a.dry_run:
        print("--dry-run: nothing written.")
    else:
        print(f"written to {out}")
        print("\nNext:\n  python -m corpus.validate\n  make ecs-generate N=6 SEED=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

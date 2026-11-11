"""Round 7 (C-org): the organisation's own training data, from the OLD versions of its sources.

ROUND3_VERSION_DRIFT.md, "Round 7". An organisation holds the logs of its sources as they are today and
the parsers it runs for them. From those alone (no new-version line, truth or parser) three kinds of
stage-1 example are built:

    (a) parse   the source as it is: variants of the old logs, answer = the old reference parser.
                Written as records in teacher/out/gold.ndjson's shape (as corpus/r3_real_old.py does),
                so training/build_dataset.py turns them into stage-1 AND stage-2 rows.
    (b) keep    the edit prompt with the old parser and old lines from other runs; nothing changed,
                so the answer is the old parser itself. This is what C never saw: an edit that should
                change nothing.
    (c) edit    the old lines changed by a NAMED perturbation, the old parser changed consistently;
                answer = the changed parser. A candidate is kept only if the changed parser passes
                V1-V3 (a real Logstash) on the changed lines AND every mapped ECS field receives, over
                the lines, exactly the values the original parser put there.

Perturbations (c): json (text to JSON), json_rename (JSON with the keys renamed), kv (to key=value),
add_field, drop_field, ts_iso (a timestamp rewritten in ISO 8601), header (a syslog-style header in
front), reword (a literal word of the message replaced by another), reword_value (a value that a value
map reads replaced, the map re-keyed by meaning).

Round 7b (declared after C-org's first Caddy runs): json_vendor, text to JSON as vendors write it, the keys
grouped into objects by what they describe (request, client, server, response, user) and renamed
(`remote_ip` -> `client.ip`), the answer reading the nested paths (`client.ip`). add_field_v, drop_field_v
and ts_iso_v apply their change on top of such a JSON. Round 7's json, add_field, drop_field and ts_iso
keep every key name, so C-org learnt that a move to JSON keeps the old names, which real changes do not.

    python -m corpus.org_pairs candidates --only-kinds json_vendor,add_field_v,drop_field_v,ts_iso_v \
        --a 0 --b 0 --c 30 --tag v --out training/data/org/candidates_v.jsonl
    python -m corpus.org_pairs merge --verified training/data/org/verified.jsonl \
        training/data/org/verified_v.jsonl --keep-json 0.33 --out training/data/org/verified_7b.jsonl

Lines: old_run1-2 and old_extra_* (testbed/r3/old_extra.py); old_run3 stays out, as in r3_real_old,
because it is the old source's own verification events.

    python -m corpus.org_pairs candidates --out training/data/org/candidates.jsonl
    python -m corpus.org_pairs verify --cands ... --out ... --workers 24          (needs Logstash)
    python -m corpus.org_pairs build --verified ... --out training/data/org          (rows a, b, c)
"""
from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
import argparse
import hashlib
import json
import random
import re

ROOT = Path(__file__).resolve().parents[1]
R3 = ROOT / "testbed" / "r3"
SOURCES = ROOT / "bench" / "sources"
SPLIT = "train_org"


# ------------------------------------------------------------------ inputs
def pairs() -> dict:
    from testbed.r3.r5specs import ALL_PAIRS
    return ALL_PAIRS


def old_lines(pair: str, keep, ir: dict | None = None) -> dict[str, list[str]]:
    """Per run file, the kept lines: old_run1, old_run2, old_extra_1..k. With `ir`, only the lines
    the organisation's parser reads: an extra run can produce a message its parser never covered
    (Apache 2.2's `File does not exist` for a missing file), and an answer must read its input."""
    out = {}
    cap = R3 / "captures" / pair
    for p in sorted(cap.glob("old_run[12].log")) + sorted(cap.glob("old_extra_*.log"), key=lambda p: int(p.stem.split("_")[-1])):
        ls = [l.rstrip("\n") for l in p.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
        ls = [l for l in ls if keep(l) and (ir is None or values(ir, l) is not None)]
        if ls:
            out[p.stem] = ls
    return out


def gold(sid: str) -> dict:
    return json.loads((R3 / "gold" / f"{sid}.ir.json").read_text(encoding="utf-8"))


# ------------------------------------------------------------------ reading a line with an IR
def _regexes(ir: dict):
    from adapter.types import grok_patterns
    from validators.v2_consistency import _grok_to_regex
    out = []
    for p in grok_patterns(ir["extraction"]):
        rx, _names = _grok_to_regex(p)
        out.append((p, re.compile(rx)))
    return out


def values(ir: dict, line: str, _cache: dict = {}) -> dict[str, str] | None:
    """key -> value as the IR reads the line (Python's reading, V2's), or None if unread."""
    kind = ir["extraction"]["kind"]
    if kind == "json":
        try:
            obj = json.loads(line)
        except ValueError:
            return None
        if not isinstance(obj, dict):
            return None
        flat: dict[str, str] = {}

        def walk(o, pre):
            for k, v in o.items():
                if isinstance(v, dict):
                    walk(v, f"{pre}{k}.")
                elif v is not None and not isinstance(v, list):
                    flat[pre + k] = str(v)
        walk(obj, "")
        return flat
    if kind == "kv":
        fs, vs = ir["extraction"]["field_split"], ir["extraction"]["value_split"]
        out = {}
        for part in re.findall(r'(\w[\w.@-]*)' + re.escape(vs) + r'("(?:[^"\\]|\\.)*"|[^' + re.escape(fs) + r']*)', line):
            k, v = part
            if v.startswith('"'):
                v = v[1:-1]
            if v != "":
                out[k] = v
        return out
    key = json.dumps(ir["extraction"], sort_keys=True)
    if key not in _cache:
        _cache[key] = _regexes(ir)
    for _p, rx in _cache[key]:
        m = rx.match(line)
        if m:
            got = {}
            for name, v in m.groupdict().items():
                if v is None:
                    continue
                base = re.sub(r"__d\d+$", "", name)
                got.setdefault(base, v)
            return got
    return None


# ------------------------------------------------------------------ perturbations
STYLES = {
    "camel": lambda k: re.sub(r"[_.](\w)", lambda m: m.group(1).upper(), k),
    "prefix": lambda k: "evt_" + k.replace(".", "_"),
    "upper": lambda k: k.replace(".", "_").upper(),
    "short": lambda k: "".join(p[:3] for p in re.split(r"[_.]", k) if p) or k,
}
EXTRA_FIELDS = [("node", lambda r: r.choice(["srv-01", "srv-02", "edge-a", "core-b"])),
                ("trace_id", lambda r: "%016x" % r.getrandbits(64)),
                ("env", lambda r: r.choice(["prod", "staging"])),
                ("seq", lambda r: str(r.randint(1, 99999)))]
HEADERS = [
    ("syslog", lambda r: f"Oct {r.randint(1, 28):>2} {r.randint(0, 23):02d}:{r.randint(0, 59):02d}:{r.randint(0, 59):02d} host{r.randint(1, 9):02d} app[{r.randint(100, 9999)}]: ",
     r"%{SYSLOGTIMESTAMP:hdr_time} %{HOSTNAME:hdr_host} %{PROG:hdr_prog}\[%{POSINT:hdr_pid}\]: ",
     ["hdr_time", "hdr_host", "hdr_prog", "hdr_pid"]),
    ("iso", lambda r: f"2026-10-{r.randint(1, 28):02d}T{r.randint(0, 23):02d}:{r.randint(0, 59):02d}:{r.randint(0, 59):02d}.{r.randint(0, 999):03d}Z collector{r.randint(1, 9)} ",
     r"%{TIMESTAMP_ISO8601:hdr_time} %{NOTSPACE:hdr_collector} ", ["hdr_time", "hdr_collector"]),
]
# append_phrase (round 9): (text appended to the line, grok appended to the pattern, [(key, ECS field or None, type)]).
# Generic vocabulary, fixed before any r6 result; a key with no ECS field is declared unresolved.
APPEND_PHRASES = [
    (lambda r: f" from {r.randint(10, 223)}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}:{r.randint(1024, 65535)}",
     r" from %{IP:peer_ip}:%{INT:peer_port}", [("peer_ip", "source.ip", "ip"), ("peer_port", "source.port", "long")]),
    (lambda r: f" from {r.randint(10, 223)}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}",
     r" from %{IP:peer_ip}", [("peer_ip", "source.ip", "ip")]),
    (lambda r: f" on {r.choice(['eth0', 'ens3', 'wg0', 'bond0'])}",
     r" on %{NOTSPACE:iface}", [("iface", "observer.ingress.interface.name", "keyword")]),
    (lambda r: f" (session {r.getrandbits(32):08x})",
     r" \(session %{NOTSPACE:session_ref}\)", [("session_ref", None, None)]),
    (lambda r: f" in {r.randint(1, 900)} ms",
     r" in %{INT:elapsed_ms} ms", [("elapsed_ms", None, None)]),
    (lambda r: f" [{r.choice(['tls', 'plain', 'starttls'])}]",
     r" \[%{WORD:transport}\]", [("transport", None, None)]),
]
SYNONYMS = {"Failed": "Failure", "Accepted": "Allowed", "failed": "rejected", "successful": "succeeded",
            "Invalid": "Unknown", "disconnected": "dropped", "Connection": "Session", "connection": "session",
            "closed": "ended", "attempt": "try", "Login": "Signin", "user": "account", "denied": "refused",
            "authentication": "auth", "password": "credential", "client": "peer", "New": "Incoming",
            "error": "fault", "Exit": "Quit", "found": "located", "Bad": "Wrong", "OK": "Success"}


def _rename_ir(ir: dict, ren: dict[str, str]) -> dict:
    ir = json.loads(json.dumps(ir))
    for f in ir.get("fields", []):
        f["source_key"] = ren.get(f["source_key"], f["source_key"])
    for u in ir.get("unresolved", []):
        u["source_key"] = ren.get(u["source_key"], u["source_key"])
    for v in ir.get("value_maps", []):
        v["from_source_key"] = ren.get(v["from_source_key"], v["from_source_key"])
    return ir


def _as_json(ir: dict, recs: list[dict]) -> tuple[list[str], dict]:
    ir2 = json.loads(json.dumps(ir)); ir2["extraction"] = {"kind": "json"}
    return [json.dumps(r) for r in recs], ir2


# Vendor JSON (round 7b). Which object a key goes into is read from the ECS field the organisation's
# parser maps it to; the leaf drops the words the object already says and may take a synonym.
VENDOR_GROUPS = [
    (("source.", "client."), ["client", "remote", "peer", "src"]),
    (("destination.", "server."), ["server", "upstream", "dst", "backend"]),
    (("http.request.", "url.", "http.version", "user_agent."), ["request", "req", "http"]),
    (("http.response.",), ["response", "resp"]),
    (("user.",), ["user", "auth", "principal"]),
]
VENDOR_DROP = {"client", "remote", "src", "source", "dst", "dest", "destination", "server", "request", "req",
               "response", "resp", "http", "user", "auth", "peer"}
VENDOR_SYN = {"ip": ["ip", "address", "addr"], "uri": ["uri", "path"], "status": ["status", "code", "status_code"],
              "size": ["size", "bytes", "length"], "method": ["method", "verb"], "agent": ["agent", "user_agent", "ua"],
              "name": ["name", "login", "id"], "port": ["port"], "host": ["host", "hostname"]}
VENDOR_EXTRA = ["details", "data", "meta", "info"]


def _vendor_names(ir: dict, keys: list[str], rng: random.Random) -> dict[str, str] | None:
    """old key -> dotted path in a vendor-style nested JSON, or None on a clash."""
    field_of = {f["source_key"]: f["ecs_field"] for f in ir.get("fields", [])}
    field_of.update({v["from_source_key"]: v["ecs_field"] for v in ir.get("value_maps", [])})
    group = {pre: rng.choice(names) for pre, names in VENDOR_GROUPS}
    camel = rng.random() < 0.35
    extra = rng.choice(VENDOR_EXTRA) if rng.random() < 0.3 else None
    ren = {}
    for k in keys:
        toks = [t for t in re.split(r"[^A-Za-z0-9]+", k.lower()) if t]
        g = next((group[pre] for pre, _ in VENDOR_GROUPS if any(field_of.get(k, "").startswith(x) for x in pre)), None)
        if g is not None:
            ecs_leaf = [t for t in re.split(r"[^a-z0-9]+", field_of[k].split(".")[-1].lower()) if t]
            kept = [t for t in toks if t not in VENDOR_DROP]
            if not kept or rng.random() < 0.25:     # "src" alone, or a vendor that names by meaning
                kept = ecs_leaf or toks[-1:]
        else:
            kept, g = toks, (extra if k not in field_of else None)
        if kept and kept[-1] in VENDOR_SYN and rng.random() < 0.5:
            kept = kept[:-1] + [rng.choice(VENDOR_SYN[kept[-1]])]
        leaf = (kept[0] + "".join(t.capitalize() for t in kept[1:])) if camel else "_".join(kept)
        ren[k] = f"{g}.{leaf}" if g else leaf
    paths = list(ren.values())
    if len(set(paths)) != len(paths) or any(q.startswith(p + ".") for p in paths for q in paths):
        return None
    if all(k == v for k, v in ren.items()):
        return None
    return ren


def _nest(flat: dict[str, str]) -> dict:
    out: dict = {}
    for k, v in flat.items():
        cur = out
        *head, leaf = k.split(".")
        for h in head:
            cur = cur.setdefault(h, {})
        cur[leaf] = v
    return out


def _as_vendor_json(ir: dict, recs: list[dict], rng: random.Random):
    """(flat dotted records, renamed JSON IR, renaming) for a vendor-style nested JSON, or None."""
    keys = sorted({k for r in recs for k in r})
    ren = _vendor_names(ir, keys, rng)
    if ren is None:
        return None
    nrecs = [{ren[k]: v for k, v in r.items()} for r in recs]
    nir = _rename_ir(ir, ren); nir["extraction"] = {"kind": "json"}
    return nrecs, nir, ren


# Round 8 (contingency, PLAN_ROUND8_C_PLUS.md). Three kinds for what C still failed in round 7b.
# add_field_mapped: a key the new version adds AND maps (round 7's add_field taught to leave it unmapped).
# The meanings are generic HTTP/logging vocabulary fixed with the plan, not read from any evaluation truth.
EXTRA_MAPPED = [
    ("forwarded_for", "network.forwarded_ip", "ip", lambda r: f"10.{r.randint(0, 9)}.{r.randint(0, 255)}.{r.randint(1, 254)}"),
    ("request_id", "http.request.id", "keyword", lambda r: "%016x" % r.getrandbits(64)),
    ("trace_id", "trace.id", "keyword", lambda r: "%032x" % r.getrandbits(128)),
    ("node", "host.name", "keyword", lambda r: r.choice(["srv-01", "srv-02", "edge-a", "core-b"])),
    ("upstream_addr", "destination.address", "keyword", lambda r: f"10.1.{r.randint(0, 9)}.{r.randint(1, 254)}:{r.choice([80, 8080, 9000])}"),
    ("duration_ms", "event.duration", "long", lambda r: str(r.randint(1, 5000))),
]
# header_restructure: a leading header rewritten into another real layout. Only when the header's timestamp
# is not mapped (it is unresolved in every organisation parser here: @timestamp is set at ingest).
_HDR_SYSLOG = re.compile(r"^\^?%\{SYSLOGTIMESTAMP:([\w.]+)\} %\{(?:HOSTNAME|IPORHOST|SYSLOGHOST|NOTSPACE|DATA):([\w.]+)\} ")
_HDR_BRACKET = re.compile(r"^\^?\\\[%\{[A-Z0-9_]+:([\w.]+)\}\\\](?: |\\s\+)")
_HDR_ISO = re.compile(r"^\^?%\{TIMESTAMP_ISO8601:([\w.]+)\} ")
_LINE_SYSLOG = re.compile(r"^[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d (\S+) ")
_LINE_BRACKET = re.compile(r"^\[[^\]]+\]\s+")
_LINE_ISO = re.compile(r"^\d{4}-\d\d-\d\d[T ][\d:.,]+(?:Z|[+-]\d\d:?\d\d)? ")
# reword_value_phrase: a value-map key reworded into a phrase with the same meaning.
PHRASES = {"Login": "logged in", "Logout": "logged out", "Disconnected": "connection closed",
           "Failed": "authentication failure", "Accepted": "session opened", "Invalid": "unknown",
           "denied": "was rejected", "OK": "succeeded", "FAIL": "rejected", "Rejected": "refused by policy",
           "success": "completed", "failure": "not completed", "failed": "did not succeed",
           "Connected": "session started", "refused": "not allowed"}


def _iso(rng: random.Random) -> str:
    return f"2026-10-{rng.randint(1, 28):02d}T{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}.{rng.randint(0, 999):03d}Z"


def _restructure(ir: dict, lines: list[str], rng: random.Random):
    x = ir["extraction"]
    pats = [x["pattern"]] + list(x.get("alternatives") or [])
    mapped = {f["source_key"] for f in ir.get("fields", [])} | {v["from_source_key"] for v in ir.get("value_maps", [])}
    for hdr_rx, line_rx, style in ((_HDR_SYSLOG, _LINE_SYSLOG, "5424"), (_HDR_BRACKET, _LINE_BRACKET, "iso"),
                                   (_HDR_ISO, _LINE_ISO, "syslog")):
        ms = [hdr_rx.match(p) for p in pats]
        if not all(ms) or len({m.group(0) for m in ms}) != 1:
            continue
        ts_key = ms[0].group(1)
        if ts_key in mapped:
            return None
        if style == "5424":
            host_key = ms[0].group(2)
            head = (f"^<%{{POSINT:hdr_pri}}>1 %{{TIMESTAMP_ISO8601:{ts_key}}} %{{HOSTNAME:{host_key}}} "
                    "%{NOTSPACE:hdr_app} %{NOTSPACE:hdr_procid} - - ")
            added = ["hdr_pri", "hdr_app", "hdr_procid"]
        elif style == "iso":
            head = f"^%{{TIMESTAMP_ISO8601:{ts_key}}} \\[pid %{{POSINT:hdr_pid}}\\] "
            added = ["hdr_pid"]
        else:
            head = f"^%{{SYSLOGTIMESTAMP:{ts_key}}} %{{HOSTNAME:hdr_host}} "
            added = ["hdr_host"]
        nl = []
        app, procid = rng.choice(["daemon", "svc", "app"]), str(rng.randint(100, 9999))
        for l in lines:
            m = line_rx.match(l)
            if not m:
                return None
            rest = l[m.end():]
            if style == "5424":
                nl.append(f"<{rng.choice([30, 38, 86, 134])}>1 {_iso(rng)} {m.group(1)} {app} {procid} - - {rest}")
            elif style == "iso":
                nl.append(f"{_iso(rng)} [pid {procid}] {rest}")
            else:
                nl.append(f"{rng.choice(['Oct', 'Nov'])} {rng.randint(1, 28):>2} {rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d} "
                          f"{rng.choice(['gw01', 'srv02', 'edge-a'])} {rest}")
        nir = json.loads(json.dumps(ir))
        npats = [head + p[ms[0].end():] for p in pats]
        nir["extraction"]["pattern"] = npats[0]
        if len(npats) > 1:
            nir["extraction"]["alternatives"] = npats[1:]
        nir.setdefault("unresolved", []).extend({"source_key": k, "reason": "added by the new header"} for k in added)
        return nl, nir
    return None


# T4 vocabulary, fixed with the plan (generic, not read from any evaluation truth).
LEVEL_SHIFT = {"INFO": "DEBUG", "NOTICE": "INFO", "WARN": "ERROR", "WARNING": "ERROR", "ERROR": "WARNING",
               "DEBUG": "INFO"}
LEVEL_SHIFT.update({k.lower(): v.lower() for k, v in list(LEVEL_SHIFT.items())})
_LEVEL_LIT = re.compile(r"(?<![\w%{:])(" + "|".join(sorted(LEVEL_SHIFT, key=len, reverse=True)) + r")(?![\w}])")
NEW_STATEMENT_WORDS = ["Retrying", "Deferred", "Throttled", "Escalated", "Quarantined", "Rescheduled"]
_LIT_WORD = re.compile(r"(?<![\w%{:\\])([A-Za-z]{4,})(?![\w}])")


def _literal_spans(pattern: str) -> list[tuple[int, int]]:
    """Spans of `pattern` outside %{...} and (?<...>...) group names, where a literal word may be rewritten."""
    out, i, start = [], 0, 0
    while i < len(pattern):
        if pattern.startswith("%{", i) or pattern.startswith("(?<", i):
            out.append((start, i)); j = pattern.find("}" if pattern[i] == "%" else ">", i); i = start = j + 1 if j >= 0 else len(pattern)
        else:
            i += 1
    out.append((start, len(pattern)))
    return [(a, b) for a, b in out if b > a]


def _one_literal(pattern: str, rx: re.Pattern) -> re.Match | None:
    """The single match of `rx` in the pattern's literal text, or None when there is none or more than one."""
    hits = [m for a, b in _literal_spans(pattern) for m in rx.finditer(pattern, a, b)]
    return hits[0] if len(hits) == 1 else None


def _t4(kind: str, ir: dict, lines: list[str], rng: random.Random):
    """Round 10 T4. (new lines, new IR, for each new line the index of the original line whose values it carries)."""
    from adapter.types import grok_patterns
    if ir["extraction"]["kind"] != "grok":
        return None
    pats = grok_patterns(ir["extraction"])
    rxs = _regexes(ir)
    hit = [next((i for i, (_p, rx) in enumerate(rxs) if rx.match(l)), None) for l in lines]
    used = sorted({i for i in hit if i is not None})

    def with_patterns(npats):
        nir = json.loads(json.dumps(ir))
        nir["extraction"]["pattern"] = npats[0]
        nir["extraction"].pop("alternatives", None)
        if len(npats) > 1:
            nir["extraction"]["alternatives"] = npats[1:]
        return nir

    if kind == "level_change":       # Li et al. (2017), logging issues: one message's level changed
        cands = [i for i in used if _one_literal(pats[i], _LEVEL_LIT)]
        if not cands:
            return None
        i = rng.choice(cands); m = _one_literal(pats[i], _LEVEL_LIT); old, new = m.group(1), LEVEL_SHIFT[m.group(1)]
        word = re.compile(r"(?<!\w)" + re.escape(old) + r"(?!\w)")
        nl = []
        for l, h in zip(lines, hit):
            if h == i:
                if len(word.findall(l)) != 1:
                    return None
                l = word.sub(new, l)
            nl.append(l)
        npats = list(pats); npats[i] = pats[i][:m.start(1)] + new + pats[i][m.end(1):]
        return nl, with_patterns(npats), list(range(len(lines)))
    if kind == "insert_statement":   # Huo et al. (2023), insert: a new message with an existing message's variables
        def words(pat):   # literal words that occur once in the whole pattern, so the rewrite has one place
            return [m for a, b in _literal_spans(pat) for m in _LIT_WORD.finditer(pat, a, b)
                    if len(re.findall(r"(?<!\w)" + re.escape(m.group(1)) + r"(?!\w)", pat)) == 1]
        cands = [i for i in used if words(pats[i])]
        if not cands or len(pats) >= 8:      # the IR holds at most 8 patterns
            return None
        i = rng.choice(cands); m = rng.choice(words(pats[i])); old = m.group(1)
        new = rng.choice([w for w in NEW_STATEMENT_WORDS if w.lower() != old.lower()])
        word = re.compile(r"(?<!\w)" + re.escape(old) + r"(?!\w)")
        src = [j for j, h in enumerate(hit) if h == i and len(word.findall(lines[j])) == 1]
        if not src:
            return None
        added = [word.sub(new, lines[j]) for j in src]
        npats = list(pats) + [pats[i][:m.start(1)] + new + pats[i][m.end(1):]]
        return lines + added, with_patterns(npats), list(range(len(lines))) + src
    if kind == "remove_statement":   # Huo et al. (2023), remove: a message no longer written; the parser stays
        if len(used) < 2:
            return None
        i = rng.choice(used)
        keep = [j for j, h in enumerate(hit) if h != i]
        return [lines[j] for j in keep], json.loads(json.dumps(ir)), keep
    return None


def perturb(kind: str, ir: dict, lines: list[str], rng: random.Random) -> tuple[list[str], dict, dict] | None:
    """(new lines, new IR, key renaming old->new) or None when the perturbation does not apply."""
    ext = ir["extraction"]["kind"]
    recs = [values(ir, l) for l in lines]
    if any(r is None for r in recs):
        return None
    ident = {k: k for r in recs for k in r}
    if kind == "json":
        if ext == "json":
            return None
        nl, nir = _as_json(ir, recs)
        return nl, nir, ident
    if kind == "json_rename":
        style = rng.choice(list(STYLES))
        ren = {k: STYLES[style](k) for k in ident}
        if len(set(ren.values())) != len(ren) or all(k == v for k, v in ren.items()):
            return None
        nrecs = [{ren[k]: v for k, v in r.items()} for r in recs]
        nl, nir = _as_json(_rename_ir(ir, ren), nrecs)
        return nl, nir, ren
    if kind == "json_vendor":
        v = _as_vendor_json(ir, recs, rng)
        if v is None:
            return None
        nrecs, nir, ren = v
        return [json.dumps(_nest(r)) for r in nrecs], nir, ren
    if kind in ("add_field_v", "drop_field_v", "ts_iso_v"):
        v = _as_vendor_json(ir, recs, rng)
        if v is None:
            return None
        vrecs, vir, ren = v
        lines_v = [json.dumps(_nest(r)) for r in vrecs]
        p = perturb(kind[:-2], vir, lines_v, rng)
        if p is None:
            return None
        nl, nir, _ = p
        return nl, nir, ren
    if kind in ("add_field_mapped", "add_field_mapped_v"):
        if kind.endswith("_v"):
            v = _as_vendor_json(ir, recs, rng)
            if v is None:
                return None
            nrecs, nir, ren = v
        else:
            ren = ident
            nrecs, nir = [dict(r) for r in recs], json.loads(json.dumps(ir if ext == "json" else _as_json(ir, recs)[1]))
            nir["extraction"] = {"kind": "json"}
        taken = {f["ecs_field"] for f in nir.get("fields", [])} | {v["ecs_field"] for v in nir.get("value_maps", [])}
        free = [e for e in EXTRA_MAPPED if e[1] not in taken and not any(e[0] in r for r in nrecs)]
        if not free:
            return None
        name, ecs_field, typ, gen = rng.choice(free)
        for r in nrecs:
            r[name] = gen(rng)
        nir.setdefault("fields", []).append({"source_key": name, "ecs_field": ecs_field, "type": typ, "confidence": 1.0})
        dump = (lambda r: json.dumps(_nest(r))) if any("." in k for r in nrecs for k in r) else json.dumps
        return [dump(r) for r in nrecs], nir, ren
    if kind == "append_phrase":
        # Round 9: a phrase with fields appended to ONE message of a text source (Dropbear 2025's
        # "Login attempt for nonexistent user" gaining " from <ip>:<port>"); the answer extends that pattern.
        if ext != "grok":
            return None
        from adapter.types import grok_patterns
        pats = grok_patterns(ir["extraction"])
        rxs = _regexes(ir)
        hit = [next((i for i, (_p, rx) in enumerate(rxs) if rx.match(l)), None) for l in lines]
        used = sorted({i for i in hit if i is not None and pats[i].endswith("$")})
        if not used:
            return None
        i = rng.choice(used)
        taken = {f["ecs_field"] for f in ir.get("fields", [])} | {v["ecs_field"] for v in ir.get("value_maps", [])}
        keys = {k for r in recs for k in r}
        free = [p for p in APPEND_PHRASES if not ({e for _k, e, _t in p[2] if e} & taken) and not ({k for k, _e, _t in p[2]} & keys)]
        if not free:
            return None
        text, rx, keyspec = rng.choice(free)
        nl = []
        for l, h in zip(lines, hit):
            nl.append(l + text(rng) if h == i else l)
        npats = list(pats)
        npats[i] = pats[i][:-1] + rx + "$"
        nir = json.loads(json.dumps(ir))
        nir["extraction"]["pattern"] = npats[0]
        if len(npats) > 1:
            nir["extraction"]["alternatives"] = npats[1:]
        for k, e, t in keyspec:
            if e:
                nir.setdefault("fields", []).append({"source_key": k, "ecs_field": e, "type": t, "confidence": 1.0})
            else:
                nir.setdefault("unresolved", []).append({"source_key": k, "reason": "added by the new version; no ECS field"})
        return nl, nir, ident
    if kind == "header_restructure":
        if ext != "grok":
            return None
        v = _restructure(ir, lines, rng)
        if v is None:
            return None
        return v[0], v[1], ident
    if kind == "kv":
        if ext == "kv":
            return None
        sep = rng.choice(["|", " "])
        def q(v):
            return f'"{v}"' if (sep in v or "=" in v or '"' in v or not v) else v
        if any('"' in v for r in recs for v in r.values()):
            return None
        nl = [sep.join(f"{k}={q(v)}" for k, v in r.items()) for r in recs]
        nir = json.loads(json.dumps(ir)); nir["extraction"] = {"kind": "kv", "field_split": sep, "value_split": "="}
        return nl, nir, ident
    if kind in ("add_field", "drop_field", "ts_iso"):
        base_ir = ir if ext == "json" else _as_json(ir, recs)[1]
        nrecs = [dict(r) for r in recs]
        nir = json.loads(json.dumps(base_ir))
        if kind == "add_field":
            name, gen = rng.choice(EXTRA_FIELDS)
            if any(name in r for r in nrecs):
                return None
            for r in nrecs:
                r[name] = gen(rng)
            nir.setdefault("unresolved", []).append({"source_key": name, "reason": "added by the new version; not mapped"})
        elif kind == "drop_field":
            unres = [u["source_key"] for u in nir.get("unresolved", []) if any(u["source_key"] in r for r in nrecs)]
            if not unres:
                return None
            k = rng.choice(unres)
            for r in nrecs:
                r.pop(k, None)
            nir["unresolved"] = [u for u in nir["unresolved"] if u["source_key"] != k]
        else:
            tk = [k for k in ident if re.search(r"time|date|^t$|^ts$|timestamp", k, re.I)]
            if not tk:
                return None
            k = tk[0]
            for r in nrecs:
                if k in r:
                    r[k] = f"2026-10-{rng.randint(1, 28):02d}T{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}Z"
        dump = (lambda r: json.dumps(_nest(r))) if ext == "json" and any("." in k for r in nrecs for k in r) else json.dumps
        return [dump(r) for r in nrecs], nir, ident
    if kind == "header":
        if ext != "grok":
            return None
        name, gen, grok, keys = rng.choice(HEADERS)
        if any(k in ident for k in keys):
            return None
        nl = [gen(rng) + l for l in lines]
        nir = json.loads(json.dumps(ir))
        x = nir["extraction"]
        x["pattern"] = "^" + grok + x["pattern"].lstrip("^")
        if x.get("alternatives"):
            x["alternatives"] = ["^" + grok + a.lstrip("^") for a in x["alternatives"]]
        nir.setdefault("unresolved", []).extend({"source_key": k, "reason": "added collector header"} for k in keys)
        return nl, nir, ident
    if kind in ("reword", "reword_value", "reword_value_phrase"):
        if ext != "grok":
            return None
        nir = json.loads(json.dumps(ir))
        x = nir["extraction"]
        pats = [x["pattern"]] + list(x.get("alternatives") or [])
        if kind in ("reword_value", "reword_value_phrase"):
            vms = nir.get("value_maps") or []
            cands = [(vm, old) for vm in vms for old in vm.get("map", {}) if re.fullmatch(r"[A-Za-z][A-Za-z ]*", old)]
            if not cands:
                return None
            vm, old = rng.choice(cands)
            if kind == "reword_value_phrase":
                new = " ".join(PHRASES.get(w, SYNONYMS.get(w, w + "ed")) for w in old.split())
            else:
                new = " ".join(SYNONYMS.get(w, w + "ed") for w in old.split())
            if new == old or not any(old in p for p in pats):
                return None
            pats = [p.replace(old, new) for p in pats]
            vm["map"] = {(new if k == old else k): v for k, v in vm["map"].items()}
            nl = [l.replace(old, new) for l in lines]
        else:
            words = set()
            for p in pats:
                lit = re.sub(r"%\{[^}]*\}|\(\?<[^>]+>(?:[^()]|\([^()]*\))*\)|\\.", " ", p)
                words |= {w for w in re.findall(r"[A-Za-z]{3,}", lit) if w in SYNONYMS}
            if not words:
                return None
            w = rng.choice(sorted(words))
            rx = re.compile(r"(?<![A-Za-z])" + w + r"(?![A-Za-z])")
            token = re.compile(r"(%\{[^}]*\}|\(\?<[^>]+>|\\.)")

            def literal_sub(p):   # only the literal text: never a %{...} capture or a group name
                return "".join(part if token.fullmatch(part) else rx.sub(SYNONYMS[w], part)
                               for part in token.split(p))
            pats = [literal_sub(p) for p in pats]
            nl = [rx.sub(SYNONYMS[w], l) for l in lines]
        x["pattern"] = pats[0]
        if len(pats) > 1:
            x["alternatives"] = pats[1:]
        return nl, nir, ident
    return None


KINDS = ["json", "json_rename", "kv", "add_field", "drop_field", "ts_iso", "header", "reword", "reword_value"]
KINDS_7B = ["json_vendor", "add_field_v", "drop_field_v", "ts_iso_v"]
KINDS_8 = ["add_field_mapped", "add_field_mapped_v", "header_restructure", "reword_value_phrase"]
KINDS_9 = ["append_phrase"]
# Round 10, T4 (PLAN_ROUND10_ARM_C.md): the change types of two published taxonomies that no kind above covers.
# Li, Shang, Zou and Hassan (2017, EMSE 22(4)) group changes to logging statements into log improvement (covered by
# add_field*, append_phrase), dependency-driven changes (json_rename, json_vendor) and LOGGING ISSUES, such as a level
# changed (Kabinna et al., 2018, EMSE 23(1), discuss how each group breaks log-processing tools). Huo et al. (2023,
# EvLog, ISSRE) classify them as INSERT, paraphrase (reword*) and REMOVE.
KINDS_10 = ["level_change", "insert_statement", "remove_statement"]


def expected(ir: dict, recs: list[dict], ren: dict[str, str]) -> dict[str, Counter]:
    """ECS field -> the multiset of values the ORIGINAL parser puts there, over the lines."""
    out: dict[str, Counter] = defaultdict(Counter)
    vms = {v["from_source_key"]: v for v in ir.get("value_maps", [])}
    for r in recs:
        for f in ir.get("fields", []):
            if f["source_key"] in r:
                out[f["ecs_field"]][str(r[f["source_key"]])] += 1
        for k, vm in vms.items():
            if k in r and r[k] in vm.get("map", {}):
                out[vm["ecs_field"]][str(vm["map"][r[k]])] += 1
    return out


# ------------------------------------------------------------------ candidates
def variant(lines_by_run: dict[str, list[str]], extract, rng: random.Random, lo=8, hi=20, exclude=()) -> tuple[list[str], list[str]]:
    """A subset of lines from some runs, every message type at least once; returns (lines, runs)."""
    runs = [k for k in lines_by_run if k not in exclude] or list(lines_by_run)
    rng.shuffle(runs)
    pick = runs[: max(1, rng.randint(1, min(4, len(runs))))]
    pool = [l for k in pick for l in lines_by_run[k]]
    by_kind: dict = defaultdict(list)
    for i, l in enumerate(pool):
        by_kind[frozenset(extract(l))].append(i)
    chosen = {rng.choice(ix) for ix in by_kind.values()}
    target = min(len(pool), max(len(chosen), rng.randint(lo, hi)))
    rest = [i for i in range(len(pool)) if i not in chosen]
    rng.shuffle(rest)
    chosen |= set(rest[: target - len(chosen)])
    return [pool[i] for i in sorted(chosen)], pick


def candidates(n_a: int, n_b: int, n_c: int, seed: int = 11, kinds: list[str] | None = None, tag: str = "",
               only_pairs: list[str] | None = None) -> list[dict]:
    out = []
    for pair, (old, _new) in pairs().items():
        if only_pairs and pair not in only_pairs:
            continue
        rng = random.Random(f"{seed}:{pair}")
        ir = gold(old.source_id)
        runs = old_lines(pair, old.keep, ir)
        for k in range(n_a):
            ls, _ = variant(runs, old.extract, rng)
            out.append({"type": "a", "pair": pair, "old": old.source_id, "id": f"org_{old.source_id}_a{k:02d}", "lines": ls})
        for k in range(n_b):
            prev, used = variant(runs, old.extract, rng)
            new, _ = variant(runs, old.extract, rng, exclude=used)
            out.append({"type": "b", "pair": pair, "old": old.source_id, "id": f"org_{old.source_id}_b{k:02d}",
                        "history": prev, "lines": new, "ir": ir})
        made, tries = Counter(), 0
        while sum(made.values()) < n_c and tries < n_c * 12:
            tries += 1
            ks = kinds or KINDS
            kind = ks[tries % len(ks)]
            if made[kind] >= -(-n_c // len(ks)) + 2:
                continue
            prev, used = variant(runs, old.extract, rng)
            new, _ = variant(runs, old.extract, rng, exclude=used)
            if kind in KINDS_10:
                p = _t4(kind, ir, new, rng)
                if p is None:
                    continue
                nl, nir, origin = p
                recs, ren = [values(ir, new[j]) for j in origin], {k: k for r in (values(ir, l) for l in new) if r for k in r}
            else:
                p = perturb(kind, ir, new, rng)
                if p is None:
                    continue
                nl, nir, ren = p
                recs = [values(ir, l) for l in new]
            exp = expected(ir, recs, ren)
            if kind.startswith("add_field_mapped") or kind == "append_phrase":    # the field the new version adds and maps
                nrecs = [values(nir, l) for l in nl]
                if any(r is None for r in nrecs):
                    continue
                for f, c in expected(nir, nrecs, {}).items():
                    exp.setdefault(f, c)
            out.append({"type": "c", "kind": kind, "pair": pair, "old": old.source_id,
                        "id": f"org_{old.source_id}_c{tag}{sum(made.values()):02d}", "history": prev, "lines": nl,
                        "ir": dict(nir, source_id=f"org_{old.source_id}_c{tag}{sum(made.values()):02d}"),
                        "expected": {k: dict(v) for k, v in exp.items()}})
            made[kind] += 1
        print(f"  {pair:<14} a {n_a}  b {n_b}  c {sum(made.values())} {dict(made)}")
    return out


# ------------------------------------------------------------------ round 9: the organisation's upgrade history
def history_chain(pair: str, old_sid: str) -> list[tuple[str, Path | None]]:
    """[(gold source id, capture dir)] from the earliest captured release to the old version (capture None:
    the pool's own old_run files). A release enters only with its gold (testbed/r3/gold/<old>_h<rel>.ir.json)."""
    hs = []
    for d in (R3 / "captures").glob(f"{pair}_h*"):
        tag = d.name[len(pair) + 1:]
        if re.fullmatch(r"h\d+", tag) and (R3 / "gold" / f"{old_sid}_{tag}.ir.json").is_file():
            hs.append((int(tag[1:]), f"{old_sid}_{tag}", d))
    return [(sid, d) for _n, sid, d in sorted(hs)] + [(old_sid, None)]


def _history_runs(cap: Path, ir: dict) -> dict[str, list[str]]:
    """A history release's lines: every line its capture script collected (the old version's `keep` would drop
    exactly the messages that release words differently), read by that release's gold."""
    out = {}
    for p in sorted(cap.glob("old_run[12].log")):
        ls = [l.rstrip("\n") for l in p.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
        ls = [l for l in ls if values(ir, l) is not None]
        if ls:
            out[p.stem] = ls
    return out


def history_candidates(n: int, seed: int = 13, only_pairs: list[str] | None = None) -> list[dict]:
    """Real edit rows from consecutive releases v(k-1) -> v(k), up to the pool's OLD version (never past it):
    the old parser is v(k-1)'s gold, the new lines are v(k)'s, the answer is v(k)'s gold. Verified like any edit."""
    out = []
    for pair, (old, _new) in pairs().items():
        if only_pairs and pair not in only_pairs:
            continue
        chain = history_chain(pair, old.source_id)
        if len(chain) < 2:
            continue
        rng = random.Random(f"{seed}:{pair}")
        runs = {}
        for sid, cap in chain:
            ir = gold(sid)
            runs[sid] = old_lines(pair, old.keep, ir) if cap is None else _history_runs(cap, ir)
        made = Counter()
        for (psid, _pc), (csid, _cc) in zip(chain, chain[1:]):
            if not runs[psid] or not runs[csid]:
                continue
            pir, cir = gold(psid), gold(csid)
            same = (pir["extraction"], pir.get("fields"), pir.get("value_maps")) == (cir["extraction"], cir.get("fields"), cir.get("value_maps"))
            kind = "history_same" if same else "history"
            # an upgrade that changed nothing is a keep row; it must not outweigh the real changes (plan R9 risks)
            for k in range(n if not same else max(2, n // 4)):
                prev, _ = variant(runs[psid], old.extract, rng)
                new, _ = variant(runs[csid], old.extract, rng)
                recs = [values(cir, l) for l in new]
                rid = f"org_{csid}_hist{k:02d}"
                out.append({"type": "c", "kind": kind, "pair": pair, "old": psid, "doc_base": old.source_id,
                            "id": rid, "history": prev, "lines": new, "ir": dict(cir, source_id=rid),
                            "expected": {f: dict(c) for f, c in expected(cir, recs, {}).items()}})
                made[kind] += 1
        print(f"  {pair:<14} history {' -> '.join(s for s, _ in chain)}  {dict(made)}")
    return out


def cap_mix(rows: list[dict], share: float, rng: random.Random) -> tuple[list[dict], dict]:
    """Round 9: no extraction kind (of the ANSWER parser) above `share` of the edit rows; the excess of the
    largest kind is dropped at random. Rows a and b are untouched."""
    edits = [i for i, r in enumerate(rows) if r["type"] == "c" and (r.get("verify") or {}).get("ok")]   # what build keeps
    by = defaultdict(list)
    for i in edits:
        by[rows[i]["ir"]["extraction"]["kind"]].append(i)
    drop, n = set(), Counter()
    total = len(edits)
    for kind, ix in sorted(by.items(), key=lambda kv: -len(kv[1])):
        others = total - len(ix)
        limit = int(share * others / (1 - share)) if share < 1 else len(ix)
        if len(ix) > limit:
            rng.shuffle(ix)
            ix.sort(key=lambda i: rows[i].get("kind", "").startswith("history"), reverse=True)   # real pairs kept first
            drop |= set(ix[limit:]); n[f"{kind} capped"] += len(ix) - limit
            total -= len(ix) - limit
    return [r for i, r in enumerate(rows) if i not in drop], dict(n)


# ------------------------------------------------------------------ verification (Logstash)
def _verify_one(c: dict) -> dict:
    from adapter.compiler import compile_ir
    from adapter.types import Sample, Source
    from bench.arms import _index
    from validators import v3_sandbox
    from validators.v1_schema import validate as v1
    ecs = _index()
    ir = c["ir"]
    try:
        rep1 = v1(ir, ecs) if callable(v1) else None
        if rep1 is not None and not getattr(rep1, "passed", True):
            return {"id": c["id"], "ok": False, "why": "V1"}
    except Exception as e:  # noqa: BLE001
        return {"id": c["id"], "ok": False, "why": f"V1 error {type(e).__name__}"}
    # A quick reading in Python first, under a time limit: a pattern that backtracks for seconds on
    # a line would make grok spend its 30 s per-line limit in Logstash and hold a worker for minutes.
    import signal

    def _slow(*_):
        raise TimeoutError
    signal.signal(signal.SIGALRM, _slow)
    signal.alarm(10)
    try:
        for l in c["lines"]:
            if values(ir, l) is None:
                return {"id": c["id"], "ok": False, "why": "V2: a line unread"}
    except TimeoutError:
        return {"id": c["id"], "ok": False, "why": "V2: pattern too slow (backtracking)"}
    finally:
        signal.alarm(0)
    try:
        fb = compile_ir(ir, ecs.all_names())
    except Exception as e:  # noqa: BLE001
        return {"id": c["id"], "ok": False, "why": f"compile {type(e).__name__}: {str(e)[:80]}"}
    src = Source(source_id=c["id"], samples=tuple(Sample.of(l, "org") for l in c["lines"]), documentation="")
    # The card's container has a CPU quota (~17.5 cores) far below the 128 it shows; a JVM that sizes
    # its threads for 128 CPUs starts in minutes under that quota. Two CPUs per JVM, few workers, and
    # a long timeout so no correct candidate is refused for time. Performance only: the pipeline is
    # the same, and so is what is checked.
    import os
    os.environ["JAVA_TOOL_OPTIONS"] = "-XX:ActiveProcessorCount=2"
    rep = v3_sandbox.validate_many(fb, [src], "8.19.7", timeout_s=900)[0]
    docs = rep.metrics.get("documents", [])
    if len(docs) != len(c["lines"]):
        return {"id": c["id"], "ok": False, "why": f"V3: {len(docs)} documents for {len(c['lines'])} lines"}
    if any(any("failure" in t for t in (d.get("tags") or [])) for d in docs):
        return {"id": c["id"], "ok": False, "why": "V3: parse failure tag"}

    def get(d, dotted):
        cur = d
        for part in dotted.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            elif isinstance(cur, dict) and dotted in cur:
                return cur[dotted]
            else:
                return None
        return cur
    for ecs_field, want in c["expected"].items():
        got = Counter()
        for d in docs:
            v = get(d, ecs_field)
            if v is None:
                continue
            for x in (v if isinstance(v, list) else [v]):
                got[str(x)] += 1
        w = Counter({str(k): n for k, n in want.items()})
        norm = lambda C: Counter({re.sub(r"\.0$", "", k): n for k, n in C.items()})
        if norm(got) != norm(w):
            return {"id": c["id"], "ok": False, "why": f"values: {ecs_field} {dict(list(norm(got).items())[:2])} != {dict(list(norm(w).items())[:2])}"}
    return {"id": c["id"], "ok": True}


def verify(cands: Path, out: Path, workers: int) -> None:
    from concurrent.futures import ProcessPoolExecutor
    rows = [json.loads(l) for l in cands.read_text().splitlines() if l.strip()]
    todo = [r for r in rows if r["type"] == "c"]
    res = {}
    with ProcessPoolExecutor(max_workers=workers) as ex:
        for i, r in enumerate(ex.map(_verify_one, todo, chunksize=1), 1):
            res[r["id"]] = r
            if i % 25 == 0 or i == len(todo):
                ok = sum(x["ok"] for x in res.values())
                print(f"VERIFY {i}/{len(todo)} checked, {ok} kept", flush=True)
    out.write_text("".join(json.dumps(dict(r, verify=res.get(r["id"]))) + "\n" for r in rows))
    why = Counter(x["why"].split(":")[0] for x in res.values() if not x["ok"])
    print("VERIFY DONE kept", sum(x["ok"] for x in res.values()), "of", len(todo), "refused by", dict(why), flush=True)


# ------------------------------------------------------------------ rows
def _report(entry: dict) -> dict:
    """The old reference parser's full-ladder result (gold_ladder.json) in the shape
    validators.v4_detection.is_detection_verified reads."""
    done, total = (int(x) for x in str(entry["scenarios"]).split("/"))
    return {"passed": entry["passed"], "rung_reached": entry["rung_reached"],
            "metrics": {"verified": bool(entry["detection_verified"]), "scenarios_passed": done,
                        "scenarios_total": total}}


def _write_source(sid: str, lines: list[str], old_sid: str) -> None:
    d = SOURCES / sid
    d.mkdir(parents=True, exist_ok=True)
    base = SOURCES / old_sid
    (d / "samples.ndjson").write_text("".join(json.dumps({"raw": l}) + "\n" for l in lines), encoding="utf-8")
    (d / "documentation.md").write_text((base / "documentation.md").read_text(encoding="utf-8"), encoding="utf-8")
    t = json.loads((base / "truth.json").read_text(encoding="utf-8"))
    t.update(source_id=sid, split=SPLIT, scenarios=[], round7={"of": old_sid, "role": "organisation training"})
    (d / "truth.json").write_text(json.dumps(t, indent=2) + "\n", encoding="utf-8")


def build(verified: Path, out: Path) -> dict:
    from datetime import datetime, timezone
    from adapter.architectures import ROLES_SCHEMA, schema_digest
    from adapter.ecs_index import retrieval_digest
    from adapter.edit import edit_prompt_digest, render_edit_prompt
    from adapter.prompts import Prompts
    from adapter.schema_order import grammar_order
    from adapter.wiring import _ecs_index, _load_source
    from corpus.roles import leaks
    from corpus.siemgen_gold import roles_for
    from teacher.revalidate import APPARATUS
    from training.build_dataset import _sanitise_grok_names

    rows = [json.loads(l) for l in verified.read_text().splitlines() if l.strip()]
    prompts, ecs = Prompts(ROOT / "prompts"), _ecs_index()
    ladder = {r["source_id"]: r for r in json.loads((R3 / "gold_ladder.json").read_text())}
    out.mkdir(parents=True, exist_ok=True)
    records, counts, refused, seen = [], Counter(), Counter(), set()
    with (out / "interpret_org_edit.jsonl").open("w", encoding="utf-8") as fh:
        for r in rows:
            old_ir = gold(r["old"])
            if r["type"] == "a":
                _write_source(r["id"], r["lines"], r["old"])
                vir = dict(old_ir, source_id=r["id"])
                credited = sorted({f["ecs_field"] for f in old_ir.get("fields", [])} | {v["ecs_field"] for v in old_ir.get("value_maps", [])})
                records.append({"source_id": r["id"], "family": r["pair"], "seed": 0, "ecs_version": "8.11", "error": None,
                                "ir": vir, "roles": roles_for(vir), "report": _report(ladder[r["old"]]), "normalisations": [],
                                "teacher": "gold:org-old", "temperature": 0.0, "usage": {}, "wall_seconds": 0.0,
                                "prompt_digest": prompts.digest, "schema_digest": schema_digest(), "retrieval_digest": retrieval_digest(),
                                "validation": {"apparatus": APPARATUS, "oracle": "ladder V1-V4 on the base old source (gold_ladder.json)",
                                               "at": datetime.now(timezone.utc).isoformat(timespec="seconds")},
                                "credit": {"fields": credited, "whole": True, "extraction": True},
                                "provenance": {"generator": "organisation-old-logs", "pair": r["pair"], "base": r["old"], "lines": len(r["lines"])}})
                counts["a"] += 1
                continue
            if r["type"] == "c" and not (r.get("verify") or {}).get("ok"):
                refused["c not verified"] += 1
                continue
            target_ir = dict(old_ir if r["type"] == "b" else r["ir"], source_id=r["id"])
            _write_source(r["id"], r["lines"], r.get("doc_base", r["old"]))
            source, _ = _load_source(r["id"])
            target = roles_for(_sanitise_grok_names(target_ir))
            if leaks([x.get("role", "") for x in target.get("roles") or []], source.documentation + "\n" + source.sample_text()):
                refused["answer in input"] += 1
                continue
            prompt = render_edit_prompt(prompts, source, _sanitise_grok_names(old_ir), r["history"])
            key = hashlib.sha256((prompt + json.dumps(target, sort_keys=True)).encode()).hexdigest()
            if key in seen:
                refused["duplicate"] += 1
                continue
            seen.add(key)
            origin = "org:keep" if r["type"] == "b" else f"org:edit:{r['kind']}"
            fh.write(json.dumps({"source_id": r["id"], "previous_source_id": r["old"], "family": r["pair"], "seed": 0,
                                 "origin": origin, "prompt": prompt, "completion": json.dumps(grammar_order(target, ROLES_SCHEMA)),
                                 "prompt_digest": prompts.digest, "edit_prompt_digest": edit_prompt_digest(),
                                 "schema_digest": schema_digest(), "retrieval_digest": retrieval_digest(),
                                 "ecs_version": ecs.version}, sort_keys=True) + "\n")
            counts[origin] += 1
    (ROOT / "teacher" / "out").mkdir(parents=True, exist_ok=True)
    (out / "org_old_records.ndjson").write_text("".join(json.dumps(x, sort_keys=True, default=str) + "\n" for x in records))
    summary = {"written": dict(counts), "refused": dict(refused)}
    (out / "org_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def merge(old: Path, new: Path, keep_json: float, out: Path, seed: int = 7, drop: tuple = (), all_types: bool = False,
          cap: float = 1.0) -> dict:
    """Round 7b's verified set: round 7's rows with only a share of its same-name `json` edits kept,
    plus the vendor-JSON edits. Rows (a) and (b) are round 7's, unchanged."""
    rng = random.Random(seed)
    rows, n = [], Counter()
    for l in old.read_text().splitlines():
        r = json.loads(l)
        if r["type"] == "c" and r.get("kind") in drop:
            n[f"{r['kind']} dropped"] += 1
            continue
        if r["type"] == "c" and r.get("kind") == "json" and rng.random() >= keep_json:
            n["json dropped"] += 1
            continue
        rows.append(r); n[f"old {r['type']}"] += 1
    for l in new.read_text().splitlines():
        r = json.loads(l)
        if r["type"] == "c" and r.get("kind") in drop:
            n[f"new {r['kind']} dropped"] += 1
            continue
        if r["type"] == "c" or all_types:   # round 8: the r6 sources bring their own (a) and (b) rows
            rows.append(r); n[f"new {r.get('kind') or r['type']}"] += 1
    if cap < 1.0:   # round 9: no extraction kind above `cap` of the edit rows
        rows, capped = cap_mix(rows, cap, rng)
        n.update(capped)
    out.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return dict(n)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="corpus.org_pairs")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("candidates"); c.add_argument("--out", type=Path, required=True)
    c.add_argument("--a", type=int, default=15); c.add_argument("--b", type=int, default=15); c.add_argument("--c", type=int, default=40)
    v = sub.add_parser("verify"); v.add_argument("--cands", type=Path, required=True); v.add_argument("--out", type=Path, required=True)
    v.add_argument("--workers", type=int, default=16)
    b = sub.add_parser("build"); b.add_argument("--verified", type=Path, required=True); b.add_argument("--out", type=Path, required=True)
    c.add_argument("--only-kinds", default=""); c.add_argument("--tag", default="")
    c.add_argument("--pairs", default="", help="comma-separated pairs (default: every pair; r6 needs R6=1)")
    m = sub.add_parser("merge"); m.add_argument("--verified", type=Path, nargs=2, required=True)
    m.add_argument("--keep-json", type=float, default=0.33); m.add_argument("--out", type=Path, required=True)
    m.add_argument("--drop-kinds", default=""); m.add_argument("--all-types", action="store_true")
    m.add_argument("--cap", type=float, default=1.0, help="round 9: max share of the edit rows per extraction kind")
    h = sub.add_parser("history"); h.add_argument("--out", type=Path, required=True); h.add_argument("--n", type=int, default=12)
    h.add_argument("--pairs", default="")
    a = ap.parse_args(argv)
    if a.cmd == "candidates":
        rows = candidates(a.a, a.b, a.c, kinds=[k for k in a.only_kinds.split(",") if k] or None, tag=a.tag,
                          only_pairs=[x for x in a.pairs.split(",") if x] or None)
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text("".join(json.dumps(r) + "\n" for r in rows))
        print(f"{len(rows)} candidates -> {a.out}  {dict(Counter(r['type'] for r in rows))}")
    elif a.cmd == "verify":
        verify(a.cands, a.out, a.workers)
    elif a.cmd == "merge":
        print(json.dumps(merge(a.verified[0], a.verified[1], a.keep_json, a.out,
                               drop=tuple(k for k in a.drop_kinds.split(",") if k), all_types=a.all_types, cap=a.cap), indent=2))
    elif a.cmd == "history":
        rows = history_candidates(a.n, only_pairs=[x for x in a.pairs.split(",") if x] or None)
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text("".join(json.dumps(r) + "\n" for r in rows))
        print(f"{len(rows)} history candidates -> {a.out}  {dict(Counter(r['kind'] for r in rows))}")
    else:
        print(json.dumps(build(a.verified, a.out), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

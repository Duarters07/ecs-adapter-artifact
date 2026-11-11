"""R3 - training sources from SIEMgen, with the truth of every line.

WHY SIEMGEN, AND WHAT IT FIXES
------------------------------
Round 1's corpus was 14 synthetic families whose "prose" is key=value with the
`=` replaced by a word (M10): the students never saw an unlabelled syslog
preamble, a free-text action, a bracketed pid, or a source that writes several
KINDS of line. SIEMgen (a separate repository, branch `classroom`) renders a
small company's activity in each service's native format - sshd, sudo, su,
cron, pam and logind in one auth log; postfix's smtpd, cleanup, qmgr and smtp;
dnsmasq's query and reply - and renders the same event as an ECS document. So
each line it writes comes with what that line means. See PLAN_R2.md.

WHAT A SOURCE DIRECTORY HOLDS (the R3 interface in PLAN_R2.md)
--------------------------------------------------------------
    samples.ndjson      <= 20 lines, ordered so that EVERY line shape comes
                        first: the loader keeps the first 20 distinct
                        signatures (adapter.sampler.deduplicate), and a shape
                        it drops is a message type the model never sees
    line_truth.ndjson   {"raw", "ecs"} for each sample line that carries truth
    truth.json          split, family, origin (SIEMgen commit), category hint
    documentation.md    the format, briefly
    known_values.json   one unambiguous value per field, from the truth, with
                        "probe_line": false - every sample line is real
and, in bench/scenarios/, two detection scenarios per source whose expected
counts are counted over the truth: `repair` for training sources, `holdout`
for the in-distribution test families.

WHICH TRUTH A LINE CARRIES
--------------------------
`render_ecs` describes an EVENT, and several sources write an event as several
lines (sshd: the accept, the pam session, the logind session; postfix: up to
seven lines across four processes; auditd: six records; dnsmasq: the query and
its reply). One rule covers all of them, so that no source is special-cased:

    a line's truth is the ECS fields of its event whose value that line
    carries - once, as a whole token - and nothing else.

`event.outcome` is the one exception: no line carries `success`, and it is the
field a brute-force rule reads, so it is attached to the event's PRIMARY line
(the one carrying the most of the event's fields). Everything else computed by
the renderer - `event.kind`, `event.category`, `event.dataset`, `event.action`
- is a constant of the pipeline or a label, not something a parser of the line
recovers, and is left out. Fields outside ECS (`auditd.*`, `winlog.*`,
`vpn.*`, `azure.*`) are left out too: no IR can produce them.

Short values are not truth: a value must be at least three characters, because
a two-digit number matches too much of a line to say which field it is.

THE IN-DISTRIBUTION TEST FAMILIES (pre-registered, PLAN_R2.md)
--------------------------------------------------------------
    dhcp, vpn, cloud_audit  ->  split "test_id", never in the training pool

They were chosen before any round-2 run for coverage, not difficulty: one
syslog source with several message types (dhcp), one prose source whose
values are packed into compound tokens (vpn), one structured JSON source
(cloud_audit). The pre-registration first named sysmon as the JSON family; it
was replaced, before any run, for the reason recorded at EXCLUDED.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
import argparse
import json
import os
import random
import re
import shutil
import sys

from adapter import anchors
from adapter.sampler import deduplicate
from adapter.wiring import ROOT

TEST_ID = ("dhcp", "vpn", "cloud_audit")
# Not generated at all. SIEMgen's classroom branch renders Sysmon as EventID 1
# only, as one JSON object of ~50 keys, and that many keys fill retrieval's
# key-matched tier and evict the reserved source/destination/observer core
# (tests/test_retrieval.py, test_the_confusable_core_fields_are_always_offered).
# A retrieval limitation, recorded here rather than worked around in the corpus;
# `cloud_audit` takes its place as the structured in-distribution test family.
EXCLUDED = ("sysmon",)
SPLIT_TRAIN, SPLIT_TEST_ID = "train", "test_id"

CATEGORY = {
    "nginx": "web", "linux_auth": "authentication", "pfsense": "firewall",
    "auditd": "endpoint", "dns": "network", "vpn": "authentication", "mail": "email",
    "dhcp": "network", "suricata": "network", "windows": "endpoint", "sysmon": "endpoint",
    "azuread": "authentication", "cloud_audit": "file",
}

DOCS = {
    "nginx": "nginx access log, combined format: client address, user, local time, "
             "request line, status, bytes, referrer, user agent.",
    "linux_auth": "Linux authentication log written by rsyslog (RFC 3164 header: time, "
                  "host, program[pid]). Several programs share it: sshd (accepted, failed, "
                  "invalid user, disconnect), pam_unix sessions, systemd-logind sessions, "
                  "sudo commands, su, cron.",
    "pfsense": "pfSense filterlog over syslog: a comma-separated record of rule, "
               "interface, action, direction, IP version and protocol details, source and "
               "destination addresses and ports.",
    "auditd": "Linux audit log: one event is several records (SYSCALL, EXECVE, CWD, PATH, "
              "PROCTITLE) sharing msg=audit(time:serial), each record key=value.",
    "dns": "dnsmasq query log over syslog: a query line (type, name, client) and the "
           "reply line that answers it.",
    "vpn": "OpenVPN server log over syslog: client authentication, address assignment "
           "and session messages, prefixed with user/address:port.",
    "mail": "Postfix mail log over syslog: smtpd connections, cleanup message ids, qmgr "
            "queue entries (from, size), smtp/lmtp delivery (to, relay, delay, status).",
    "dhcp": "ISC dhcpd log over syslog: DISCOVER, OFFER, REQUEST and ACK messages with "
            "the leased address, the client MAC and hostname, and the interface.",
    "suricata": "Suricata EVE JSON: one object per event, flow and alert records with "
                "addresses, ports, protocol and alert details.",
    "windows": "Windows Security events shipped as JSON by a Winlogbeat-style agent.",
    "sysmon": "Sysmon events shipped as JSON by a Winlogbeat-style agent: process "
              "creation, network connection and file events.",
    "azuread": "Azure AD sign-in logs as JSON: user, application, client address, result.",
    "cloud_audit": "Nextcloud audit log as JSON: request id, user, remote address, method, "
                   "url, file actions.",
}

# Capture names for text formats, as the held-out documentation gives them
# (bench/sources/sshd_auth/documentation.md): a word for the value's role,
# never an ECS name - stage 1 must stay blind to ECS (tests/test_blindness.py).
CAPTURE_NAMES = {
    "source.ip": ("src_ip", "the address the connection or request came from"),
    "source.port": ("src_port", "the port it came from"),
    "destination.ip": ("dst_ip", "the address it went to"),
    "destination.port": ("dst_port", "the port it went to"),
    "user.name": ("user", "the account involved"),
    "user.effective.name": ("target_user", "the account a command ran as"),
    "user.id": ("uid", "the numeric account id"),
    "host.name": ("host", "the machine that wrote the line"),
    "process.pid": ("pid", "the process id"),
    "process.parent.pid": ("ppid", "the parent process id"),
    "process.name": ("program", "the program name"),
    "process.executable": ("exe", "the program's full path"),
    "process.command_line": ("command", "the command line that ran"),
    "process.working_directory": ("cwd", "the working directory"),
    "dns.question.name": ("query_name", "the name looked up"),
    "dns.question.type": ("query_type", "the record type asked for"),
    "dns.response_code": ("rcode", "the answer's status"),
    "http.request.method": ("method", "the request method"),
    "url.original": ("url", "the requested path and query, as written"),
    "http.response.status_code": ("status", "the response status code"),
    "http.response.body.bytes": ("bytes", "the response size"),
    "http.version": ("http_version", "the protocol version"),
    "user_agent.original": ("agent", "the client's user agent string"),
    "source.mac": ("client_mac", "the client's hardware address"),
    "observer.ingress.interface.name": ("interface", "the interface the packet arrived on"),
    "network.transport": ("proto", "the transport protocol"),
    "rule.uuid": ("tracker", "the rule's tracking id"),
    "event.outcome": ("outcome", "whether the attempt succeeded"),
    "event.id": ("queue_id", "the message's queue id"),
    "log.level": ("level", "the line's severity"),
}

MIN_VALUE_LEN = 3
MAX_SAMPLES = 20
_SKIP_PREFIX = ("@timestamp", "message", "event.original", "ecs.", "data_stream.", "labels.",
                "related.", "event.kind", "event.category", "event.dataset", "event.module",
                "event.action", "event.type", "event.sequence", "tags")
# Preference order for scenario targets: the fields detection rules filter on.
_TARGETS = ("source.ip", "user.name", "destination.ip", "event.outcome", "url.original",
            "dns.question.name", "client.ip", "process.name", "host.name", "source.port",
            "destination.port", "email.to.address", "email.from.address", "user_agent.original")


# ---------------------------------------------------------------- SIEMgen

def _siemgen_dir() -> Path:
    d = os.environ.get("SIEMGEN_DIR", "").strip()
    if not d or not (Path(d) / "siemgen").is_dir():
        sys.exit("Set SIEMGEN_DIR to an export of SIEMgen's classroom branch "
                 "(see testbed/drift/siemgen_bridge.py).")
    if d not in sys.path:
        sys.path.insert(0, d)
    return Path(d)


def siemgen_commit() -> str:
    f = _siemgen_dir() / "COMMIT"
    return f.read_text().strip() if f.is_file() else "unknown"


def source_names() -> list[str]:
    _siemgen_dir()
    from siemgen.sources import SOURCES
    return sorted(SOURCES)


def generate_events(source: str, n: int, seed: int, org_seed: int = 7) -> list[tuple[list[str], dict]]:
    """(native lines, ECS document) per event, deterministic in (seed, org_seed)."""
    d = _siemgen_dir()
    import yaml
    from siemgen.org.generate import generate_org
    from siemgen.sources import SOURCES

    cfg = yaml.safe_load((d / "config" / "classroom.yaml").read_text())
    org = generate_org(cfg, seed=org_seed)
    src = SOURCES[source]()
    src.bind(org)
    rng = random.Random(seed)
    t = datetime(2026, 10, 14, 8, 0, tzinfo=timezone.utc) + timedelta(days=seed % 7)
    out: list[tuple[list[str], dict]] = []
    guard = 0
    while len(out) < n and guard < n * 50:
        guard += 1
        u = rng.choice(org.users)
        h = org.host_for(u)
        if not src.applies_to(u, h):
            continue
        t = t + timedelta(seconds=rng.randint(3, 90))
        made = src.make_event(u, h, t, org, rng)
        for ev in (made if isinstance(made, list) else [made]):
            if ev is not None:
                out.append((src.render_native(ev).split("\n"), src.render_ecs(ev)))
    return out[:n]


# ------------------------------------------------------------------ truth

def _flatten(doc: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in doc.items():
        if isinstance(v, dict):
            out.update(_flatten(v, f"{prefix}{k}."))
        else:
            out[f"{prefix}{k}"] = v
    return out


def _skipped(name: str) -> bool:
    return any(name == p or (p.endswith(".") and name.startswith(p)) or name.startswith(p + ".")
               for p in _SKIP_PREFIX)


def _count(value: str, line: str) -> int:
    """Whole-value occurrences in a line.

    JSON lines compare value by value (adapter.anchors). Text lines treat a
    value as whole when no word character, dot or hyphen touches it - looser
    than the anchors' rule, which also refuses `/`, `:` and `@` next to a
    value: OpenVPN writes `alice/192.0.2.206:50894`, and under that rule no
    value on its lines was ever whole. A dot or a word character still may not
    touch it, so `10.0.0.1` is never found inside `10.0.0.12`.
    """
    if line.lstrip().startswith("{"):
        return anchors._occurrences(value, line)
    rx = re.compile(r"(?<![\w.-])" + re.escape(value) + r"(?![\w.-])")
    return len(rx.findall(line))


def line_truth(lines: list[str], doc: dict[str, Any], is_ecs) -> list[dict[str, Any]]:
    """The truth of each line of one event. See the module docstring."""
    flat = {k: v for k, v in _flatten(doc).items()
            if not _skipped(k) and is_ecs(k) and not isinstance(v, (list, dict))
            and v is not None and not isinstance(v, bool)}
    per_line: list[dict[str, Any]] = []
    for ln in lines:
        carried = {}
        for name, v in flat.items():
            s = str(v)
            if len(s) < MIN_VALUE_LEN:
                continue
            if _count(s, ln) == 1:
                carried[name] = v
        per_line.append(carried)
    outcome = (doc.get("event") or {}).get("outcome")
    if outcome is not None and per_line:
        primary = max(range(len(lines)), key=lambda i: len(per_line[i]))
        if per_line[primary]:
            per_line[primary]["event.outcome"] = outcome
    return [{"raw": ln, "ecs": t} for ln, t in zip(lines, per_line) if t]


# ---------------------------------------------------------------- samples

_DIGITS = re.compile(r"\d")


def _shapes(lines: list[str]) -> list[str]:
    """A template per line: frequent words kept, everything else masked.

    The sampler's signature keeps every word, so a mail log has as many
    "shapes" as messages. What matters for coverage is the message TYPE, which
    is the words the template repeats; words that recur on at least 5% of the
    lines are the template, the rest are values.
    """
    def toks(ln: str) -> list[str]:
        return ln.split()

    n = max(len(lines), 1)
    freq: Counter[str] = Counter()
    for ln in lines:
        if ln.lstrip().startswith("{"):
            continue
        freq.update(set(toks(ln)))
    floor = max(3, int(0.05 * n))
    out = []
    for ln in lines:
        s = ln.lstrip()
        if s.startswith("{"):
            try:
                obj = json.loads(s)
                out.append("json:" + ",".join(sorted(_flatten(obj))))
                continue
            except ValueError:
                pass
        tpl = [t if freq[t] >= floor and not _DIGITS.search(t) else "*" for t in toks(ln)]
        out.append(" ".join(tpl[:14]))
    return out


def select_samples(events: list[tuple[list[str], dict]], is_ecs,
                   cap: int = MAX_SAMPLES) -> tuple[list[str], list[dict[str, Any]]]:
    """Up to `cap` lines covering as many line shapes as possible, shapes first.

    Returns the lines and the truth rows of exactly those lines, so VT judges a
    parser on the lines it was run over.
    """
    lines, truth_of = [], {}
    for ev_lines, doc in events:
        for row in line_truth(ev_lines, doc, is_ecs):
            truth_of.setdefault(row["raw"], row)
        lines.extend(ev_lines)
    shapes = _shapes(lines)
    by_shape: dict[str, list[str]] = defaultdict(list)
    for ln, sh in zip(lines, shapes):
        if ln not in by_shape[sh]:
            by_shape[sh].append(ln)
    # Lines with more truth first within a shape; shapes by frequency.
    for sh in by_shape:
        by_shape[sh].sort(key=lambda ln: -len((truth_of.get(ln) or {}).get("ecs", {})))
    order = sorted(by_shape, key=lambda sh: -len(by_shape[sh]))
    picked: list[str] = []
    rnd = 0
    while len(picked) < cap and any(len(by_shape[sh]) > rnd for sh in order):
        for sh in order:
            if len(by_shape[sh]) > rnd and len(picked) < cap:
                picked.append(by_shape[sh][rnd])
        rnd += 1
    # What the loader will actually keep, in its order - nothing else gets truth.
    kept = [s.raw for s in deduplicate(picked, per_signature=3, total_cap=cap)]
    rows = [truth_of[ln] for ln in kept if ln in truth_of]
    return kept, rows


# -------------------------------------------------------------- scenarios

def _normalised(raw: str) -> str:
    """tests/test_pools.py's normalisation: lines equal under it are the same line."""
    s = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>", raw)
    s = re.sub(r"\b\d{4}-\d{2}-\d{2}[T ][\d:.+Z-]+", "<ts>", s)
    return re.sub(r"\b\d+\b", "<n>", s)


def build_scenarios(events: list[tuple[list[str], dict]], is_ecs, forbidden: set[str],
                    split: str, n: int = 2) -> list[dict[str, Any]]:
    """Scenarios whose expected count is counted over the truth.

    For a target field and a value it takes, the events are the lines that
    carry that value in that field plus up to six that do not; the rule is a
    term query on the field; expected_hits is the count of the first group. No
    line the model was shown (`forbidden`, normalised) is used.
    """
    rows = [r for ev_lines, doc in events for r in line_truth(ev_lines, doc, is_ecs)
            if _normalised(r["raw"]) not in forbidden]
    by_field: dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        for f, v in r["ecs"].items():
            by_field[f][json.dumps(v)] += 1
    out: list[dict[str, Any]] = []
    used_lines: set[str] = set()
    for field in _TARGETS + tuple(sorted(by_field)):
        if len(out) >= n or field not in by_field:
            continue
        if any(field == o["targets"][0] for o in out):
            continue
        for vjson, cnt in by_field[field].most_common():
            if cnt < 3:
                continue
            v = json.loads(vjson)
            # ONLY A VALUE THE LINE CARRIES. A computed field - `event.outcome`
            # is the case, `success` appears in no line - made a scenario that
            # nothing could pass: on 2026-10-15 the hand-written gold IRs failed
            # it on nginx, mail and dns. VT still checks such a field per line,
            # through the old lines' marker words; V4 tests what a parser reads.
            pos = [r["raw"] for r in rows if r["ecs"].get(field) == v
                   and str(v) in r["raw"] and r["raw"] not in used_lines]
            neg = [r["raw"] for r in rows if field in r["ecs"] and r["ecs"][field] != v
                   and r["raw"] not in used_lines][:6]
            if len(pos) < 3 or len(neg) < 2:
                continue
            pos = pos[:8]
            used_lines.update(pos + neg)
            out.append({
                "targets": [field],
                "value": v,
                "events": pos + neg,
                "expected_hits": len(pos),
                "split": split,
            })
            break
    return out


def _write_scenario(sid: str, i: int, sc: dict[str, Any], commit: str) -> None:
    d = ROOT / "bench" / "scenarios" / f"{sid}__{'repair' if sc['split'] == 'repair' else 'holdout'}_truth_{i:02d}"
    d.mkdir(parents=True, exist_ok=True)
    field, v = sc["targets"][0], sc["value"]
    (d / "events.ndjson").write_text(
        "".join(json.dumps({"raw": e}) + "\n" for e in sc["events"]), encoding="utf-8")
    (d / "query.json").write_text(json.dumps(
        {"bool": {"filter": [{"term": {field: v}}]}}, indent=2) + "\n", encoding="utf-8")
    (d / "expected.json").write_text(json.dumps({
        "description": f"{sc['expected_hits']} events carrying {field}={v!r}, mixed with "
                       f"{len(sc['events']) - sc['expected_hits']} that carry another value.",
        "expected_hits": sc["expected_hits"],
        "origin": f"generated by corpus/siemgen_corpus.py from SIEMgen {commit} - "
                  "expected_hits is counted over the per-line truth",
        "split": sc["split"],
        "targets": [field],
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# ------------------------------------------------------------------ write

def write_source(source: str, seed: int, is_ecs, n_events: int = 400,
                 commit: str | None = None) -> dict[str, Any]:
    commit = commit or siemgen_commit()
    split = SPLIT_TEST_ID if source in TEST_ID else SPLIT_TRAIN
    sid = f"sg_{source}_native"
    d = ROOT / "bench" / "sources" / sid
    if d.exists():
        shutil.rmtree(d)
    for old in (ROOT / "bench" / "scenarios").glob(f"{sid}__*"):
        shutil.rmtree(old)
    d.mkdir(parents=True)

    events = generate_events(source, n_events, seed)
    samples, rows = select_samples(events, is_ecs)
    (d / "samples.ndjson").write_text(
        "".join(json.dumps({"raw": s}) + "\n" for s in samples), encoding="utf-8")
    (d / "line_truth.ndjson").write_text(
        "".join(json.dumps(r, sort_keys=True, default=str) + "\n" for r in rows),
        encoding="utf-8")
    (d / "truth.json").write_text(json.dumps({
        "source_id": sid,
        "split": split,
        "family": f"sg_{source}",
        "origin": f"siemgen {commit} (seed {seed})",
        "category_hint": CATEGORY.get(source),
        "contamination_risk": "low",
        "fields": [],
        "_note": ("Field-level truth is per LINE, in line_truth.ndjson (SIEMgen's "
                  "render_ecs); VT reads it. No source-key truth exists for a native "
                  "format until an IR does."),
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    doc = f"# {sid}\n\n{DOCS.get(source, '')}\n"
    if samples and not samples[0].lstrip().startswith("{"):
        present = sorted({f for r in rows for f in r["ecs"]} & set(CAPTURE_NAMES))
        if present:
            doc += ("\n## Capture names\n\nUse these names for the values the lines carry:\n\n"
                    + "".join(f"- `{CAPTURE_NAMES[f][0]}` - {CAPTURE_NAMES[f][1]}\n"
                              for f in present))
    (d / "documentation.md").write_text(doc, encoding="utf-8")

    hist = defaultdict(Counter)
    for r in rows:
        for f, v in r["ecs"].items():
            hist[f][str(v)] += 1
    kv = anchors.anchor(dict(hist), samples).known_values()
    # A file with no values claims nothing (tests/test_known_values.py); OpenVPN
    # packs every value into compound tokens no anchor can isolate.
    if kv:
      (d / "known_values.json").write_text(json.dumps({
        "note": "NOT ground truth. Values the sample lines carry, taken from SIEMgen's "
                "per-line truth; every line in samples.ndjson is real.",
        "origin": "corpus/siemgen_corpus.py",
        "probe_line": False,
        "source_id": sid,
        "values": kv,
      }, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    sc_split = "holdout" if split == SPLIT_TEST_ID else "repair"
    forbidden = {_normalised(s) for s in samples}
    # A DIFFERENT ORGANISATION for the scenarios. A line is the same line to
    # tests/test_pools.py once numbers and addresses are masked, and OpenVPN's
    # lines differ only in the account: with the same 20 people, every scenario
    # line was a sample line. Other people, other hosts - the same formats.
    scen = build_scenarios(generate_events(source, n_events, seed + 1, org_seed=8), is_ecs,
                           forbidden, sc_split)
    for i, sc in enumerate(scen, 1):
        _write_scenario(sid, i, sc, commit)
    return {"source_id": sid, "split": split, "samples": len(samples),
            "shapes": len(set(_shapes(samples))), "truth_rows": len(rows),
            "truth_fields": len({f for r in rows for f in r["ecs"]}),
            "scenarios": len(scen), "known_values": len(kv)}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="corpus.siemgen_corpus", description=__doc__.splitlines()[0])
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--only", nargs="*")
    p.add_argument("--events", type=int, default=400)
    a = p.parse_args(argv)

    from adapter.wiring import _ecs_index
    ecs = _ecs_index()
    commit = siemgen_commit()
    print(f"SIEMgen {commit}, seed {a.seed}")
    for source in source_names():
        if (a.only and source not in a.only) or source in EXCLUDED:
            continue
        r = write_source(source, a.seed, ecs.exists, a.events, commit)
        print(f"  {r['source_id']:24} {r['split']:8} samples={r['samples']:2} "
              f"shapes={r['shapes']:2} truth_rows={r['truth_rows']:2} "
              f"fields={r['truth_fields']:2} scenarios={r['scenarios']} kv={r['known_values']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

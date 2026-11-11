"""Wrong acceptances: does a parser the system accepted, or would deploy, carry a wrong value?

Written 2026-11-04 (ROUND3_VERSION_DRIFT.md, "Wrong acceptances"). Laptop only, no model, no Logstash.

METHOD
------
Every run's IR and the source's reference IR (`testbed/r3/gold/<source>.ir.json`) are run over the same lines
(the source's samples and its held-out events) by a Python reading of the extraction:

    json            the line parsed as one object; keys addressed as `json_lookup` does
    json + inner    compiler.py A4: a grok over one key's text, its captures beside the JSON keys
    grok            the first pattern (or alternative) that matches, through V2's simulator
    kv              split on the declared separators

and the two ECS documents of each line are compared field by field. This approximates Logstash: no date
parsing and no type conversion (values compared as strings); `@timestamp`, `event.dataset`, `event.module`,
`event.original` and `message` are ignored; `event.kind/category/type` (constants) are compared apart.

Two tiers per run:

    T1 (gold field)   a field the reference parser fills carries a different value on some line
                      (a trailing dot or a difference of case is not counted)
    T2 (over-mapping) a field the reference leaves empty is filled from a key the reference leaves
                      unmapped. Judged by hand per (ecs_field, source_key) in CLEAR below: CLEAR = a
                      wrong meaning or a value ECS forbids; anything else is "debatable".

"What would ship" applies adapter/deploy.py: only fields V4 (or VC) verified reach production, so the IR is
cut to `verified_ecs_fields` before the comparison. VC is not stored in run records, so V4 alone is used, a
lower bound on what ships. A failed run past V1 with at least one verified field deploys partially.

The CLEAR judgements are a DRAFT written with the arm visible; the author reviews them blind. The figure that
needs no judgement is "any T1 or T2".
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any
import json
import re

from adapter.types import grok_patterns, json_lookup
from adapter.ecs_index import EQUIVALENT_TO
from validators.v2_consistency import _grok_to_regex, grok_values

ROOT = Path(__file__).resolve().parents[1]
GOLD = ROOT / "testbed/r3/gold"
SKIP = {"@timestamp", "event.dataset", "event.original", "message", "event.ingested", "event.module"}
CONST = {"event.kind", "event.category", "event.type"}

# (ecs_field, source_key) judged a wrong meaning or a value ECS forbids. DRAFT, see the module docstring.
CLEAR = {
    # r7
    ("process.parent.pid", "key"), ("event.code", "idx"), ("process.parent.working_directory", "message"),
    ("rule.name", "logprefix"), ("host.name", "server_id"), ("process.parent.title", "user_id"),
    ("event.timezone", "uptime"), ("network.bytes", "bytes_in"), ("network.inner.vlan.name", "bytes_in"),
    ("network.protocol", "conn"), ("network.vlan.name", "bytes_out"), ("network.vlan.id", "socket"),
    ("source.domain", "src_location"), ("dns.answers.data", "answer_is_variable"), ("dns.answers.type", "answers"),
    ("dns.header_flags", "maxdepth"), ("event.outcome", "is_spam"), ("network.direction", "dns_req"),
    ("threat.enrichments.indicator.file.size", "symbols"), ("email.attachments.file.name", "mime_rcpts"),
    ("event.reason", "metric"), ("process.parent.name", "worker"), ("destination.bytes", "nentries"),
    ("event.end", "optime"), ("http.request.method", "method"), ("http.version", "version"),
    ("observer.ingress.zone", "slot"), ("process.args_count", "nentries"), ("process.entity_id", "conn_id"),
    ("process.pid", "fd"), ("process.vpid", "fd"), ("tls.version", "tls"), ("client.top_level_domain", "cert"),
    ("process.code_signature.status", "cert"), ("dns.answers.ttl", "messages"), ("dns.id", "serial"),
    ("dns.question.class", "serial"), ("observer.serial_number", "server_id"), ("process.exit_code", "close_code"),
    ("process.thread.id", "session"), ("event.created", "uptime"), ("network.community_id", "conn"),
    ("network.iana_number", "conn"), ("observer.egress.interface.id", "socket"),
    ("observer.ingress.interface.id", "socket"), ("observer.name", "socket"), ("observer.egress.interface.id", "thread"),
    ("observer.name", "thread"), ("process.parent.pid", "thread"), ("process.parent.vpid", "thread"),
    ("destination.user.domain", "backend"), ("destination.user.hash", "auth_method"), ("observer.vendor", "backend"),
    ("destination.bytes", "dns_req"), ("event.provider", "tag"), ("event.risk_score_norm", "required_score"),
    ("log.syslog.procid", "function"), ("network.forwarded_ip", "dns_req"), ("package.size", "size"),
    ("process.parent.command_line", "function"), ("process.parent.name", "module"), ("email.cc.address", "mime_rcpts"),
    ("destination.bytes", "nrcpts"), ("email.cc.address", "nrcpts"), ("email.content_type", "class"),
    ("email.delivery_timestamp", "dsn"), ("email.direction", "class"), ("event.outcome", "stat"),
    ("process.parent.elf.sections.physical_size", "class"), ("process.parent.name", "daemon"),
    ("threat.enrichments.indicator.file.size", "dsn"), ("observer.name", "ssl_location"), ("dns.resolved_ip", "size"),
    ("dns.answers.ttl", "cached"), ("dns.resolved_ip", "cached"), ("event.duration", "uptime"),
    ("observer.type", "auth_method"),
    # r6
    ("destination.port", "body"), ("event.timezone", "time"), ("server.nat.port", "headers"),
    ("destination.top_level_domain", "domain"), ("related.ip", "body"), ("log.syslog.procid", "origin"),
    ("destination.bytes", "nrcpt"), ("email.sender.address", "msgid"), ("email.to.address", "nrcpt"),
    ("process.code_signature.subject_name", "command"), ("process.parent.code_signature.subject_name", "command"),
    ("client.bytes", "rate"), ("event.duration", "rate"), ("event.outcome", "rate"), ("destination.domain", "module"),
    ("process.name", "module"), ("network.community_id", "fd"), ("event.outcome", "headers"),
    ("network.protocol", "headers"), ("process.working_directory", "body"), ("observer.version", "src_line"),
    ("destination.user.email", "nrcpt"), ("email.attachments.file.size", "msgid"), ("email.bcc.address", "nrcpt"),
    ("event.duration", "size"), ("event.outcome", "command"), ("event.risk_score", "nrcpt"), ("related.user", "nrcpt"),
    ("user.name", "user"), ("destination.user.name", "module"), ("destination.user.domain", "vhost"),
    ("event.outcome", "state"), ("process.parent.pid", "conn"), ("user.effective.roles", "banned_until"),
    ("http.request.body.content", "fd"), ("network.iana_number", "fd"), ("observer.name", "fd"),
}


def _norm(v: Any) -> str:
    if isinstance(v, (list, dict)):
        return json.dumps(v, sort_keys=True)
    if isinstance(v, bool):
        return str(v).lower()
    return str(v).strip()


def _compile(patterns: list[str]) -> list[re.Pattern]:
    out = []
    for p in patterns:
        try:
            out.append(re.compile(_grok_to_regex(p)[0]))
        except Exception:  # noqa: BLE001 - a pattern this reading cannot compile reads nothing
            pass
    return out


def reader(ir: dict[str, Any]):
    """(line -> parsed object or None, (object, key) -> value), or (None, None) for an unread kind."""
    ex = ir.get("extraction") or {}
    kind = ex.get("kind")
    if kind == "json":
        inner = ex.get("inner") if isinstance(ex.get("inner"), dict) else None
        irxs = _compile(grok_patterns(inner)) if inner else []

        def rd(line):
            try:
                o = json.loads(line)
            except ValueError:
                return None
            if not isinstance(o, dict):
                return None
            if inner:
                txt = json_lookup(o, inner.get("source", ""))
                if isinstance(txt, str):
                    for r in irxs:
                        m = r.search(txt)
                        if m:
                            return {**o, **grok_values(m)}
            return o
        return rd, json_lookup
    if kind == "grok":
        rxs = _compile(grok_patterns(ex))

        def rd(line):
            for r in rxs:
                m = r.search(line)
                if m:
                    return grok_values(m)
            return None
        return rd, (lambda o, k: o.get(k))
    if kind == "kv":
        fs = ex.get("field_split") or " "
        vs = ex.get("value_split") or "="

        def rd(line):
            out = {}
            for tok in line.split(fs):
                if vs in tok:
                    k, v = tok.split(vs, 1)
                    out[k.strip()] = v.strip().strip('"')
            return out or None
        return rd, (lambda o, k: o.get(k))
    return None, None


def document(ir: dict[str, Any], line: str, rd, get) -> dict[str, str] | None:
    o = rd(line)
    if o is None:
        return None
    d: dict[str, str] = {}
    consumed = set()
    for vm in ir.get("value_maps") or []:
        sk = vm.get("from_source_key")
        if not sk:
            continue
        consumed.add(sk)
        v = get(o, sk)
        if v is None:
            continue
        v = _norm(v)
        if v in (vm.get("map") or {}):
            d[vm["ecs_field"]] = _norm(vm["map"][v])
        elif vm.get("fallback"):
            d[vm["ecs_field"]] = _norm(vm["fallback"])
    for f in ir.get("fields") or []:
        if f["source_key"] in consumed or not f.get("ecs_field"):
            continue
        v = get(o, f["source_key"])
        if v is not None and _norm(v) != "":
            d.setdefault(f["ecs_field"], _norm(v))
    for k, v in (ir.get("constants") or {}).items():
        d.setdefault(k, _norm(v))
    return {k: v for k, v in d.items() if k not in SKIP}


def lines(source_id: str) -> list[str]:
    out = []
    for p in (ROOT / "bench/sources" / source_id / "samples.ndjson", ROOT / "bench/heldout_events" / f"{source_id}.ndjson"):
        if p.exists():
            out += [json.loads(l)["raw"] for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    return out


def _equiv(a: str, b: str) -> bool:
    return b in EQUIVALENT_TO.get(a, frozenset()) or a in EQUIVALENT_TO.get(b, frozenset())


def _trivial(gv: str, cv: str) -> bool:
    return gv.rstrip(".") == cv.rstrip(".") or gv.lower() == cv.lower()


def judge(ir: dict[str, Any], source_id: str) -> dict[str, Any] | None:
    """Tiers of one IR against the source's reference parser, or None without a reference."""
    gp = GOLD / f"{source_id}.ir.json"
    if not gp.exists():
        return None
    gold = json.loads(gp.read_text(encoding="utf-8"))
    grd, gget = reader(gold)
    crd, cget = reader(ir)
    key_of = {f.get("ecs_field"): f.get("source_key") for f in ir.get("fields") or []}
    t1, clear, deb, cat = set(), set(), set(), set()
    agree = total = 0
    gold_fields, bad_gold, missing_gold = set(), set(), set()   # field-level view
    for ln in lines(source_id):
        g = document(gold, ln, grd, gget)
        if g is None:
            continue
        k = (document(ir, ln, crd, cget) if crd else None) or {}
        for f, gv in g.items():
            if f in CONST:
                if f in k and k[f] != gv:
                    cat.add(f)
                continue
            total += 1
            gold_fields.add(f)
            if f in k:
                if k[f] == gv or _trivial(gv, k[f]):
                    agree += 1
                else:
                    t1.add((f, gv, k[f]))
                    bad_gold.add(f)
            elif any(_equiv(f, f2) and k[f2] == gv for f2 in k):
                agree += 1
            else:
                missing_gold.add(f)
        for f, kv in k.items():
            if f in g or f in CONST or any(_equiv(f, f2) for f2 in g):
                continue
            (clear if (f, key_of.get(f)) in CLEAR else deb).add((f, key_of.get(f)))
    verdict = "T1" if t1 else "T2-clear" if clear else "T2-debatable" if deb else "clean"
    right = gold_fields - bad_gold - missing_gold          # gold fields delivered right on every line
    wrong = len(bad_gold) + len(clear)                     # fields that carry a wrong value somewhere
    return {"verdict": verdict, "f_gold": len(gold_fields), "f_right": len(right), "f_wrong": wrong,
            "f_debatable": len(deb), "t1": sorted(t1), "clear": sorted(clear), "debatable": sorted(deb),
            "category_differs": bool(cat), "coverage": agree / total if total else 1.0}


def shipped_ir(rec: dict[str, Any]) -> dict[str, Any] | None:
    """The IR adapter/deploy.py would deploy from this run (V4-verified fields only), or None."""
    ir = rec.get("ir") or {}
    ver = set(rec.get("verified_ecs_fields") or [])
    if not ir or rec.get("rung_reached") in (None, "", "pre", "V1") or not ver:
        return None
    cut = dict(ir)
    cut["fields"] = [f for f in ir.get("fields") or [] if f.get("ecs_field") in ver]
    cut["value_maps"] = [v for v in ir.get("value_maps") or [] if v.get("ecs_field") in ver]
    return cut


def summarise(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts for one cell: the accepted IRs as proposed, and what would ship."""
    acc, ship = Counter(), Counter()
    cov_rep, cat = [], 0
    srcs_any = set()
    srcs = set()
    for r in records:
        if r.get("outcome") == "accepted":
            j = judge(r.get("ir") or {}, r["source_id"])
            if j is not None:
                acc[j["verdict"]] += 1
                srcs.add(r["source_id"])
                cat += j["category_differs"]
                if j["verdict"] != "clean":
                    srcs_any.add(r["source_id"])
        cut = shipped_ir(r)
        kind = "repaired" if r.get("outcome") == "accepted" else "partial"
        if cut is None:
            ship["nothing"] += 1
            continue
        j = judge(cut, r["source_id"])
        if j is None:
            continue
        ship[f"{kind}:{'wrong' if j['verdict'] == 'T1' or j['verdict'] == 'T2-clear' else 'clean'}"] += 1
        if kind == "repaired":
            cov_rep.append(j["coverage"])
    n_acc = sum(acc.values())
    return {"accepted": n_acc, "acc_t1": acc["T1"], "acc_clear": acc["T2-clear"], "acc_debatable": acc["T2-debatable"],
            "acc_clean": acc["clean"], "acc_any": n_acc - acc["clean"], "sources": len(srcs),
            "sources_any": len(srcs_any), "category_differs": cat,
            "ship_nothing": ship["nothing"], "ship_repaired_clean": ship["repaired:clean"],
            "ship_repaired_wrong": ship["repaired:wrong"], "ship_partial_clean": ship["partial:clean"],
            "ship_partial_wrong": ship["partial:wrong"],
            "ship_coverage": sum(cov_rep) / len(cov_rep) if cov_rep else None}

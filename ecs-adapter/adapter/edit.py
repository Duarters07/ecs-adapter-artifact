"""Edit mode (round 4, phase 1.4): a new version of a source is parsed by EDITING the old parser.

WHY THIS EXISTS
---------------
Round 3 asked every arm to write the new version's parser from nothing, and
all three failed on Apache 2.2 -> 2.4 (15 of 15 runs). In 13 of them the cause
was the same: writing a bracketed header the model had never seen. The gold
2.4 parser is the 2.2 one with only its header edited - the three message
bodies are unchanged - and it passes all five 2.4 rules. An organisation
upgrading a source HAS the old parser, so the realistic task is that edit:

    stage 1   sees the new samples, the new documentation, the OLD stage-1
              answer (extraction + roles, rebuilt from the old IR) and the
              sample lines the old parser no longer reads (computed, not
              guessed), and is asked to edit, not to invent;
    stage 2   unchanged;
    carry     a key the new extraction still captures, that the old parser
              mapped and the new IR leaves unmapped, keeps its old mapping -
              the organisation already validated it. Never overrides a mapping
              the model made, never creates a duplicate ECS target.

The old parser lives with the new source: bench/sources/<id>/previous_version.ir.json.
The edit prompt is prompts/edit/s1_interpret_edit.md, outside the prompts/
root on purpose: the apparatus digest hashes prompts/*.md, and changing it
would orphan every existing training record. Its own digest is recorded.

Declared after the round-3 results (2026-10-19); ROUND3_VERSION_DRIFT.md.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
import hashlib
import json
import re

from adapter.architectures import StagedArchitecture
from adapter.types import Source, Usage, grok_patterns

ROOT = Path(__file__).resolve().parents[1]
EDIT_PROMPT = "edit/s1_interpret_edit"
MAX_UNREAD_SHOWN = 6


def edit_prompt_digest() -> str:
    p = ROOT / "prompts" / f"{EDIT_PROMPT}.md"
    return "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()[:16]


def load_previous_ir(source_id: str) -> dict[str, Any] | None:
    from adapter.wiring import bench_root
    p = bench_root() / "sources" / source_id / "previous_version.ir.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else None


def unread_lines(ir: dict[str, Any], lines: list[str]) -> list[str]:
    """The lines the old extraction yields nothing on, read as V2 reads them."""
    from validators.v2_consistency import _grok_to_regex, _keys_in

    e = ir.get("extraction") or {}
    if e.get("kind") == "grok":
        rxs = []
        for p in grok_patterns(e):
            try:
                rxs.append(re.compile(_grok_to_regex(p)[0]))
            except re.error:
                pass
        return [l for l in lines if not any(r.match(l) for r in rxs)]
    return [l for l in lines if not _keys_in(l, e)]


def old_roles(ir: dict[str, Any]) -> dict[str, Any]:
    """The old version's stage-1 answer, rebuilt from its IR exactly as gold roles are."""
    from corpus.siemgen_gold import roles_for

    return roles_for(ir)


def _captured(ir: dict[str, Any]) -> set[str] | None:
    """Keys the new extraction produces, when that is decidable from the IR alone (grok)."""
    from validators.v2_consistency import _grok_to_regex

    e = ir.get("extraction") or {}
    if e.get("kind") != "grok":
        return None
    out: set[str] = set()
    for p in grok_patterns(e):
        try:
            out |= set(_grok_to_regex(p)[1])
        except re.error:
            pass
    return out


def _renamed_key(old_key: str, old: dict[str, Any], new: dict[str, Any], lines: list[str],
                 old_lines: list[str], taken: set[str]) -> str | None:
    """The one new key whose sample values are the old key's values (a renamed key), or None.

    Phase 4e (2026-10-21), r3_firewall_json: the text format's `prefix`, `IN` and host became
    the JSON's `oob.prefix`, `oob.in` and `dvc`. The words did not survive the change; the
    values did - `R3-DROP-SSH`, `eth0`, `fw01` on both sides. A key is taken as renamed only
    when exactly one unclaimed new key shares at least half of the old key's values and the
    old values are not all numbers (ports and counters recur by chance).
    """
    from adapter.normalise import _captured_values

    olds = _captured_values(old, old_lines).get(old_key) or set()
    if not olds or all(v.isdigit() for v in olds):
        return None
    news = _captured_values(new, lines)
    cands = [k for k, vs in news.items()
             if k not in taken and vs and len(olds & vs) >= max(1, len(olds) // 2)]
    return cands[0] if len(cands) == 1 else None


def carry_old_mappings(new: dict[str, Any], old: dict[str, Any], lines: list[str] | None = None,
                       old_lines: list[str] | None = None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Keep the old mapping of a key the new parser still captures and leaves unmapped.

    Phase 4e (2026-10-21): for a json extraction `_captured` is None, and the check "does the
    new version still carry this key" was skipped, so every old key was carried - on
    r3_firewall_json `IN`, `prefix` and `host`, keys the JSON does not have, which left the
    fields empty. With sample lines the check is made for every kind, and under
    ECS_RENAME_BY_VALUE an old key the new version renamed is carried to its new name.
    """
    import os

    captured = _captured(new)
    if captured is None and lines:
        captured = _new_keys(new, lines)
    rename = os.environ.get("ECS_RENAME_BY_VALUE", "") == "1" and lines and old_lines
    mapped_keys = {f["source_key"] for f in new.get("fields") or []}
    mapped_keys |= {v.get("from_source_key") for v in new.get("value_maps") or []}
    targets = {f["ecs_field"] for f in new.get("fields") or []}
    targets |= {v.get("ecs_field") for v in new.get("value_maps") or []}
    out = json.loads(json.dumps(new))
    made: list[dict[str, Any]] = []
    for f in old.get("fields") or []:
        k, ecs_field = f["source_key"], f["ecs_field"]
        if k in mapped_keys or ecs_field in targets:
            continue
        if captured is not None and k not in captured:
            nk = _renamed_key(k, old, new, lines or [], old_lines or [], mapped_keys) if rename else None
            if not nk:
                continue
            f = {**f, "source_key": nk}
            mapped_keys.add(nk)
            k = nk
        out.setdefault("fields", []).append(dict(f))
        out["unresolved"] = [u for u in out.get("unresolved") or [] if u.get("source_key") != k]
        targets.add(ecs_field)
        made.append({"rule": "old_mapping_carried", "source_key": k, "ecs_field": ecs_field,
                     "action": f"{k} -> {ecs_field} kept from the previous version",
                     "reason": "the new extraction still captures it and the new IR left it unmapped"})
    for v in old.get("value_maps") or []:
        k, ecs_field = v.get("from_source_key"), v.get("ecs_field")
        if not k or k in mapped_keys or ecs_field in targets:
            continue
        if captured is not None and k not in captured:
            continue
        out.setdefault("value_maps", []).append(dict(v))
        out["unresolved"] = [u for u in out.get("unresolved") or [] if u.get("source_key") != k]
        targets.add(ecs_field)
        made.append({"rule": "old_mapping_carried", "source_key": k, "ecs_field": ecs_field,
                     "action": f"{k} -> {ecs_field} (value map) kept from the previous version",
                     "reason": "the new extraction still captures it and the new IR left it unmapped"})
    return out, made


# ---------------------------------------------- the old mapping prevails (phase 4b)
#
# Declared 2026-10-20, after phase 4's first rows, outside the pre-registration.
# In edit mode only stage 1 sees the previous parser; stage 2 maps every key again
# from nothing, and carry_old_mappings only fills keys the new IR LEFT unmapped. So
# the C-gold edit of Suricata 7 - whose old parser still fired 6 of 6 rules (T3) -
# remapped alert.signature to rule.id, signature_id to rule.version and dns.rrname
# to url.query, and failed. The previous parser is the one the organisation already
# ran and verified. For a key BOTH versions carry, its old mapping wins; the model's
# mapping is kept only for keys the old parser never had. A new key the model sent
# to an ECS field the old mapping now holds is moved to `unresolved`, not dropped.
def _new_keys(ir: dict[str, Any], lines: list[str]) -> set[str] | None:
    captured = _captured(ir)
    if captured is not None:
        return captured
    if (ir.get("extraction") or {}).get("kind") != "json":
        return None
    keys: set[str] = set()

    def walk(o: Any, pre: str) -> None:
        for k, v in o.items():
            if isinstance(v, dict):
                walk(v, f"{pre}{k}.")
            keys.add(pre + k)
    for l in lines:
        try:
            obj = json.loads(l)
        except ValueError:
            continue
        if isinstance(obj, dict):
            walk(obj, "")
    return keys


def prefer_old_mappings(new: dict[str, Any], old: dict[str, Any],
                        lines: list[str]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """For every key both versions carry, the previous parser's mapping replaces the model's."""
    present = _new_keys(new, lines)
    if present is None:
        return new, []
    out = json.loads(json.dumps(new))
    made: list[dict[str, Any]] = []
    olds = [("fields", f["source_key"], f["ecs_field"], f) for f in old.get("fields") or []]
    olds += [("value_maps", v.get("from_source_key"), v.get("ecs_field"), v) for v in old.get("value_maps") or []]
    for section, k, ecs_field, entry in olds:
        if not k or k not in present:
            continue
        same = [e for e in out.get(section) or []
                if (e.get("source_key") if section == "fields" else e.get("from_source_key")) == k
                and e.get("ecs_field") == ecs_field]
        if same:
            continue
        displaced: list[str] = []
        for sec in ("fields", "value_maps"):
            keep = []
            for e in out.get(sec) or []:
                ek = e.get("source_key") if sec == "fields" else e.get("from_source_key")
                if ek == k or e.get("ecs_field") == ecs_field:
                    if ek != k:
                        displaced.append(ek)
                    continue
                keep.append(e)
            if sec in out:
                out[sec] = keep
        out.setdefault(section, []).append(dict(entry))
        unresolved = [u for u in out.get("unresolved") or [] if u.get("source_key") != k]
        for d in displaced:
            if d and all(u.get("source_key") != d for u in unresolved):
                unresolved.append({"source_key": d, "reason": f"{ecs_field} is held by {k}, as in the previous version"})
        out["unresolved"] = unresolved
        made.append({"rule": "old_mapping_prevails", "source_key": k, "ecs_field": ecs_field,
                     "action": f"{k} -> {ecs_field} restored from the previous version",
                     "reason": "both versions carry the key; the verified old mapping wins"})
    return out, made


def render_edit_prompt(prompts, source: Source, old_ir: dict[str, Any], history: list[str],
                       errors: str = "", previous_roles: str = "") -> str:
    """The stage-1 edit prompt. THE ONLY place it is built - serving and training both call it.

    Round 1's C-gold failed because it was trained on one prompt and served
    another. Phase 2 trains on edit prompts, so the training builder
    (corpus/edit_pairs.py) and the architecture must render byte-identical
    prompts for the same inputs; one function is how that is guaranteed.
    """
    unread = unread_lines(old_ir, [s.raw for s in source.samples])[:MAX_UNREAD_SHOWN]
    changes = "\n\n".join(c for c in (describe_change(history, l) for l in unread[:4]) if c)
    return prompts.render(
        EDIT_PROMPT,
        source_id=source.source_id,
        samples=source.sample_text(),
        documentation=source.documentation,
        previous_version=json.dumps(old_roles(old_ir), indent=2, sort_keys=True),
        unread="\n".join(unread),
        changes=changes,
        errors=errors,
        previous_roles=previous_roles,
    )


class EditStagedArchitecture(StagedArchitecture):
    """Staged B/T/C, stage 1 editing the previous version's answer."""

    def __init__(self, *a, **kw) -> None:
        super().__init__(*a, **kw)
        self.name = f"{self.name}+edit"
        self.last_carried: list[dict[str, Any]] = []

    def subset(self, source: Source) -> list:
        """Retrieval's subset, plus every field the previous version's parser maps (round 10, A5).

        Those fields were verified on this source's previous version, so they
        are the likeliest answers after an upgrade; a budget or a one-word
        category must not be what keeps one of them out of reach. Appended,
        never displacing what retrieval chose, as `previous_fields` already is.
        Off under ECS_PIPELINE=round9.
        """
        from adapter.types import round9_pipeline

        sub = super().subset(source)
        old = load_previous_ir(source.source_id)
        if old and not round9_pipeline() and not getattr(self, "_old_fields_added", {}).get(source.source_id):
            have = {f.name for f in sub}
            for m in old.get("fields") or []:
                n = m.get("ecs_field") if isinstance(m, dict) else None
                if n and n in self.ecs.fields and n not in have:
                    sub.append(self.ecs.fields[n])
                    have.add(n)
            self.__dict__.setdefault("_old_fields_added", {})[source.source_id] = True
        return sub

    def _interpret(self, source: Source, usage: Usage, errors: str = "",
                   previous_roles: str = "") -> dict[str, Any]:
        from adapter.architectures import ROLES_SCHEMA

        old = load_previous_ir(source.source_id)
        if old is None:
            # No predecessor: the plain staged stage 1, so the variant degrades to "staged".
            return super()._interpret(source, usage, errors, previous_roles)
        prompt = render_edit_prompt(self.prompts, source, old, old_lines_for(source.source_id),
                                    errors=errors, previous_roles=previous_roles)
        with self._serving(self.interpret_model):
            return self.client.complete_json(prompt, ROLES_SCHEMA, usage)

    def _map(self, source: Source, roles: dict[str, Any], usage: Usage,
             errors: str = "", previous_ir: str = "") -> dict[str, Any]:
        ir = super()._map(source, roles, usage, errors, previous_ir)
        old = load_previous_ir(source.source_id)
        if old is None:
            return ir
        ir, self.last_carried = carry_old_mappings(ir, old, [s.raw for s in source.samples],
                                                   old_lines_for(source.source_id))
        import os
        if os.environ.get("ECS_OLD_MAPPING_PREVAILS", "") == "1":   # phase 4b; off by default
            ir, made = prefer_old_mappings(ir, old, [s.raw for s in source.samples])
            self.last_carried = self.last_carried + made
        return ir


# ------------------------------------------------------------------ what changed
#
# Phase 1.6. V2's own diagnosis is about the REGEX: on Apache 2.4 it says the
# old `%{LOGLEVEL:level}` "matched only 'auth' - widen it", which points at the
# wrong edit (the level did not change; a module was inserted before it). What
# an editor needs is the STRUCTURAL change between an old line and a new line
# of the same message, which a token diff states directly. The organisation
# has old lines - it is its own history - and in the benchmark they are the old
# version's samples.

def old_lines_for(source_id: str) -> list[str]:
    """Sample lines of the previous version, when its source is on disk."""
    old = load_previous_ir(source_id)
    if not old:
        return []
    from adapter.wiring import bench_root
    p = bench_root() / "sources" / old.get("source_id", "") / "samples.ndjson"
    if not p.is_file():
        return []
    return [json.loads(l)["raw"] for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def _masked_tokens(line: str) -> tuple[list[str], list[str]]:
    from adapter.templates import tokens
    toks = tokens(line)
    # Digits become 9, the punctuation around them stays: `172.21.0.3` and
    # `172.21.0.3:40696` must differ (a port was added), two addresses must not.
    return toks, [re.sub(r"\d+", "9", t) for t in toks]


def describe_change(old_lines: list[str], new_line: str, max_ops: int = 6) -> str:
    """The structural difference between `new_line` and the most similar old line, in words."""
    import difflib

    if not old_lines:
        return ""
    new_toks, new_mask = _masked_tokens(new_line)
    best, best_ratio = None, -1.0
    for ol in old_lines:
        _, om = _masked_tokens(ol)
        ratio = difflib.SequenceMatcher(a=om, b=new_mask, autojunk=False).ratio()
        if ratio > best_ratio:
            best, best_ratio = ol, ratio
    old_toks, old_mask = _masked_tokens(best)
    sm = difflib.SequenceMatcher(a=old_mask, b=new_mask, autojunk=False)
    ops = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        before = " ".join(old_toks[max(0, i1 - 2):i1]) or "(start of line)"
        if tag == "insert":
            ops.append(f"inserted `{' '.join(new_toks[j1:j2])}` after `{before}`")
        elif tag == "delete":
            ops.append(f"removed `{' '.join(old_toks[i1:i2])}` after `{before}`")
        else:
            ops.append(f"`{' '.join(old_toks[i1:i2])}` became `{' '.join(new_toks[j1:j2])}` (after `{before}`)")
        if len(ops) >= max_ops:
            break
    if not ops:
        return ""
    return (f"closest old line: {best}\n  new line:         {new_line}\n  changes (digit values ignored): "
            + "; ".join(ops))

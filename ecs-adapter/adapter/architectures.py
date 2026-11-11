"""The arms.

Four arms exist, and they are **research comparisons, not deployment options**.
Exactly one configuration is ever deployed: the two staged specialists with
escalation, which is arm C once its adapters exist and arm B before that.

    A   7B,  combined, one call,   untrained   is decomposition needed at all?
    B   7B,  staged,   two calls,  untrained   decomposition without training
    T   32B, staged,   two calls,  untrained   THE TEACHER. The ceiling to beat
    C   7B,  staged,   two calls,  TRAINED     the proposal

B, T and C run **identical code**. They differ only in which model name and
which adapters the client was configured with. That is deliberate: if the arms
differed in code, a difference in results could not be attributed to the
variable under study.

All arms share ``_Base.subset()``, which guarantees every arm is offered exactly
the same ECS fields. If that differed between arms, the experiment would be
measuring the retrieval rather than the architecture.
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any
import json
import re

from adapter import diagnose
from adapter.ecs_index import DEFAULT_MAX_FIELDS, EcsIndex, render_fields
from adapter.prompts import Prompts
from adapter.types import STAGE_MAP, Source, Usage, ValidationReport, round9_pipeline

if TYPE_CHECKING:  # ModelClient is only an annotation here, and it pulls in httpx.
    from adapter.model_client import ModelClient

_SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schema"

IR_SCHEMA: dict[str, Any] = json.loads(
    (_SCHEMA_DIR / "ir.schema.json").read_text(encoding="utf-8")
)
ROLES_SCHEMA: dict[str, Any] = json.loads(
    (_SCHEMA_DIR / "roles.schema.json").read_text(encoding="utf-8")
)
# Round 10 (A4) added `extraction.inner`. The schemas are a grammar the server
# enforces, so round 9 is reproduced only if the grammar is round 9's too.
if round9_pipeline():
    for _s in (IR_SCHEMA, ROLES_SCHEMA):
        _s["properties"]["extraction"]["properties"].pop("inner", None)

STAGED_ARMS = ("B", "T", "C")
# How an arm reaches its answer. Orthogonal to the arm; see build().
VARIANTS = ("staged", "staged-split", "staged-edit")


def schema_digest() -> str:
    """The output contract, hashed. Recorded beside the prompt digest.

    `prompt_digest` identifies what the model was ASKED. It says nothing about
    what it was ALLOWED to answer, and the schemas are sent to the server as
    structured output, so they constrain generation as firmly as the prompt
    does - a required field, an enum, a conditional requirement.

    Without this, restricting `ecs_field` to the offered subset changed what the
    teacher could produce while leaving every proposal's provenance byte for
    byte identical to the previous corpus. Two runs that are not comparable
    would have looked comparable, which is the failure this field exists to
    prevent.

    The per-source enum is deliberately NOT part of it: that varies by source
    and would make the digest meaningless as an identifier of the apparatus.
    What is hashed is the contract as it is written down.
    """
    from adapter.types import digest

    blob = "".join(
        sorted(
            p.read_text(encoding="utf-8")
            for p in _SCHEMA_DIR.glob("*.json")
        )
    )
    return digest(blob)


def ir_schema_for(subset: list) -> dict[str, Any]:
    """IR_SCHEMA with `ecs_field` restricted to the fields this source was shown.

    THE PROMPT ALREADY SAYS THIS; THE SCHEMA IS WHERE IT BECOMES TRUE.

    Rule 2 of the map prompt reads "Use ONLY fields from the list above. A field
    that is not listed does not exist for this task". The schema accepted any
    dotted identifier, so `destination.host.name` - which exists in no version
    of ECS - passed structure validation and died at V1 as an unknown field.
    Twelve of thirteen windows-security failures were that one invention, with
    `host.name` sitting in the candidate list the model had just been given.

    The schema is sent to the server as a structured-output schema, so `enum` is
    a grammar constraint rather than a request: the model becomes unable to emit
    a field it was not offered. This is the same lever that fixed
    `format_summary`, and it is the same kind of move - a rule stated in prose
    becoming a rule the machine enforces.

    It does not help the model CHOOSE. Picking `client.ip` where the flow says
    `source.ip` is still available to it, and that is the error the ladder exists
    to filter and the thesis exists to measure.
    """
    import copy

    names = sorted({f.name for f in subset})
    schema = copy.deepcopy(IR_SCHEMA)
    field_props = schema["properties"]["fields"]["items"]["properties"]
    field_props["ecs_field"] = {"type": "string", "enum": names}
    # value_maps names a field too, and an invented one there fails just as hard.
    vm = schema["properties"].get("value_maps", {}).get("items", {}).get("properties")
    if vm and "ecs_field" in vm:
        vm["ecs_field"] = {"type": "string", "enum": names}
    return schema




# ---------------------------------------------------------------- phase 4d: no key is discarded
#
# Phase 4d (2026-10-21), r3_nginx_json: stage 1 declared `forwarded_for` and `request_id`
# unresolved - "carries nothing a field here needs" - so stage 2, which never sees a line,
# never saw them either, and could not map them however much it knew. The phrase is the
# generator gold's own: there, a key outside the 73 fields it uses is marked so, and stage 1
# learned to discard what it does not recognise. Deciding whether a key has an ECS home is
# stage 2's job, so under ECS_ROLES_FOR_ALL a key stage 1 discarded reaches stage 2 as a role
# described by its own name. A key stage 1 found genuinely ambiguous stays unresolved.
_KEEP_UNRESOLVED = ("more than one", "ambiguous")


def _words(key: str) -> str:
    k = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key)
    return re.sub(r"[_.\-]+", " ", k).strip().lower()


def promote_discarded_keys(roles: dict[str, Any]) -> dict[str, Any]:
    import os
    if os.environ.get("ECS_ROLES_FOR_ALL", "") != "1" or not isinstance(roles, dict):
        return roles
    unresolved = roles.get("unresolved") or []
    keep, promoted = [], []
    for u in unresolved:
        reason = (u.get("reason") or "").lower()
        k = u.get("source_key")
        if not k or any(t in reason for t in _KEEP_UNRESOLVED):
            keep.append(u)
            continue
        promoted.append({"source_key": k, "role": f"{_words(k)} (described by the key name only)",
                         "confidence": 0.5, "evidence": "key name"})
    if not promoted:
        return roles
    out = dict(roles)
    out["roles"] = list(roles.get("roles") or []) + promoted
    out["unresolved"] = keep
    return out

class _Base:
    last_roles: dict[str, Any] | None = None

    def __init__(
        self,
        client: "ModelClient",
        prompts: Prompts,
        ecs: EcsIndex,
        max_fields: int = DEFAULT_MAX_FIELDS,
    ) -> None:
        self.client = client
        self.prompts = prompts
        self.ecs = ecs
        self.max_fields = max_fields
        self._subset_cache: dict[str, list] = {}
        self._source: Source | None = None

    def subset(self, source: Source) -> list:
        """Identical for every arm - the ECS budget must not differ."""
        if source.source_id not in self._subset_cache:
            self._subset_cache[source.source_id] = self.ecs.relevant_subset(
                source.observed_keys(),
                source.documentation,
                source.category_hint,
                self.max_fields,
                doc_hints=source.documentation_hints(),
            )
            # A drift's previous fields must be OFFERABLE, or the prompt names
            # fields the output schema then forbids. Appended, never displacing
            # what retrieval chose, and absent for every benchmark source.
            have = {f.name for f in self._subset_cache[source.source_id]}
            self._subset_cache[source.source_id] += [
                self.ecs.fields[n] for n in source.previous_fields
                if n in self.ecs.fields and n not in have
            ]
        return self._subset_cache[source.source_id]


class CombinedArchitecture(_Base):
    """A - one model, one call.

    Simplest and cheapest. Its weakness is diagnostic: when validation fails
    there is no way to tell whether the model misread the source or understood
    it correctly and picked the wrong ECS field. Both look identical in the
    output, so repair can only hand back the whole IR and the error list.

    A exists to answer one question: is decomposition worth its second call?
    """

    name = "A"

    def propose(self, source: Source, usage: Usage) -> dict[str, Any]:
        self._source = source
        prompt = self.prompts.render(
            "a_combined",
            ecs_version=self.ecs.version,
            samples=source.sample_text(),
            documentation=source.documentation,
            ecs_fields=render_fields(self.subset(source)),
            previous_fields=list(source.previous_fields),
        )
        return self.client.complete_json(prompt, ir_schema_for(self.subset(source)), usage)

    def repair(
        self, ir: dict[str, Any], report: ValidationReport, usage: Usage
    ) -> dict[str, Any]:
        assert self._source is not None, "repair() called before propose()"
        prompt = self.prompts.render(
            "repair",
            ecs_version=self.ecs.version,
            previous_ir=json.dumps(ir, indent=2),
            errors=diagnose.render(report, ir, self._source),
            ecs_fields=render_fields(self.subset(self._source)),
        )
        return self.client.complete_json(
            prompt, ir_schema_for(self.subset(self._source)), usage
        )


def _carry_extraction(roles: dict[str, Any], ir: dict[str, Any]) -> dict[str, Any]:
    """Stage 1 decided how to split the line. Make that survive the handoff.

    The prompt asks Stage 2 to copy the block unchanged, and a prompt is a
    request. This makes it true. The failure it prevents was measured: Stage 1
    handed over a complete 26-name column list for postgres_csv and Stage 2
    emitted `{"kind": "csv"}`, dropping it. A csv with no columns yields no
    keys at all, so the run died at V1 four times - the original and three
    repairs - against an error that named a property and not a fix.

    Stage 2 has no evidence that could justify disagreeing: it has never seen a
    line. So where the two differ, Stage 1 wins on everything mechanical, and
    the only thing Stage 2 contributes here is nothing.

    A missing or impossible Stage 1 extraction is left alone rather than
    patched. Inventing one here would hide a Stage 1 failure inside Stage 2's
    output and make the attribution in R7 a fiction.
    """
    s1 = (roles or {}).get("extraction") or {}
    if not s1.get("kind"):
        return ir
    merged = dict(s1)
    # Keep anything Stage 2 added that Stage 1 did not speak to, but never let
    # it overwrite a key Stage 1 set. Round 10 (A1): only when the two agree on
    # the kind. A grok pattern carried into a json extraction made the
    # incoherent `{"kind": "json", "pattern": ...}`.
    s2 = ir.get("extraction") or {}
    if round9_pipeline() or s2.get("kind") in (None, s1.get("kind")):
        for k, v in s2.items():
            merged.setdefault(k, v)
    # column_order is the human-readable twin of columns; prefer the explicit one.
    if merged.get("kind") == "csv" and not merged.get("columns"):
        if cols := (roles or {}).get("column_order"):
            merged["columns"] = list(cols)
    ir["extraction"] = merged
    return ir


def _keep_prior_mappings(prior: dict[str, Any], new: dict[str, Any],
                         roles: dict[str, Any]) -> dict[str, Any]:
    """`new`, plus each mapping of `prior` whose key stage 1 still names and `new` left unmapped."""
    if not isinstance(prior, dict) or not isinstance(new, dict):
        return new
    named = {r.get("source_key") for r in (roles or {}).get("roles") or [] if isinstance(r, dict)}
    mapped = {f.get("source_key") for f in new.get("fields") or [] if isinstance(f, dict)}
    taken = {f.get("ecs_field") for f in new.get("fields") or [] if isinstance(f, dict)}
    kept = [f for f in prior.get("fields") or []
            if isinstance(f, dict) and f.get("source_key") in named
            and f.get("source_key") not in mapped and f.get("ecs_field") not in taken]
    if not kept:
        return new
    out = dict(new)
    out["fields"] = list(new.get("fields") or []) + kept
    return out


class StagedArchitecture(_Base):
    """B, T and C - two calls, blind to each other.

    Stage 1 sees log samples and documentation and NO ECS vocabulary.
    Stage 2 sees the resulting roles and the candidate ECS fields and NOT the
    raw lines.

    The blindness is load-bearing rather than cosmetic. If stage 1 saw ECS names
    it would skip the reasoning and guess a field; if stage 2 saw raw lines it
    would re-interpret from scratch. Either way the decomposition would be
    decorative, and - the part that matters for this thesis - the two stages
    could not be trained separately, because neither would have a clean input
    distribution.

    It is enforced by what the templates are GIVEN, not by instruction. See
    tests/test_blindness.py, which asserts the Stage 1 template never references
    an ECS field list and that no ECS field name survives into its rendering.
    """

    def __init__(
        self,
        *args,
        name: str = "B",
        interpret_model: str | None = None,
        map_model: str | None = None,
        **kw,
    ) -> None:
        """``interpret_model`` / ``map_model`` name a model per stage.

        Both default to None, which means "use whatever the client was built
        with" - the behaviour every arm had before adapters existed, and the
        behaviour B and T still have. Arm C sets them, because training produces
        TWO adapters, one per stage, and a single Ollama model cannot carry both.

        This does not weaken the invariant that B, T and C run identical code.
        The code path is the same; only the configuration differs, which is what
        the module docstring already claims: the arms "differ only in which model
        name and which adapters the client was configured with".
        """
        super().__init__(*args, **kw)
        self.name = name
        self.interpret_model = interpret_model
        self.map_model = map_model

    @contextmanager
    def _serving(self, model: str | None):
        """Temporarily point the client at ``model``. A no-op when it is None."""
        if not model or model == self.client.cfg.model:
            yield
            return
        previous = self.client.cfg.model
        self.client.cfg.model = model
        try:
            yield
        finally:
            self.client.cfg.model = previous

    # ------------------------------------------------------------------ stages
    def _interpret(
        self,
        source: Source,
        usage: Usage,
        errors: str = "",
        previous_roles: str = "",
    ) -> dict[str, Any]:
        prompt = self.prompts.render(
            "s1_interpret",
            source_id=source.source_id,
            samples=source.sample_text(),
            documentation=source.documentation,
            errors=errors,
            previous_roles=previous_roles,
        )
        with self._serving(self.interpret_model):
            return self.client.complete_json(prompt, ROLES_SCHEMA, usage)

    def _map(
        self,
        source: Source,
        roles: dict[str, Any],
        usage: Usage,
        errors: str = "",
        previous_ir: str = "",
    ) -> dict[str, Any]:
        roles = promote_discarded_keys(roles)
        prompt = self.prompts.render(
            "s2_map",
            source_id=source.source_id,
            ecs_version=self.ecs.version,
            roles=json.dumps(roles, indent=2, sort_keys=True),
            ecs_fields=render_fields(self.subset(source)),
            errors=errors,
            previous_ir=previous_ir,
            previous_fields=list(source.previous_fields),
        )
        with self._serving(self.map_model):
            ir = self.client.complete_json(
                prompt, ir_schema_for(self.subset(source)), usage
            )
        return _carry_extraction(roles, ir)

    # ------------------------------------------------------------------ protocol
    def propose(self, source: Source, usage: Usage) -> dict[str, Any]:
        self._source = source
        self.last_roles = self._interpret(source, usage)
        return self._map(source, self.last_roles, usage)

    def repair(
        self, ir: dict[str, Any], report: ValidationReport, usage: Usage
    ) -> dict[str, Any]:
        """Route the repair to the stage at fault.

        A wrong semantic role is a Stage 1 fault; a correct role mapped to the
        wrong ECS field is a Stage 2 fault. Sending Stage 1's errors to Stage 2
        would ask it to compensate for a wrong premise, which is how a two-stage
        system quietly degrades into a one-stage one.

        Stage 2 always re-runs, because the IR depends on the roles either way.
        """
        assert self._source is not None, "repair() called before propose()"
        feedback = diagnose.render(report, ir, self._source)

        if report.blames_interpretation():
            self.last_roles = self._interpret(
                self._source,
                usage,
                errors=feedback,
                previous_roles=json.dumps(self.last_roles, indent=2, sort_keys=True),
            )
            # The premise changed, so the previous IR is not a useful starting
            # point and is deliberately not shown.
            if round9_pipeline():
                return self._map(self._source, self.last_roles or {}, usage)
            # Round 10 (A1): stage 2 still hears its own findings, and a
            # mapping it already had for a key stage 1 still names is kept
            # when the new answer leaves that key unmapped (P9: a repair of
            # the extraction must not cost the fields that were right).
            map_errors = diagnose.render(report, ir, self._source, stage=STAGE_MAP)
            new = self._map(self._source, self.last_roles or {}, usage, errors=map_errors,
                            previous_ir=json.dumps(ir, indent=2, sort_keys=True) if map_errors else "")
            return _keep_prior_mappings(ir, new, self.last_roles or {})

        return self._map(
            self._source,
            self.last_roles or {},
            usage,
            errors=feedback,
            previous_ir=json.dumps(ir, indent=2, sort_keys=True),
        )


def build(
    name: str,
    client: "ModelClient",
    prompts: Prompts,
    ecs: EcsIndex,
    max_fields: int = DEFAULT_MAX_FIELDS,
    interpret_model: str | None = None,
    map_model: str | None = None,
    variant: str = "staged",
):
    """Factory. The arm is a run-time choice, never a branch.

    T and C cost nothing to add here precisely because they are B with a
    different client: T points at the 32B, C points at the 7B carrying the two
    trained adapters. Neither needs a line of new logic.

    ``variant`` is orthogonal to the arm. "staged" is every arm as it always
    was. "staged-split" groups the samples by message shape and runs stage 1
    once per group (adapter/decompose.py); the arm records as "<arm>+split".
    """
    if variant not in VARIANTS:
        raise ValueError(f"unknown variant {variant!r}. Expected one of: {', '.join(VARIANTS)}")
    arm = name.upper()
    if variant == "staged-split":
        from adapter.decompose import SplitCombinedArchitecture, SplitStagedArchitecture

        if arm == "A":
            return SplitCombinedArchitecture(client, prompts, ecs, max_fields)
        if arm in STAGED_ARMS:
            return SplitStagedArchitecture(
                client, prompts, ecs, max_fields, name=arm,
                interpret_model=interpret_model, map_model=map_model,
            )
    elif variant == "staged-edit":
        # Round 4 (adapter/edit.py): stage 1 edits the previous version's parser.
        from adapter.edit import EditStagedArchitecture

        if arm in STAGED_ARMS:
            return EditStagedArchitecture(
                client, prompts, ecs, max_fields, name=arm,
                interpret_model=interpret_model, map_model=map_model,
            )
    elif arm == "A":
        return CombinedArchitecture(client, prompts, ecs, max_fields)
    elif arm in STAGED_ARMS:
        return StagedArchitecture(
            client, prompts, ecs, max_fields, name=arm,
            interpret_model=interpret_model, map_model=map_model,
        )
    raise ValueError(
        f"unknown arm {name!r}. Expected one of: A, {', '.join(STAGED_ARMS)}"
    )

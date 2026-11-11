"""The validation ladder: V1 -> V4, stopping at the first failure.

The rung a candidate reaches is a primary result, not a log line. If everything
fails at V1 the model cannot produce valid IR and the later rungs are untested;
if candidates routinely reach V4 and fail there, the interesting result is how
often V4 caught something V1-V3 missed.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from adapter.compiler import compile_ir
from adapter.types import Sample, Source, ValidationReport
from validators import (
    vt_truth,
    v1_schema,
    v2_consistency,
    v3_5_known_values,
    v3_sandbox,
    v4_detection,
)


class Ladder:
    def __init__(
        self,
        ecs_index,
        source: Source,
        es,
        bench_root: Path,
        stack_version: str,
        scenario_split: str = "repair",
        skip_v3: bool = False,
        skip_v4: bool = False,
        known_values: dict[str, Any] | None = None,
    ) -> None:
        self.ecs = ecs_index
        self.source = source
        self.es = es
        self.bench_root = bench_root
        self.stack_version = stack_version
        self.scenario_split = scenario_split
        self.skip_v3 = skip_v3
        self.skip_v4 = skip_v4
        # Values a probe injected into this source. NOT ground truth - see the
        # module docstring of v3_5_known_values for why the ladder may read
        # these and may never read truth.json.
        self.known_values = known_values or {}

    def _line_truth(self) -> list[dict[str, Any]]:
        """Per-line truth for a source generated with it (corpus/siemgen_corpus)."""
        import json

        p = self.bench_root / "sources" / self.source.source_id / "line_truth.ndjson"
        if not p.is_file():
            return []
        return [json.loads(ln) for ln in p.read_text(encoding="utf-8").splitlines()
                if ln.strip()]

    def _with_vt(self, rep: ValidationReport, documents: list[dict[str, Any]]) -> ValidationReport:
        """Attach VT's verdict to a report WITHOUT touching its verdict.

        VT verifies training material against SIEMgen's per-line truth (see
        validators/vt_truth.py). It must not decide `passed`: the arms are
        compared on the ladder alone, and a rung only some sources can run
        would make the comparison depend on which sources happen to have it.
        """
        truth = self._line_truth()
        if truth:
            vt = vt_truth.validate(documents, truth)
            verdict = rep.passed
            rep.metrics["vt"] = {k: v for k, v in vt.metrics.items() if k != "documents"}
            assert rep.passed is verdict, "VT must not change the ladder's verdict"
        return rep

    def run(self, ir: dict[str, Any], candidate_id: str) -> ValidationReport:
        r1 = v1_schema.validate(ir, self.ecs)
        if not r1.passed:
            return r1

        r2 = v2_consistency.validate(ir, self.source)
        if not r2.passed:
            return r2

        if self.skip_v3:
            r2.metrics["skipped"] = "V3 and V4 disabled"
            return r2

        filter_block = compile_ir(ir, self.ecs.all_names())

        # V3 and V4's parsing, in ONE Logstash run (v3_sandbox.validate_many):
        # the samples and each scenario's events go in as separate inputs and
        # come out as separate document sets. Start-up was most of the cost,
        # and it was being paid once per scenario. Nothing about what is judged
        # changes: V3 still sees only the samples, and each scenario only its
        # own events, parsed by the same filter.
        will_replay = not (self.skip_v4 or self.es is None)
        scenarios = v4_detection.load_scenarios(
            self.bench_root, self.source.source_id, self.scenario_split
        ) if will_replay else []
        scen_sources = [
            Source(
                source_id=self.source.source_id,
                samples=tuple(Sample.of(raw, "scenario") for raw in sc["events"]),
                documentation="",
                category_hint=self.source.category_hint,
            )
            for sc in scenarios
        ]
        batch = v3_sandbox.validate_many(
            filter_block, [self.source] + scen_sources, self.stack_version)
        r3 = batch[0]

        # V3: does Logstash actually run this parser over the samples?
        if not r3.passed:
            return r3

        # V3.5: did each value the probe injected land in the field it belongs
        # to? Needs no Elasticsearch and no detection rule, so it runs even when
        # V4 cannot - and it names the offending field instead of reporting a
        # count that came out wrong.
        #
        # ITS FINDINGS ARE CARRIED, NOT FATAL, AND THAT IS THE WHOLE POINT OF IT.
        #
        # This rung exists for attribution - its own docstring says so - and V4
        # is the oracle. Returning here decided the proposal's fate on a
        # placement judgement, without ever asking whether a detection rule
        # cares. That question is the thesis: a mapping is wrong when it breaks
        # detection, not when it differs from an opinion.
        #
        # It was measured. Twenty-eight of thirty nginx proposals assigned the
        # request path to `url.path`, whose ECS description is "Path of the
        # request"; the ground truth, recovered from a hand-written pipeline,
        # says `url.original`. Both are defensible, V3.5 killed all twenty-eight
        # before V4 could rule, and the family yielded 2 of 30 against 18 of 30
        # for a family whose questions are unambiguous.
        #
        # So V3.5 now reports and the ladder continues. If a rule reads the
        # field the probe named, V4 fails the candidate and the V3.5 finding
        # explains why. If no detection depends on it, the candidate is admitted
        # - and operationally that is the correct answer.
        r35 = v3_5_known_values.validate(
            r3.metrics.get("documents", []), self.known_values, ir
        )
        carried = list(r35.findings)

        if self.skip_v4 or self.es is None:
            # Without V4 there is no oracle, so V3.5 is the strongest evidence
            # available and its verdict stands.
            r35.metrics["skipped"] = "V4 disabled or no Elasticsearch available"
            r35.metrics["v3_documents"] = len(r3.metrics.get("documents", []))
            self._with_vt(r35, r3.metrics.get("documents", []))
            return r35

        # V4: parse each scenario's OWN events with the candidate parser, then
        # run that scenario's detection rule over the result. Scenario events are
        # never the samples the model was shown. Parsed above, in the same
        # Logstash run as V3; each scenario is still replayed into its own index.
        parsed: dict[str, list[dict[str, Any]]] = {
            sc["id"]: rr.metrics.get("documents", [])
            for sc, rr in zip(scenarios, batch[1:])
        }

        declared = {f.get("ecs_field") for f in ir.get("fields") or [] if isinstance(f, dict)}
        r4 = v4_detection.validate(
            self.es, f"replay-{candidate_id}", parsed, scenarios, declared
        )
        r4.metrics["v3_documents"] = len(r3.metrics.get("documents", []))

        # V3.5's findings travel with the verdict. A candidate V4 admits while
        # V3.5 objected is worth seeing: it means the probe's value went
        # somewhere else and no rule in this scenario set noticed, which is
        # either a defensible alternative mapping or a gap in the scenarios.
        if carried:
            # `passed` is set explicitly by each rung, never derived from
            # findings, so attaching these does not change V4's verdict. That is
            # deliberate and worth stating: the whole point is that V4 decides.
            verdict = r4.passed
            r4.findings.extend(carried)
            r4.metrics["v3_5_objections"] = len(carried)
            assert r4.passed is verdict, "V3.5 must not be able to overturn V4"
        return self._with_vt(r4, r3.metrics.get("documents", []))

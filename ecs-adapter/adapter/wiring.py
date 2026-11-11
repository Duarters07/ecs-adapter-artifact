"""Assembling the pieces from the environment.

Shared by the CLI (adapter/main.py) and by Phase 1 (teacher/generate.py), so
that a run-time proposal and a training-data proposal are built by identical
code. If they drifted apart, the training distribution would stop matching the
deployment distribution and the distillation claim would quietly lose its
premise.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import os
import sys

ROOT = Path(__file__).resolve().parents[1]


def bench_root() -> Path:
    """Where sources and scenarios live: `bench/`, unless ECS_BENCH_ROOT names another tree.

    Task 3 (TASK3_EXTERNAL.md) is the reason: AIT-LDS is CC BY-NC-SA, so its sources stay in ~/.cache/ecs-r10/task3
    and never enter the repository; bench/task3_bench.py assembles a tree there with the same layout.
    """
    return Path(os.environ.get("ECS_BENCH_ROOT") or ROOT / "bench")


def _ecs_index():
    from adapter.ecs_index import EcsIndex

    version = os.environ.get("ECS_SCHEMA_VERSION", "8.11")
    candidates = sorted(ROOT.joinpath("ecs").glob("ecs_flat_*.yml"))
    if not candidates:
        sys.exit(
            f"No ECS schema found in {ROOT / 'ecs'}.\n"
            "Download it with:  make ecs-download-schema"
        )
    return EcsIndex(candidates[-1], version)


def _load_source(source_id: str):
    from adapter.sampler import deduplicate
    from adapter.types import Source

    d = bench_root() / "sources" / source_id
    if not d.is_dir():
        available = sorted(p.name for p in (bench_root() / "sources").glob("*") if p.is_dir())
        sys.exit(f"Unknown source {source_id!r}. Available: {', '.join(available) or '(none)'}")

    lines = [
        json.loads(line)["raw"]
        for line in (d / "samples.ndjson").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    doc_path = d / "documentation.md"
    truth_path = d / "truth.json"
    truth: dict[str, Any] = (
        json.loads(truth_path.read_text(encoding="utf-8")) if truth_path.is_file() else {}
    )
    # The last line is the probe when this source declares known values. It is
    # held apart: the sandbox must run it, the model must not read it. See the
    # note on Source.probe_lines.
    probe: tuple[str, ...] = ()
    kv_path = d / "known_values.json"
    # A source captured from a drift carries known values harvested from
    # history (adapter/anchors.py), and its last line is a real captured line,
    # not a probe. It says so, and keeps that line in front of the model.
    has_probe = kv_path.is_file() and json.loads(
        kv_path.read_text(encoding="utf-8")).get("probe_line", True)
    if has_probe and lines:
        probe, lines = (lines[-1],), lines[:-1]
    prev_path = d / "previous.json"
    previous = tuple(json.loads(prev_path.read_text(encoding="utf-8")).get("fields", [])) \
        if prev_path.is_file() else ()

    return (
        Source(
            source_id=source_id,
            samples=tuple(deduplicate(lines)),
            probe_lines=probe,
            documentation=doc_path.read_text(encoding="utf-8") if doc_path.is_file() else "",
            category_hint=truth.get("category_hint"),
            previous_fields=previous,
        ),
        truth,
    )


def _load_known_values(source_id: str) -> dict[str, Any]:
    """Values a probe injected into this source, for V3.5.

    Deliberately a separate file from truth.json. truth.json is a human's
    semantic judgement about what a field means, and the ladder must never read
    it. known_values.json records what a probe DID - an observation that needs
    no understanding of the log format. Keeping them apart is what keeps that
    invariant checkable.
    """
    p = bench_root() / "sources" / source_id / "known_values.json"
    if not p.is_file():
        return {}
    return json.loads(p.read_text(encoding="utf-8")).get("values", {})


def _es():
    """An Elasticsearch client, or None - and None is a supported answer.

    The host check comes BEFORE the import on purpose. Without it, every command
    that merely passes an optional ES client into the ladder crashed with
    ModuleNotFoundError on a machine that had no elasticsearch package - which
    is the machine the guide tells you to run Gate 1 on, since Gate 1 is
    supposed to need nothing but the venv.
    """
    host = os.environ.get("ELASTICSEARCH_HOST")
    if not host:
        return None

    try:
        from elasticsearch import Elasticsearch
    except ImportError:
        sys.exit(
            "ELASTICSEARCH_HOST is set but the elasticsearch package is missing.\n"
            "Install the full requirements, or unset the variable to run without "
            "V4 - the ladder will stop at V3 and say so."
        )
    ca = os.environ.get("ELASTICSEARCH_CA")
    return Elasticsearch(
        host,
        basic_auth=(os.environ.get("ELASTIC_USER", "elastic"),
                    os.environ.get("ELASTIC_PASSWORD", "")),
        ca_certs=ca if ca and Path(ca).is_file() else None,
        verify_certs=bool(ca and Path(ca).is_file()),
        request_timeout=30,
    )


def _model_client(seed: int | None = None):
    from adapter.model_client import ModelClient, ModelConfig

    cfg = ModelConfig(
        backend=os.environ.get("ECS_MODEL_BACKEND", "ollama"),
        model=os.environ.get("ECS_MODEL_NAME", ""),
        endpoint=os.environ.get("ECS_MODEL_ENDPOINT", "http://ollama:11434"),
        seed=seed,
    )

    # ECS_MODEL_NUM_CTX is an override, not a required setting. Left empty the
    # declared default applies, and that default is the window the retrieval
    # budget was measured against. A window too small for the prompt is refused
    # by the client rather than truncated, so there is nothing to fail loudly
    # about here - the client already does.
    num_ctx = os.environ.get("ECS_MODEL_NUM_CTX", "").strip()
    if num_ctx:
        cfg.num_ctx = int(num_ctx)

    # Same shape: an override for hardware faster or slower than the design
    # point. On a GPU a call is seconds and this can come down a long way.
    timeout_s = os.environ.get("ECS_MODEL_TIMEOUT_S", "").strip()
    if timeout_s:
        cfg.timeout_s = float(timeout_s)

    # Temperature 0 is the default and it is deterministic: every "seed" of a
    # run at temperature 0 is the same run. That is how the arms of stage F came
    # to report three seeds per cell that were byte-identical - 24 runs that
    # were 8 observations. Sampling several candidates (ECS_SAMPLES > 1) needs a
    # temperature above 0, and the controller refuses the combination otherwise.
    temperature = os.environ.get("ECS_MODEL_TEMPERATURE", "").strip()
    if temperature:
        cfg.temperature = float(temperature)

    return ModelClient(cfg)


def _student_models() -> tuple[str | None, str | None]:
    """The per-stage models for arm C, or (None, None).

    Training produces TWO adapters because the stages are blind to each other and
    therefore separately trainable. Each is registered with Ollama as its own
    model (see training/export_ollama.py), so arm C needs two names, not one.

    ``ECS_STUDENT_MODEL`` is still honoured as a single-name fallback, for a
    deployment that merged both stages into one model. Returning (None, None)
    means "arm C is not configured", which every caller reports rather than
    silently running arm B.
    """
    interpret = os.environ.get("ECS_STUDENT_INTERPRET_MODEL", "").strip()
    mapping = os.environ.get("ECS_STUDENT_MAP_MODEL", "").strip()
    if interpret or mapping:
        return (interpret or None, mapping or None)
    single = os.environ.get("ECS_STUDENT_MODEL", "").strip()
    return (single, single) if single else (None, None)

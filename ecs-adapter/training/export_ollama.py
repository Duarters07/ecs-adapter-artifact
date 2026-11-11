"""Turn a trained LoRA adapter into a model the local server can actually serve.

THE GAP THIS CLOSES
-------------------
``train_lora.py`` writes a PEFT adapter with ``save_pretrained`` - safetensors,
a HuggingFace artefact. Ollama cannot load that. It serves an adapter only when

    1. the adapter is converted to GGUF, and
    2. a Modelfile names a base and points ``ADAPTER`` at that GGUF, and
    3. ``ollama create`` registers the pair under a model name.

None of those three steps existed, so ``make ecs-regression`` and arm C both
resolved a model name that nothing had ever created. This module is those three
steps.

THE BASE MUST BE THE SAME ARTEFACT
----------------------------------
An adapter is a delta against specific weights. Training quantises
``ECS_BASE_MODEL`` (a HuggingFace id) to 4-bit NF4 itself; the served model is
normally a separately quantised Ollama tag. Attaching the first to the second is
not obviously safe, and nothing in the repository checked it.

So the Modelfile's FROM is taken from the adapter's own ``training_record.json``
rather than from ``ECS_MODEL_NAME``, and the mapping from a HuggingFace id to an
Ollama tag is explicit and recorded. ``--base-tag`` overrides it when you know
better; ``--allow-base-mismatch`` is required to proceed when it cannot be
resolved, and the fact is written into the export record so a result can never
silently rest on it.

WHY TWO MODELS AND NOT ONE
--------------------------
Training produces TWO adapters, one per stage, because the stages are blind to
each other and therefore separately trainable - the property the whole
decomposition exists to buy. One Ollama model cannot carry two adapters, so each
stage gets its own registered model, and StagedArchitecture is told which to use
per stage. Merging them would undo the decomposition.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
import argparse
import json
import os
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

# HuggingFace id -> the Ollama tag built from the same weights. Extend as needed;
# an unknown base is an error, not a guess.
# The 7B is served at q8_0 since 2026-10-17. The adapters are trained against
# the bf16 weights; at q4_K_M the base they are attached to differs from that
# more than LoRA corrections are sized for, and arms A and B are served on the
# same q8_0 tag so the comparison stays like for like.
KNOWN_BASES: dict[str, str] = {
    "Qwen/Qwen2.5-Coder-7B-Instruct": "qwen2.5-coder:7b-instruct-q8_0",
    "Qwen/Qwen2.5-Coder-14B-Instruct": "qwen2.5-coder:14b-instruct-q4_K_M",
    "meta-llama/Llama-3.1-8B-Instruct": "llama3.1:8b-instruct-q4_K_M",
    "mistralai/Mistral-7B-Instruct-v0.3": "mistral:7b-instruct-v0.3-q4_K_M",
}

STAGES = ("interpret", "map")


class ExportError(RuntimeError):
    """Raised when an adapter cannot be exported safely. Never caught silently."""


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    print("  $ " + " ".join(cmd))
    return subprocess.run(cmd, check=True, **kw)


def _record(adapter: Path) -> dict[str, Any]:
    p = adapter / "training_record.json"
    if not p.is_file():
        raise ExportError(
            f"{p} is missing.\n"
            "An adapter that cannot say which base produced it must not be exported:\n"
            "attaching it to the wrong weights would fail silently, not loudly."
        )
    return json.loads(p.read_text(encoding="utf-8"))


def resolve_base_tag(hf_base: str, override: str | None, allow_mismatch: bool) -> tuple[str, bool]:
    """Return (ollama_tag, exact) for the base this adapter was trained on."""
    if override:
        return override, False
    if hf_base in KNOWN_BASES:
        return KNOWN_BASES[hf_base], True
    if allow_mismatch:
        fallback = os.environ.get("ECS_MODEL_NAME", "")
        if not fallback:
            raise ExportError("--allow-base-mismatch needs ECS_MODEL_NAME or --base-tag")
        return fallback, False
    raise ExportError(
        f"No known Ollama tag for base {hf_base!r}.\n"
        "An adapter is a delta against specific weights, so guessing the base is\n"
        "how you get a model that loads and quietly produces nonsense.\n\n"
        "Either:\n"
        "  --base-tag <tag>            if you know the tag built from these weights\n"
        "  --allow-base-mismatch       to proceed anyway; recorded in the export record\n"
        "or add the mapping to KNOWN_BASES in training/export_ollama.py."
    )


def find_convert_script(llama_cpp: Path) -> Path:
    """llama.cpp has moved this script more than once."""
    for name in ("convert_lora_to_gguf.py", "convert-lora-to-gguf.py"):
        p = llama_cpp / name
        if p.is_file():
            return p
    raise ExportError(
        f"No LoRA conversion script under {llama_cpp}.\n"
        "Clone llama.cpp and point --llama-cpp at it:\n"
        "  git clone --depth 1 https://github.com/ggerganov/llama.cpp /opt/llama.cpp\n"
        "  pip install -r /opt/llama.cpp/requirements.txt"
    )


def convert_to_gguf(adapter: Path, llama_cpp: Path, out: Path) -> Path:
    script = find_convert_script(llama_cpp)
    out.parent.mkdir(parents=True, exist_ok=True)
    _run([sys.executable, str(script), str(adapter), "--outfile", str(out), "--outtype", "f16"])
    if not out.is_file():
        raise ExportError(f"conversion reported success but {out} does not exist")
    return out


def write_modelfile(path: Path, base_tag: str, gguf: Path, stage: str, rec: dict[str, Any]) -> Path:
    path.write_text(
        f"""# Generated by training/export_ollama.py - do not edit by hand.
# stage        : {stage}
# base (HF)    : {rec.get('base_model', 'unknown')}
# examples     : {rec.get('examples', '?')}
# prompt digest: {rec.get('prompt_digest', 'unknown')}
# ecs version  : {rec.get('ecs_version', 'unknown')}
FROM {base_tag}
ADAPTER {gguf}
PARAMETER temperature 0
""",
        encoding="utf-8",
    )
    return path


def _register(model_name: str, modelfile: Path, gguf: Path, container: str | None) -> None:
    """`ollama create`, wherever the server happens to live.

    THIS PROJECT SERVES OLLAMA IN A CONTAINER, which the first version of this
    module did not handle. `ollama create` reads the Modelfile and the GGUF it
    points at from the FILESYSTEM OF THE MACHINE RUNNING THE CLI, and the
    stack's container mounts only /root/.ollama, so neither file is visible
    from inside it. The host, in turn, has no `ollama` binary, because the
    whole point of the compose file is that it does not need one.

    So the two files are copied in, registered, and removed. The GGUF is a few
    hundred megabytes and lands in the container's own filesystem for the
    duration of one command; /root/.ollama is a volume and keeps the result.
    """
    if container is None:
        if not shutil.which("ollama"):
            raise ExportError(
                "`ollama` is not on PATH and no --container was given.\n"
                "This repository runs the model server in a container, so pass it:\n"
                "  make ecs-export-adapter ... ARGS=\"--container siem-ollama\""
            )
        _run(["ollama", "create", model_name, "-f", str(modelfile)])
        return

    probe = subprocess.run(["docker", "exec", container, "ollama", "--version"],
                           capture_output=True, text=True, check=False)
    if probe.returncode != 0:
        raise ExportError(
            f"`docker exec {container} ollama --version` failed:\n{probe.stderr.strip()}"
        )

    remote_dir = "/root/.ollama/ecs-export"
    remote_gguf = f"{remote_dir}/{gguf.name}"
    remote_mf = f"{remote_dir}/{modelfile.name}"
    # The Modelfile's ADAPTER path has to be the path INSIDE the container.
    inner = modelfile.with_suffix(modelfile.suffix + ".container")
    inner.write_text(modelfile.read_text(encoding="utf-8").replace(str(gguf), remote_gguf),
                     encoding="utf-8")
    try:
        _run(["docker", "exec", container, "mkdir", "-p", remote_dir])
        _run(["docker", "cp", str(gguf), f"{container}:{remote_gguf}"])
        _run(["docker", "cp", str(inner), f"{container}:{remote_mf}"])
        _run(["docker", "exec", container, "ollama", "create", model_name, "-f", remote_mf])
    finally:
        subprocess.run(["docker", "exec", container, "rm", "-rf", remote_dir],
                       capture_output=True, check=False)
        inner.unlink(missing_ok=True)


def export(
    adapter: Path,
    stage: str,
    llama_cpp: Path,
    base_tag_override: str | None,
    allow_mismatch: bool,
    name_override: str | None,
    dry_run: bool,
    container: str | None = None,
) -> dict[str, Any]:
    if stage not in STAGES:
        raise ExportError(f"stage must be one of {STAGES}, not {stage!r}")
    if not adapter.is_dir():
        raise ExportError(f"{adapter} is not a directory")

    rec = _record(adapter)
    hf_base = rec.get("base_model", "")
    base_tag, exact = resolve_base_tag(hf_base, base_tag_override, allow_mismatch)
    model_name = name_override or f"{base_tag.split(':')[0]}:ecs-{stage}"

    print(f"\nadapter      : {adapter}")
    print(f"stage        : {stage}")
    print(f"base (HF)    : {hf_base}")
    print(f"base (Ollama): {base_tag}" + ("" if exact else "   <- NOT a verified match"))
    print(f"model name   : {model_name}")

    gguf = ROOT / "training" / "gguf" / f"{adapter.name}-{stage}.gguf"
    modelfile = ROOT / "training" / "gguf" / f"Modelfile.{stage}"

    if dry_run:
        print("\n--dry-run: nothing was converted or registered.")
    else:
        print("\nconverting adapter to GGUF...")
        convert_to_gguf(adapter, llama_cpp, gguf)
        write_modelfile(modelfile, base_tag, gguf, stage, rec)
        print(f"\nregistering {model_name} with Ollama...")
        _register(model_name, modelfile, gguf, container)

    out = {
        "adapter": str(adapter),
        "stage": stage,
        "base_model_hf": hf_base,
        "base_tag_ollama": base_tag,
        "base_match_verified": exact,
        "model_name": model_name,
        "gguf": str(gguf),
        "modelfile": str(modelfile),
        "dry_run": dry_run,
    }
    if not dry_run:
        (adapter / "export_record.json").write_text(
            json.dumps(out, indent=2, sort_keys=True), encoding="utf-8"
        )
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Convert a trained LoRA adapter and register it with Ollama."
    )
    p.add_argument("--adapter", required=True, help="the directory make ecs-train wrote")
    p.add_argument("--stage", required=True, choices=STAGES)
    p.add_argument("--llama-cpp", default=os.environ.get("LLAMA_CPP_DIR", "/opt/llama.cpp"))
    p.add_argument("--base-tag", default=None, help="Ollama tag built from the SAME weights")
    p.add_argument("--allow-base-mismatch", action="store_true")
    p.add_argument("--name", default=None, help="override the registered model name")
    p.add_argument("--dry-run", action="store_true", help="resolve and print, change nothing")
    p.add_argument("--container", default=os.environ.get("ECS_OLLAMA_CONTAINER"),
                   help="run `ollama create` inside this container instead of on the host")
    a = p.parse_args(argv)

    if not a.dry_run and not a.container and not shutil.which("ollama"):
        print(
            "FAILED: `ollama` is not on PATH.\n"
            "Run this on the host that serves the models, or inside the ollama container:\n"
            "  docker exec -it siem-ollama ollama --version",
            file=sys.stderr,
        )
        return 1

    try:
        out = export(
            Path(a.adapter).resolve(), a.stage, Path(a.llama_cpp),
            a.base_tag, a.allow_base_mismatch, a.name, a.dry_run, a.container,
        )
    except (ExportError, subprocess.CalledProcessError) as exc:
        print(f"\nFAILED: {exc}", file=sys.stderr)
        return 1

    env = "ECS_STUDENT_INTERPRET_MODEL" if out["stage"] == "interpret" else "ECS_STUDENT_MAP_MODEL"
    print("\nDone. Add this to stack/.env:")
    print(f"  {env}={out['model_name']}")
    if not out["base_match_verified"]:
        print(
            "\nWARNING: the base was not a verified match. This is recorded in\n"
            "export_record.json as base_match_verified=false. Any result obtained\n"
            "with this model must state it."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

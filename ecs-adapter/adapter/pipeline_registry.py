"""Turn an accepted candidate into a pipeline Logstash will actually load.

`compile_ir` returns a `filter { }` block and nothing else - no `input`, no
`output`. Copying that into `stack/pipelines/<id>.conf` produces a file Logstash
cannot run, and `stack/pipeline.yaml` does not list it, so Logstash never even
looks. Until this module existed, `make ecs-install` copied the filter, printed
two manual steps and stopped, and every one of those steps was a chance to get
a name wrong in a way that starts cleanly and ingests nothing.

Two jobs, both idempotent:

    wrap()      the generated filter, inside the input and output the
                repository's other pipelines use, with the names derived from
                the source id rather than typed again
    register()  an entry in stack/pipeline.yaml, added once

WHAT THIS DOES NOT DO
---------------------
It does not restart Logstash, it does not disable the pipeline the new one is
meant to replace, and it is not reached until the operator has answered the
prompt in `make ecs-install`. Nothing auto-deploys; this removes the transcription
errors from a step that stays deliberate.

THE NAMES ARE LOAD-BEARING
--------------------------
the stack's Logstash conventions fix them, because three files have to agree:

    topic          logs-<source>-default
    consumer group logstash-<source>-consumer
    pipeline file  stack/pipelines/<source>.conf
    pipeline id    <source>
"""
from __future__ import annotations

from pathlib import Path
import argparse
import os
import re
import sys

REPO = Path(__file__).resolve().parents[2]          # SIEM-in-a-box/
# Overridable because the watcher runs in a container where the repository is
# not at parents[2]: compose mounts the two paths and names them here.
PIPELINES = Path(os.environ.get("ECS_STACK_PIPELINES") or REPO / "stack" / "pipelines")
REGISTRY = Path(os.environ.get("ECS_STACK_REGISTRY") or REPO / "stack" / "pipeline.yaml")

# A source id reaches a filename, a Kafka consumer group and a YAML key, so it
# is constrained rather than escaped.
SOURCE_RE = re.compile(r"\A[a-z][a-z0-9-]{1,63}\Z")


class RegistryError(RuntimeError):
    """The pipeline could not be written or registered in a state that would run."""


def names(source_id: str) -> dict[str, str]:
    if not SOURCE_RE.match(source_id):
        raise RegistryError(
            f"refusing source id {source_id!r}: lower-case letters, digits and "
            "hyphens only. It becomes a filename, a Kafka consumer group and a "
            "YAML key, and a name that is legal in one and not another fails "
            "silently in the third."
        )
    return {
        "topic": f"logs-{source_id}-default",
        "group_id": f"logstash-{source_id}-consumer",
        "index": f"logs-{source_id}-default",
        "conf": f"{source_id}.conf",
        "pipeline_id": source_id,
    }


def wrap(filter_block: str, source_id: str, topic: str | None = None,
         index: str | None = None) -> str:
    """The generated filter, inside a runnable pipeline."""
    n = names(source_id)
    topic = topic or n["topic"]
    index = index or n["index"]

    if "filter {" not in filter_block:
        raise RegistryError(
            "the candidate does not contain a `filter {` block. Only the output "
            "of adapter/compiler.py belongs here."
        )
    if "input {" in filter_block or "output {" in filter_block:
        raise RegistryError(
            "the candidate already carries an input or an output. It was either "
            "wrapped once already, or it is not a compiler artefact."
        )

    return f"""#=========================
#   {source_id}  (generated)
#=========================
#
# The filter block below was produced by the ECS adapter and compiled by
# adapter/compiler.py. The input and output around it were added by
# adapter/pipeline_registry.py, following the stack's Logstash conventions.
#
# Regenerate the filter from the IR; do not hand-edit it here.

input {{
  kafka {{
    bootstrap_servers => "kafka:9092"
    topics            => ["{topic}"]
    group_id          => "{n['group_id']}"
    codec             => json
    auto_offset_reset => "earliest"
    consumer_threads  => 1
  }}
}}

{filter_block.strip()}

output {{
  elasticsearch {{
    hosts    => ["https://es01:9200"]
    index    => "{index}"
    action   => "create"
    user     => "${{ELASTIC_USER}}"
    password => "${{ELASTIC_PASSWORD}}"
    ssl_enabled                 => true
    ssl_certificate_authorities => ["/certs/ca/ca.crt"]
  }}
}}
"""


def is_registered(registry_text: str, source_id: str) -> bool:
    return bool(re.search(rf"^\s*-\s*pipeline\.id:\s*{re.escape(source_id)}\s*$",
                          registry_text, re.M))


def register(source_id: str, registry: Path | None = None) -> bool:
    """Add the entry to pipeline.yaml. Returns False if it was already there."""
    n = names(source_id)
    path = registry or REGISTRY
    if not path.is_file():
        raise RegistryError(f"{path} does not exist")

    text = path.read_text(encoding="utf-8")
    if is_registered(text, source_id):
        return False

    entry = f"""
#
# Generated by the ECS adapter
#
- pipeline.id: {n['pipeline_id']}
  path.config: "/usr/share/logstash/pipeline/{n['conf']}"
  pipeline.workers: 1
  pipeline.batch.size: 50
  pipeline.batch.delay: 50
"""
    path.write_text(text.rstrip("\n") + "\n" + entry, encoding="utf-8")
    return True


_GENERATED_ENTRY = (
    r"\n#\n# Generated by the ECS adapter\n#\n- pipeline\.id: {id}\n"
    r"(?:  [^\n]*\n?)*"
)


def unregister(source_id: str, registry: Path | None = None) -> bool:
    """Remove an entry `register` wrote. Returns False if there was none.

    Only an entry carrying the generated header is removed: a hand-written
    pipeline that happens to share the id is the operator's, and a rollback
    that deleted it would turn one broken source into two.
    """
    names(source_id)
    path = registry or REGISTRY
    text = path.read_text(encoding="utf-8")
    rx = re.compile(_GENERATED_ENTRY.format(id=re.escape(source_id)))
    new, n = rx.subn("\n", text)
    if not n:
        return False
    path.write_text(new.rstrip("\n") + "\n", encoding="utf-8")
    return True


def family_target(family: str, pipelines_dir: Path | None = None) -> dict[str, str] | None:
    """Where the hand-written pipeline for a failure-tag family writes.

    The watcher knows a family only by its tag, `_nginx_grok_failure`. A
    repaired parser must write to the index the detection rules already read,
    so the hand-written pipeline that sets that tag is found and its
    Elasticsearch output read. Returns None when no pipeline sets the tag, or
    when it writes to more than one index - guessing which one the rules read
    would be exactly the wrong-source mistake the watcher refuses to make.
    """
    tag = f"_{family}_grok_failure"
    d = pipelines_dir or PIPELINES
    for conf in sorted(d.glob("*.conf")):
        text = conf.read_text(encoding="utf-8")
        # A generated pipeline names the tag too, in the guard that keeps only
        # this family's failures. Its header says what it is.
        if f'"{tag}"' not in text or "(generated" in text[:300]:
            continue
        indices = sorted(set(re.findall(r'(?<![\w.])index\s*=>\s*"([^"]+)"', text)))
        # linux-auditd writes its own parse errors to a side index; that is not
        # where any rule looks for the events.
        indices = [i for i in indices if "parse-errors" not in i]
        if len(indices) != 1:
            return None
        return {"conf": conf.name, "index": indices[0], "failure_tag": tag}
    return None


def install(source_id: str, candidate: Path, topic: str | None,
            index: str | None) -> int:
    n = names(source_id)
    if not candidate.is_file():
        raise RegistryError(f"{candidate} does not exist")

    target = PIPELINES / n["conf"]
    target.write_text(wrap(candidate.read_text(encoding="utf-8"), source_id, topic, index),
                      encoding="utf-8")
    added = register(source_id)

    print(f"  pipeline   : {target}")
    print(f"  topic      : {topic or n['topic']}")
    print(f"  group_id   : {n['group_id']}")
    print(f"  index      : {index or n['index']}")
    print(f"  registered : {'yes' if added else 'already present'}")
    print()
    print("  The pipeline this one is meant to replace is STILL RUNNING and still")
    print("  consuming its topic. Until you remove or disable it, the same events are")
    print("  parsed twice - once into the old index with a failure tag, once into the")
    print("  new one. Which of the two to retire is a judgement about the data you")
    print("  already hold, so it is left to you.")
    print()
    print("  Then:  make restart SERVICE=logstash")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--source-id", required=True)
    p.add_argument("--candidate", required=True, type=Path,
                   help="the compiled filter block to wrap")
    p.add_argument("--topic", default=None, help="override the derived Kafka topic")
    p.add_argument("--index", default=None, help="override the derived ES index")
    a = p.parse_args(argv)
    try:
        return install(a.source_id, a.candidate, a.topic, a.index)
    except RegistryError as exc:
        print(f"FAILED: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

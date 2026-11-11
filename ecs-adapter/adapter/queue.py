"""Consume unparsed events from the unknown-format queue.

Logstash publishes a COPY of every event its grok patterns could not parse to
``logs-unknown-default``. This module drains that topic, deduplicates by
structural signature, and writes a benchmark source directory the rest of the
pipeline can work with.

`drain` and `write_source` are a batch operation: they read what is on the queue
now and stop. They are called two ways, and the difference is who decides:

    make ecs-capture     a person names the source and runs it
    adapter/watcher.py   a loop that confirms a drift first, then calls the same
                         functions with a source id derived from the failure tag

Neither installs anything. The objection that shaped this module - that a
service silently proposing parsers for whatever appeared on a queue would be
unbounded autonomy - is answered by the watcher's refusals rather than by
refusing to have a watcher: a new shape must be seen repeatedly, over a real
window, within a per-source cap, and the result is parked for a human.
"""
from __future__ import annotations

from pathlib import Path
from dataclasses import dataclass
from typing import Any
import json

from adapter.sampler import deduplicate


@dataclass(frozen=True)
class CapturedEvent:
    """One line off the unknown-format queue, with the tag that sent it there.

    ``drain()`` returns bare strings and throws the rest of the event away. That
    was enough while a human named the source on the command line, and it is not
    enough for anything that has to work out WHICH source drifted on its own:
    the failure tag is the only thing in the event that says so.

    The Logstash route publishes with ``codec => json``, which serialises the
    whole event, so the tags are already on the wire. Nothing upstream changes.
    """

    raw: str
    tags: tuple[str, ...] = ()

    def failure_tag(self) -> str | None:
        """The ``_<source>_grok_failure`` tag, if the event carries one."""
        for t in self.tags:
            if t.startswith("_") and t.endswith("_grok_failure"):
                return t
        return None
from adapter.types import Sample


class QueueError(RuntimeError):
    pass


def _extract_message(payload: dict[str, Any]) -> str | None:
    """Pull the raw log line out of a Logstash event.

    Logstash's json codec preserves the original line in ``message``. Beats
    sometimes nests it under ``log.original`` or ``event.original``.
    """
    for key in ("message", "log_original", "original"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for outer, inner in (("log", "original"), ("event", "original")):
        nested = payload.get(outer)
        if isinstance(nested, dict):
            value = nested.get(inner)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def drain(
    bootstrap_servers: str,
    topic: str,
    max_messages: int = 500,
    timeout_s: float = 15.0,
    group_id: str = "ecs-adapter-capture",
    from_beginning: bool = True,
) -> list[str]:
    """Read up to ``max_messages`` raw log lines, or until ``timeout_s`` of silence.

    Kept returning bare strings because that is what ``cmd_capture`` and
    ``write_source`` consume, and a human naming the source on the command line
    needs nothing more. Use :func:`drain_events` where the tag matters.
    """
    return [e.raw for e in drain_events(
        bootstrap_servers, topic, max_messages, timeout_s, group_id, from_beginning
    )]


def drain_events(
    bootstrap_servers: str,
    topic: str,
    max_messages: int = 500,
    timeout_s: float = 15.0,
    group_id: str = "ecs-adapter-capture",
    from_beginning: bool = True,
) -> list[CapturedEvent]:
    """The same drain, keeping the tag that sent each event to the queue."""
    try:
        from confluent_kafka import Consumer, KafkaError
    except ImportError as exc:  # pragma: no cover - only in the container
        raise QueueError(
            "confluent-kafka is not installed. This command runs inside the "
            "adapter container: use `make ecs-capture`."
        ) from exc

    consumer = Consumer(
        {
            "bootstrap.servers": bootstrap_servers,
            "group.id": group_id,
            "auto.offset.reset": "earliest" if from_beginning else "latest",
            "enable.auto.commit": False,  # re-runnable; capture must not lose data
            "session.timeout.ms": 10000,
        }
    )
    consumer.subscribe([topic])

    events: list[CapturedEvent] = []
    try:
        idle = 0.0
        while len(events) < max_messages and idle < timeout_s:
            msg = consumer.poll(1.0)
            if msg is None:
                idle += 1.0
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    idle += 1.0
                    continue
                raise QueueError(f"kafka error: {msg.error()}")
            idle = 0.0
            try:
                payload = json.loads(msg.value().decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            raw = _extract_message(payload)
            if raw:
                tags = payload.get("tags")
                events.append(CapturedEvent(
                    raw=raw,
                    tags=tuple(t for t in tags if isinstance(t, str))
                    if isinstance(tags, list) else (),
                ))
    finally:
        consumer.close()

    return events


def write_source(
    root: Path,
    source_id: str,
    lines: list[str],
    category_hint: str | None = None,
    per_signature: int = 3,
    total_cap: int = 20,
) -> tuple[Path, list[Sample]]:
    """Write a benchmark source directory from captured lines.

    Never overwrites ``truth.json``: ground truth is reviewed by a human and a
    capture must not silently replace it.
    """
    samples = deduplicate(lines, per_signature=per_signature, total_cap=total_cap)
    if not samples:
        raise QueueError("no usable log lines captured")

    d = root / "bench" / "sources" / source_id
    d.mkdir(parents=True, exist_ok=True)

    (d / "samples.ndjson").write_text(
        "".join(json.dumps({"raw": s.raw}) + "\n" for s in samples), encoding="utf-8"
    )

    doc = d / "documentation.md"
    if not doc.is_file():
        doc.write_text(
            f"# {source_id}\n\n"
            "_No vendor documentation supplied._\n\n"
            "Captured from the unknown-format queue. Paste the vendor's field\n"
            "reference here if one exists: it is the single largest lever on\n"
            "mapping quality, and the `-doc` ablation measures exactly that.\n",
            encoding="utf-8",
        )

    truth = d / "truth.json"
    if not truth.is_file():
        truth.write_text(
            json.dumps(
                {
                    "source_id": source_id,
                    "split": "dev",
                    "category_hint": category_hint,
                    "contamination_risk": "unknown",
                    "_note": (
                        "STUB. Ground truth must be filled in by hand before any "
                        "score from this source is reported. Scoring is skipped "
                        "while 'fields' is empty."
                    ),
                    "fields": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    return d, samples

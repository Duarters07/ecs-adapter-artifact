"""Structural deduplication of unparsed events.

A broken parser produces thousands of near-identical failures. Sending all of
them to a model would be wasteful and pointless: what matters is the distinct
SHAPES of line, not their volume.

Masking rules turn::

    client_ip=192.0.2.10 account=alice result=denied
    client_ip=10.0.0.7   account=bob   result=allowed

into the same signature, so only the first is kept.
"""
from __future__ import annotations

from collections import defaultdict
import hashlib
import re

from adapter.types import Sample

_MASKS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<IP>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b"), "<UUID>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*"), "<TS>"),
    (re.compile(r'"[^"]*"'), "<QUOTED>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<HEX>"),
    (re.compile(r"\b\d+\b"), "<NUM>"),
)


def signature(line: str) -> str:
    masked = line
    for pattern, repl in _MASKS:
        masked = pattern.sub(repl, masked)
    masked = re.sub(r"\s+", " ", masked).strip()
    return hashlib.sha256(masked.encode("utf-8")).hexdigest()[:16]


def deduplicate(lines: list[str], per_signature: int = 3, total_cap: int = 20) -> list[Sample]:
    """Keep up to ``per_signature`` examples of each distinct shape.

    Several examples per shape, not one: variation within a shape is what lets
    the model tell a constant apart from a value.
    """
    buckets: dict[str, list[str]] = defaultdict(list)
    order: list[str] = []
    for line in lines:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        sig = signature(line)
        if sig not in buckets:
            order.append(sig)
        if len(buckets[sig]) < per_signature:
            buckets[sig].append(line)

    out: list[Sample] = []
    for sig in order:
        for raw in buckets[sig]:
            out.append(Sample.of(raw, sig))
            if len(out) >= total_cap:
                return out
    return out

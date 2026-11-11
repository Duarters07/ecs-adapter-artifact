"""The watcher: notice a format drift and propose a parser, without being asked.

WHAT CHANGED, AND WHAT DID NOT
------------------------------
Before this module the loop began with a person: somebody noticed detection had
gone quiet, ran `make ecs-capture`, and named the source. Everything downstream
was automatic. So the claim "the module is activated when a format changes" was
not true of the code - a human was the trigger, and the paper could only say
that the RECURRING work disappeared, not the noticing.

This module removes the noticing. It still does not install anything itself:

    detect drift  ->  propose_fn(...)

and `tests/test_watcher.py` asserts that against the source rather than
trusting the sentence. What `propose_fn` does is the deployment's choice:

    ECS_DEPLOY_MODE=park   propose, validate, WRITE AS PENDING; a person runs
                           ecs-install. The behaviour before 2026-10-14
    ECS_DEPLOY_MODE=auto   `adapter/drift_loop.py`: propose, verify each field
                           against the old parser's history, shadow-deploy what
                           was verified, promote or roll back, and tell the
                           analyst every time

Log content is written by whoever is on the monitored network, so a system
that installed its own parsers in response to it would hand configuration
changes to an attacker - unless what it may install is bounded. The bounds are
`adapter/deploy.py`'s, and they are refusals, not reviews: the model never
writes configuration, only fields an oracle verified ship, a shadow window
precedes production, a failing deployment rolls itself back, and deployments
per source per day are capped on top of this module's own limits.

WHY DRIFT HAS TO BE CONFIRMED BEFORE ACTING
-------------------------------------------
One malformed line is not a format change. It is a truncated write, a probe, a
scanner, or a genuinely corrupt event - and a 7B model is minutes of CPU. Acting
on the first unparsed line would mean anyone able to put one line into a log
could make the SIEM start proposing configuration.

So a structural signature must be seen ``min_occurrences`` times across at least
``min_window_s`` of wall clock before it counts as drift. Both halves matter: the
count alone is satisfied by one burst, and the window alone by one line seen
twice an hour apart.

WHICH SOURCE DRIFTED
--------------------
Nothing asks. The Logstash route publishes with ``codec => json``, so each event
carries the tag that sent it - ``_nginx_grok_failure`` - and the source id is
derived from it. A source whose events carry no recognisable failure tag is
skipped and counted, never guessed: acting on the wrong source would write a
parser for a format nobody is running.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
import json
import re
import time

from adapter.queue import CapturedEvent
from adapter.sampler import signature

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "results" / "watcher_state.json"
PENDING = ROOT / "results" / "pending"

FAILURE_TAG = re.compile(r"\A_(?P<family>[a-z0-9_]+)_grok_failure\Z")


def derive_source_id(tag: str) -> str | None:
    """``_linux_auth_grok_failure`` -> ``linux-auth-adapted``.

    The suffix matters. The new parser is a SECOND pipeline reading the same
    topic, not a replacement for the hand-written one - which is still running
    until an operator retires it - so it cannot take the name that is already
    in `stack/pipeline.yaml`.
    """
    m = FAILURE_TAG.match(tag)
    if not m:
        return None
    family = m.group("family").replace("_", "-").strip("-")
    return f"{family}-adapted" if family else None


@dataclass
class Shape:
    """One structural signature, and what we know about when it appeared."""

    first_seen: float
    last_seen: float
    count: int = 0

    def window_s(self) -> float:
        return self.last_seen - self.first_seen


@dataclass
class Policy:
    """Every bound the watcher operates under. All of them are refusals."""

    min_occurrences: int = 20
    min_window_s: float = 300.0        # 5 minutes of the same new shape
    cooldown_s: float = 3600.0         # per source, after a proposal
    max_proposals_per_source_per_day: int = 4
    poll_interval_s: float = 60.0
    max_messages: int = 500

    def validate(self) -> None:
        if self.min_occurrences < 2:
            raise ValueError(
                "min_occurrences below 2 means a single line triggers a proposal, "
                "which hands the trigger to whoever can write one log line."
            )
        if self.min_window_s <= 0:
            raise ValueError(
                "min_window_s must be positive, or a burst of identical lines in "
                "one second counts as a sustained format change."
            )


@dataclass
class Watcher:
    """Holds the per-source state between polls.

    Every side effect is injected: ``drain_fn`` reads the queue, ``propose_fn``
    runs the pipeline, ``clock`` reads the time. That is what lets the refusals
    be tested without Kafka, without a model and without waiting five minutes.
    """

    policy: Policy = field(default_factory=Policy)
    drain_fn: Callable[[int], list[CapturedEvent]] | None = None
    propose_fn: Callable[[str, list[str], str | None], dict[str, Any]] | None = None
    # Whether a parser the module already deployed reads this line. The
    # hand-written pipeline keeps tagging every line of a drifted source after
    # the repair, so without this the same shape would be proposed again once
    # the cooldown ran out. A line the deployed parser cannot read still counts.
    handled_fn: Callable[[str, str], bool] | None = None
    clock: Callable[[], float] = time.time
    state_path: Path = STATE

    shapes: dict[str, dict[str, Shape]] = field(default_factory=lambda: defaultdict(dict))
    lines: dict[str, dict[str, list[str]]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(list)))
    last_proposal: dict[str, float] = field(default_factory=dict)
    proposals_today: dict[str, int] = field(default_factory=dict)
    skipped_untagged: int = 0
    skipped_handled: int = 0

    # ---------------------------------------------------------------- state
    def observe(self, events: list[CapturedEvent]) -> None:
        """Fold a batch of events into the per-source shape counts."""
        now = self.clock()
        for e in events:
            tag = e.failure_tag()
            source_id = derive_source_id(tag) if tag else None
            if not source_id:
                self.skipped_untagged += 1
                continue
            if self.handled_fn is not None and self.handled_fn(source_id, e.raw):
                self.skipped_handled += 1
                continue
            sig = signature(e.raw)
            shape = self.shapes[source_id].get(sig)
            if shape is None:
                self.shapes[source_id][sig] = Shape(first_seen=now, last_seen=now, count=1)
            else:
                shape.last_seen = now
                shape.count += 1
            kept = self.lines[source_id][sig]
            if len(kept) < 40:            # enough for deduplicate() to sample from
                kept.append(e.raw)

    def confirmed(self, source_id: str) -> list[str]:
        """Signatures for this source that now count as drift, not noise."""
        p = self.policy
        return sorted(
            sig for sig, sh in self.shapes[source_id].items()
            if sh.count >= p.min_occurrences and sh.window_s() >= p.min_window_s
        )

    # --------------------------------------------------------------- limits
    def _day(self) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime(self.clock()))

    def refusal(self, source_id: str) -> str | None:
        """Why this source may not be proposed for right now, or None."""
        now = self.clock()
        last = self.last_proposal.get(source_id)
        if last is not None and now - last < self.policy.cooldown_s:
            return f"cooldown: {int(self.policy.cooldown_s - (now - last))}s remaining"
        key = f"{source_id}:{self._day()}"
        used = self.proposals_today.get(key, 0)
        if used >= self.policy.max_proposals_per_source_per_day:
            return f"daily cap reached ({used}/{self.policy.max_proposals_per_source_per_day})"
        return None

    def _record_proposal(self, source_id: str) -> None:
        self.last_proposal[source_id] = self.clock()
        key = f"{source_id}:{self._day()}"
        self.proposals_today[key] = self.proposals_today.get(key, 0) + 1

    # ----------------------------------------------------------------- tick
    def tick(self) -> list[dict[str, Any]]:
        """One poll. Returns a record per action taken or deliberately not taken."""
        self.policy.validate()
        events = self.drain_fn(self.policy.max_messages) if self.drain_fn else []
        self.observe(events)

        actions: list[dict[str, Any]] = []
        for source_id in sorted(self.shapes):
            sigs = self.confirmed(source_id)
            if not sigs:
                continue
            why = self.refusal(source_id)
            if why:
                actions.append({"source_id": source_id, "action": "refused", "reason": why})
                continue

            raw = [ln for sig in sigs for ln in self.lines[source_id][sig]]
            self._record_proposal(source_id)
            result = self.propose_fn(source_id, raw, None) if self.propose_fn else {}
            actions.append({
                "source_id": source_id,
                "action": "proposed",
                "shapes": len(sigs),
                "lines": len(raw),
                "outcome": result.get("outcome"),
                "rung_reached": result.get("rung_reached"),
                "run_id": result.get("run_id"),
            })
            # Consumed: the shapes that produced this proposal must not produce
            # another one on the next tick.
            for sig in sigs:
                self.shapes[source_id].pop(sig, None)
                self.lines[source_id].pop(sig, None)

        self.save()
        return actions

    # ---------------------------------------------------------------- audit
    def save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps({
            "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.clock())),
            "policy": self.policy.__dict__,
            "skipped_untagged": self.skipped_untagged,
            "skipped_handled": self.skipped_handled,
            "last_proposal": self.last_proposal,
            "proposals_today": self.proposals_today,
            "watching": {
                s: {"shapes": len(v), "confirmed": len(self.confirmed(s))}
                for s, v in sorted(self.shapes.items())
            },
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")

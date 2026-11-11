"""The teacher's second job: escalation.

The teacher appears twice in this design and the two appearances must not be
confused.

    Job 1 - generation   Phase 1, offline, before any student exists. It reads
                         corpora we already hold and produces the training data.
                         See teacher/generate.py.

    Job 2 - escalation   Phase 2, online, when the specialists exhaust their
                         repair budget on a real source. THIS FILE.

Job 2 is the exception, not the rule. Between escalations the machine carries
only the ~6 GB of the two specialists; the teacher costs disk permanently and
RAM only occasionally. That distinction is what makes the "minimal tier" figure
honest, so this module's contract is that the teacher is loaded here and
unloaded before it returns - including when the attempt fails.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from adapter.architectures import StagedArchitecture
from adapter.ecs_index import DEFAULT_MAX_FIELDS, EcsIndex
from adapter.prompts import Prompts
from adapter.types import Source, Usage, ValidationReport

if TYPE_CHECKING:
    from adapter.model_client import ModelClient


class Escalation:
    """A teacher held at arm's length.

    Deliberately not a subclass of the arms: escalation is not an arm. It never
    appears in the experimental comparison, because a run that escalated is
    reported as an escalation, not as a better result for the students.
    """

    def __init__(
        self,
        client: "ModelClient",
        prompts: Prompts,
        ecs: EcsIndex,
        max_fields: int = DEFAULT_MAX_FIELDS,
    ) -> None:
        self.client = client
        # The teacher runs the SAME two-stage structure as the students. That is
        # not a convenience: it is why its output splits cleanly into both
        # training sets in Phase 1, and why an escalated case is admissible as
        # training material afterwards.
        self._arch = StagedArchitecture(client, prompts, ecs, max_fields, name="T")

    @property
    def model(self) -> str:
        return self.client.cfg.model

    def propose(self, source: Source, usage: Usage) -> dict[str, Any]:
        return self._arch.propose(source, usage)

    def repair(
        self, ir: dict[str, Any], report: ValidationReport, usage: Usage
    ) -> dict[str, Any]:
        return self._arch.repair(ir, report, usage)

    @property
    def last_roles(self) -> dict[str, Any] | None:
        return self._arch.last_roles

    def unload(self) -> None:
        """Release the teacher's RAM immediately.

        Called from a finally block. A crashed escalation must not leave 24 GB
        resident on a machine sized for 6.
        """
        self.client.unload()

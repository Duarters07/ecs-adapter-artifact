"""Prompt loading and rendering.

Prompts are experimental apparatus: they live in the repository, are versioned,
and are hashed into every run record so a result can be traced to the exact text
that produced it.
"""
from __future__ import annotations

from pathlib import Path
import functools

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from adapter.types import digest


class Prompts:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.env = Environment(
            loader=FileSystemLoader(str(root)),
            undefined=StrictUndefined,  # a missing variable is a bug, not a blank
            autoescape=False,
        )
        # Round 10 adds text the round-9 prompts did not have (A4). It sits in
        # `{% if round10 %}` blocks, so ECS_PIPELINE=round9 renders round 9's
        # prompts byte for byte.
        from adapter.types import round9_pipeline

        self.env.globals["round10"] = not round9_pipeline()

    def render(self, name: str, **kw) -> str:
        return self.env.get_template(f"{name}.md").render(**kw)

    @functools.cached_property
    def digest(self) -> str:
        """All prompts hashed together - identifies the apparatus in a run record."""
        blob = "".join(sorted(p.read_text(encoding="utf-8") for p in self.root.glob("*.md")))
        return digest(blob)

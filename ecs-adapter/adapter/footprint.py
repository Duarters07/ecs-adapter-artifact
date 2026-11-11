"""What the system actually holds in memory while it runs.

The paper's cost argument is a number: the minimal tier is claimed to serve a
source with roughly six gigabytes resident, and `tab:tiers` says the measured
footprints are reported in the results. Until now `RunRecord` declared
`peak_rss_mb` and `peak_vram_mb` and nothing ever wrote to them, so the claim
was stated and never measured.

WHICH MEMORY IS THE CLAIM ABOUT
-------------------------------
Not this process. The adapter is a thin client: it renders a prompt, posts it
and parses JSON back. The weights live in the model server, in its own
container, and that is what an operator has to buy RAM for. Reporting the
adapter's resident set would be measuring the wrong process and would report
a comfortable number for the wrong reason.

So two things are recorded, and they are not interchangeable:

    process_peak_rss_mb   this process's high-water mark. Small, and the
                          honest answer to "what does the orchestration cost".

    server_resident_mb    what the model server reports holding, split into
                          total and the part in VRAM. THIS is the tier claim.

HIGH-WATER MARK, NOT A SAMPLE
-----------------------------
`ru_maxrss` is the maximum resident set the kernel has seen for this process
since it started, so it is monotonic and is not reset between runs. Across a
batch of runs in one process it reports the peak of the batch, not of the run.
That is the correct quantity for a hardware-sizing claim and the wrong one for
a per-run comparison, so the field name says `peak` and this docstring says
which peak.

The server figure is sampled once, after the model has been called, because
a server that has not loaded anything yet reports nothing and would make the
footprint look like zero.

EVERY FAILURE IS SOFT
---------------------
A cost measurement must never fail a run. No server, wrong backend, timeout,
unexpected payload: all return None, and the record carries None rather than a
zero that would be read as a measurement.
"""
from __future__ import annotations

import resource
import sys
from typing import Any

# Linux reports ru_maxrss in kilobytes, macOS in bytes.
_RSS_DIVISOR = 1024.0 if sys.platform != "darwin" else 1024.0 * 1024.0


def process_peak_rss_mb() -> float:
    """This process's high-water resident set, in MB. Never raises."""
    try:
        return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / _RSS_DIVISOR, 1)
    except Exception:
        return 0.0


def server_resident_mb(endpoint: str | None, timeout: float = 5.0) -> dict[str, Any] | None:
    """What the model server reports holding resident, in MB.

    Returns ``{"total_mb", "vram_mb", "models"}`` or None when the figure
    cannot be obtained. `httpx` is imported inside the function on purpose:
    `adapter/controller.py` must stay importable in an environment with no HTTP
    client, which is how the offline test suite runs.
    """
    if not endpoint:
        return None
    try:
        import httpx
    except ImportError:
        return None

    try:
        # Ollama reports loaded models with their resident and VRAM sizes.
        # Other backends do not offer an equivalent, and return None below.
        r = httpx.get(f"{endpoint.rstrip('/')}/api/ps", timeout=timeout)
        r.raise_for_status()
        models = r.json().get("models") or []
    except Exception:
        return None

    if not models:
        # The server is up and holding nothing. That is a real measurement of
        # zero, and distinct from "could not ask", so it is not None.
        return {"total_mb": 0.0, "vram_mb": 0.0, "models": []}

    def _mb(n: Any) -> float:
        return round(float(n or 0) / (1024.0 * 1024.0), 1)

    return {
        "total_mb": round(sum(_mb(m.get("size")) for m in models), 1),
        "vram_mb": round(sum(_mb(m.get("size_vram")) for m in models), 1),
        "models": [
            {"name": m.get("name") or m.get("model"),
             "size_mb": _mb(m.get("size")),
             "vram_mb": _mb(m.get("size_vram"))}
            for m in models
        ],
    }


def endpoint_of(arch: Any) -> str | None:
    """The model endpoint behind an architecture, if it has one.

    Defensive by design: the controller is exercised with test doubles that
    have no client, and a cost measurement must not be the thing that makes
    them fail.
    """
    return getattr(getattr(getattr(arch, "client", None), "cfg", None), "endpoint", None)

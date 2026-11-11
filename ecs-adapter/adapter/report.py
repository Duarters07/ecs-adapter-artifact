"""What the analyst reads when the module hands a case over.

The report has one job: let a person who did not watch the attempt pick it up
where it stopped, without re-running anything. So it says, in this order, what
broke, what the module tried, how far the attempt got, which fields are already
live and proved, which are missing, and exactly what to do next. It does not
summarise the model's reasoning - the person needs the evidence, not a
narrative about it.

Plain Markdown, because it is read in a mail client, attached to a ticket and
committed next to the candidate, and none of those render anything richer
reliably.
"""
from __future__ import annotations

from typing import Any
import json

MAX_LINES = 6
MAX_FINDINGS = 10


def _lines(block: list[str], limit: int = MAX_LINES) -> str:
    if not block:
        return "_none captured_\n"
    shown = "\n".join(ln[:300] for ln in block[:limit])
    more = f"\n... and {len(block) - limit} more" if len(block) > limit else ""
    return f"```text\n{shown}{more}\n```\n"


def _field_table(ir: dict[str, Any] | None, status: dict[str, str]) -> str:
    rows = []
    for f in (ir or {}).get("fields") or []:
        ecs = f.get("ecs_field") or ""
        rows.append(f"| `{f.get('source_key', '')}` | `{ecs}` | {status.get(ecs, 'untested')} |")
    if not rows:
        return "_The attempt produced no field mapping._\n"
    return ("| source key | ECS field | status |\n|---|---|---|\n"
            + "\n".join(rows) + "\n")


def field_status(decision: dict[str, Any]) -> dict[str, str]:
    st: dict[str, str] = {}
    for f in decision.get("untested", []):
        st[f] = "untested - not deployed"
    for f in decision.get("contradicted", []):
        st[f] = "**contradicts the old parser - not deployed**"
    for f in decision.get("deliver", []):
        st[f] = "verified - deployed"
    return st


def render(case: dict[str, Any]) -> str:
    """The full report, as Markdown. `case` is the loop's record of one drift."""
    rec = case.get("record") or {}
    dec = case.get("decision") or {}
    fam = case.get("family", "?")
    out: list[str] = []

    out.append(f"# Parser repair report - {fam}\n")
    out.append(f"- **Outcome:** {dec.get('kind', 'unknown')}")
    out.append(f"- **Detected:** {case.get('detected_at', '?')}")
    out.append(f"- **Source id:** `{case.get('source_id', '?')}`")
    out.append(f"- **Index:** `{case.get('index', '?')}`")
    out.append(f"- **Run:** `{rec.get('run_id', '-')}` "
               f"(arm {rec.get('architecture', '?')}, model `{rec.get('model', '?')}`)")
    if case.get("deployment"):
        d = case["deployment"]
        out.append(f"- **Deployed:** pipeline `{d.get('pipeline_id')}`, stage "
                   f"{d.get('stage')}, version {d.get('version')}")
    out.append("")

    out.append("## What changed\n")
    out.append("Lines the current parser can no longer read:\n")
    out.append(_lines(case.get("new_lines") or []))
    if case.get("old_lines"):
        out.append("The same source before the change:\n")
        out.append(_lines(case["old_lines"]))

    out.append("## What was tried\n")
    out.append(f"- validation reached **{rec.get('rung_reached', '-')}**, "
               f"outcome `{rec.get('outcome', '-')}`")
    out.append(f"- model calls {((rec.get('usage') or {}).get('calls', '-'))}, "
               f"repair rounds {rec.get('repairs', '-')}, "
               f"candidates sampled {case.get('samples_k', 1)}")
    if rec.get("escalated"):
        out.append(f"- escalated to `{rec.get('escalation_model')}`")
    if dec.get("reasons"):
        out.append("- decision: " + "; ".join(dec["reasons"]))
    out.append("")

    out.append("## Fields\n")
    out.append(_field_table(rec.get("ir"), field_status(dec)))
    if dec.get("missing"):
        out.append("\nFields the old parser produced that are **not** back:\n")
        out.append("".join(f"- `{m}`\n" for m in dec["missing"]))
        out.append("\nDetection rules that read these fields are still blind for "
                   "this source.\n")

    findings = rec.get("findings") or []
    if findings:
        out.append("## Why it stopped\n")
        for f in findings[:MAX_FINDINGS]:
            out.append(f"- **{f.get('rung')}/{f.get('code')}** - {f.get('message')}")
        if len(findings) > MAX_FINDINGS:
            out.append(f"- ... {len(findings) - MAX_FINDINGS} more in the run record")
        out.append("")

    if case.get("shadow"):
        out.append("## Shadow check\n")
        out.append("```json\n" + json.dumps(case["shadow"], indent=2, sort_keys=True)
                   + "\n```\n")

    out.append("## What to do\n")
    kind = dec.get("kind")
    cand = f"candidates/{rec.get('run_id', '<run>')}"
    if kind == "repaired":
        out.append("Nothing. The record is kept for audit.\n")
    else:
        out.append(
            f"1. The proposal is in `{cand}/ir.json` - the mapping above, editable. "
            "Fix or add the missing fields there rather than in the compiled "
            "pipeline, which is regenerated from it.\n"
            f"2. Check it: `make ecs-check-ir IR={cand}/ir.json "
            f"SOURCE={case.get('source_id', '<source>')}`\n"
            f"3. Install it: `make ecs-install CANDIDATE={rec.get('run_id', '<run>')} "
            f"SOURCE={case.get('source_id', '<source>')}`\n"
            "4. The case you resolve becomes a training example for the next "
            "retraining, so the same shape is less likely to need you again.\n")
    return "\n".join(out)


def email_body(kind: str, case: dict[str, Any]) -> str:
    """A short body; the report travels as an attachment."""
    fam = case.get("family", "?")
    dec = case.get("decision") or {}
    if kind == "detected":
        return (
            f"The parser for {fam} stopped recognising its log lines at "
            f"{case.get('detected_at', '?')}.\n\n"
            "Detection rules that depend on this source are blind until it is "
            "repaired. An automatic repair has started; you will receive a second "
            "message with the outcome.\n\nExample of the new lines:\n\n"
            + "\n".join(ln[:300] for ln in (case.get("new_lines") or [])[:3]) + "\n"
        )
    deliver = ", ".join(dec.get("deliver") or []) or "none"
    missing = ", ".join(dec.get("missing") or []) or "none"
    head = {
        "repaired": f"A new parser for {fam} is live. Every field the previous parser "
                    "produced is back and was verified against its history.",
        "partial": f"A new parser for {fam} is live with SOME fields. The fields "
                   "below are still missing and need you.",
        "escalated": f"The automatic repair for {fam} could not produce a parser it "
                     "could verify. Nothing was deployed and detection for this "
                     "source is still down.",
        "rolled_back": f"The automatically deployed parser for {fam} failed its live "
                       "check and was removed.",
    }[kind]
    return (f"{head}\n\nDeployed fields: {deliver}\nMissing fields: {missing}\n\n"
            "The full report is attached.\n")

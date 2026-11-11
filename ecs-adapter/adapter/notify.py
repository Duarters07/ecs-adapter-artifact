"""Telling the analyst, and keeping a record that the analyst was told.

WHY THE ANALYST IS TOLD EVERY TIME, NOT ONLY ON FAILURE
-------------------------------------------------------
The design removes the analyst from the repairs that succeed, not from the
knowledge that they happened. A parser that replaced another without anyone
hearing of it is configuration drift by a different name, and the first person
to discover it would be whoever investigates the incident it hid. So every
outcome is announced:

    detected      a source stopped parsing. Sent at once, before any model
                  runs, because detection is down from this moment
    repaired      a new parser is live and every field the old one produced is
                  back. Nothing to do
    partial       a new parser is live with SOME fields; the rest are listed,
                  with the report, for a person
    escalated     nothing could be verified; detection for this source stays
                  down until a person writes the parser. The report says where
                  the attempt stopped
    rolled_back   a deployed parser failed its live check and was removed

THE OUTBOX IS THE RECORD, SMTP IS THE COURIER
---------------------------------------------
Every message is written to `results/notifications/` as an .eml file BEFORE it
is sent. If the mail server is down, misconfigured or not configured at all,
the message still exists and says so in the delivery log. A notifier that lost
messages when SMTP failed would turn a mail outage into an unannounced
deployment.

Configuration is environment only, and `stack/.env.example` carries the keys
empty. In the testbed the server is Mailpit, which accepts everything and
exposes it over HTTP, so a run can assert on what the analyst received.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from typing import Any, Callable
import json
import os
import re
import smtplib
import time

KINDS = ("detected", "repaired", "partial", "escalated", "rolled_back")

SUBJECT = {
    "detected": "[SIEM] Parser failure detected: {family}",
    "repaired": "[SIEM] Parser repaired automatically: {family}",
    "partial": "[SIEM] Parser partially repaired, action needed: {family}",
    "escalated": "[SIEM] Parser repair FAILED, action needed: {family}",
    "rolled_back": "[SIEM] Automatic parser rolled back, action needed: {family}",
}


@dataclass
class SmtpConfig:
    host: str = ""
    port: int = 25
    user: str = ""
    password: str = ""
    sender: str = ""
    recipients: list[str] = field(default_factory=list)
    starttls: bool = False
    timeout_s: float = 15.0

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "SmtpConfig":
        e = os.environ if env is None else env
        return cls(
            host=e.get("ECS_NOTIFY_SMTP_HOST", "").strip(),
            port=int(e.get("ECS_NOTIFY_SMTP_PORT", "25") or 25),
            user=e.get("ECS_NOTIFY_SMTP_USER", "").strip(),
            password=e.get("ECS_NOTIFY_SMTP_PASSWORD", ""),
            sender=e.get("ECS_NOTIFY_FROM", "").strip() or "siem-ecs-adapter@localhost",
            recipients=[r.strip() for r in re.split(r"[,;\s]+", e.get("ECS_NOTIFY_TO", ""))
                        if r.strip()],
            starttls=e.get("ECS_NOTIFY_SMTP_STARTTLS", "").strip().lower() in ("1", "true", "yes"),
        )

    @property
    def configured(self) -> bool:
        return bool(self.host and self.recipients)


@dataclass
class Notifier:
    outbox: Path
    smtp: SmtpConfig = field(default_factory=SmtpConfig.from_env)
    # Injected so the delivery path can be tested without a mail server.
    send_fn: Callable[[SmtpConfig, EmailMessage], None] | None = None
    clock: Callable[[], float] = time.time

    def notify(
        self,
        kind: str,
        family: str,
        body: str,
        attachments: dict[str, str] | None = None,
        facts: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Write the message to the outbox, then try to deliver it.

        Returns the delivery record that is also appended to the log. Never
        raises on a delivery failure: a deployment decision has already been
        taken and must not be undone by a mail server.
        """
        if kind not in KINDS:
            raise ValueError(f"unknown notification kind {kind!r}; one of {KINDS}")

        msg = EmailMessage()
        msg["Subject"] = SUBJECT[kind].format(family=family)
        msg["From"] = self.smtp.sender
        msg["To"] = ", ".join(self.smtp.recipients) or "undisclosed-recipients:;"
        msg["Date"] = formatdate(self.clock(), localtime=False)
        msg["Message-ID"] = make_msgid(domain="ecs-adapter")
        msg["X-ECS-Adapter-Kind"] = kind
        msg["X-ECS-Adapter-Family"] = family
        msg.set_content(body)
        for name, text in (attachments or {}).items():
            msg.add_attachment(text.encode("utf-8"), maintype="text",
                               subtype="markdown" if name.endswith(".md") else "plain",
                               filename=name)

        self.outbox.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(self.clock()))
        eml = self.outbox / f"{stamp}_{family}_{kind}.eml"
        n = 1
        while eml.exists():
            n += 1
            eml = self.outbox / f"{stamp}_{family}_{kind}_{n}.eml"
        eml.write_bytes(bytes(msg))

        record: dict[str, Any] = {
            "at": stamp, "kind": kind, "family": family, "file": eml.name,
            "subject": msg["Subject"], "recipients": self.smtp.recipients,
            "facts": facts or {},
        }
        if not self.smtp.configured:
            record["delivery"] = "not_configured"
        else:
            try:
                (self.send_fn or _smtp_send)(self.smtp, msg)
                record["delivery"] = "sent"
            except (OSError, smtplib.SMTPException) as exc:
                record["delivery"] = "failed"
                record["error"] = f"{type(exc).__name__}: {exc}"

        with (self.outbox / "delivery.ndjson").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        return record


def _smtp_send(cfg: SmtpConfig, msg: EmailMessage) -> None:
    with smtplib.SMTP(cfg.host, cfg.port, timeout=cfg.timeout_s) as s:
        if cfg.starttls:
            s.starttls()
        if cfg.user:
            s.login(cfg.user, cfg.password)
        s.send_message(msg)

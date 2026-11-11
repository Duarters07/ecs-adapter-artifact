"""r7_rspamd: Rspamd console log (level info), Debian 12 (3.4) -> Debian 13 (3.12.1): the per-message scan result."""
from __future__ import annotations

import re

from testbed.heldout_r2.specs import Spec, _f

_LINE = re.compile(
    r"^(?P<timestamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) #(?P<pid>\d+)\((?P<worker>\w+)\) <(?P<tag>[0-9a-f]+)>; "
    r"(?P<module>\w+); (?P<function>\w+): id: <(?P<message_id>[^>]*)>, ip: (?P<client_ip>[0-9.]+), "
    r"from: <(?P<sender>[^>]*)>, \((?P<metric>\w+): (?P<is_spam>[TF]) \((?P<action>[^)]+)\): "
    r"\[(?P<score>-?[\d.]+)/(?P<required_score>-?[\d.]+)\] \[(?P<symbols>.*)\]\), len: (?P<size>\d+), "
    r"time: (?P<time>[\d.]+)ms, dns req: (?P<dns_req>\d+), digest: <(?P<digest>[0-9a-f]+)>, "
    r"rcpts: <(?P<rcpts>[^>]*)>, mime_rcpts: <(?P<mime_rcpts>[^>]*)>$")


def _extract(line: str) -> dict[str, str]:
    m = _LINE.match(line.strip())
    return {k: v for k, v in m.groupdict().items() if v is not None} if m else {}


def _doc(version: str) -> str:
    return f"""
# Rspamd {version} - log, console, level info

Source: Rspamd documentation, "logging" configuration (vendor documentation), Debian package. Messages are submitted
to the normal worker's /checkv2 endpoint as an MTA would, with the SMTP client address, HELO, sender and recipient in
the request headers. After each scan the task logs one line (rspamd_task_write_log):

    <yyyy-mm-dd hh:mm:ss> #<pid>(<worker>) <<tag>>; <module>; <function>: id: <<message_id>>, ip: <client_ip>,
    from: <<sender>>, (<metric>: <is_spam> (<action>): [<score>/<required_score>] [<symbols>]), len: <size>,
    time: <time>ms, dns req: <dns_req>, digest: <<digest>>, rcpts: <<rcpts>>, mime_rcpts: <<mime_rcpts>>

(one line; wrapped here)

- `client_ip` - the SMTP client that sent the message; `sender` - the envelope sender; `rcpts` - the envelope
  recipients, `mime_rcpts` - the recipients in the message headers
- `action` - what the MTA is told to do: no action, add header, rewrite subject, greylist, soft reject, reject;
  `is_spam` - T or F; `score` / `required_score` - the message's score and the reject threshold
- `symbols` - the rules that matched, each `NAME(score){{options}}`
- `message_id` - the Message-ID header (`undef` when absent); `digest` - a digest of the message
- `size` - bytes; `time` - scan time; `dns_req` - DNS requests made; `pid`, `worker`, `tag`, `module`, `function` -
  the process, worker type, task tag and logging place
"""


_FIELDS = [
    _f("client_ip", "source.ip", "ip", "client_ip", "easy", "client.ip is equivalent."),
    _f("sender", "email.from.address", "keyword", "sender", "medium"),
    _f("rcpts", "email.to.address", "keyword", "recipient", "medium"),
    _f("action", "event.action", "keyword", "verdict_action", "medium"),
    _f("pid", "process.pid", "long", "process_id", "easy"),
    _f("message_id", None, "keyword", "message_id", "hard", "email.message_id is right in kind, but the value is always `undef` in the lab; declining accepted.", abstain=True),
    _f("score", None, "keyword", "spam_score", "hard", "event.risk_score is arguable; declining accepted.", abstain=True),
    _f("required_score", None, "keyword", "threshold", "hard", "No ECS field.", abstain=True),
    _f("is_spam", None, "keyword", "is_spam", "hard", "No ECS field.", abstain=True),
    _f("symbols", None, "keyword", "matched_rules", "hard", "A list with scores; rule.name holds one name. Declining accepted.", abstain=True),
    _f("mime_rcpts", None, "keyword", "header_recipient", "hard", "email.to.address already holds the envelope recipient.", abstain=True),
    _f("digest", None, "keyword", "digest", "hard", "Not a file hash; declining accepted.", abstain=True),
    _f("size", None, "long", "message_size", "hard", "email has no plain size field in ECS 8.11.", abstain=True),
    _f("time", None, "keyword", "scan_ms", "hard", "event.duration is in nanoseconds; declining accepted.", abstain=True),
    _f("dns_req", None, "long", "dns_requests", "hard", "No ECS field.", abstain=True),
    _f("worker", None, "keyword", "worker_type", "hard", "No ECS field.", abstain=True),
    _f("tag", None, "keyword", "task_tag", "hard", "No ECS field.", abstain=True),
    _f("module", None, "keyword", "log_module", "hard", "log.logger is arguable; declining accepted.", abstain=True),
    _f("function", None, "keyword", "log_function", "hard", "log.origin.function is arguable; declining accepted.", abstain=True),
    _f("metric", None, "keyword", "metric", "hard", "No ECS field.", abstain=True),
    _f("timestamp", None, "keyword", "timestamp", "hard", "@timestamp is set at ingest.", abstain=True),
]

OLD = Spec(
    source_id="r7_rspamd_34", family="rspamd",
    software="Rspamd 3.4 (Debian 12)", category="email",
    contamination="high", split="train_r7",
    notes="ROUND 10 (pool r7), OLD VERSION: Rspamd 3.4, console log at info, /checkv2 submissions.",
    documentation=_doc("3.4"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

NEW = Spec(
    source_id="r7_rspamd_3121", family="rspamd",
    software="Rspamd 3.12.1 (Debian 13)", category="email",
    contamination="high", split="test_r7",
    notes="ROUND 10 (pool r7), NEW VERSION of r7_rspamd_34. CONTROL: the task line's layout is unchanged (symbol sets and scores differ).",
    documentation=_doc("3.12.1"), keep=lambda ln: bool(_extract(ln)), extract=_extract, fields=_FIELDS,
)

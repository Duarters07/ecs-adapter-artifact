# Exim 4.96 — main log

Source: Exim Specification, chapter 52 "Log files", sections "Logging message
reception", "Logging deliveries" and "Log line flags",
https://www.exim.org/exim-html-4.96/doc/html/spec_html/ch-log_files.html

Every line starts with a timestamp; lines about one message carry its queue id.

    <timestamp> <msgid> <= <sender> H=<host_name> (<helo>) [<host_ip>] P=<protocol> S=<size>
    <timestamp> <msgid> => <local_part> [(<address>)] <<recipient>> R=<router> T=<transport>
    <timestamp> <msgid> Completed
    <timestamp> H=<host_name> (<helo>) [<host_ip>] F=<<sender>> rejected RCPT <<recipient>>: <reason>

- `timestamp` — `yyyy-mm-dd HH:MM:SS`
- `msgid` — Exim's own id for the message in its queue
- `flag` — `<=` message arrival, `=>` normal delivery, `Completed`, or `rejected RCPT`
- `sender` — the envelope sender address
- `recipient` — the envelope recipient address
- `host_name` — the sending host's name, from reverse DNS
- `helo` — the name the sending host gave in its HELO/EHLO command
- `host_ip` — the sending host's IP address
- `protocol` — the protocol the message was received with: `esmtp`, `smtp`, `local`
- `size` — the message size in bytes
- `local_part` — the local mailbox the message was delivered to
- `router`, `transport` — the Exim router and transport that delivered it
- `reason` — why the recipient was refused

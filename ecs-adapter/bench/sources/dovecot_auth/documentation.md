# Dovecot 2.3 — login and authentication log

Source: Dovecot documentation, "Logging" and the login_log_format settings,
https://doc.dovecot.org/2.3/configuration_manual/logging/ and
https://doc.dovecot.org/2.3/settings/core/#core_setting-login_log_format_elements

Dovecot's default log line is a timestamp, the process that wrote it, a level,
and the message. Two processes are captured here.

## Login processes: `imap-login`, `pop3-login`

    <timestamp> <process>: <level>: <event>: user=<<user>>, method=<method>, rip=<rip>, lip=<lip>[, mpid=<mpid>], session=<<session>>

- `event` — what happened: `Login`, or `Disconnected: Connection closed (auth failed, N attempts in M secs)`
- `user` — the account the client logged in as, or tried to
- `method` — the SASL mechanism: `PLAIN`, `LOGIN`
- `rip` — the REMOTE IP: the client's address
- `lip` — the LOCAL IP: the address of this server the client connected to
- `mpid` — the pid of the mail process started for the session (successful logins only)
- `session` — Dovecot's session identifier, the same on every line of one session

## Authentication process: `auth`

    <timestamp> auth: <level>: <backend>(<user>,<rip>,<<session>>): <reason>

- `backend` — the password database that answered: `passwd-file`
- `user`, `rip`, `session` — as above
- `reason` — why authentication failed: `Password mismatch`, `unknown user`

## Fields common to both

- `timestamp` — `Mmm dd HH:MM:SS`, local time, no year
- `process` — the Dovecot process that wrote the line
- `level` — `Info`, `Warning`, `Error`, `Fatal`

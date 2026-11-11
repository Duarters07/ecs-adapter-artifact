# fail2ban 1.x — jail decisions

Written by the fail2ban server, one line per decision about an address:

```
TIMESTAMP LOGGER [PID]: LEVEL [JAIL] ACTION IP[ - MATCH_TIMESTAMP]
```

Real examples:

```
2026-10-02 15:39:43,098 fail2ban.filter         [1]: INFO    [sshd] Found 198.51.100.23 - 2026-10-02 15:39:43
2026-10-02 15:39:44,277 fail2ban.actions        [1]: NOTICE  [sshd] Ban 198.51.100.23
2026-10-02 15:40:49,309 fail2ban.actions        [1]: NOTICE  [sshd] Unban 198.51.100.23
```

- The timestamp uses a comma before the milliseconds.
- `LOGGER` is the fail2ban subsystem that made the decision: `fail2ban.filter`
  observes, `fail2ban.actions` acts.
- `PID` is the fail2ban server's process id, the same on every line.
- `JAIL` in square brackets is the name of the rule set that matched. It is
  configured by the operator and names a protected service.
- `ACTION` is `Found` when a matching line was observed, `Ban` when the
  threshold was crossed, `Unban` when the ban expired.
- `Found` lines append ` - ` and the timestamp of the matched line. `Ban` and
  `Unban` lines do not.

fail2ban reports a DECISION about an address. The address is the subject of the
decision, and fail2ban is the actor.

## Capture names

- `logger` — the dotted subsystem name
- `pid` — the number in square brackets after it
- `level` — `INFO` or `NOTICE`
- `jail` — the name in square brackets
- `action` — `Found`, `Ban` or `Unban`
- `ip` — the address the decision is about

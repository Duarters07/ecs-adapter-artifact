# Prosody 0.12 - log file, info level

Source: Prosody documentation, "Logging" (https://prosody.im/doc/logging), and the Debian package's
log sink, /var/log/prosody/prosody.log.

Every line is `<timestamp> <session>\t<level>\t<message>`, tab-separated after the session.

## The client-session messages kept

    Client connected
    Authenticated as <user>@<domain>
    Client disconnected: <reason>

- `timestamp` - local time, `Mmm dd HH:MM:SS`
- `session` - the id of the client-to-server session (`c2s` and a hexadecimal number); the same id
  on every line of one connection
- `level` - the log level (`info`)
- `event` - what happened: `connected`, `Authenticated`, `disconnected`
- `user`, `domain` - the account that authenticated, and its XMPP domain
- `reason` - why the session ended

A login that fails is logged at this level only as a connection followed by a disconnection,
with no `Authenticated` line between them.

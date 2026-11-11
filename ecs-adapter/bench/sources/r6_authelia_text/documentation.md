# Authelia 4.38 - server log, format text

Source: Authelia documentation, "Log" configuration (https://www.authelia.com/configuration/miscellaneous/logging/),
`log.format: text`. The server writes one logfmt line per event (Go logrus text formatter):

    time="<time>" level=<level> msg="<message>" [error="<error>"] method=<method> path=<path> remote_ip=<remote_ip>

## The messages kept

    Unsuccessful 1FA authentication attempt by user '<user>'
    Unsuccessful 1FA authentication attempt by user '<user>' and they are banned until <banned_until>

Successful first-factor logins are not logged at level info.

- `time` - UTC, RFC 3339; `level` - error for these events
- `user` - the username submitted; `banned_until` - when regulation lifts the ban after repeated failures
- `error` - present when the backend gives a reason, such as `user not found`
- `method`, `path` - the HTTP request (`POST /api/firstfactor`)
- `remote_ip` - the client address

# Gitea 1.22.6 - console log (default logger)

Source: Gitea documentation, "Logging Configuration" (https://docs.gitea.com/administration/logging-config), official
image. The server writes one line per event to standard output:

    <timestamp> <origin> [<level>] router: completed <method> <path> for <client_ip>:<client_port>, <status> <status_text> in <duration> @ <handler>
    <timestamp> <origin> [<level>] UserSignIn: <reason> [uid: <uid>, name: <user>]

## Fields

- `timestamp` - local time `YYYY/MM/DD hh:mm:ss`
- `method`, `path` - the HTTP request; `client_ip`, `client_port` - the client
- `status`, `status_text` - the response (401 Unauthorized for refused credentials)
- `duration` - the request's handling time; `handler` - the Go handler that answered
- `origin` - the source file, line and function that logged the event (shortened with `...`)
- `level` - one letter: I info, W warning, E error
- UserSignIn: a refused sign-in of an existing account; `reason`, `uid`, `user`

# Gitea 1.19.4 - console log (default logger)

Source: Gitea documentation, "Logging Configuration" (https://docs.gitea.com/administration/logging-config), official
image. The server writes one line per event to standard output:

    <timestamp> [<request_id>] router: completed <method> <path> for <client_ip>:<client_port>, <status> <status_text> in <duration> @ <handler>

## Fields

- `timestamp` - local time `YYYY/MM/DD hh:mm:ss`
- `method`, `path` - the HTTP request; `client_ip`, `client_port` - the client
- `status`, `status_text` - the response (401 Unauthorized for refused credentials)
- `duration` - the request's handling time; `handler` - the Go handler that answered
- `request_id` - the request's id, suffixed `-2`, `-3`... for requests that reuse a connection

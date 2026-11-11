# Grafana 11.3 - server log, console format `console` (logfmt)

Source: Grafana documentation, "Configure Grafana", sections [log], [log.console] and [server]
router_logging, https://grafana.com/docs/grafana/v11.3/setup-grafana/configure-grafana/

One message per line, as logfmt: `key=value` pairs separated by spaces; a value that contains a
space is written in double quotes, and an empty value is written as nothing after the `=`.

    logger=context userId=<userId> orgId=<orgId> uname=<uname> t=<t> level=<level> msg=<msg> method=<method> path=<path> status=<status> remote_addr=<remote_addr> time_ms=<time_ms> duration=<duration> size=<size> referer=<referer> handler=<handler> status_source=<status_source>
    logger=context userId=<userId> orgId=<orgId> uname=<uname> t=<t> level=<level> msg=<msg> error=<error> remote_addr=<remote_addr> traceID=<traceID>

## The keys of the request-context logger (`logger=context`)

Every request writes one `Request Completed` message; a request whose authentication fails also
writes a message carrying the authentication error.

- `logger` - the logger that wrote the message, here `context`
- `t` - the time of the message, RFC 3339 with nanoseconds
- `level` - the log level (`info`)
- `msg` - the message: `Request Completed`, `Unauthorized`, or empty on a failed API authentication
- `error` - the authentication error, for example `[password-auth.failed] ... invalid password` or
  `... [identity.not-found] no user found`
- `userId`, `uname` - the numeric id and the login name of the signed-in user; `0` and empty when none
- `orgId` - the organisation the request ran in; `0` when none
- `method`, `path` - the request method and URL path
- `status` - the HTTP status code of the response
- `remote_addr` - the address of the client
- `size` - the response body size, bytes
- `time_ms`, `duration` - the time taken to serve the request
- `handler` - the route that handled the request (`notfound` when none matched)
- `referer` - the Referer header, empty when absent
- `status_source` - which side decided the status (`server` here)
- `traceID` - the trace identifier, empty when tracing is off

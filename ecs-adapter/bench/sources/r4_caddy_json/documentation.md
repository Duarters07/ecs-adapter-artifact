# Caddy 2.8 - access log, JSON encoder

Source: Caddy documentation, "log" directive, `format json`,
https://caddyserver.com/docs/caddyfile/directives/log

One JSON object per request: `level`, `ts` (Unix time), `logger`, `msg` and:

- `level` - the log level (`info`)
- `logger` - the logger that wrote the line (`http.log.access.log0`)
- `request.remote_ip`, `request.remote_port` - the address and port the connection came from
- `request.client_ip` - the client address after trusted-proxy processing (here the same)
- `request.proto`, `request.method`, `request.host`, `request.uri` - the request
- `request.headers.*` - the request headers, each a list of values
- `bytes_read` - the request body bytes read
- `user_id` - the authenticated user, empty when none
- `duration` - the time to serve the request, seconds
- `size` - the response body size, bytes
- `status` - the HTTP status code
- `resp_headers.*` - the response headers

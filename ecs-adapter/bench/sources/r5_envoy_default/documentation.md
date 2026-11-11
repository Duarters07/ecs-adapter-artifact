# Envoy 1.31 - access log, default format

Source: Envoy documentation, "Access logging", section "Default format string",
https://www.envoyproxy.io/docs/envoy/v1.31.10/configuration/observability/access_log/usage

    [<start_time>] "<method> <path> <protocol>" <response_code> <response_flags> <bytes_received> <bytes_sent> <duration> <upstream_service_time> "<x_forwarded_for>" "<user_agent>" "<request_id>" "<authority>" "<upstream_host>"

- `upstream_service_time` - the x-envoy-upstream-service-time response header, milliseconds; `-` when absent
- `x_forwarded_for` - the X-Forwarded-For header of the request; `-` when absent

- `start_time` - when the request started, ISO 8601 UTC with milliseconds
- `method`, `path`, `protocol` - the request line (`path` is the original path when a route rewrote it)
- `response_code` - the HTTP status code returned to the client
- `response_flags` - Envoy's response flags (`-` when none; for example `NR` no route, `UF` upstream failure)
- `bytes_received` - the request body bytes received
- `bytes_sent` - the response body bytes sent
- `duration` - the total time of the request, milliseconds
- `user_agent` - the User-Agent header of the request
- `request_id` - the X-Request-Id header, which Envoy generates when the client sends none
- `authority` - the :authority (Host) header of the request, `host[:port]`
- `upstream_host` - the upstream host that served the request, `ip:port`; `-` when Envoy answered itself
  (a direct response, as for the denied `/admin` paths)

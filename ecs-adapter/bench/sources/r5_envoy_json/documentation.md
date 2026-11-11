# Envoy 1.31 - the site's JSON access log

Source: the site's envoy.yaml (`log_format.json_format`, Envoy documentation "Access logging",
"Format dictionaries").

    json_format:
      start_time: "%START_TIME%"
      client_ip: "%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%"
      client_port: "%DOWNSTREAM_REMOTE_PORT%"
      method: "%REQ(:METHOD)%"
      path: "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%"
      protocol: "%PROTOCOL%"
      response_code: "%RESPONSE_CODE%"
      response_flags: "%RESPONSE_FLAGS%"
      bytes_received: "%BYTES_RECEIVED%"
      bytes_sent: "%BYTES_SENT%"
      duration: "%DURATION%"
      user_agent: "%REQ(USER-AGENT)%"
      request_id: "%REQ(X-REQUEST-ID)%"
      authority: "%REQ(:AUTHORITY)%"
      upstream_host: "%UPSTREAM_HOST%"

One JSON object per request; numeric operators are written as JSON numbers, and a value that is not
available is written as `null`. The keys appear in no fixed order.

- `client_ip`, `client_port` - the address and port of the client that connected to Envoy

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

# nginx — access log, the site's JSON format

Source: the site's nginx.conf (ngx_http_log_module, `log_format ... escape=json`),
https://nginx.org/en/docs/http/ngx_http_log_module.html#log_format

    log_format r3json escape=json '{"time":"$time_iso8601","client":"$remote_addr",'
        '"user":"$remote_user","host":"$host","method":"$request_method",'
        '"uri":"$request_uri","protocol":"$server_protocol","status":$status,'
        '"bytes_sent":$body_bytes_sent,"referer":"$http_referer",'
        '"agent":"$http_user_agent","forwarded_for":"$http_x_forwarded_for",'
        '"duration":$request_time,"request_id":"$request_id"}';

One JSON object per request. With `escape=json` a variable with no value is
written as an empty string.

- `time` — local time in ISO 8601
- `host` — the host name the request was addressed to (Host header or server name)
- `forwarded_for` — the X-Forwarded-For header: the original client when a proxy
  forwarded the request
- `duration` — request processing time in seconds, millisecond resolution
- `request_id` — a unique identifier nginx generated for the request (32 hex digits)

- `client` — the address of the client that connected to nginx
- `user` — the user name the client authenticated as with HTTP basic
  authentication; `-` (or empty) when it sent none
- `method` — the request method
- `uri` — the request URI as sent, path and query string
- `protocol` — the request protocol, `HTTP/1.1`
- `status` — the response status code
- `bytes_sent` — the bytes of the response body sent to the client
- `referer` — the Referer header of the request
- `agent` — the User-Agent header of the request

# nginx — access log, `combined` format

Source: nginx documentation, ngx_http_log_module,
https://nginx.org/en/docs/http/ngx_http_log_module.html#log_format

The predefined `combined` format writes

    <client> - <user> [<time>] "<method> <uri> <protocol>" <status> <bytes_sent> "<referer>" "<agent>"

- `time` — local time in the Common Log Format, `dd/Mmm/yyyy:HH:MM:SS +zzzz`

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

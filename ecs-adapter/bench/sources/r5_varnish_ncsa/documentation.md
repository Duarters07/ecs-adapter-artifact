# Varnish 7.6 - varnishncsa, default format

Source: varnishncsa(1), Varnish Cache 7.6 documentation,
https://varnish-cache.org/docs/7.6/reference/varnishncsa.html

With no -F, varnishncsa writes NCSA combined format, `%h %l %u %t "%r" %s %b "%{Referer}i" "%{User-agent}i"`:

    <client> <ident> <user> [<time>] "<method> <url> <protocol>" <status> <bytes> "<referer>" "<user_agent>"

- `client` - the remote host: the client's IP address
- `ident`, `user` - the remote log name and the authenticated user; `-` when none (always here)
- `time` - when the request was received, Common Log Format
- `method`, `url`, `protocol` - the first line of the request, with the URL rewritten as an absolute
  URL (`http://<host>/<path>`)
- `status` - the HTTP status code sent to the client
- `bytes` - the size of the response body, bytes; `-` when none
- `referer`, `user_agent` - the Referer and User-Agent request headers; `-` when absent

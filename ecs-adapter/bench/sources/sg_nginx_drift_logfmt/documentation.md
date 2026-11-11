# nginx access log

Key=value pairs separated by " ", key and value joined by "=", one entry per line.

```
ts=TS bytes=BYTES method=METHOD proto=PROTO referrer=REFERRER server=SERVER src_ip=SRC_IP status=STATUS user=USER vhost=VHOST
```

Example lines:

```
ts=1791964819.000 bytes=21216 method=GET proto=HTTP/2.0 referrer=https://intranet.acme.local/projects server=web.acme.local src_ip=10.10.6.11 status=200 user=- vhost=intranet.acme.local
ts=1791964842.000 bytes=31403 method=GET proto=HTTP/2.0 referrer=https://intranet.acme.local/dashboard server=web.acme.local src_ip=10.20.7.12 status=200 user=- vhost=intranet.acme.local
```

- `ts` — event time
- `bytes` — bytes sent
- `method` — request verb
- `proto` — vendor-specific value
- `referrer` — referer
- `server` — kept as written
- `src_ip` — client IP
- `status` — status
- `user` — kept as written
- `vhost` — Host header

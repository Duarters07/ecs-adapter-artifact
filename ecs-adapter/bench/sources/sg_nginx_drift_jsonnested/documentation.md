# nginx access log

One JSON object per line, one entry per line.

```
{"time": TIME, "referrer": REFERRER, "user": USER, "server": SERVER, "bytes": BYTES, "proto": PROTO, "ua": UA, "method": METHOD, "src_ip": SRC_IP, "vhost": VHOST, "url": URL, "status": STATUS}
```

Example lines:

```
{"time": 1791964819, "referrer": "https://intranet.acme.local/projects", "user": "-", "server": "web.acme.local", "bytes": "21216", "proto": "HTTP/2.0", "ua": "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0", "method": "GET", "src_ip": "10.10.6.11", "vhost": "intranet.acme.local", "url": "/", "status": "200"}
{"time": 1791964842, "referrer": "https://intranet.acme.local/dashboard", "user": "-", "server": "web.acme.local", "bytes": "31403", "proto": "HTTP/2.0", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", "method": "GET", "src_ip": "10.20.7.12", "vhost": "intranet.acme.local", "url": "/dashboard", "status": "200"}
```

- `time` — event time
- `referrer` — referer
- `user` — internal to the product
- `server` — recorded by the source
- `bytes` — response size
- `proto` — vendor-specific value
- `ua` — user agent
- `method` — HTTP verb
- `src_ip` — IP of the requesting host
- `vhost` — site
- `url` — URL as received
- `status` — HTTP status

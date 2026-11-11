# Nextcloud audit log

One JSON object per line, one entry per line.

```
{"timestamp": TIMESTAMP, "target": TARGET, "path": PATH, "method": METHOD, "message": MESSAGE, "url": URL, "ip": IP, "action": ACTION, "ua": UA, "reqid": REQID, "path2": PATH2, "user": USER}
```

Example lines:

```
{"timestamp": "2026-10-14T08:00:24+00:00", "target": "amy.brown", "path": "/HR/invoice-668.csv", "method": "PUT", "message": "File created: \"/HR/invoice-668.csv\"", "url": "/remote.php/dav/files/erin.patterson/HR/invoice-668.csv", "ip": "10.10.7.15", "action": "file_created", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", "reqid": "fe929d9f1d8a731a962b", "path2": "/HR/forecast-191.csv", "user": "erin.patterson"}
{"timestamp": "2026-10-14T08:01:50+00:00", "target": "brian.harris", "path": "/Finance/forecast-280.pdf", "method": "PROPFIND", "message": "File accessed: \"/Finance/forecast-280.pdf\"", "url": "/remote.php/dav/files/brian.romero/Finance/forecast-280.pdf", "ip": "10.30.2.11", "action": "file_accessed", "ua": "Mozilla/5.0 (Windows) mirall/3.13.2stable-Win64 (build 20240710) (Nextcloud, windows-10.0.19045 ClientArchitecture: x86_64 OsArchitecture: x86_64)", "reqid": "c531b32423a01d8b66ce", "path2": "/Finance/budget-363.pdf", "user": "brian.romero"}
```

- `timestamp` — event time
- `target` — vendor-specific value
- `path` — vendor-specific value
- `method` — method
- `message` — recorded by the source
- `url` — request line target
- `ip` — client IP
- `action` — operation
- `ua` — User-Agent header
- `reqid` — queue ID
- `path2` — internal to the product
- `user` — account

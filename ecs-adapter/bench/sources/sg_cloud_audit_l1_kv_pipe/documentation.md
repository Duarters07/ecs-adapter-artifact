# Nextcloud audit log

Key=value pairs separated by "|", key and value joined by "=", one entry per line.

```
timestamp=TIMESTAMP|ip=IP|ua=UA|path2=PATH2|reqid=REQID|action=ACTION|path=PATH|user=USER|target=TARGET|method=METHOD
```

Example lines:

```
timestamp=2026-10-14T08:00:24+00:00|ip=10.10.7.15|ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"|path2=/HR/forecast-191.csv|reqid=fe929d9f1d8a731a962b|action=file_created|path=/HR/invoice-668.csv|user=erin.patterson|target=amy.brown|method=PUT
timestamp=2026-10-14T08:01:50+00:00|ip=10.30.2.11|ua="Mozilla/5.0 (Windows) mirall/3.13.2stable-Win64 (build 20240710) (Nextcloud, windows-10.0.19045 ClientArchitecture: x86_64 OsArchitecture: x86_64)"|path2=/Finance/budget-363.pdf|reqid=c531b32423a01d8b66ce|action=file_accessed|path=/Finance/forecast-280.pdf|user=brian.romero|target=brian.harris|method=PROPFIND
```

- `timestamp` — when the entry was logged
- `ip` — remote peer IP
- `ua` — user agent
- `path2` — internal to the product
- `reqid` — queue ID
- `action` — operation
- `path` — vendor-specific value
- `user` — user
- `target` — kept as written
- `method` — method

# Nextcloud audit log

Key=value pairs separated by " ", key and value joined by "=", one entry per line.

```
timestamp=TIMESTAMP action=ACTION path=PATH path2=PATH2 ip=IP reqid=REQID user=USER method=METHOD ua=UA target=TARGET
```

Example lines:

```
timestamp=2026-10-14T08:00:24+00:00 action=file_created path=/HR/invoice-668.csv path2=/HR/forecast-191.csv ip=10.10.7.15 reqid=fe929d9f1d8a731a962b user=erin.patterson method=PUT ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" target=amy.brown
timestamp=2026-10-14T08:01:50+00:00 action=file_accessed path=/Finance/forecast-280.pdf path2=/Finance/budget-363.pdf ip=10.30.2.11 reqid=c531b32423a01d8b66ce user=brian.romero method=PROPFIND ua="Mozilla/5.0 (Windows) mirall/3.13.2stable-Win64 (build 20240710) (Nextcloud, windows-10.0.19045 ClientArchitecture: x86_64 OsArchitecture: x86_64)" target=brian.harris
```

- `timestamp` — event time
- `action` — action
- `path` — internal to the product
- `path2` — kept as written
- `ip` — remote peer IP
- `reqid` — entry identifier
- `user` — user
- `method` — HTTP verb
- `ua` — user agent
- `target` — vendor-specific value

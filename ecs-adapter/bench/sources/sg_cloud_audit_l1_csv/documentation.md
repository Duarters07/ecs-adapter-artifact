# Nextcloud audit log

Positional columns separated by ",", one entry per line.

```
TIMESTAMP,ACTION,METHOD,PATH2,TARGET,USER,URL,PATH,MESSAGE,REQID,IP,UA
```

Example lines:

```
2026-10-14T08:00:24+00:00,file_created,PUT,/HR/forecast-191.csv,amy.brown,erin.patterson,/remote.php/dav/files/erin.patterson/HR/invoice-668.csv,/HR/invoice-668.csv,"File created: ""/HR/invoice-668.csv""",fe929d9f1d8a731a962b,10.10.7.15,"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
2026-10-14T08:01:50+00:00,file_accessed,PROPFIND,/Finance/budget-363.pdf,brian.harris,brian.romero,/remote.php/dav/files/brian.romero/Finance/forecast-280.pdf,/Finance/forecast-280.pdf,"File accessed: ""/Finance/forecast-280.pdf""",c531b32423a01d8b66ce,10.30.2.11,"Mozilla/5.0 (Windows) mirall/3.13.2stable-Win64 (build 20240710) (Nextcloud, windows-10.0.19045 ClientArchitecture: x86_64 OsArchitecture: x86_64)"
```

- `timestamp` — when the entry was logged
- `action` — verb logged by the device
- `method` — request verb
- `path2` — internal to the product
- `target` — internal to the product
- `user` — account
- `url` — request line target
- `path` — vendor-specific value
- `message` — recorded by the source
- `reqid` — entry identifier
- `ip` — client IP
- `ua` — UA string

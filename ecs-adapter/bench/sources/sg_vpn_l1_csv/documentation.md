# vpn

Positional columns separated by ",", one entry per line.

```
TIMESTAMP,PUB_PORT,PUB_IP,TUNNEL_IP,PID,BYTES,ASSIGNED_IP,USER,OUTCOME,ACTION
```

Example lines:

```
2026-10-14T08:00:21+00:00,20889,192.0.2.110,10.8.0.12,2921,750051861,10.30.3.12,roger.serrano,success,rekey
2026-10-14T08:01:05+00:00,34377,192.0.2.206,10.8.0.11,2921,354901049,10.30.2.11,brian.romero,success,rekey
```

- `timestamp` — when the entry was logged
- `pub_port` — remote peer's TCP/UDP port
- `pub_ip` — remote peer IP
- `tunnel_ip` — vendor-specific value
- `pid` — internal to the product
- `bytes` — kept as written
- `assigned_ip` — vendor-specific value
- `user` — account
- `outcome` — recorded by the source
- `action` — kept as written

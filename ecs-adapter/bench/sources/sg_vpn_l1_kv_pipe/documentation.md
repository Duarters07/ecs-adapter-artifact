# vpn

Key=value pairs separated by "|", key and value joined by "=", one entry per line.

```
timestamp=TIMESTAMP|bytes=BYTES|pub_port=PUB_PORT|user=USER|outcome=OUTCOME|assigned_ip=ASSIGNED_IP|pub_ip=PUB_IP|pid=PID|tunnel_ip=TUNNEL_IP|action=ACTION
```

Example lines:

```
timestamp=2026-10-14T08:00:21+00:00|bytes=750051861|pub_port=20889|user=roger.serrano|outcome=success|assigned_ip=10.30.3.12|pub_ip=192.0.2.110|pid=2921|tunnel_ip=10.8.0.12|action=rekey
timestamp=2026-10-14T08:01:05+00:00|bytes=354901049|pub_port=34377|user=brian.romero|outcome=success|assigned_ip=10.30.2.11|pub_ip=192.0.2.206|pid=2921|tunnel_ip=10.8.0.11|action=rekey
```

- `timestamp` — when the entry was logged
- `bytes` — kept as written
- `pub_port` — client port
- `user` — login name
- `outcome` — vendor-specific value
- `assigned_ip` — internal to the product
- `pub_ip` — client IP
- `pid` — internal to the product
- `tunnel_ip` — kept as written
- `action` — internal to the product

# Postfix MTA log

Key=value pairs separated by "; ", key and value joined by "=", one entry per line.

```
time=TIME; status=STATUS; relay=RELAY; client_ip=CLIENT_IP; ext_domain=EXT_DOMAIN; delay=DELAY; relay_ip=RELAY_IP; size=SIZE; msgid=MSGID; to=TO; from=FROM; client_host=CLIENT_HOST; qid=QID
```

Example lines:

```
time=2026-10-14T08:00:19+00:00; status=sent; relay=mail.supplier.example; client_ip=10.10.6.11; ext_domain=supplier.example; delay=1.57; relay_ip=198.51.100.40; size=133387; msgid=<77e18a0a5abcca95@acme.local>; to=billing@supplier.example; from=kyle.cabrera@acme.local; client_host=ws-exe-001; qid=5F0F54F304
time=2026-10-14T08:01:24+00:00; status=sent; relay=gmail-smtp-in.l.google.com; client_ip=10.10.7.14; ext_domain=gmail.com; delay=2.51; relay_ip=142.250.27.27; size=60784; msgid=<dd77b6c29163d00d@acme.local>; to=john.smith@gmail.com; from=brian.harris@acme.local; client_host=ws-general-004; qid=59F823CDEF
```

- `time` — when the entry was logged
- `status` — operation
- `relay` — kept as written
- `client_ip` — kept as written
- `ext_domain` — kept as written
- `delay` — vendor-specific value
- `relay_ip` — vendor-specific value
- `size` — recorded by the source
- `msgid` — vendor-specific value
- `to` — to
- `from` — from
- `client_host` — vendor-specific value
- `qid` — queue ID

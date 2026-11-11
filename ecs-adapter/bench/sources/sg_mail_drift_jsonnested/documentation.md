# Postfix MTA log

One JSON object per line, one entry per line.

```
{"time": TIME, "client.host": CLIENT_HOST, "client.ip": CLIENT_IP, "relay": RELAY, "size": SIZE, "from": FROM, "msgid": MSGID, "ext_domain": EXT_DOMAIN, "to": TO, "delay": DELAY, "status": STATUS, "relay_ip": RELAY_IP, "qid": QID}
```

Example lines:

```
{"time": 1791964819, "client": {"host": "ws-exe-001", "ip": "10.10.6.11"}, "relay": "mail.supplier.example", "size": "133387", "from": "kyle.cabrera@acme.local", "msgid": "<77e18a0a5abcca95@acme.local>", "ext_domain": "supplier.example", "to": "billing@supplier.example", "delay": "1.57", "status": "sent", "relay_ip": "198.51.100.40", "qid": "5F0F54F304"}
{"time": 1791964884, "client": {"host": "ws-general-004", "ip": "10.10.7.14"}, "relay": "gmail-smtp-in.l.google.com", "size": "60784", "from": "brian.harris@acme.local", "msgid": "<dd77b6c29163d00d@acme.local>", "ext_domain": "gmail.com", "to": "john.smith@gmail.com", "delay": "2.51", "status": "sent", "relay_ip": "142.250.27.27", "qid": "59F823CDEF"}
```

- `time` — event time
- `client.host` — recorded by the source
- `client.ip` — internal to the product
- `relay` — recorded by the source
- `size` — internal to the product
- `from` — envelope sender
- `msgid` — kept as written
- `ext_domain` — kept as written
- `to` — to
- `delay` — vendor-specific value
- `status` — operation
- `relay_ip` — internal to the product
- `qid` — queue ID

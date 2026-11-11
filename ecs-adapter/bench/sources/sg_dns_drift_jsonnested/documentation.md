# dnsmasq resolver log

One JSON object per line, one entry per line.

```
{"time": TIME, "pid": PID, "src_ip": SRC_IP, "host": HOST, "qtype": QTYPE, "txid": TXID, "upstream": UPSTREAM, "domain": DOMAIN, "path": PATH, "sport": SPORT, "resolver": RESOLVER, "rcode": RCODE}
```

Example lines:

```
{"time": 1791964819, "pid": "2866", "src_ip": "10.10.6.11", "host": "dns", "qtype": "TXT", "txid": "33787", "upstream": "1.1.1.1", "domain": "mail.acme.local", "path": "config", "sport": "33375", "resolver": "10.10.0.15", "rcode": "NOERROR"}
{"time": 1791964882, "pid": "2866", "src_ip": "10.20.1.11", "host": "dns", "qtype": "PTR", "txid": "33147", "upstream": "1.1.1.1", "domain": "web.acme.local", "path": "config", "sport": "10334", "resolver": "10.10.0.15", "rcode": "NOERROR"}
```

- `time` — timestamp as written
- `pid` — recorded by the source
- `src_ip` — IP of the requesting host
- `host` — L7 protocol
- `qtype` — record type
- `txid` — DNS ID
- `upstream` — internal to the product
- `domain` — lookup target
- `path` — internal to the product
- `sport` — vendor-specific value
- `resolver` — target IP
- `rcode` — response code

# pfSense filterlog

One JSON object per line, one entry per line.

```
{"time": TIME, "iface": IFACE, "ttl": TTL, "dst.ip": DST_IP, "dst.port": DST_PORT, "ipid": IPID, "src.ip": SRC_IP, "src.port": SRC_PORT, "action": ACTION, "tracker": TRACKER, "rule": RULE, "window": WINDOW, "length": LENGTH, "tcp_flags": TCP_FLAGS, ...}
```

Example lines:

```
{"time": 1791964819, "iface": "igb1", "ttl": "51", "dst": {"ip": "140.82.121.4", "port": "443"}, "ipid": "53325", "src": {"ip": "10.10.6.11", "port": "26600"}, "action": "pass", "tracker": "1000000118", "rule": "13", "window": "65535", "length": "1000", "tcp_flags": "S", "seq": "675949904", "pid": "49671", "direction": "out", "proto": "tcp"}
{"time": 1791965538, "iface": "igb1", "ttl": "69", "dst": {"ip": "203.0.113.5", "port": "1337"}, "ipid": "57228", "src": {"ip": "10.20.1.11", "port": "22783"}, "action": "block", "tracker": "1000000103", "rule": "4", "window": "26883", "length": "309", "tcp_flags": "S", "seq": "1389739731", "pid": "49671", "direction": "out", "proto": "tcp"}
```

- `time` — event time
- `iface` — ingress port name
- `ttl` — kept as written
- `dst.ip` — target IP
- `dst.port` — server port
- `ipid` — kept as written
- `src.ip` — client IP
- `src.port` — remote peer's TCP/UDP port
- `action` — verb logged by the device
- `tracker` — tracker
- `rule` — policy line number
- `window` — recorded by the source
- `length` — internal to the product
- `tcp_flags` — vendor-specific value
- `seq` — recorded by the source
- `pid` — internal to the product
- `direction` — recorded by the source
- `proto` — transport name

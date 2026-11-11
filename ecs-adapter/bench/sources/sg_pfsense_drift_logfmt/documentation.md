# pfSense filterlog

Key=value pairs separated by " ", key and value joined by "=", one entry per line.

```
ts=TS action=ACTION direction=DIRECTION dst_ip=DST_IP dst_port=DST_PORT iface=IFACE ipid=IPID length=LENGTH pid=PID proto=PROTO rule=RULE seq=SEQ src_ip=SRC_IP src_port=SRC_PORT ...
```

Example lines:

```
ts=1791964819.000 action=pass direction=out dst_ip=140.82.121.4 dst_port=443 iface=igb1 ipid=53325 length=1000 pid=49671 proto=tcp rule=13 seq=675949904 src_ip=10.10.6.11 src_port=26600 tcp_flags=S tracker=1000000118 ttl=51 window=65535
ts=1791965538.000 action=block direction=out dst_ip=203.0.113.5 dst_port=1337 iface=igb1 ipid=57228 length=309 pid=49671 proto=tcp rule=4 seq=1389739731 src_ip=10.20.1.11 src_port=22783 tcp_flags=S tracker=1000000103 ttl=69 window=26883
```

- `ts` — event time
- `action` — operation
- `direction` — recorded by the source
- `dst_ip` — server IP
- `dst_port` — target port
- `iface` — ingress port name
- `ipid` — recorded by the source
- `length` — internal to the product
- `pid` — vendor-specific value
- `proto` — transport name
- `rule` — rule number
- `seq` — kept as written
- `src_ip` — IP of the requesting host
- `src_port` — client port
- `tcp_flags` — internal to the product
- `tracker` — tracker
- `ttl` — internal to the product
- `window` — vendor-specific value

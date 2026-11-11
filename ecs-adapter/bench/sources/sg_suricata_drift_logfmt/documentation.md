# Suricata EVE events

Key=value pairs separated by " ", key and value joined by "=", one entry per line.

```
ts=TS dest_ip=DEST_IP dest_port=DEST_PORT event_type=EVENT_TYPE flow_age=FLOW_AGE flow_bytes_toclient=FLOW_BYTES_TOCLIENT flow_bytes_toserver=FLOW_BYTES_TOSERVER flow_end=FLOW_END flow_id=FLOW_ID flow_pkts_toclient=FLOW_PKTS_TOCLIENT flow_pkts_toserver=FLOW_PKTS_TOSERVER flow_reason=FLOW_REASON flow_start=FLOW_START flow_state=FLOW_STATE ...
```

Example lines:

```
ts=1791964837.000 dest_ip=104.16.132.229 dest_port=53 event_type=flow flow_age=22 flow_bytes_toclient=61464 flow_bytes_toserver=41436 flow_end=2026-10-14T08:00:59.000000Z flow_id=236469737815096 flow_pkts_toclient=44 flow_pkts_toserver=38 flow_reason=shutdown flow_start=2026-10-14T08:00:37.000000Z flow_state=established in_iface=ens192 proto=TCP src_ip=10.20.7.12 src_port=12809 timestamp=2026-10-14T08:00:37.000000+0000
ts=1791964847.000 app_proto=tls dest_ip=140.82.121.4 dest_port=443 event_type=tls flow_id=289416180627755 in_iface=ens192 proto=TCP src_ip=10.10.7.11 src_port=21927 timestamp=2026-10-14T08:00:47.000000+0000 tls_cipher=TLS_CHACHA20_POLY1305_SHA256 tls_fingerprint=7521219bb851bf06160e9c0d594985243e060e92c6d9b36d32fefc9f03a56fd3 tls_ja3_hash=6dce586e00692cf65d5bc0da8f6c867e tls_ja3s_hash=6b69345a5736f33ed10d77d28b08c257 tls_notafter=2026-12-28T08:00:47.000000Z tls_notbefore=2026-08-30T08:00:47.000000Z tls_sni=www.google.com tls_version="TLS 1.3"
```

- `ts` — when the entry was logged
- `dest_ip` — target IP
- `dest_port` — server port
- `event_type` — internal to the product
- `flow_age` — internal to the product
- `flow_bytes_toclient` — server-to-client byte counter
- `flow_bytes_toserver` — upstream byte count
- `flow_end` — end time
- `flow_id` — vendor-specific value
- `flow_pkts_toclient` — packets returned by the server
- `flow_pkts_toserver` — upstream packet count
- `flow_reason` — recorded by the source
- `flow_start` — session opened at
- `flow_state` — kept as written
- `in_iface` — ingress port name
- `proto` — kept as written
- `src_ip` — client IP
- `src_port` — client port
- `timestamp` — recorded by the source
- `app_proto` — app protocol
- `tls_cipher` — vendor-specific value
- `tls_fingerprint` — kept as written
- `tls_ja3_hash` — internal to the product
- `tls_ja3s_hash` — kept as written
- `tls_notafter` — kept as written
- `tls_notbefore` — vendor-specific value
- `tls_sni` — recorded by the source
- `tls_version` — kept as written
- `http_hostname` — site
- `http_http_content_type` — kept as written
- `http_http_method` — HTTP verb
- `http_http_user_agent` — vendor-specific value
- `http_length` — response bytes incl. headers
- `http_protocol` — vendor-specific value
- `http_status` — status
- `http_url` — request URI
- `dns_id` — kept as written
- `dns_rrname` — recorded by the source
- `dns_rrtype` — recorded by the source
- `dns_tx_id` — kept as written
- `dns_type` — internal to the product
- `dns_version` — recorded by the source

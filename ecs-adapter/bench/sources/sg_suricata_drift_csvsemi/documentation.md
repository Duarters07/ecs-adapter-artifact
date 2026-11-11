# Suricata EVE events

Positional columns separated by ";", one entry per line.

```
TIME;FLOW_END;DNS_RRTYPE;FLOW_ID;FLOW_REASON;HTTP_HTTP_CONTENT_TYPE;EVENT_TYPE;TLS_NOTBEFORE;TLS_ISSUERDN;SRC_PORT;DNS_ID;HTTP_HTTP_METHOD;DNS_RRNAME;FLOW_STATE;TLS_JA3S_HASH;FLOW_BYTES_TOCLIENT;DEST_IP;TLS_SNI;IN_IFACE;FLOW_PKTS_TOSERVER;TLS_FINGERPRINT;SRC_IP;FLOW_BYTES_TOSERVER;HTTP_HOSTNAME;DNS_TYPE;TLS_NOTAFTER;TLS_SUBJECT;COMMUNITY_ID;TLS_JA3_HASH;TLS_CIPHER;HTTP_HTTP_USER_AGENT;DNS_TX_ID;HTTP_LENGTH;PROTO;DNS_VERSION;HTTP_STATUS;FLOW_PKTS_TOCLIENT;HTTP_URL;FLOW_AGE;TIMESTAMP;FLOW_START;TLS_VERSION;APP_PROTO;DEST_PORT;HTTP_PROTOCOL
```

Example lines:

```
2026-10-14T08:00:19+00:00;2026-10-14T08:01:25.000000Z;;308191131346054;timeout;;flow;;;22060;;;;established;;150616;151.101.1.140;;ens192;32;;10.10.6.11;10412;;;;;1:jsAnAkCDD7jVTz8gNTjGjzPQvdo=;;;;;;TCP;;;12;;66;2026-10-14T08:00:19.000000+0000;2026-10-14T08:00:19.000000Z;;;53;
2026-10-14T08:00:37+00:00;2026-10-14T08:00:59.000000Z;;236469737815096;shutdown;;flow;;;12809;;;;established;;61464;104.16.132.229;;ens192;38;;10.20.7.12;41436;;;;;1:SLtFMQCiND6XmzwTecXXPK0THaA=;;;;;;TCP;;;44;;22;2026-10-14T08:00:37.000000+0000;2026-10-14T08:00:37.000000Z;;;53;
```

- `time` — when the entry was logged
- `flow_end` — end time
- `dns_rrtype` — vendor-specific value
- `flow_id` — internal to the product
- `flow_reason` — vendor-specific value
- `http_http_content_type` — internal to the product
- `event_type` — internal to the product
- `tls_notbefore` — kept as written
- `tls_issuerdn` — kept as written
- `src_port` — remote peer's TCP/UDP port
- `dns_id` — vendor-specific value
- `http_http_method` — method
- `dns_rrname` — internal to the product
- `flow_state` — internal to the product
- `tls_ja3s_hash` — recorded by the source
- `flow_bytes_toclient` — downstream byte count
- `dest_ip` — IP the session was opened to
- `tls_sni` — recorded by the source
- `in_iface` — interface
- `flow_pkts_toserver` — pkts from client
- `tls_fingerprint` — vendor-specific value
- `src_ip` — client IP
- `flow_bytes_toserver` — client-to-server byte counter
- `http_hostname` — site
- `dns_type` — vendor-specific value
- `tls_notafter` — vendor-specific value
- `tls_subject` — kept as written
- `community_id` — flow hash
- `tls_ja3_hash` — kept as written
- `tls_cipher` — kept as written
- `http_http_user_agent` — kept as written
- `dns_tx_id` — kept as written
- `http_length` — total bytes
- `proto` — kept as written
- `dns_version` — vendor-specific value
- `http_status` — status
- `flow_pkts_toclient` — pkts to client
- `http_url` — URL as received
- `flow_age` — internal to the product
- `timestamp` — vendor-specific value
- `flow_start` — session opened at
- `tls_version` — internal to the product
- `app_proto` — L7 protocol
- `dest_port` — listening port on the target
- `http_protocol` — internal to the product

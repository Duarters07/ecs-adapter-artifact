# Zeek 7.0 — `conn.log`, tab-separated

One record per network connection, written by Zeek's ASCII log writer. The file
carries its own schema in the header, which is part of the format:

```
#separator \x09
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]
```

Columns are tab-separated, in that order. `-` means the field is unset.

## What the columns mean

Zeek names the two ends of a connection by their ROLE IN THE HANDSHAKE, not by
any security notion of source and destination:

- `id.orig_h`, `id.orig_p` — the ORIGINATOR, the endpoint that sent the first packet
- `id.resp_h`, `id.resp_p` — the RESPONDER, the endpoint that answered

- `proto` — transport protocol: `tcp`, `udp`, `icmp`
- `service` — the application protocol Zeek's analysers identified: `dns`, `http`, …
- `duration` — connection lifetime in SECONDS, as a decimal
- `orig_bytes`, `resp_bytes` — PAYLOAD bytes each side sent
- `orig_ip_bytes`, `resp_ip_bytes` — total IP-layer bytes each side sent, headers included
- `orig_pkts`, `resp_pkts` — packet counts
- `conn_state` — Zeek's connection-state summary: `S0`, `SF`, `RSTO`, `REJ`, …
- `history` — one letter per connection event, in order: `ShR`, `D`, …
- `local_orig`, `local_resp` — whether each endpoint is inside Zeek's configured local networks
- `missed_bytes` — bytes the sensor did not capture
- `uid` — Zeek's connection identifier, shared by every log describing this connection
- `tunnel_parents` — the enclosing tunnel connections, if any

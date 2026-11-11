# Suricata 7.0.17 — EVE JSON output, alert and dns events

Source: Suricata 7.0.17 user guide, "Eve JSON Format",
https://docs.suricata.io/en/suricata-7.0.17/output/eve/eve-json-format.html

One JSON object per event. Nested objects are addressed here with dots
(`alert.signature` is the `signature` key of the `alert` object).

## Keys of every event

- `timestamp` — when the packet was seen, ISO 8601 with microseconds
- `flow_id` — the identifier Suricata gives the flow, the same on every event of it
- `in_iface` — the network interface the packet was captured on
- `event_type` — the kind of event: `alert`, `dns`, ...
- `src_ip`, `src_port` — the address and port the packet came from
- `dest_ip`, `dest_port` — the address and port the packet went to
- `proto` — the transport protocol: `TCP`, `UDP`, `ICMP`
- `pkt_src` — where the packet came from: `wire/pcap`, `stream (flow timeout)`, ...
- `direction` — `to_server` or `to_client`, the direction of the packet in its flow
- `dns.version` — the version of the EVE DNS format (2)
- `flow.src_ip`, `flow.dest_ip`, `flow.src_port`, `flow.dest_port` — the flow's own
  endpoints, as the flow was first seen

## alert events

- `alert.action` — what the engine did: `allowed` (IDS mode) or `blocked`
- `alert.gid`, `alert.signature_id`, `alert.rev` — the rule's group id, its id (sid)
  and its revision
- `alert.signature` — the rule's name, its message text (`msg`)
- `alert.category` — the rule's classification (`classtype`), as text
- `alert.severity` — the priority of that classification, 1 (highest) to 4
- `app_proto` — the application protocol detected on the flow: `http`, `dns`, ...
- `tx_id` — the transaction the alert belongs to, within the flow
- `http.*` — the HTTP transaction that triggered the alert, when there is one
- `flow.*` — counters of the flow so far: `pkts_toserver`, `bytes_toclient`, `start`, ...

## dns events

- `dns.type` — `query` for a request
- `dns.id` — the DNS transaction id of the message
- `dns.rrname` — the name queried
- `dns.rrtype` — the record type queried: `A`, `AAAA`, `TXT`, ...
- `dns.opcode` — the DNS opcode, 0 for a standard query
- `dns.tx_id` — the transaction within the flow

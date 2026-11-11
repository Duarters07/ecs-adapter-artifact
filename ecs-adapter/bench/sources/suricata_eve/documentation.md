# Suricata 7.0 — EVE JSON, `alert` records

One JSON object per line. These are `event_type: alert` records only; Suricata
writes `http`, `dns`, `flow` and other record types to the same file with the
same envelope.

## Top-level keys

- `timestamp` — ISO 8601 with a numeric offset
- `flow_id` — Suricata's identifier for the flow this packet belongs to
- `in_iface` — the capture interface the sensor read the packet from
- `event_type` — the record discriminator; `alert` for every line here
- `src_ip`, `src_port` — the endpoint that sent the packet that triggered the rule
- `dest_ip`, `dest_port` — the endpoint it was sent to
- `proto` — transport protocol, upper case: `TCP`, `UDP`
- `app_proto` — the application protocol Suricata's parsers identified: `http`, `dns`
- `pkt_src` — where the packet came from inside Suricata: `wire/pcap`
- `tx_id` — the application-layer transaction this alert belongs to
- `direction` — `to_server` or `to_client`

## Nested objects

`alert`, `http` and `flow` are JSON OBJECTS, not values. `alert` carries
`signature`, `signature_id`, `category`, `severity` and `action`; `http`
carries the request; `flow` carries byte and packet counts per direction.

They are documented here because they are part of the format, and they are not
annotated below, for the reason recorded in the ground truth.

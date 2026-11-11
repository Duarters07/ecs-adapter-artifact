# BIND 9.18 — query and security log

Source: BIND 9 Administrator Reference Manual, "logging" statement and the
`queries`, `security` and `xfer-out` categories,
https://bind9.readthedocs.io/en/v9.18.50/reference.html#logging-block

Every line starts with the time and the client that sent the request:

    <timestamp> client @<client_object> <client_ip>#<client_port> (<query_name>): <message>

- `timestamp` — `dd-Mmm-yyyy HH:MM:SS.mmm`
- `client_object` — the memory address of the server's client object, for debugging
- `client_ip`, `client_port` — where the query came from
- `query_name` — the name the query is about

## The three messages captured

    query: <query_name> <query_class> <query_type> <flags> (<server_ip>)
    <action> '<question>' denied[ (<reason>)]
    query failed (<response_code>) for <question> at <code_location>

- `query_class` — the DNS class, `IN`
- `query_type` — the record type asked for: `A`, `AAAA`, `MX`, `TXT`, `AXFR`, ...
- `flags` — `+` recursion requested, `-` not; `E(0)` EDNS version 0, `T` TCP, `K` cookie
- `server_ip` — the address of this server the query was sent to
- `action` — what was refused: `query (cache)` or `zone transfer`
- `question` — `name/type/class` of the refused request
- `reason` — which access-control list refused it
- `response_code` — the DNS response code sent back: `REFUSED`, `SERVFAIL`, ...
- `code_location` — the source file and line in BIND that logged the failure

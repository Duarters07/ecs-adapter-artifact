# Knot DNS 3.2.6 - server log, target stdout, level info

Source: Knot DNS reference manual, "log" section (vendor documentation), Debian package. The server is authoritative
for four zones and allows zone transfers to two secondary addresses. One line per event:

    <timestamp> <level>: [<zone>.] <xfr_type>, outgoing, remote <client_ip>@<client_port>, <event>

`timestamp` is ISO 8601 with a numeric offset.

## The events kept (outgoing zone transfers)

    started, serial <serial>
    finished, <duration> seconds, <messages> messages, <bytes> bytes
    incomplete history, serial <serial>, fallback to AXFR

- `zone` - the zone transferred (the question name of the transfer request)
- `xfr_type` - AXFR (full) or IXFR (incremental) transfer; `direction` - outgoing (this server sends the zone)
- `client_ip`, `client_port` - the secondary that requested the transfer
- `serial` - the zone serial sent, or the serial the requester holds when an IXFR falls back to AXFR
- `duration`, `messages`, `bytes` - size and time of a finished transfer
- Transfers refused by the ACL are not logged at level info.

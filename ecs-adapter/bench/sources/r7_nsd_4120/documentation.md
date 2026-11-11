# NSD 4.12.0 - log, verbosity 2, foreground on stderr

Source: nsd.conf(5) ("verbosity", "provide-xfr"), Debian package. The server is authoritative for four zones and
provides zone transfers to two secondary addresses. One line per event:

    [<yyyy-mm-dd hh:mm:ss.mmm>] nsd[<pid>]: <level>: <message>

## The messages kept

    <xfr_type> for <zone>. from <client_ip>  not-verified
    <xfr_type> for <zone>. from <client_ip> refused, no acl matches
    ixfr fallback to axfr, no ixfr info for zone: <zone>.

- `xfr_type` - axfr (full) or ixfr (incremental) zone transfer request; `zone` - the zone requested
- `client_ip` - the requester; `pid` - the serving process; `level` - info
- `reason` - why the request was refused (no `provide-xfr` entry matches the requester), or why an IXFR falls back to AXFR
- `verification` - not-verified: the request was allowed without a TSIG key (NOKEY)

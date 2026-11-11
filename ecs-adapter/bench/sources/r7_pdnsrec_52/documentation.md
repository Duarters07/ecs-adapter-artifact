# PowerDNS Recursor 5.2.13 - console log, quiet=no (every question and answer)

Source: PowerDNS Recursor documentation, "Logging" (structured logging, key="value" pairs) and the settings
"quiet" and "allow-from", Debian package. One line per event: a syslog-style time, then key="value" pairs:

    <Mon dd hh:mm:ss> msg="<message>" subsystem="<subsystem>" level="<n>" prio="<prio>" tid="<tid>" ts="<epoch>" ...

## The messages kept

    msg="Question" ... proto="<proto>" qname="<qname>" qtype="<qtype>" remote="<client_ip>:<client_port>"
    msg="Answer" ... additional="<n>" answer-is-variable="<0|1>" answers="<answers>" dotout="<n>" ecs="" into-packetcache="<0|1>" maxdepth="<n>" mtid="<n>" netms="<ms>"
        outqueries="<n>" proto="<proto>" qname="<qname>" qtype="<qtype>" rcode="<rcode>" rd="<0|1>" received="<n>" remote="<client_ip>:<client_port>"
        tcpout="<n>" throttled="<n>" timeouts="<n>" totms="<ms>" validationState="<state>"
    msg="Question answered from packet cache" ... qname="<qname>" qtype="<qtype>" remote="<client_ip>:<client_port>" source="..." tag="<n>"
    msg="Dropping UDP query, address not matched by allow-from" ... proto="<proto>" source="<client_ip>:<client_port>"

- `client_ip`, `client_port` - the client (`remote`, or `source` for a dropped query)
- `qname`, `qtype` - the question; `rcode` - the numeric DNS response code (0 NOERROR, 3 NXDOMAIN)
- `answers` - number of answer records; `proto` - udp or tcp
- `subsystem` - the logging subsystem (syncres, in); `prio` - Info, Notice, Error; `tid` - the worker thread

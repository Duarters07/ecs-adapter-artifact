# OpenLDAP 2.5 - slapd, `stats` log level

Source: slapd.conf(5) / slapd-config(5), "olcLogLevel" (`stats`: connections, operations and
results), OpenLDAP 2.5 Administrator's Guide, https://www.openldap.org/doc/admin25/

Run with `-d 256`, slapd writes one line per event to standard error:

    <timestamp> <thread> conn=<conn> <event>

- `timestamp` - the time, `<seconds>.<nanoseconds>` since the Unix epoch, both in hexadecimal
- `thread` - the id of the thread that logged the line

## The events kept

    fd=<fd> ACCEPT from IP=<client_ip>:<client_port> (IP=<listener_ip>:<listener_port>)
    op=<op> BIND dn="<bind_dn>" method=<method>
    op=<op> BIND dn="<bind_dn>" mech=<mech> bind_ssf=<bind_ssf> ssf=<ssf>
    op=<op> RESULT tag=<tag> err=<err> qtime=<qtime> etime=<etime> text=<text>
    op=<op> RESULT oid=<oid> err=<err> qtime=<qtime> etime=<etime> text=<text>
    op=<op> SRCH base="<base>" scope=<scope> deref=<deref> filter="<filter>"
    op=<op> SEARCH RESULT tag=<tag> err=<err> qtime=<qtime> etime=<etime> nentries=<nentries> text=<text>

- `conn`, `op`, `fd` - the connection number, the operation number within it, and the socket
- `client_ip`, `client_port` - the address and port of the client that connected
- `listener_ip`, `listener_port` - the address and port slapd accepted the connection on
- `bind_dn` - the distinguished name the client authenticated as (empty for an anonymous bind)
- `method`, `mech` - the bind method (128: simple) and the SASL mechanism name (`SIMPLE`)
- `tag` - the LDAP response type (97: bind response, 101: search result done)
- `err` - the LDAP result code: 0 success, 49 invalid credentials, 32 no such object, ...
- `text` - the diagnostic text of the result, often empty
- `oid` - the OID of an extended operation's response, often empty
- `base`, `scope`, `deref`, `filter` - the search request
- `nentries` - how many entries the search returned
- `qtime`, `etime` - seconds the operation waited in the queue, and seconds it took

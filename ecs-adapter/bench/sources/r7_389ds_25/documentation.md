# 389 Directory Server 2.5.0 - access log

Source: Red Hat Directory Server / 389 Directory Server documentation ("Access log reference"), official container
image. The access log records every client connection and operation; lines of one connection share `conn`.

One line per operation:

    [<timestamp>] conn=<conn> fd=<fd> slot=<slot> connection from <client_ip> to <server_ip>
    [<timestamp>] conn=<conn> op=<op> BIND dn="<bind_dn>" method=<method> version=<version>
    [<timestamp>] conn=<conn> op=<op> RESULT err=<err> tag=<tag> nentries=<nentries> wtime=<wtime> optime=<optime> etime=<etime>[ dn="<bind_dn>"| - <reason>]
    [<timestamp>] conn=<conn> op=<op> fd=<fd> Disconnect - <close_reason>

- a successful bind's RESULT repeats the bound DN; a refused one ends with the reason (`Invalid credentials`,
  `No such entry`)

- `conn`, `op` - connection and operation numbers; `fd`, `slot` - the file descriptor and connection slot
- `client_ip` - the client; `server_ip` - the server address it connected to
- `bind_dn` - the DN a client binds as; `method` - 128 is a simple (password) bind; `version` - the LDAP version
- `err` - the LDAP result code (0 success, 49 invalid credentials); `tag` - the response type (97 bind, 120 extended)
- `nentries` - entries returned; `wtime`, `optime`, `etime` - wait, operation and elapsed times in seconds
- `close_reason` - why the connection closed (`Cleanly Closed Connection - U1`)
- the lines kept are connections, binds, results and disconnections; unbinds and extended operations are left out

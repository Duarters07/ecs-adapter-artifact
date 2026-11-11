# 389 Directory Server 3.1.2 - access log

Source: Red Hat Directory Server / 389 Directory Server documentation ("Access log reference"), official container
image. The access log records every client connection and operation; lines of one connection share `conn`.

One JSON object per line (`nsslapd-accesslog-log-format: json`, new in 3.1.2), its `operation` naming the event:

    {"local_time": "<timestamp>", "operation": "CONNECTION", "key": "<key>", "conn_id": <conn>, "fd": <fd>, "slot": <slot>, "tls": <tls>, "client_ip": "<client_ip>", "server_ip": "<server_ip>"}
    {"local_time": ..., "operation": "BIND", "key": ..., "conn_id": ..., "op_id": <op>, "bind_dn": "<bind_dn>", "version": <version>, "method": "<method>"}
    {"local_time": ..., "operation": "RESULT", "key": ..., "conn_id": ..., "op_id": ..., "msg": "<reason>", "tag": <tag>, "err": <err>, "nentries": <nentries>, "wtime": "<wtime>", "optime": "<optime>", "etime": "<etime>", "client_ip": "<client_ip>"[, "bind_dn": "<bind_dn>"]}
    {"local_time": ..., "operation": "DISCONNECT", "key": ..., "conn_id": ..., "op_id": ..., "fd": ..., "close_reason": "<close_reason>"}

- `key` - a key unique to the connection (`<epoch>-<conn>`); `tls` - whether the connection uses TLS
- `msg` - the result's text: the refusal reason (` - Invalid credentials`, ` - No such entry`), or a status

- `conn`, `op` - connection and operation numbers; `fd`, `slot` - the file descriptor and connection slot
- `client_ip` - the client; `server_ip` - the server address it connected to
- `bind_dn` - the DN a client binds as; `method` - 128 is a simple (password) bind; `version` - the LDAP version
- `err` - the LDAP result code (0 success, 49 invalid credentials); `tag` - the response type (97 bind, 120 extended)
- `nentries` - entries returned; `wtime`, `optime`, `etime` - wait, operation and elapsed times in seconds
- `close_reason` - why the connection closed (`Cleanly Closed Connection - U1`)
- the lines kept are connections, binds, results and disconnections; unbinds and extended operations are left out

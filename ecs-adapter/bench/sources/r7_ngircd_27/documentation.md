# ngIRCd 27 - console log (`ngircd -n`)

Source: ngIRCd documentation and ngircd(8) manual page, Debian package; a server password and one IRC operator block.
In the foreground the daemon writes one line per event:

    [<pid>:<level> <uptime>] <message>

`level` is the syslog severity number (3 error, 5 notice, 6 info); `uptime` counts seconds since the server started.

## The messages kept

    Accepted connection <conn> from "<client_ip>:<client_port>" on socket <socket>.
    User "<nick>!~<ident>@<client_ip>" registered (connection <conn>).
    User "<nick>!~<ident>@<client_ip>" rejected (connection <conn>): <reason>!
    User "<nick>!~<ident>@<client_ip>" unregistered (connection <conn>): <reason>.
    Client "<nick>" unregistered (connection <conn>): <reason>.
    Shutting down connection <conn> (<reason>) with "<client_ip>:<client_port>" ...
    Connection <conn> with "<client_ip>:<client_port>" closed (in: <bytes_in>, out: <bytes_out>).
    Got valid OPER for "<oper_name>" from "<nick>!~<ident>@<client_ip>", user is an IRC operator now.
    Got invalid OPER from "<nick>!~<ident>@<client_ip>": "<oper_name>" -- <reason>!

- `conn` - the connection number, reused once a connection closes; `socket` - the listening socket
- `nick` - the client's nickname, `ident` - its user name; `client_ip`, `client_port` - the client
- `reason` - why the client left or was refused (`Bad server password`, `Got QUIT command`, `bad password`,
  `not configured`)
- `oper_name` - the IRC operator account the client asked for; a valid OPER grants operator rights
- `bytes_in`, `bytes_out` - traffic of the connection, in kilobytes with one decimal (`2.2k`)

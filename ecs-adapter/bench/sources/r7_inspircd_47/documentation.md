# InspIRCd 4.7.0 - log file (`<log method="file" type="* -USERINPUT -USEROUTPUT">`)

Source: InspIRCd documentation (configuration, `<log>` tag), Debian package; one IRC operator block. One line per event:

    <timestamp> <type>: <message>

`timestamp` is local time, Fri 30 Oct 2026 19:12:52 (weekday, day, month, year, time); `type` is the log type that wrote the line (CONNECT, QUIT, OPER).

## The messages kept

    CONNECT: Client connecting on port <port> (class <conn_class>): <nick>!<ident>@<client_ip> (<client_ip>) [<realname>]
    QUIT: Client exiting: <nick>!<ident>@<client_ip> (<client_ip>) [<reason>]
    OPER: <nick> (<ident>@<client_ip>) [<client_ip>] is now a server operator of type <oper_type> (using account <oper_name>).
    OPER: <nick> (<ident>@<client_ip>) [<client_ip>] failed to log into the <oper_name> oper account because <reason>.

- `port` - the server port the client connected to; `conn_class` - the connect class that admitted it
- `nick`, `ident` - the client's nickname and user name; `client_ip` - its address; `realname` - the real name it sent
- `reason` - the quit message, or why an OPER attempt failed
- `oper_name` - the operator account asked for; `oper_type` - the operator type it grants

Values may carry IRC formatting codes, which are not part of the value: the real name is followed by a reset
(`\x0f`), and the operator account and type are wrapped in bold (`\x02admin\x02`).

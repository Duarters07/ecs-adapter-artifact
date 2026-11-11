# InspIRCd 3.15.0 - log file (`<log method="file" type="* -USERINPUT -USEROUTPUT">`)

Source: InspIRCd documentation (configuration, `<log>` tag), Debian package; one IRC operator block. One line per event:

    <timestamp> <type>: <message>

`timestamp` is local time, Fri Oct 30 2026 19:12:13 (weekday, month, day, year, time); `type` is the log type that wrote the line (CONNECT, QUIT, OPER).

## The messages kept

    CONNECT: Client connecting on port <port> (class <conn_class>): <nick>!<ident>@<client_ip> (<client_ip>) [<realname>]
    QUIT: Client exiting: <nick>!<ident>@<client_ip> (<client_ip>) [<reason>]
    OPER: <nick> (<ident>@<client_ip>) is now a server operator of type <oper_type> (using oper '<oper_name>')
    OPER: WARNING! Failed oper attempt by <nick>!<ident>@<client_ip> using login '<oper_name>': The following fields do not match: <reason>

- `port` - the server port the client connected to; `conn_class` - the connect class that admitted it
- `nick`, `ident` - the client's nickname and user name; `client_ip` - its address; `realname` - the real name it sent
- `reason` - the quit message, or why an OPER attempt failed
- `oper_name` - the operator account asked for; `oper_type` - the operator type it grants

Values may carry IRC formatting codes, which are not part of the value: the real name is followed by a reset
(`\x0f`).

# ProFTPD 1.3.8 - system log

Source: ProFTPD documentation, "SystemLog" and "Logging" (http://www.proftpd.org/docs/howto/Logging.html),
and the Debian package's configuration. Run in the foreground, ProFTPD writes its system log to
standard error:

    <timestamp> <host> <process>[<pid>] <server_ip> (<client_name>[<client_ip>]): <message>

## The messages kept

    FTP session opened.
    USER <user>: Login successful.
    USER <user> (Login failed): <reason>
    USER <user>: no such user found from <client_name> [<client_ip>] to <server_ip>:<server_port>
    SECURITY VIOLATION: <reason>

- `timestamp` - local time, with milliseconds after a comma
- `host`, `process`, `pid` - the server's host name, the daemon, and the id of the session's process
- `server_ip` - the server address the client connected to
- `client_name`, `client_ip` - the client's name (its address, since reverse DNS is off) and address
- `user` - the account named in the USER command
- `result` - `Login successful` or `Login failed`
- `reason` - why a login was refused: `Incorrect password`, `no such user found`, or a security
  violation such as `Root login attempted` (root logins are refused by default)
- `server_port` - the server's FTP port

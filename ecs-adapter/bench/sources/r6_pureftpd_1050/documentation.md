# Pure-FTPd 1.0.50 - syslog messages

Source: Pure-FTPd README ("Logging") and the Debian package. Pure-FTPd logs through syslog (facility ftp); here
rsyslog writes them to a file in its default high-precision format, and the daemon runs with `-H` (no reverse
DNS), so the client is shown by address:

    <timestamp> <host> pure-ftpd: (<session_user>@<client_ip>) [<level>] <message>

## The messages kept

    New connection from <client_ip>
    <user> is now logged in
    Authentication failed for user [<user>]
    Logout.
    <file> downloaded  (<bytes> bytes, <rate>)
    Can't open <file>: <reason>

- `timestamp` - RFC 3339 with microseconds; `host` - the server's host name
- `session_user` - the session's account, `?` before a successful login
- `client_ip` - the client address; `level` - INFO, NOTICE, WARNING, ERROR
- `user` - the account that logged in, or the name a failed login used
- `file`, `bytes`, `rate` - a download: path, size and transfer rate; `reason` - why a file could not be opened

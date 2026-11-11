# lighttpd 1.4.69 - error log, authentication

Source: lighttpd documentation, "server.errorlog" and mod_auth (https://redmine.lighttpd.net/projects/lighttpd/wiki/Mod_auth),
and the Debian package's configuration (/var/log/lighttpd/error.log). One line per event:

    <timestamp>: (<module>.c.<line>) <message>

## The message kept

    password doesn't match for <path> username: <user> IP: <client_ip>

Logged by mod_auth when a basic-auth login to a protected path is refused: a wrong password, or a user the
user file does not hold (the two are not told apart). A request without credentials is not logged here.

- `timestamp` - local time, seconds
- `module`, `line` - the source file and line that logged the event
- `path` - the requested protected path
- `user` - the username sent; `client_ip` - the client address

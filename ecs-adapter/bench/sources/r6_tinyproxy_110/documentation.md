# Tinyproxy 1.10.0 - log file, LogLevel Info

Source: tinyproxy.conf(5) ("LogFile", "LogLevel", "Allow", "BasicAuth") (https://tinyproxy.github.io/), Debian package.
One line per event:

    <LEVEL> <timestamp> [<pid>]: <message>

`timestamp` is local time, Mon DD hh:mm:ss.

## The messages kept

    Connect (file descriptor <fd>): <client_name> [<client_ip>]
    Request (file descriptor <fd>): <method> <url> HTTP/<http_version>
    Unauthorized connection from "<client_name>" [<client_ip>].
    Established connection to host "<dest_host>" using file descriptor <fd>.

- `level` - CONNECT, NOTICE, INFO...; `pid` - the process serving the client
- `fd` - the descriptor that ties a client's Connect and Request lines together
- `client_ip` - the client address; `client_name` its reverse-DNS name
- `method`, `url`, `http_version` - the proxied request; `dest_host` - the upstream host the proxy connected to
- Unauthorized connection: the client is outside the `Allow` list and is refused

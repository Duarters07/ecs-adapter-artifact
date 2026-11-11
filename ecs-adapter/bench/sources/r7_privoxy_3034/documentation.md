# Privoxy 3.0.34 - log (debug 1, 1024, 4096, 8192), written to the console under --no-daemon

Source: Privoxy user manual, configuration file section "debug" and "logfile", Debian package. One line per event:

    <yyyy-mm-dd hh:mm:ss.mmm> <thread> <message>

## The messages kept

    Request: <host><path>
    Crunch: <reason>: <url>

- `thread` - the id of the thread serving the request (hexadecimal)
- `host`, `path` - the requested host and path (the request line in short form)
- Crunch: Privoxy answered the request itself instead of forwarding it; `reason` is why (`Blocked` for a block
  action, `DNS failure` for an unresolvable host) and `url` the full requested URL
- the client's address is not written in these lines

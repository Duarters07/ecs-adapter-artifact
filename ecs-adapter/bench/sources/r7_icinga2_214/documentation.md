# Icinga 2 2.14.6 - main log (/var/log/icinga2/icinga2.log), REST API connections

Source: Icinga 2 documentation, "Logging" (the mainlog feature) and "Icinga 2 API" (ApiUser objects, HTTP basic
authentication), Debian package. One line per event:

    [<yyyy-mm-dd hh:mm:ss +zzzz>] <level>/<logger>: <message>

## The messages kept

    New client connection from [<client_ip>]:<client_port> (<cert>)
    Request <method> <path> (from [<client_ip>]:<client_port>), user: <user>, agent: <agent>, status: <status>) took total <took_ms>ms.
    HTTP client disconnected (from [<client_ip>]:<client_port>)

- `level` - information for these lines; `logger` - the component (ApiListener, HttpServerConnection)
- `client_ip`, `client_port` - the API client (written as an IPv4-mapped IPv6 address, `::ffff:` + IPv4)
- `cert` - whether the client presented a TLS certificate
- `method`, `path` - the API request; `agent` - its User-Agent
- `user` - the ApiUser authenticated by basic auth, `<unauthenticated>` when authentication failed (the name
  attempted is not logged)
- `status` - the HTTP status phrase of the answer (OK, Unauthorized...)
- `took_ms` - the time the request took, in milliseconds

# HAProxy 2.8 - the site's JSON log format

Source: the site's haproxy.cfg (log-format, HAProxy 2.8 Configuration Manual section 8.2.4).

    log-format '{"client_ip":"%ci","client_port":%cp,"accept_date":"%tr","frontend":"%ft","backend":"%b","server":"%s","status":%ST,"bytes_read":%B,"method":"%HM","path":"%HU","http_version":"%HV","total_ms":%Ta,"user_agent":"%[capture.req.hdr(0)]"}'

One JSON object per request.

- `total_ms` - the total time to serve the request, milliseconds
- `user_agent` - the User-Agent header of the request

- `client_ip`, `client_port` - the address and port of the client that connected
- `accept_date` - when the connection was accepted, `dd/Mmm/yyyy:HH:MM:SS.mmm`
- `frontend` - the frontend (listener) that received the request
- `backend`, `server` - the backend and server the request was sent to; `<NOSRV>` when
  the request was answered by the proxy itself (for example a deny rule)
- `status` - the HTTP status code returned to the client
- `bytes_read` - the bytes sent to the client, headers included
- `method`, `path`, `http_version` - the request line

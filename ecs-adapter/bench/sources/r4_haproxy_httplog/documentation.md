# HAProxy 2.8 - HTTP log (option httplog)

Source: HAProxy 2.8 Configuration Manual, section 8.2.3 "HTTP log format",
https://docs.haproxy.org/2.8/configuration.html#8.2.3

    <client_ip>:<client_port> [<accept_date>] <frontend> <backend>/<server> <timers> <status> <bytes_read> <req_cookie> <res_cookie> <term_state> <conns> <queues> "<method> <path> <http_version>"

- `timers` - Tq/Tw/Tc/Tr/Ta, milliseconds
- `term_state` - the session termination state, four characters
- `conns` - actconn/feconn/beconn/srv_conn/retries
- `queues` - srv_queue/backend_queue

- `client_ip`, `client_port` - the address and port of the client that connected
- `accept_date` - when the connection was accepted, `dd/Mmm/yyyy:HH:MM:SS.mmm`
- `frontend` - the frontend (listener) that received the request
- `backend`, `server` - the backend and server the request was sent to; `<NOSRV>` when
  the request was answered by the proxy itself (for example a deny rule)
- `status` - the HTTP status code returned to the client
- `bytes_read` - the bytes sent to the client, headers included
- `method`, `path`, `http_version` - the request line

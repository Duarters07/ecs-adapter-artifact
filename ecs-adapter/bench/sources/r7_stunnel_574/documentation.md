# stunnel 5.74 (OpenSSL 3.5) - log, debug level 5 (notice), foreground on stderr

Source: stunnel(8) manual ("debug", "foreground", "verifyChain", "requireCert") (https://www.stunnel.org/static/stunnel.html),
Debian package. A TLS front end that requires a client certificate from the lab CA. One line per event:

    <yyyy.mm.dd hh:mm:ss> LOG<level>[<thread>]: <message>

## The messages kept

    Service [<service>] accepted connection from <client_ip>:<client_port>
    Certificate accepted at depth=<depth>: <subject>
    CERT: Pre-verification error: <verify_error>
    Rejected by CERT at depth=<depth>: <subject>
    SSL_accept: <ssl_location>: <ssl_error>
    Connection closed: <bytes_tls> byte(s) sent to TLS, <bytes_socket> byte(s) sent to socket
    Connection reset/closed: <bytes_tls> byte(s) sent to TLS, <bytes_socket> byte(s) sent to socket

- `level` - syslog severity number (5 notice, 4 warning, 3 error); `thread` - the connection's thread id, which ties
  the lines of one client connection together (only the first names the client)
- `service` - the stunnel service section; `client_ip`, `client_port` - the TLS client
- `subject` - the client certificate's subject; `depth` - its position in the chain
- `verify_error` - why OpenSSL's pre-verification refused the certificate; `ssl_error` - the OpenSSL error of the
  refused handshake, `ssl_location` - where in OpenSSL it was raised
- `bytes_tls`, `bytes_socket` - bytes sent each way when the connection ends

# Unbound 1.17.1 - log on stderr, verbosity 1, log-queries and log-replies

Source: unbound.conf(5) ("log-queries", "log-replies", "verbosity", "access-control"), Debian package. One line per
query and one per reply:

    [<timestamp>] unbound[<pid>:<thread>] <level>: <client_ip> <qname> <qtype> <qclass>
    [<timestamp>] unbound[<pid>:<thread>] <level>: <client_ip> <qname> <qtype> <qclass> <rcode> <response_time> <cached> <size>

`timestamp` is seconds since the epoch. A query refused by access-control is logged as a reply only, with the
question unread: `<client_ip> null TYPE0 CLASS0 REFUSED ...`.

- `client_ip` - the client; `qname`, `qtype`, `qclass` - the question
- `rcode` - the reply's response code (NOERROR, NXDOMAIN, REFUSED...)
- `response_time` - seconds taken; `cached` - 1 if answered from the cache; `size` - reply size in bytes
- `pid`, `thread` - the server process and its thread; `level` - info for these lines

# Courier IMAP 5.0 (Debian 11) - imapd syslog messages

Source: courier-imap documentation (imapd(8), "Logging") (https://www.courier-mta.org/imap/), Debian package. imapd logs
through syslog (facility mail); rsyslog writes them in its default high-precision format:

    <timestamp> <host> imapd: <event>, [user=<user>, ]ip=[<client_ip>], port=[<client_port>][, <key>=<value>...]

The address is shown as an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`).

## The events kept

    Connection, ip=[...], port=[...]
    LOGIN, user=<user>, ip=[...], port=[...], protocol=IMAP
    LOGIN FAILED, user=<user>, ip=[...], port=[...]
    LOGOUT, user=<user>, ip=[...], port=[...], headers=<n>, body=<n>, rcvd=<bytes>, sent=<bytes>, time=<s>
    Disconnected, ip=[...], port=[...], time=<s>

- `user` - the account; `client_ip`, `client_port` - the client's address and port
- `protocol` - IMAP; `rcvd`, `sent` - bytes received and sent in the session; `time` - its length in seconds

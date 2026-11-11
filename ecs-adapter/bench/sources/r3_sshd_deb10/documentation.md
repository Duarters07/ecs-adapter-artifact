# OpenSSH 7.9 — sshd authentication messages

Source: OpenSSH sshd(8) and the messages of auth.c / sshd.c in OpenSSH 7.9.
`sshd` writes one line per event to its log target; collected here from its
standard error (`sshd -D -e`), so a line carries no syslog header.

    Failed password for <user> from <src_ip> port <src_port> ssh2
    Failed password for invalid user <user> from <src_ip> port <src_port> ssh2
    Accepted password for <user> from <src_ip> port <src_port> ssh2
    Invalid user <user> from <src_ip> port <src_port>
    Connection closed by authenticating user <user> <src_ip> port <src_port> [preauth]
    Connection closed by invalid user <user> <src_ip> port <src_port> [preauth]
    Did not receive identification string from <src_ip> port <src_port>

- `outcome` — `Failed` or `Accepted`: whether the authentication attempt succeeded
- `method` — the authentication method (`password`)
- `user` — the account the client tried to log in as
- `src_ip`, `src_port` — the address and port the client connected from

# Dovecot 2.4 - IMAP login log

Source: Dovecot 2.4 documentation, "Logging" and the imap-login messages.

    <timestamp> <process>: Info: <message>

## The messages kept

    Logged in: user=<<user>>, method=<method>, rip=<rip>, lip=<lip>, mpid=<mpid>, session=<<session>>
    Login aborted: Connection closed (auth failed, N attempts in S secs) (auth_failed): user=<<user>>, method=<method>, rip=<rip>, lip=<lip>, session=<<session>>

- `result` - the event: a successful login, or a connection closed after failed authentication
- `user` - the account the client tried to log in as
- `method` - the SASL mechanism (PLAIN)
- `rip`, `lip` - the remote (client) and local (server) addresses
- `mpid` - the process id of the mail process started for a successful login
- `session` - the session identifier

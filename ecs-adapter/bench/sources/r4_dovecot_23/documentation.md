# Dovecot 2.3 - IMAP login log

Source: Dovecot 2.3 documentation, "Logging" and the imap-login messages.

    <timestamp> <process>: Info: <message>

## The messages kept

    Login: user=<<user>>, method=<method>, rip=<rip>, lip=<lip>, mpid=<mpid>, session=<<session>>
    Disconnected (auth failed, N attempts in S secs): user=<<user>>, method=<method>, rip=<rip>, lip=<lip>, session=<<session>>

- `result` - the event: a successful login, or a connection closed after failed authentication
- `user` - the account the client tried to log in as
- `method` - the SASL mechanism (PLAIN)
- `rip`, `lip` - the remote (client) and local (server) addresses
- `mpid` - the process id of the mail process started for a successful login
- `session` - the session identifier

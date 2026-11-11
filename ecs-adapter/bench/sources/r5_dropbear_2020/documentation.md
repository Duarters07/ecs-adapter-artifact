# Dropbear SSH server 2020.81 - log

Source: dropbear(8), Debian package 2020.81 (`-F` foreground, `-E` log to standard error).

Every line is `[<pid>] <timestamp> <message>`, with the id of the process that handles the
connection and the local time as `Mmm dd HH:MM:SS`.

## The messages kept

    Child connection from <client_ip>:<client_port>
    Password auth succeeded for '<user>' from <client_ip>:<client_port>
    Bad password attempt for '<user>' from <client_ip>:<client_port>
    Login attempt for nonexistent user
    Exit before auth from <<client_ip>:<client_port>>: (user '<user>', <fails> fails): <reason>
    Exit before auth from <<client_ip>:<client_port>>: <reason>
    Exit (<user>) from <<client_ip>:<client_port>>: <reason>

- `pid` - the id of the process serving the connection
- `client_ip`, `client_port` - the address and port of the client
- `user` - the account the client tried, or logged in as
- `result` - what happened to the authentication attempt (the text of the message)
- `fails` - how many authentication attempts failed before the connection ended
- `reason` - why the connection ended (`Exited normally`, `Disconnect received`, ...)

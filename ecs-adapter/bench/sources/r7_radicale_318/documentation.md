# Radicale 3.1.8 - server log on stderr, level info

Source: Radicale documentation ("Logging" and "Authentication" settings), Debian package, htpasswd authentication.
One line per event:

    [<timestamp>] [<pid>/<thread>] [<level>] <message>

`timestamp` is local time with its UTC offset; `thread` names the request thread (`Thread-N (process_request_thread)`).

## The messages kept

    Successful login: '<user>'
    Failed login attempt from <client_ip>: '<user>'

- `level` - INFO for a success, WARNING for a refusal
- `user` - the username the client sent; `client_ip` - the client address (only on the refusal line)

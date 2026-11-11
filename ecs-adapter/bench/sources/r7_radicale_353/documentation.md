# Radicale 3.5.3 - server log on stderr, level info

Source: Radicale documentation ("Logging" and "Authentication" settings), Debian package, htpasswd authentication.
One line per event:

    [<timestamp>] [<pid>/<thread>] [<level>] <message>

`timestamp` is local time with its UTC offset; `thread` names the request thread (`Thread-N (process_request_thread)`).

## The messages kept

    Successful login: '<user>' (<backend>)
    Failed login attempt from <client_ip>: '<user>' (<backend>)
    Login verification failed for user: '<user>' (<auth_method>)
    Login verification user not found (<backend>): '<user>'

- `level` - INFO for a success, WARNING for a refusal
- `user` - the username the client sent; `client_ip` - the client address (only on the refusal line)
- `backend` - the authentication backend that answered (`htpasswd`)
- `auth_method` - backend, password encryption and method (`htpasswd/plain/PLAIN`)
- a refused login logs the backend's reason first (wrong password, or unknown user), then the
  `Failed login attempt` line with the client address

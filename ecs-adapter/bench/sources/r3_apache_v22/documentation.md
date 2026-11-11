# Apache httpd 2.2 — error log

Source: Apache HTTP Server 2.2 documentation, "Log Files",
https://httpd.apache.org/docs/2.2/logs.html#errorlog

A line of the error log reads

    [<timestamp>] [<level>] [client <client_ip>] <message>[, referer: <referer>]

- `timestamp` — `Www Mmm dd HH:MM:SS yyyy`
- `level` — the severity of the message: `error`, `warn`, `info`, ...
- `client_ip` — the address of the client that sent the request
- `referer` — the Referer header of the request, when the client sent one

## The three messages captured, and the names of their parts

    user <user>: authentication failure for "<url_path>": <reason>
    user <user> <reason>: <url_path>          (reason is "not found")
    <reason>: <file_path>                      (reason is "client denied by server configuration")

- `user` — the account in the request's credentials
- `url_path` — the path of the requested URL
- `file_path` — the file system path the request was resolved to
- `reason` — why the request was refused

# Apache httpd 2.4 — error log

Source: Apache HTTP Server documentation, "ErrorLogFormat" and "Log Files",
https://httpd.apache.org/docs/2.4/mod/core.html#errorlogformat and
https://httpd.apache.org/docs/2.4/logs.html#errorlog

With the default ErrorLogFormat a line reads

    [<timestamp>] [<module>:<level>] [pid <pid>:tid <tid>] [client <client_ip>:<client_port>] <code>: <message>[, referer: <referer>]

- `timestamp` — `Www Mmm dd HH:MM:SS.uuuuuu yyyy`
- `module` — the module that logged the message: `auth_basic`, `authz_core`
- `level` — the log level: `error`, `warn`, `info`, ...
- `pid`, `tid` — the process and thread of the server worker
- `client_ip`, `client_port` — the address and port of the client that sent the request
- `code` — Apache's message identifier, `AH` and five digits
- `referer` — the Referer header of the request, when the client sent one

## The three messages captured, and the names of their parts

    AH01617: user <user>: authentication failure for "<url_path>": <reason>
    AH01618: user <user> <reason>: <url_path>          (reason is "not found")
    AH01630: <reason>: <file_path>                      (reason is "client denied by server configuration")

- `user` — the account in the request's credentials
- `url_path` — the path of the requested URL
- `file_path` — the file system path the request was resolved to
- `reason` — why the request was refused

# Matrix Synapse 1.120.2 - homeserver log, default text formatter

Source: Synapse documentation, "Logging" / structured logging (vendor documentation), official image. The server writes
the default formatter of the packaged log configuration, one line per record:

    <yyyy-mm-dd hh:mm:ss,mmm> - <logger> - <lineno> - <level> - <request> - <message>

`logger` is the Python logger (synapse.rest.client.login, synapse.handlers.auth, synapse.access.http.<port>),
`lineno` the source line that logged it, `request` the request id (`POST-7`) that ties the lines of one request.

## The messages kept (password logins through the client API)

    Got login request with identifier: {'type': 'm.id.user', 'user': '<login_user>'}, medium: None, address: None, user: None
    Logging in user <user_id> on device <device>
    Failed password login for user <user_id>
    Attempted to login as <user_id> but they do not exist
    <client_ip> - <port> - {<requester>} Processed request: <timings> <bytes>B <status> "<method> <url> HTTP/<http_version>" "<user_agent>" [<n> dbevts]

- `login_user` - the user name the client submitted; `user_id` - the full Matrix id (`@name:server`)
- `device` - the device id a successful login is given
- `client_ip` - the client address (IPv4-mapped IPv6 here); `status` - 200 for a login, 403 for a refused one
- `bytes` - the response size; `method`, `url`, `http_version`, `user_agent` - the HTTP request

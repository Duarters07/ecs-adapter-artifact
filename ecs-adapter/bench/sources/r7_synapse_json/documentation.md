# Matrix Synapse 1.120.2 - homeserver log, TerseJsonFormatter

Source: Synapse documentation, "Logging" / structured logging (vendor documentation), official image. The server writes
synapse.logging.TerseJsonFormatter, one JSON object per record:

    {"log": "<message>", "namespace": "<logger>", "level": "<level>", "time": <epoch seconds>, "request": "<request>",
     "ip_address": "<client_ip>", "site_tag": "<port>", "requester": ..., "authenticated_entity": ...,
     "method": "<method>", "url": "<url>", "protocol": "HTTP/<version>", "user_agent": "<agent>",
     "server_name": "<server name>"}

Every record carries the request's client address, method, URL and agent; `request` ties the records of one request.

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

# Mattermost Team Edition 10.5.2 - server console log, plain (LogSettings.ConsoleJson=false)

Source: Mattermost documentation, "Logging" settings (vendor documentation), official image. Console level DEBUG.
The server writes one line per record, the message padded, then key=value pairs:

    <level> [<yyyy-mm-dd hh:mm:ss.mmm Z>] <message> caller="<file:line>" <key>=<value> ...

A value with spaces is quoted; an empty value is written `key=`.

## The messages kept (password logins through the API, POST /api/v4/users/login)

    Received HTTP request                 caller, method, url, request_id, user_id, status_code
    A user tried to sign in, which matched a Mattermost account, but the password was incorrect.
                                          caller, path, request_id, ip_addr, user_id, method, username
    Enter a valid email or username and/or password.
                                          caller, path, request_id, ip_addr, user_id, method, err_where, http_code, error

- `request_id` ties the lines of one request; only the refusal lines carry the client address (`ip_addr`)
- `user_id` - the account id of a successful login (empty when refused); `username` - the account a wrong password was
  tried against (an unknown user is refused without it)
- `status_code` - the response status of the request line; `http_code` - the status the refusal sets (401)
- `url` (request line) and `path` (refusal lines) are both the request path; `caller` - source file and line

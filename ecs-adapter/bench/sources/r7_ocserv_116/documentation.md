# ocserv 1.1.6 - OpenConnect VPN server, syslog (default level), via rsyslog

Source: ocserv(8) manual (vendor documentation), Debian package. Password authentication against a plain password
file. rsyslog writes one line per message:

    <timestamp> <host> ocserv[<pid>]: <component>: <message>

## The messages kept

    sec-mod: initiating session for user '<user>' (session: <session>)
    sec-mod: invalidating session of user '<user>' (session: <session>)
    plain-auth: error authenticating user '<user>'
    worker[<user>]: <client_ip> <src_location>: failed authentication for '<user>'

- `component` - the ocserv process that logs: sec-mod (security module), plain-auth, worker (one per client), main
- `user` - the username submitted; `session` - the session id sec-mod assigns
- `client_ip` - the VPN client
- `src_location` - the source file and line that logged the failure
- A successful login is logged only by sec-mod, without the client address.

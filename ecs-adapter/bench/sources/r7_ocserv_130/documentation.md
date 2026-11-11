# ocserv 1.3.0 - OpenConnect VPN server, syslog (default level), via rsyslog

Source: ocserv(8) manual (vendor documentation), Debian package. Password authentication against a plain password
file. rsyslog writes one line per message:

    <timestamp> <host> ocserv[<pid>]: <component>: <message>

## The messages kept

    sec-mod: initiating session for user '<user>' (session: <session>)
    sec-mod: invalidating session of user '<user>' (session: <session>)
    plain-auth: error authenticating user '<user>'
    worker[<user>]: <client_ip> <src_location>: failed authentication for '<user>'
    main[<user>]:<client_ip>:<client_port> new user session
    main[<user>]:<client_ip>:<client_port> user logged in
    main[<user>]:<client_ip>:<client_port> user disconnected (reason: <reason>, rx: <rx>, tx: <tx>)

- `component` - the ocserv process that logs: sec-mod (security module), plain-auth, worker (one per client), main
- `user` - the username submitted; `session` - the session id sec-mod assigns
- `client_ip`, `client_port` - the VPN client
- `src_location` - the source file and line that logged the failure
- `reason`, `rx`, `tx` - why the session ended and the bytes received from and sent to the client

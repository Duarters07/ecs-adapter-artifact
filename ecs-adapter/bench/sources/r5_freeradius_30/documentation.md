# FreeRADIUS 3.0 - authentication log

Source: radiusd.conf(5) and the packaged radiusd.conf, section `log` (`auth = yes` logs every
authentication request and its result), FreeRADIUS 3.0 documentation, https://freeradius.org/documentation/

Run with `-l stdout`, every request writes one line:

    <timestamp> : Auth: (<request_id>) <result>: [<user>] (from client <nas> port <nas_port>)
    <timestamp> : Auth: (<request_id>) <result> (<reason>): [<user>] (from client <nas> port <nas_port>)

- `timestamp` - local time, `Www Mmm dd HH:MM:SS yyyy`
- `request_id` - the server's number for the request
- `result` - `Login OK` (Access-Accept) or `Login incorrect` (Access-Reject)
- `reason` - why the request was rejected, as the module reports it: a wrong password
  (`pap: Cleartext password does not match "known good" password`), or an unknown user
  (`No Auth-Type found: rejecting the user via Post-Auth-Type = Reject`)
- `user` - the User-Name of the request
- `nas` - the short name of the RADIUS client (the network access server) that sent the request:
  `ap-floor1` (a Wi-Fi access point) or `vpn-gw` (a VPN gateway)
- `nas_port` - the NAS-Port of the request

# sg_vpn_native

OpenVPN server log over syslog: client authentication, address assignment and session messages, prefixed with user/address:port.

## Capture names

Use these names for the values the lines carry:

- `src_ip` - the address the connection or request came from
- `src_port` - the port it came from
- `user` - the account involved

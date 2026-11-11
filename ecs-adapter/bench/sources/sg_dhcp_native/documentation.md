# sg_dhcp_native

ISC dhcpd log over syslog: DISCOVER, OFFER, REQUEST and ACK messages with the leased address, the client MAC and hostname, and the interface.

## Capture names

Use these names for the values the lines carry:

- `outcome` - whether the attempt succeeded
- `host` - the machine that wrote the line
- `src_ip` - the address the connection or request came from
- `client_mac` - the client's hardware address

# OpenVPN 2.6 - server log, verb 3

Source: openvpn(8), "--verb", and the OpenVPN 2.6 reference manual,
https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/

Every line is `<timestamp> <peer> <message>`. The peer is the client's `<client_ip>:<client_port>`;
once the client's certificate has been accepted and the session set up it becomes
`<common_name>/<client_ip>:<client_port>`; some messages have no peer.

## The messages kept (authentication and certificate verification)

    VERIFY OK: depth=<depth>, CN=<cert_cn>
    VERIFY ERROR: depth=<depth>, error=<error>: CN=<cert_cn>, serial=<serial>
    TLS Auth Error: <error>
    [<common_name>] Peer Connection Initiated with [AF_INET]<client_ip>:<client_port>
    SENT CONTROL [<common_name>]: '<control>' (status=<status>)
    TLS Error: <error>
    MULTI_sva: pool returned IPv4=<vpn_ip>, IPv6=<vpn_ipv6>

- `timestamp` - local time
- `client_ip`, `client_port` - the client's address and port
- `common_name` - the common name of the client's certificate, the identity the session runs as
- `depth`, `cert_cn` - the position of a certificate in the chain (0 the client, 1 its CA) and its
  common name
- `error` - why verification or authentication failed: an untrusted certificate
  (`unable to get local issuer certificate`), a rejected username or password
  (`Auth Username/Password verification failed for peer`), a failed TLS handshake
- `serial` - the serial number of the refused certificate
- `control`, `status` - a control message sent to the client (`AUTH_FAILED`) and its status
- `vpn_ip`, `vpn_ipv6` - the tunnel address given to the client
- `sid` - the TLS session id

A refused password is answered twice, once to the session before its name is known (`[UNDEF]`).

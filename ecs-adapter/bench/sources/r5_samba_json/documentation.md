# Samba 4.17 - authentication audit as JSON (`auth_json_audit`)

Source: smb.conf(5), "log level" (debug class `auth_json_audit`), and the Samba wiki, "Setting up
Audit Logging", https://wiki.samba.org/index.php/Setting_up_Audit_Logging

With `log level = 1 auth_json_audit:3`, every authentication attempt writes one JSON object on a
line of its own, indented by two spaces, always with the keys in this order:

    {"timestamp": "<timestamp>", "type": "Authentication", "Authentication": {"version": {"major": 1, "minor": 2}, "eventId": <eventId>, "logonId": "<logonId>", "logonType": <logonType>, "status": "<status>", "localAddress": "ipv4:<local_ip>:<local_port>", "remoteAddress": "ipv4:<remote_ip>:<remote_port>", "serviceDescription": "<..>", "authDescription": <..>, "clientDomain": "<..>", "clientAccount": "<..>", "workstation": "<..>", "becameAccount": <..>, "becameDomain": <..>, "becameSid": <..>, "mappedAccount": "<..>", "mappedDomain": "<..>", "netlogonComputer": null, "netlogonTrustAccount": null, "netlogonNegotiateFlags": "0x00000000", "netlogonSecureChannelType": 0, "netlogonTrustAccountSid": null, "passwordType": "<..>", "duration": <duration>}}

A value that does not apply is `null` (the `became*` keys of a failed attempt).

- `timestamp` - the time of the attempt
- `Authentication.eventId` - the Windows event id of the result: 4624 logon succeeded, 4625 logon failed
- `Authentication.logonId`, `Authentication.logonType` - the logon session id and type (3: network)
- `Authentication.status` - the NT status of the result: `NT_STATUS_OK`, `NT_STATUS_WRONG_PASSWORD`, ...
- `Authentication.localAddress`, `Authentication.remoteAddress` - the server's and the client's
  address, `ipv4:<ip>:<port>`
- `Authentication.serviceDescription` - the service that asked for authentication (`SMB2`)
- `Authentication.clientDomain`, `Authentication.clientAccount` - the domain and account the client presented
- `Authentication.workstation` - the NetBIOS name the client gave for its machine
- `Authentication.becameAccount`, `becameDomain`, `becameSid` - the local account the session runs as
- `Authentication.mappedAccount`, `mappedDomain` - the account the attempt was mapped to
- `Authentication.passwordType` - how the password was presented (`NTLMv2`)
- `Authentication.duration` - the time the authentication took, microseconds

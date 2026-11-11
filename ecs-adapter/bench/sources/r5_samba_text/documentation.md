# Samba 4.17 - authentication audit, human-readable (`auth_audit`)

Source: smb.conf(5), "log level" (debug classes `auth_audit` and `auth_json_audit`), and the Samba
wiki, "Setting up Audit Logging", https://wiki.samba.org/index.php/Setting_up_Audit_Logging

With `log level = 1 auth_audit:3` and `debug prefix timestamp = yes`, every authentication attempt
writes one line to the log file. A successful attempt:

    [<timestamp>, <level>]   Auth: [<service>,<auth_description>] user [<client_domain>]\[<client_account>] at [<event_time>] with [<password_type>] status [<status>] workstation [<workstation>] remote host [ipv4:<remote_ip>:<remote_port>] became [<became_domain>]\[<became_account>] [<became_sid>]. local host [ipv4:<local_ip>:<local_port>]

A failed attempt ends `mapped to [<mapped_domain>]\[<mapped_account>]. local host [...]` instead
of `became ...`.

- `timestamp`, `level` - the debug header: the time, and the debug level of the message (3 for a
  success, 2 for a failure)
- `service` - the service that asked for authentication (`SMB2`)
- `auth_description` - a further description of the authentication, `(null)` when none
- `client_domain`, `client_account` - the domain and account the client presented
- `event_time` - the time of the attempt, as a date string
- `password_type` - how the password was presented (`NTLMv2`)
- `status` - the NT status of the result: `NT_STATUS_OK`, `NT_STATUS_WRONG_PASSWORD`,
  `NT_STATUS_NO_SUCH_USER`, ...
- `workstation` - the NetBIOS name the client gave for its machine
- `remote_ip`, `remote_port` - the client's address and port
- `local_ip`, `local_port` - the server's address and port
- `became_domain`, `became_account`, `became_sid` - the local account the session runs as, and its SID
- `mapped_domain`, `mapped_account` - the account the attempt was mapped to

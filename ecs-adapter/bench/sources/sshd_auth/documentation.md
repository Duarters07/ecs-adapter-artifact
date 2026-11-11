# OpenSSH 9.x — password authentication outcomes

Written by `sshd` to its log target, one line per authentication attempt. Two
message shapes, both ending in the authentication method:

```
Accepted password for USER from SRC_IP port SRC_PORT ssh2
Failed password for USER from SRC_IP port SRC_PORT ssh2
Failed password for invalid user USER from SRC_IP port SRC_PORT ssh2
```

The literal `invalid user` appears when the account does not exist on the host.
When it is absent the account exists and the password was wrong, or correct.

## Capture names

Use these names for the four values:

- `outcome` — the first word, `Accepted` or `Failed`
- `user` — the account the client offered
- `src_ip` — the address the connection came from
- `src_port` — the source port of that connection

`invalid user` is a literal in the pattern, not a value.

These lines carry no timestamp and no host: the daemon was started with `-e`,
so the surrounding syslog envelope that would normally supply both is absent.

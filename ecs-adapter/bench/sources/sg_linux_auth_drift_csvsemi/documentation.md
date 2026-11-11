# OpenSSH, sudo and PAM authentication log

Positional columns separated by ";", one entry per line.

```
TIME;SRC_IP;PID;SESSION;PORT;LOGIND_PID;UID;KEY_TYPE;USER;FINGERPRINT;KIND;TARGET_HOST;TTY;COMMAND;PWD;METHOD;OUTCOME
```

Example lines:

```
2026-10-14T08:01:21+00:00;10.20.1.11;11314;588;55373;659;1562;ED25519;mario.hernandez;SHA256:DQSXrPVed5HjrAoVrtyzpnVs+i4K9gVVk9jKMw378d/;ssh_accept;file.acme.local;;;;publickey;success
2026-10-14T09:06:43+00:00;10.20.1.11;11314;588;55373;659;1562;;mario.hernandez;;ssh_close;file.acme.local;;;;;success
```

- `time` — when the entry was logged
- `src_ip` — IP of the requesting host
- `pid` — recorded by the source
- `session` — recorded by the source
- `port` — remote peer's TCP/UDP port
- `logind_pid` — recorded by the source
- `uid` — uid
- `key_type` — recorded by the source
- `user` — user
- `fingerprint` — kept as written
- `kind` — internal to the product
- `target_host` — internal to the product
- `tty` — recorded by the source
- `command` — argv as typed
- `pwd` — kept as written
- `method` — vendor-specific value
- `outcome` — verdict

# OpenSSH, sudo and PAM authentication log

Key=value pairs separated by "; ", key and value joined by "=", one entry per line.

```
time=TIME; port=PORT; kind=KIND; src_ip=SRC_IP; pid=PID; fingerprint=FINGERPRINT; target_host=TARGET_HOST; user=USER; session=SESSION; outcome=OUTCOME; key_type=KEY_TYPE; uid=UID; logind_pid=LOGIND_PID; method=METHOD ...
```

Example lines:

```
time=2026-10-14T08:01:21+00:00; port=55373; kind=ssh_accept; src_ip=10.20.1.11; pid=11314; fingerprint=SHA256:DQSXrPVed5HjrAoVrtyzpnVs+i4K9gVVk9jKMw378d/; target_host=file.acme.local; user=mario.hernandez; session=588; outcome=success; key_type=ED25519; uid=1562; logind_pid=659; method=publickey
time=2026-10-14T09:06:43+00:00; port=55373; kind=ssh_close; src_ip=10.20.1.11; pid=11314; target_host=file.acme.local; user=mario.hernandez; session=588; outcome=success; uid=1562; logind_pid=659
```

- `time` — when the entry was logged
- `port` — remote peer's TCP/UDP port
- `kind` — recorded by the source
- `src_ip` — client IP
- `pid` — kept as written
- `fingerprint` — vendor-specific value
- `target_host` — recorded by the source
- `user` — account
- `session` — vendor-specific value
- `outcome` — status keyword
- `key_type` — kept as written
- `uid` — uid
- `logind_pid` — kept as written
- `method` — recorded by the source
- `command` — full invocation
- `pwd` — internal to the product
- `tty` — recorded by the source

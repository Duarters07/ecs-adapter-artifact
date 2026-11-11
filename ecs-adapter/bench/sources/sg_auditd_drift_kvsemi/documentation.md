# Linux audit daemon records

Key=value pairs separated by "; ", key and value joined by "=", one entry per line.

```
time=TIME; comm=COMM; euid=EUID; user=USER; cwd=CWD; uid=UID; tty=TTY; dev=DEV; pid=PID; exe=EXE; ses=SES; host=HOST; auid=AUID; syscall=SYSCALL ...
```

Example lines:

```
time=2026-10-14T08:01:21+00:00; comm=sudo; euid=0; user=mario.hernandez; cwd=/var/log; uid=1562; tty=pts3; dev=fd:01; pid=19029; exe=/usr/bin/sudo; ses=25; host=ws-it-001.acme.local; auid=1562; syscall=59; ppid=1257; seq=540686; inode=2740429
time=2026-10-14T08:01:40+00:00; comm=ss; euid=1562; user=mario.hernandez; cwd=/home/mario.hernandez/src; uid=1562; tty=pts0; dev=fc:02; pid=10310; exe=/usr/bin/ss; ses=176; host=ws-it-001.acme.local; auid=1562; syscall=59; ppid=1236; seq=353359; inode=9657465
```

- `time` — event time
- `comm` — program
- `euid` — recorded by the source
- `user` — account
- `cwd` — working dir
- `uid` — vendor-specific value
- `tty` — recorded by the source
- `dev` — kept as written
- `pid` — process ID
- `exe` — exe
- `ses` — kept as written
- `host` — kept as written
- `auid` — internal to the product
- `syscall` — internal to the product
- `ppid` — parent PID
- `seq` — serial
- `inode` — vendor-specific value

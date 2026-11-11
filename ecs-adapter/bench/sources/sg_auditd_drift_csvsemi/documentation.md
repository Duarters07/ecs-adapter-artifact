# Linux audit daemon records

Positional columns separated by ";", one entry per line.

```
TIME;COMM;USER;EUID;UID;SES;HOST;EXE;SEQ;CWD;INODE;TTY;PID;DEV;AUID;PPID;SYSCALL
```

Example lines:

```
2026-10-14T08:01:21+00:00;sudo;mario.hernandez;0;1562;25;ws-it-001.acme.local;/usr/bin/sudo;540686;/var/log;2740429;pts3;19029;fd:01;1562;1257;59
2026-10-14T08:01:40+00:00;ss;mario.hernandez;1562;1562;176;ws-it-001.acme.local;/usr/bin/ss;353359;/home/mario.hernandez/src;9657465;pts0;10310;fc:02;1562;1236;59
```

- `time` — event time
- `comm` — comm
- `user` — login name
- `euid` — recorded by the source
- `uid` — vendor-specific value
- `ses` — recorded by the source
- `host` — kept as written
- `exe` — image path
- `seq` — serial
- `cwd` — directory at exec time
- `inode` — recorded by the source
- `tty` — vendor-specific value
- `pid` — PID of the daemon
- `dev` — kept as written
- `auid` — vendor-specific value
- `ppid` — parent PID
- `syscall` — vendor-specific value

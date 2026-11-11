# vsftpd 3.x — transfer records

Written to vsftpd's own log, one line per completed or refused transfer:

```
DAY MON DD HH:MM:SS YYYY [pid PID] [USER] RESULT OPERATION: Client "CLIENT_IP", "PATH", SIZE bytes, RATE Kbyte/sec
```

Real examples:

```
Fri Oct  2 15:31:32 2026 [pid 17] [ftpuser] OK UPLOAD: Client "198.51.100.22", "/report.txt", 22 bytes, 46.91Kbyte/sec
Fri Oct  2 15:32:58 2026 [pid 40] [ftpuser] OK DOWNLOAD: Client "198.51.100.22", "/q4.csv", 18 bytes, 23.63Kbyte/sec
```

- The timestamp is vsftpd's own format, not syslog's, and carries no zone.
- `RESULT` is `OK` or `FAIL`.
- `OPERATION` is `UPLOAD`, `DOWNLOAD`, `DELETE`, `MKDIR` or `RMDIR`.
- `PATH` is absolute within the server's root, quoted.
- `SIZE` is the number of bytes transferred.
- `RATE` is the throughput in kilobytes per second, with the unit attached to
  the number.

The same file also carries `CONNECT` and `LOGIN` lines, which have a different
shape and are a different source.

## Capture names

- `pid` — the number after `pid` in the first bracket
- `user` — the account in the second bracket
- `result` — `OK` or `FAIL`
- `operation` — the transfer verb
- `client_ip` — the quoted address after `Client`
- `path` — the quoted path
- `size` — the byte count
- `rate` — the throughput figure, without the unit

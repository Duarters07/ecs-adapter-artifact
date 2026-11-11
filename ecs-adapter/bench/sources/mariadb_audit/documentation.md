# MariaDB 11.4 — server_audit plugin log (CSV)

Source: MariaDB Knowledge Base, "MariaDB Audit Plugin - Log Format",
https://mariadb.com/kb/en/mariadb-audit-plugin-log-format/

One event per line, comma-separated, no header, in this column order:

    timestamp,serverhost,username,host,connectionid,queryid,operation,database,object,retcode

- `timestamp` — `yyyyMMdd HH:mm:ss`, server local time
- `serverhost` — the host name of the MariaDB server writing the log
- `username` — the account the client connected as
- `host` — the host the CLIENT connected FROM (its address)
- `connectionid` — the server's connection number
- `queryid` — the query number within the connection; 0 for connection events
- `operation` — `CONNECT`, `FAILED_CONNECT`, `DISCONNECT`, `QUERY`, ...
- `database` — the default database of the connection, empty when none
- `object` — for QUERY, the statement text in single quotes; empty otherwise
- `retcode` — the server's return code: 0 on success, 1045 access denied, ...

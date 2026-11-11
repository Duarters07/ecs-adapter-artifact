# PostgreSQL 16 — `csvlog`

Written when `log_destination = csvlog` and `logging_collector = on`. One
comma-separated record per log message, with RFC 4180 quoting: a value
containing a comma or a quote is wrapped in double quotes and an embedded
quote is doubled. An empty value means the column does not apply to this
message. Every record has the same 26 columns, in this order:

```
log_time, user_name, database_name, process_id, connection_from, session_id,
session_line_num, command_tag, session_start_time, virtual_transaction_id,
transaction_id, error_severity, sql_state_code, message, detail, hint,
internal_query, internal_query_pos, context, query, query_pos, location,
application_name, backend_type, leader_pid, query_id
```

## What the columns mean

- `log_time` — when the message was written, with milliseconds and a zone
- `user_name`, `database_name` — the database role and database the session is using
- `process_id` — the operating-system process serving the session
- `connection_from` — the client's address and port joined by a colon, or
  `[local]` for a Unix-socket connection
- `session_id`, `session_line_num` — session identifier and the message's position within it
- `command_tag` — what the session was doing: `authentication`, `startup`, `idle`, `SELECT`
- `session_start_time` — when the session began
- `virtual_transaction_id`, `transaction_id` — transaction identifiers
- `error_severity` — `LOG`, `WARNING`, `ERROR`, `FATAL`, `PANIC`
- `sql_state_code` — the five-character SQLSTATE: `00000` for success, `42P01`
  for undefined table, `28000` for an invalid authorisation specification
- `message` — the message itself
- `detail`, `hint`, `context`, `internal_query`, `internal_query_pos`, `query`,
  `query_pos`, `location` — diagnostic detail, mostly empty
- `application_name` — a label the client chose for itself, such as `psql`
- `backend_type` — `client backend`, `checkpointer`, `autovacuum launcher`, …
- `leader_pid` — the parallel-query leader, empty outside parallel execution
- `query_id` — the query's hash when `compute_query_id` is on, otherwise 0

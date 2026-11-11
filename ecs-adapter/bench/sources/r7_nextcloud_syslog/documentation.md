# Nextcloud 30.0.17 - admin_audit log, log_type_audit = syslog

Source: Nextcloud administration manual, "Logging" (log_type, log_type_audit, logfile_audit, syslog_tag_audit) and the
admin_audit app (vendor documentation), official image. The audit app logs at level 1 (info). The server writes
through syslog (`syslog_tag_audit` = Nextcloud-audit), rsyslog's line with the same JSON object as its message:

    <ISO 8601 time> <host> Nextcloud-audit[<pid>]: {"reqId": "<req_id>", "level": <level>, "time": "<ISO 8601>", "remoteAddr": "<client address>", "user": "<user>",
     "app": "admin_audit", "method": "<method>", "url": "<url>", "message": "<message>", "userAgent": "<agent>",
     "version": "<server version>", "data": {"app": "admin_audit"}}

## The messages kept (WebDAV logins)

    Login attempt: "<login_user>"
    Login successful: "<login_user>"
    Login failed: "<login_user>"

- `login_user` - the account named in the attempt (an unknown account is named too)
- `user` - the session's user: `--` until the login succeeds
- `remoteAddr` - the client address; `reqId` - ties the attempt to its outcome
- `level` - Nextcloud's numeric level (0 debug, 1 info, 2 warning, 3 error, 4 fatal)

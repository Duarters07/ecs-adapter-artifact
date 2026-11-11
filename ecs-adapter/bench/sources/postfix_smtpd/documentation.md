# Postfix 3.10 — `smtpd` recipient rejections

Written by the `smtpd` daemon through syslog, one line per rejected RCPT
command. The shape:

```
TIMESTAMP INFO    postfix/smtpd[PID]: NOQUEUE: reject: RCPT from CLIENT_NAME[CLIENT_IP]: ENHANCED_CODE <RECIPIENT>: REASON; from=<SENDER> to=<RECIPIENT> proto=PROTO helo=<HELO>
```

A real example, wrapped for reading:

```
2026-10-02T15:31:32.302065+00:00 INFO    postfix/smtpd[1047]:
  NOQUEUE: reject: RCPT from mail-out.example[198.51.100.9]:
  450 4.1.2 <bob@example.test>: Recipient address rejected: Domain not found;
  from=<alice@example.test> to=<bob@example.test> proto=ESMTP helo=<m1>
```

- `NOQUEUE` means the message never entered the queue, so it has no queue ID.
- `CLIENT_NAME` is the reverse-DNS name of the connecting host, or `unknown`.
- The SMTP status is a three-digit reply code followed by an enhanced status
  code, here `450` and `4.1.2`.
- The recipient appears twice: once in the rejection phrase and once as `to=`.
- `helo=` is whatever the client announced, which is unverified.

## Capture names

- `pid` — the smtpd process id in brackets after the program name
- `client_name` — the reverse-DNS name before the bracketed address
- `client_ip` — the address in brackets
- `smtp_code` — the three-digit SMTP reply code
- `dsn_code` — the enhanced status code
- `reason` — the text after the colon, before the semicolon
- `from` — the value of `from=`, without the angle brackets
- `to` — the value of `to=`, without the angle brackets
- `proto` — the value of `proto=`
- `helo` — the value of `helo=`

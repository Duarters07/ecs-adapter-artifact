# Postfix 3.5 - mail log (maillog_file)

Source: Postfix documentation, MAILLOG_README and the smtpd, qmgr and local manual pages,
https://www.postfix.org/MAILLOG_README.html

    <timestamp> <host> postfix/<process>[<pid>]: <message>

## The messages kept

    connect from <client_name>[<client_ip>]
    <queue_id>: client=<client_name>[<client_ip>]
    <queue_id>: from=<<from>>, size=<size>, nrcpt=<nrcpt> (queue active)
    <queue_id>: to=<<to>>, relay=<relay>, delay=<delay>, delays=..., dsn=<dsn>, status=<status> (<status_text>)
    NOQUEUE: reject: RCPT from <client_name>[<client_ip>]: <smtp_code> <dsn> <<rcpt>>: <reason>; from=<<from>> to=<<to>> proto=<proto> helo=<<helo>>

- `process`, `pid` - the Postfix daemon (smtpd, qmgr, local, cleanup) and its process id
- `queue_id` - the queue identifier of the message
- `client_name`, `client_ip` - the connecting client's reverse name and address
- `from`, `to` - envelope sender and recipient
- `relay` - where the message was delivered (`local`, or a next hop)
- `dsn`, `status` - the delivery status code and outcome (`sent`, `bounced`, `deferred`)
- `smtp_code`, `reason` - the SMTP reply code and text of a rejection
- `helo` - the name the client gave in HELO/EHLO

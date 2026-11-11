# Sendmail 8.18.1 - mail log (syslog facility mail, via rsyslog)

Source: Sendmail Installation and Operation Guide, logging section (vendor documentation), Debian package. Listens on
port 25 for lab.example, local delivery through procmail. rsyslog writes one line per message:

    <timestamp> <host> sendmail[<pid>]: <queue_id>: <message>

## The messages kept

    from=<<sender>>, size=<size>, class=<class>, nrcpts=<nrcpts>, [msgid=<<msgid>>, ]proto=<proto>, daemon=<daemon>, relay=<relay_host> [<client_ip>]
    to=<<rcpt>>, delay=<delay>, xdelay=<xdelay>, mailer=<mailer>, pri=<pri>, dsn=<dsn>, stat=<stat>
    <<rcpt>>... User unknown
    ruleset=<ruleset>, arg1=<<rcpt>>, relay=<relay_host> [<client_ip>], reject=<reason>

- `queue_id` - the queue id, the same on every line of one transaction
- `client_ip`, `relay_host` - the SMTP client's address and its reverse name
- `sender` - the envelope sender; `rcpt` - a recipient (delivered, unknown, or refused)
- `msgid` - the Message-ID header (absent when no recipient was accepted)
- `stat` - the delivery status (Sent); `dsn` - its enhanced status code
- `reason` - why a recipient was refused (`User unknown`, or the reply of a refused relay attempt);
  `ruleset` - the ruleset that refused it
- `size`, `class`, `nrcpts`, `proto`, `daemon`, `delay`, `xdelay`, `mailer`, `pri` - message and queue details

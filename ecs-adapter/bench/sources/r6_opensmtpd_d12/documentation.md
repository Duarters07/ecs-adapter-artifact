# OpenSMTPD 6.8 (Debian 12) - smtpd log, SMTP sessions

Source: OpenSMTPD manual, smtpd(8) and smtpd.conf(5) (https://man.openbsd.org/smtpd), and the Debian package. In the
foreground (`smtpd -d`) the daemon writes one line per session event to standard error, prefixed by the session id:

    <session> smtp <event> <key>=<value> ...

## The events kept

    <session> smtp connected address=<client_ip> host=<client_host>
    <session> smtp message msgid=<msgid> size=<size> nrcpt=<nrcpt> proto=<proto>
    <session> smtp failed-command command="<command>" result="<reason>"
    <session> smtp disconnected reason=<reason>

- `session` - the SMTP session id (16 hex digits), the same on every line of one session
- `client_ip`, `client_host` - the client's address and its reverse-DNS name
- `msgid`, `size`, `nrcpt`, `proto` - an accepted message: internal id, size in bytes, recipients, ESMTP or SMTP
- `command`, `reason` (the `result` value) - a refused command and the reply, such as an unknown recipient or a relay attempt
  (`550 Invalid recipient: <...>`)
- `reason` - why the session ended (`quit`, `disconnect`, or an I/O error)

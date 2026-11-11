# Kamailio 5.8.4 - SIP registrar log, JSON log engine

Source: Kamailio core cookbook ("log_prefix", "log_stderror") and the core's JSON log engine (vendor documentation),
official image. A registrar with digest authentication. Kamailio logs no authentication outcome by itself: the event
messages below are the routing script's own xlog lines, identical in both formats. The server writes the core JSON log engine (`kamailio --log-engine=json:M`), one JSON object per line:

    { "idx": <process rank>, "pid": <pid>, "level": "<LEVEL>", "module": "<module>", "file": "<source file>",
      "line": <source line>, "function": "<function>", "logprefix": "<log_prefix>", "message": "<message>" }

`log_prefix` is set to `{$mt $hdr(CSeq) $ci} `: the SIP message type (1 request), the CSeq header (number and
method) and the Call-ID.

## The messages kept (SIP REGISTER with digest authentication)

    REGISTER challenge for <user>@<domain> from <client_ip>:<client_port> ua=[<user_agent>]
    REGISTER accepted for <user>@<domain> from <client_ip>:<client_port> contact=<<contact>> expires=<expires>
    REGISTER auth failed: wrong password for <user>@<domain> from <client_ip>:<client_port> ua=[<user_agent>]
    REGISTER auth failed: unknown user <user>@<domain> from <client_ip>:<client_port> ua=[<user_agent>]

- `reason` - `wrong password` or `unknown user` (the second written without `for`); `user`, `domain` - the account and SIP domain
- `client_ip`, `client_port` - the SIP client (source of the request); `user_agent` - its User-Agent header
- `contact` - the registered contact URI; `expires` - its lifetime in seconds
- `call_id`, `cseq` - tie the challenge to the authenticated request

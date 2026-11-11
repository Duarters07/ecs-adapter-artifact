# Vaultwarden 1.25.2 - server log (LOG_LEVEL=warn, EXTENDED_LOGGING=true)

Source: Vaultwarden wiki, "Logging" and "Fail2Ban Setup" (https://github.com/dani-garcia/vaultwarden/wiki), official
image. The server writes to standard output, one line per event:

    [<timestamp>][<logger>][<level>] <message>

## The messages kept

    Username or password is incorrect. Try again. IP: <client_ip>. Username: <user>.
    Invalid admin token. IP: <client_ip>

- `timestamp` - local time with milliseconds; `logger` - the module (`vaultwarden::api::identity`, `::admin`)
- `level` - ERROR for these events
- `client_ip` - the client address; `user` - the account (an e-mail address) a refused vault login used
- the reason is the message itself: a refused vault login, or a wrong admin-panel token

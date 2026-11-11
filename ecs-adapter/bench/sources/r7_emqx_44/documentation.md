# EMQX 4.4.19 - console log, level info

Source: EMQX documentation ("Logs" configuration), official Docker image, default listener on 1883, default file ACL.

## The messages kept

    <timestamp> [<level>] <client_id>@<client_ip>:<client_port> PUBLISH to <topic>: <<<payload>>>
    <timestamp> [<level>] <client_id>@<client_ip>:<client_port> <client_id> SUBSCRIBE <topic>: Options: <options>
    <timestamp> [<level>] <client_id>@<client_ip>:<client_port> [Channel] Cannot subscribe <topic> with options <options> due to <reason>.
    <timestamp> [<level>] <client_id>@<client_ip>:<client_port> file: <file>, line: <line>, mfa: <mfa>, msg: terminate, pid: <erlang_pid>, reason: <reason>

EMQX 4 prefixes each client's lines with `clientid@address:port`. A publish logs the payload as an Erlang binary
(`<<"...">>`); a refused subscription logs the reason (`Not authorized`); the username is not logged.

- `level` - info, warning...; `client_id` - the MQTT client id; `client_ip`, `client_port` - the client
- `topic` - the MQTT topic (or filter) published or subscribed to
- `reason` - why a subscription was refused, or how the connection ended (`{shutdown,normal}`)

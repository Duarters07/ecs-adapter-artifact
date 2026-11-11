# EMQX 5.8.6 - console log, level info

Source: EMQX documentation ("Logs" configuration), official Docker image, default listener on 1883, default file ACL.

## The messages kept

    <timestamp> [<level>] tag: <tag>, clientid: <client_id>, msg: <action>, peername: <client_ip>:<client_port>, [username: <user>, ]topic: <topic>, source: <authz_source>, action: <operation>
    <timestamp> [<level>] clientid: <client_id>, msg: terminate, peername: <client_ip>:<client_port>, [username: <user>, ]reason: <reason>

EMQX 5 writes structured log events as `key: value` pairs separated by `, `. The authorization check of every publish
and subscribe is logged (`tag: AUTHZ`): `msg` is `authorization_permission_allowed` or
`authorization_permission_denied`, `source` the authorizer that decided (`file`, the default ACL), `action` the MQTT
operation with its QoS and retain flags (`PUBLISH(Q0,R0)`, `SUBSCRIBE(Q0)`). `username` is present only when the
client sent one.

- `level` - info, warning...; `client_id` - the MQTT client id; `client_ip`, `client_port` - the client
- `topic` - the MQTT topic (or filter) published or subscribed to
- `reason` - why a subscription was refused, or how the connection ended (`{shutdown,normal}`)

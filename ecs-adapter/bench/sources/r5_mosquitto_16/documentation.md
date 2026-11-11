# Eclipse Mosquitto 1.6 - broker log

Source: mosquitto.conf(5) (`log_dest`, `log_type`, `connection_messages`), Mosquitto 1.6
documentation, https://mosquitto.org/man/mosquitto-conf-5.html

With `log_dest stdout` and the default log types, every line is `<timestamp>: <message>`, where the
timestamp is in seconds since the Unix epoch.

## The messages kept

    New connection from <client_ip> on port <listener_port>.
    New client connected from <client_ip> as <client_id> (p<protocol_version>, c<clean_session>, k<keepalive>, u'<user>').
    Client <client_id> disconnected.
    Socket error on client <client_id>, disconnecting.

- `client_ip` - the address the client connected from
- `listener_port` - the broker's listener port the connection arrived on
- `client_id` - the MQTT client identifier the client chose
- `protocol_version` - the MQTT protocol level (`2` here, MQTT 3.1.1 on the wire is reported as 2 by this version)
- `clean_session`, `keepalive` - the session flag and the keep-alive interval, seconds
- `user` - the user name the client authenticated with
- a connection refused for a wrong user name or password is logged as a socket error on a client whose identifier is still `<unknown>`

# RabbitMQ 3.13 - console log (default text format)

Source: RabbitMQ documentation, "Logging" (https://www.rabbitmq.com/docs/logging). The official image logs
to standard output, one event per line, coloured with terminal escape codes:

    <timestamp> [<level>] <pid> <message>

A connection error is written as two lines with the same timestamp and pid: the error header, then the
reason.

## The messages kept

    accepting AMQP connection <conn> (<client_ip>:<client_port> -> <server_ip>:<server_port>)
    connection <conn> (<client>... -> <server>...): user '<user>' authenticated and granted access to vhost '<vhost>'
    closing AMQP connection <conn> (<client> -> <server>[, vhost: '<vhost>', user: '<user>'])
    Error on AMQP connection <conn> (<client> -> <server>[, user: '<user>'], state: <state>):
    PLAIN login refused: user '<user>' - invalid credentials
    access to vhost '<vhost>' refused for user '<user>'

- `timestamp` - UTC with microseconds and offset; `level` - info, warning, error
- `pid` - the Erlang process handling the connection; `conn` repeats it
- client and server address and port of the AMQP connection
- `user` - the account presented; `vhost` - the virtual host asked for
- `state` - the connection's state when it failed (starting: authentication, opening: vhost access)
- `reason` - `invalid credentials`, or `refused` for a vhost the account may not use

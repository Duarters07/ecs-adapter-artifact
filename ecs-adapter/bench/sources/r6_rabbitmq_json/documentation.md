# RabbitMQ 3.13 - console log, JSON formatter

Source: RabbitMQ documentation, "Logging", JSON output (https://www.rabbitmq.com/docs/logging#json),
enabled with `log.console.formatter = json`. One JSON object per line:

    {"time": "<timestamp>", "level": "<level>", "msg": "<message>", "pid": "<pid>", "domain": "<domain>"}

`msg` is the same text as in the default format; a connection error and its reason are one event, the
reason after a newline inside `msg`. `domain` is the logging domain (`rabbitmq.connection`).

## The messages kept (inside msg)

    accepting AMQP connection <conn> (<client_ip>:<client_port> -> <server_ip>:<server_port>)
    connection <conn> (...): user '<user>' authenticated and granted access to vhost '<vhost>'
    closing AMQP connection <conn> (...[, vhost: '<vhost>', user: '<user>'])
    Error on AMQP connection <conn> (...[, user: '<user>'], state: <state>):\nPLAIN login refused: user '<user>' - invalid credentials
    Error on AMQP connection <conn> (...):\naccess to vhost '<vhost>' refused for user '<user>'

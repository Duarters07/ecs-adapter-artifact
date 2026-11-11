# Apache Tomcat 10.1 - access log (AccessLogValve, `common` pattern)

Source: Apache Tomcat 10.1 Configuration Reference, "The Valve Component", Access Log Valve,
https://tomcat.apache.org/tomcat-10.1-doc/config/valve.html#Access_Logging

The valve as shipped in conf/server.xml writes `%h %l %u %t "%r" %s %b`:

    <host> <logical_user> <user> [<time>] "<method> <path> <protocol>" <status> <bytes>

- `host` - the remote host: the client's IP address (host name lookups are off)
- `logical_user` - the remote logical user name from identd, always `-`
- `user` - the user authenticated by the application (BASIC authentication here); `-` when none
- `time` - date and time, in Common Log Format
- `method`, `path`, `protocol` - the first line of the request
- `status` - the HTTP status code of the response (401: authentication required or failed)
- `bytes` - bytes sent, excluding HTTP headers, or `-` if zero

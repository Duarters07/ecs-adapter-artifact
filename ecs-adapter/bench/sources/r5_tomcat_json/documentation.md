# Apache Tomcat 10.1 - access log as JSON (JsonAccessLogValve, `combined` pattern)

Source: Apache Tomcat 10.1 Configuration Reference, "The Valve Component", JSON Access Log Valve,
https://tomcat.apache.org/tomcat-10.1-doc/config/valve.html#JSON_Access_Log_Valve

One JSON object per request. The valve names each element of the `combined` pattern
(`%h %l %u %t "%r" %s %b "%{Referer}i" "%{User-Agent}i"`) and writes them in that order:

    {"host":"<host>","logicalUserName":"<..>","user":"<user>","time":"[<time>]","request":"<method> <path> <protocol>","statusCode":"<status>","size":"<bytes>","requestHeaders": {"Referer":"<referer>","User-Agent":"<user agent>"}}

Every value is a JSON string.

- `host` - the remote host: the client's IP address (host name lookups are off)
- `logicalUserName` - the remote logical user name from identd, always `-`
- `user` - the user authenticated by the application (BASIC authentication here); `-` when none
- `time` - date and time in Common Log Format, inside brackets
- `request` - the first line of the request: `<method> <path> <protocol>`
- `statusCode` - the HTTP status code of the response (401: authentication required or failed)
- `size` - bytes sent, excluding HTTP headers, or `-` if zero
- `requestHeaders.Referer`, `requestHeaders.User-Agent` - the Referer and User-Agent request headers; `-` when absent

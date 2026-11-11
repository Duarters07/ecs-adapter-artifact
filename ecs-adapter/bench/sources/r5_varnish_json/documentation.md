# Varnish 7.6 - varnishncsa, the site's JSON format

Source: the site's varnishncsa invocation, `varnishncsa -j -F '<format>'`, and varnishncsa(1),
https://varnish-cache.org/docs/7.6/reference/varnishncsa.html (-j makes every string JSON-safe)

    {"client":"%h","time":"%{%Y-%m-%dT%H:%M:%S%z}t","method":"%m","url":"%U%q","protocol":"%H","status":%s,"bytes_sent":%O,"referer":"%{Referer}i","user_agent":"%{User-agent}i","cache":"%{Varnish:hitmiss}x","duration_us":%D}

One JSON object per request.

- `client` - the remote host: the client's IP address
- `time` - when the request was received, ISO 8601 with offset
- `method`, `protocol` - the request method and protocol
- `url` - the URL path and query string of the request
- `status` - the HTTP status code sent to the client
- `bytes_sent` - total bytes sent to the client, headers included
- `referer`, `user_agent` - the Referer and User-Agent request headers; empty when absent
- `cache` - whether the object came from the cache: `hit` or `miss`
- `duration_us` - the time to serve the request, microseconds

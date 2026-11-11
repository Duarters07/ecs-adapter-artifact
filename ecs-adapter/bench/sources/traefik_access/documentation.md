# Traefik 3.1 — access log, JSON format

One flat JSON object per request, written by `--accesslog.format=json`. All
keys are top level; there is no nesting. Header capture is off, which is the
default, so the key set is the same on every line.

## Keys

The proxy sits between a client and a backend, and the log names BOTH legs.

Client side:
- `ClientAddr` — the client's address and port joined by a colon
- `ClientHost`, `ClientPort` — the same two values, separately
- `ClientUsername` — the authenticated user, `-` when there is none

What the client asked for:
- `RequestAddr` — the Host header, port included when the client sent one
- `RequestHost` — the Host header without the port
- `RequestPort` — the port from the Host header, `-` when absent
- `RequestMethod`, `RequestPath`, `RequestProtocol`, `RequestScheme`
- `RequestContentSize` — bytes in the request body
- `RequestCount` — how many requests this Traefik process has served

Backend side:
- `ServiceAddr` — host and port of the backend that answered
- `ServiceName`, `ServiceURL`, `RouterName` — Traefik's own routing identifiers
- `OriginStatus` — the status code the BACKEND returned
- `OriginContentSize` — the body size the BACKEND returned
- `OriginDuration` — time spent waiting for the backend, in NANOSECONDS
- `RetryAttempts` — retries before an answer was obtained

What the client received:
- `DownstreamStatus` — the status code sent TO THE CLIENT
- `DownstreamContentSize` — the body size sent to the client
- `Duration` — total request time, in NANOSECONDS
- `Overhead` — `Duration` minus `OriginDuration`, in nanoseconds
- `GzipRatio` — compression ratio, 0 when no compression was applied

Envelope:
- `StartUTC`, `StartLocal`, `time` — timestamps
- `entryPointName` — the Traefik listener the request arrived on
- `level`, `msg` — logger level and message; `msg` is empty for access records

Origin and downstream values differ whenever Traefik rewrites a response, when
a retry succeeds after a failure, or when the backend is unreachable and
Traefik answers 502 on its own.

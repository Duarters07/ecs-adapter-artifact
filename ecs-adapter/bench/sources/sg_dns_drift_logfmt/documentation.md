# dnsmasq resolver log

Key=value pairs separated by " ", key and value joined by "=", one entry per line.

```
ts=TS domain=DOMAIN host=HOST path=PATH pid=PID qtype=QTYPE rcode=RCODE resolver=RESOLVER sport=SPORT src_ip=SRC_IP txid=TXID upstream=UPSTREAM
```

Example lines:

```
ts=1791964819.000 domain=mail.acme.local host=dns path=config pid=2866 qtype=TXT rcode=NOERROR resolver=10.10.0.15 sport=33375 src_ip=10.10.6.11 txid=33787 upstream=1.1.1.1
ts=1791964882.000 domain=web.acme.local host=dns path=config pid=2866 qtype=PTR rcode=NOERROR resolver=10.10.0.15 sport=10334 src_ip=10.20.1.11 txid=33147 upstream=1.1.1.1
```

- `ts` — timestamp as written
- `domain` — qname
- `host` — service protocol
- `path` — recorded by the source
- `pid` — recorded by the source
- `qtype` — RR type
- `rcode` — rcode
- `resolver` — server IP
- `sport` — vendor-specific value
- `src_ip` — remote peer IP
- `txid` — query id
- `upstream` — recorded by the source

# netfilter packet log — ulogd2 LOGEMU (iptables LOG format)

Source: ulogd2 documentation (output plugin LOGEMU) and the iptables-extensions(8)
LOG target, https://www.netfilter.org/projects/ulogd/ and
https://ipset.netfilter.org/iptables-extensions.man.html

    <timestamp> <host> <prefix> IN=<in> OUT=<out> MAC=<mac> SRC=<src> DST=<dst> LEN=<len> TOS=.. PREC=.. TTL=<ttl> ID=<id> [DF] PROTO=<proto> ...

then, by protocol: `SPT=<sport> DPT=<dport>` and TCP's `SEQ= ACK= WINDOW=` and flag
words (`SYN`) for TCP; `SPT= DPT= LEN=` for UDP; `TYPE= CODE= ID= SEQ=` for ICMP.

- `timestamp` — `Mmm dd HH:MM:SS`, local time, no year
- `host` — the firewall's host name
- `prefix` — the log prefix of the rule that matched, naming the rule
- `IN`, `OUT` — the interface the packet came in on, and went out on (empty for input)
- `MAC` — destination MAC, source MAC and EtherType, joined with colons
- `SRC`, `DST` — source and destination addresses
- `LEN` — the length of the IP packet in bytes
- `TTL`, `ID` — the IP time to live and identification
- `PROTO` — the transport protocol: `TCP`, `UDP`, `ICMP`
- `SPT`, `DPT` — source and destination ports

# netfilter packet log — ulogd2 JSON output

Source: ulogd2 documentation, output plugin JSON (ulogd2-json),
https://www.netfilter.org/projects/ulogd/

One flat JSON object per logged packet. The dots are part of the key names
(`oob.prefix` is one key), not nesting.

- `timestamp` — ISO 8601 with microseconds
- `dvc` — the device name configured for the output: the firewall's name
- `oob.prefix` — the log prefix of the rule that matched, naming the rule
- `oob.in`, `oob.out` — the interface the packet came in on, and went out on
- `oob.hook`, `oob.family`, `oob.protocol`, `oob.mark`, `oob.ifindex_in` — netfilter
  hook number, address family, EtherType, packet mark, interface index
- `raw.pktlen` — the length of the packet in bytes
- `src_ip`, `dest_ip` — source and destination addresses
- `src_port`, `dest_port` — source and destination ports (TCP, UDP)
- `ip.protocol` — the IP protocol number: 6 TCP, 17 UDP, 1 ICMP
- `ip.ttl`, `ip.id`, `ip.tos`, `ip.totlen` — IP header fields
- `tcp.*` — TCP header fields and flags (`tcp.syn` is 1 on a SYN)
- `udp.len` — the UDP length
- `icmp.type`, `icmp.code` — the ICMP type and code
- `mac.saddr.str`, `mac.daddr.str` — source and destination MAC addresses

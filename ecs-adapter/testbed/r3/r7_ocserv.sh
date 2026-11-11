#!/usr/bin/env bash
# r7_ocserv (round 10, 2026-10-30): ocserv 1.1.6 (Debian bookworm) -> 1.3.0 (Debian trixie), same config
# (r7ocserv/ocserv.conf, plain password file), logging through rsyslog to /var/log/syslog (default level).
# Logins from fixed addresses: right passwords open a real session (openconnect with a tun device, closed after a few
# seconds); wrong passwords and unknown users go through r7ocserv/acauth.py, which answers every password prompt with
# the same password until the server gives up (openconnect would abandon after the first prompt, and an abandoned
# login logs no failure). Kept: the lines that name a user's session (main[...], failed authentication, plain-auth,
# session initiation and invalidation). 1.1.6 records a success only in sec-mod, without the address; 1.3.0 adds
# main[user]:ip:port lines (new user session, user logged in, user disconnected).
. "$(dirname "$0")/r7_common.sh"
OUT=$(cap r7_ocserv)
D=$(cd "$(dirname "$0")" && pwd)/r7ocserv
setup(){  # <container> <version>
  docker rm -f $1 >/dev/null 2>&1
  docker run -d --cpus 1 --name $1 --hostname vpn01 --network $NET --cap-add NET_ADMIN --device /dev/net/tun \
    r7-ocserv:$2 >/dev/null; sleep 5
  PIN=$(docker exec $1 sh -c 'openssl x509 -in /etc/ocserv/server.crt -pubkey -noout | openssl pkey -pubin -outform der |
    openssl dgst -sha256 -binary | base64'); }
GOOD="ana:AnaVpn2026 rui:RuiVpn2026 monitor:MonVpn2026"
drive(){
  python3 -c "
import ast, sys
for u, p, ip in ast.literal_eval(sys.argv[1]):
    print(ip, u, p)" "$2" | while read -r ip u p; do
    if [[ " $GOOD " == *" $u:$p "* ]]; then
      echo "$p" | timeout 30 docker run --rm -i --cpus 1 --network $NET --ip "$ip" --cap-add NET_ADMIN --device /dev/net/tun \
        r7-occlient timeout 5 openconnect --passwd-on-stdin -u "$u" --servercert pin-sha256:$PIN --script /bin/true $1 >/dev/null 2>&1
    else
      client "$ip" python3 -c "$(cat $D/acauth.py)" $1 "$u" "$p"
    fi; sleep 0.5
  done; }
log_lines(){ docker exec $1 cat /var/log/syslog | grep -E "main\[|failed authentication|plain-auth|initiating session|invalidating session"; }
mark(){ log_lines $1 | wc -l; }
slice(){ log_lines $1 | sed -n "$(($2+1)),$3p"; }
OLD1='[("ana","AnaVpn2026","172.21.91.11"),("ana","wrong1","172.21.91.11"),("rui","RuiVpn2026","172.21.91.12"),("ghost","x","172.21.91.201"),("monitor","MonVpn2026","172.21.91.13")]'
OLD2='[("rui","123456","172.21.91.14"),("admin","admin","172.21.91.202"),("ana","AnaVpn2026","172.21.91.15")]'
OLD3='[("root","toor","172.21.91.203"),("monitor","MonVpn2026","172.21.91.21"),("rui","Natal2024","172.21.91.22")]'
NEWA='[("ana","AnaVpn2026","172.21.91.11"),("ana","Outono24","172.21.91.11"),("rui","RuiVpn2026","172.21.91.12"),("ghost","x","172.21.91.211"),("monitor","MonVpn2026","172.21.91.13")]'
NEWB='[("deploy","deploy","172.21.91.31"),("ana","AnaVpn2026","172.21.91.32"),("guest","guest","172.21.91.213")]'
setup r7-oc-old 1.1.6; capture_old r7-oc-old drive r7-oc-old; docker rm -f r7-oc-old >/dev/null
setup r7-oc-new 1.3.0; capture_new r7-oc-new drive r7-oc-new; docker rm -f r7-oc-new >/dev/null
printf '{"captured_utc":"%s","old":"ocserv 1.1.6 (Debian bookworm)","new":"ocserv 1.3.0 (Debian trixie)","collected_by":"rsyslog /var/log/syslog: session lines"}\n' "$(date -u +%FT%TZ)" > $OUT/capture.json
wc -l $OUT/*.log

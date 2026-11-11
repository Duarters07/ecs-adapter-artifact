#!/usr/bin/env bash
# r7_stunnel (round 10, 2026-10-30): stunnel 5.68 (Debian bookworm, OpenSSL 3.0) -> 5.74 (Debian trixie, OpenSSL 3.5),
# same config (r7stunnel/stunnel.conf: TLS front end requiring a client certificate from the lab CA, in front of an
# echo service), log on stderr at notice. Connections from fixed addresses (r7stunnel/tlsclient.py) with a valid
# certificate, one from a rogue CA, a self-signed one, and none. The PKI is generated at capture time
# (r7stunnel/mkpki.sh) and both images are built from it. Part of the change is the OpenSSL error text, which the
# distribution upgrade brings with stunnel; the verification messages themselves are stunnel's.
# Event runs (old run 3, new run b) use accounts, certificates, zones or paths the sample runs never use, so their
# lines stay held out once addresses and numbers are masked (testbed/r3/build.py), as r6 did for Tinyproxy.
. "$(dirname "$0")/r7_common.sh"
OUT=$(cap r7_stunnel)
D=$(cd "$(dirname "$0")" && pwd)/r7stunnel
"$D/mkpki.sh"
docker build -q -t r7-stunnel:5.68 --build-arg DIST=bookworm "$D" >/dev/null
docker build -q -t r7-stunnel:5.74 --build-arg DIST=trixie "$D" >/dev/null
setup(){ docker rm -f $1 >/dev/null 2>&1; docker run -d --cpus 1 --name $1 --hostname gw01 --network $NET r7-stunnel:$2 >/dev/null; sleep 4; }
drive(){
  python3 -c "
import ast, sys
for c, ip in ast.literal_eval(sys.argv[1]):
    print(ip, c)" "$2" | while read -r ip c; do
    docker run --rm --cpus 1 --network $NET --ip "$ip" -v "$D/pki:/pki:ro" r7-client python3 -c "$(cat $D/tlsclient.py)" $1 "$c" \
      >/dev/null 2>&1; sleep 0.5
  done; }
log_lines(){ docker logs "$1" 2>&1 | grep -E "LOG[0-9]\[[0-9]+\]"; }
mark(){ log_lines $1 | wc -l; }
slice(){ log_lines $1 | sed -n "$(($2+1)),$3p"; }
OLD1='[("ana","172.21.91.11"),("mallory","172.21.91.201"),("rui","172.21.91.12"),("none","172.21.91.202"),("monitor","172.21.91.13")]'
OLD2='[("selfsigned","172.21.91.203"),("rui","172.21.91.14"),("ana","172.21.91.15")]'
OLD3='[("ops","172.21.91.204"),("eve","172.21.91.21"),("printer","172.21.91.205")]'
NEWA='[("ana","172.21.91.11"),("mallory","172.21.91.211"),("rui","172.21.91.12"),("none","172.21.91.212"),("monitor","172.21.91.13")]'
NEWB='[("backup","172.21.91.213"),("eve","172.21.91.32"),("printer","172.21.91.214")]'
setup r7-st-old 5.68; capture_old r7-st-old drive r7-st-old; docker rm -f r7-st-old >/dev/null
setup r7-st-new 5.74; capture_new r7-st-new drive r7-st-new; docker rm -f r7-st-new >/dev/null
printf '{"captured_utc":"%s","old":"stunnel 5.68 (Debian bookworm, OpenSSL 3.0)","new":"stunnel 5.74 (Debian trixie, OpenSSL 3.5)","collected_by":"docker logs (stderr, debug 5): connection lines"}\n' "$(date -u +%FT%TZ)" > $OUT/capture.json
wc -l $OUT/*.log

#!/usr/bin/env bash
# r7_rspamd (round 10, 2026-10-30): Rspamd, Debian 12 (3.4) -> Debian 13 (3.12.1), console log at level info.
# Messages submitted to /checkv2 from clients at fixed addresses, as an MTA would: a clean message, a spam-like one, a
# phishing-like one, with the client address, HELO, sender and recipient in the request headers.
. "$(dirname "$0")/r7_common.sh"
OUT=$(cap r7_rspamd)
docker build -q --build-arg BASE=debian:12 -t r7-rspamd12 "$HERE/docker/r7rspamd" >/dev/null
docker build -q --build-arg BASE=debian:13 -t r7-rspamd13 "$HERE/docker/r7rspamd" >/dev/null
start(){ docker rm -f $1 >/dev/null 2>&1; docker run -d --cpus 2 --name $1 --network $NET $2 >/dev/null; sleep 12; }
# (kind, from, rcpt, smtp client address, request source address)
drive(){
  python3 -c "
import ast, sys
for k, f, r, sip, ip in ast.literal_eval(sys.argv[1]):
    print(ip, k, f, r, sip)" "$2" | while read -r ip k f r sip; do
    case $k in
      clean) body='Subject: Q3 report\n\nPlease find the quarterly numbers attached.' ;;
      spam)  body='Subject: CHEAP VIAGRA BUY NOW\n\nCLICK HERE http://bit.ly/x win money $$$ free FREE FREE' ;;
      phish) body='Subject: Your account is suspended\n\nVerify your password at http://paypa1-login.example/verify immediately' ;;
    esac
    client "$ip" sh -c "printf 'From: $f\nTo: $r\n$body\n' | curl -s -m 15 -H 'IP: $sip' -H 'Helo: mx.$sip.example' -H 'From: $f' -H 'Rcpt: $r' --data-binary @- http://$1:11333/checkv2"; sleep 0.5
  done; }
log_lines(){ docker logs "$1" 2>&1 | grep -E "rspamd_task_write_log|task_write_log"; }
mark(){ log_lines $1 | wc -l; }
slice(){ log_lines $1 | sed -n "$(($2+1)),$3p"; }
OLD1='[("clean","ana@lab.example","rui@lab.example","172.21.87.11","172.21.87.2"),("spam","promo@cheap.example","ana@lab.example","198.51.100.23","172.21.87.2"),("phish","security@paypa1.example","rui@lab.example","203.0.113.9","172.21.87.2")]'
OLD2='[("clean","rui@lab.example","ana@lab.example","172.21.87.12","172.21.87.2"),("spam","deals@offer.example","rui@lab.example","198.51.100.77","172.21.87.2")]'
OLD3='[("phish","it-support@lab-example.example","ana@lab.example","203.0.113.41","172.21.87.2"),("clean","hr@lab.example","rui@lab.example","172.21.87.13","172.21.87.2")]'
NEWA='[("clean","ana@lab.example","rui@lab.example","172.21.87.11","172.21.87.2"),("spam","promo@cheap.example","ana@lab.example","198.51.100.23","172.21.87.2"),("phish","security@paypa1.example","rui@lab.example","203.0.113.9","172.21.87.2")]'
NEWB='[("phish","billing@micr0soft.example","ana@lab.example","203.0.113.77","172.21.87.2"),("clean","ops@lab.example","ana@lab.example","172.21.87.14","172.21.87.2")]'
start r7-rsp-old r7-rspamd12; capture_old r7-rsp-old drive r7-rsp-old
v1=$(docker exec r7-rsp-old rspamd --version 2>&1 | head -1); docker rm -f r7-rsp-old >/dev/null
start r7-rsp-new r7-rspamd13; capture_new r7-rsp-new drive r7-rsp-new
v2=$(docker exec r7-rsp-new rspamd --version 2>&1 | head -1); docker rm -f r7-rsp-new >/dev/null
printf '{"captured_utc":"%s","old":"Debian 12 %s","new":"Debian 13 %s","collected_by":"docker logs (console, level info): the per-task result line"}\n' "$(date -u +%FT%TZ)" "$v1" "$v2" > $OUT/capture.json
wc -l $OUT/*.log

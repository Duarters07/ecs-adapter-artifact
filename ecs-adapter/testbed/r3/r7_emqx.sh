#!/usr/bin/env bash
# r7_emqx (round 10, 2026-10-30): EMQX, official image 4.4.19 -> 5.8.6 (5.9+ changed licence), console log at info.
# MQTT clients at fixed addresses publish and subscribe, with and without a username, through the default listener.
. "$(dirname "$0")/r7_common.sh"
OUT=$(cap r7_emqx)
ENVS="-e EMQX_LOG__LEVEL=info -e EMQX_LOG__TO=console -e EMQX_LOG__CONSOLE_HANDLER__LEVEL=info -e EMQX_LOG__CONSOLE__LEVEL=info"
start(){ docker rm -f $1 >/dev/null 2>&1; docker run -d --cpus 2 --name $1 --network $NET $ENVS $2 >/dev/null; sleep 30; }
# (client id, username or "-", action pub|sub, topic, client address)
drive(){
  python3 -c "
import ast, sys
for c, u, a, t, ip in ast.literal_eval(sys.argv[1]):
    print(ip, c, u, a, t)" "$2" | while read -r ip c u a t; do
    auth=""; [ "$u" != "-" ] && auth="-u $u -P Pw2026x"
    if [ $a = pub ]; then client "$ip" mosquitto_pub -h $1 -i $c $auth -t $t -m '{"v":1}'
    else client "$ip" timeout 3 mosquitto_sub -h $1 -i $c $auth -t $t -C 1 -W 2; fi; sleep 0.5
  done; }
log_lines(){ docker logs "$1" 2>&1 | grep -E "PUBLISH|SUBSCRIBE|terminate|AUTHZ|AUTHN|authoriz|authent"; }
mark(){ log_lines $1 | wc -l; }
slice(){ log_lines $1 | sed -n "$(($2+1)),$3p"; }
OLD1='[("dev-ana","ana","pub","plant/line1/temp","172.21.88.11"),("dev-rui","-","pub","plant/line2/temp","172.21.88.12"),("ops-mon","monitor","sub","plant/#","172.21.88.13"),("x-201","-","pub","admin/cmd","172.21.88.201")]'
OLD2='[("dev-ana","ana","pub","plant/line1/pressure","172.21.88.14"),("x-202","guest","sub","$SYS/#","172.21.88.202")]'
OLD3='[("dev-scan","-","sub","#","172.21.88.21"),("x-203","root","pub","admin/reboot","172.21.88.203")]'
NEWA='[("dev-ana","ana","pub","plant/line1/temp","172.21.88.11"),("dev-rui","-","pub","plant/line2/temp","172.21.88.12"),("ops-mon","monitor","sub","plant/#","172.21.88.13"),("x-211","-","pub","admin/cmd","172.21.88.211")]'
NEWB='[("dev-hr","hr","pub","office/badge","172.21.88.31"),("x-213","guest","sub","#","172.21.88.213")]'
start r7-emqx-old emqx/emqx:4.4.19; capture_old r7-emqx-old drive r7-emqx-old; docker rm -f r7-emqx-old >/dev/null
start r7-emqx-new emqx/emqx:5.8.6; capture_new r7-emqx-new drive r7-emqx-new; docker rm -f r7-emqx-new >/dev/null
printf '{"captured_utc":"%s","old":"EMQX 4.4.19 (official image emqx/emqx:4.4.19)","new":"EMQX 5.8.6 (official image emqx/emqx:5.8.6)","collected_by":"docker logs (console, level info): publish, subscribe, authorization and terminate lines"}\n' "$(date -u +%FT%TZ)" > $OUT/capture.json
wc -l $OUT/*.log

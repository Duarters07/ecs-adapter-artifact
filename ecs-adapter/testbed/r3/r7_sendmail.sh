#!/usr/bin/env bash
# r7_sendmail (round 10, 2026-10-30): Sendmail 8.17.1.9 (Debian bookworm) -> 8.18.1 (Debian trixie), same .mc
# (r7sendmail/Dockerfile: all addresses, local delivery for lab.example, unresolvable sender domains accepted),
# rsyslog /var/log/mail.log. SMTP transactions from fixed addresses (r7sendmail/smtp.py): delivery to a local user,
# unknown local recipient, relay attempt to an outside domain. Each client container is named after its address
# (r7-ws<last octet>), so `relay=` (the reverse name Docker's resolver gives) is the same in every run.
. "$(dirname "$0")/r7_common.sh"
OUT=$(cap r7_sendmail)
D=$(cd "$(dirname "$0")" && pwd)/r7sendmail
setup(){  # <container> <version>
  docker rm -f $1 >/dev/null 2>&1
  docker run -d --cpus 1 --name $1 --hostname mail01 --domainname lab.example --network $NET r7-sendmail:$2 >/dev/null; sleep 10; }
drive(){
  python3 -c "
import ast, sys
for f, r, ip in ast.literal_eval(sys.argv[1]):
    print(ip, f, r)" "$2" | while read -r ip f r; do
    docker run --rm --cpus 1 --name r7-ws${ip##*.} --network $NET --ip "$ip" r7-client python3 -c "$(cat $D/smtp.py)" \
      $1 "ws${ip##*.}.lab.example" "$f" "$r" >/dev/null 2>&1; sleep 0.5
  done; }
log_lines(){ docker exec $1 cat /var/log/mail.log | grep -E "relay=|stat=|reject=|User unknown"; }
mark(){ log_lines $1 | wc -l; }
slice(){ log_lines $1 | sed -n "$(($2+1)),$3p"; }
OLD1='[("billing@partner.example","ana@lab.example","172.21.91.11"),("x@partner.example","jdoe@lab.example","172.21.91.11"),("ops@partner.example","rui@lab.example","172.21.91.12"),("promo@spam.example","victim@gmail.com","172.21.91.201"),("alerts@partner.example","monitor@lab.example","172.21.91.13")]'
OLD2='[("a@partner.example","admin@lab.example","172.21.91.14"),("bulk@spam.example","target@yahoo.com","172.21.91.202"),("hr@partner.example","ana@lab.example","172.21.91.15")]'
OLD3='[("x@spam.example","root@outside.example","172.21.91.203"),("alerts@partner.example","monitor@lab.example","172.21.91.21"),("y@partner.example","postmaster2@lab.example","172.21.91.22")]'
NEWA='[("billing@partner.example","ana@lab.example","172.21.91.11"),("x@partner.example","jdoe@lab.example","172.21.91.11"),("ops@partner.example","rui@lab.example","172.21.91.12"),("promo@spam.example","victim@gmail.com","172.21.91.211"),("alerts@partner.example","monitor@lab.example","172.21.91.13")]'
NEWB='[("q@partner.example","deploy@lab.example","172.21.91.31"),("hr@partner.example","ana@lab.example","172.21.91.32"),("bulk@spam.example","ceo@hotmail.com","172.21.91.213")]'
setup r7-sm-old 8.17; capture_old r7-sm-old drive r7-sm-old; docker rm -f r7-sm-old >/dev/null
setup r7-sm-new 8.18; capture_new r7-sm-new drive r7-sm-new; docker rm -f r7-sm-new >/dev/null
printf '{"captured_utc":"%s","old":"Sendmail 8.17.1.9 (Debian bookworm)","new":"Sendmail 8.18.1 (Debian trixie)","collected_by":"rsyslog /var/log/mail.log: transaction lines (from/to/reject)"}\n' "$(date -u +%FT%TZ)" > $OUT/capture.json
wc -l $OUT/*.log

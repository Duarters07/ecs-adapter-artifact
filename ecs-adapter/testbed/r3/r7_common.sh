#!/usr/bin/env bash
# Shared by the round-10 capture scripts (pool r7, ROUND3_VERSION_DRIFT.md "Decisions at the end of F0").
# Everything is named r7-*, on round 3's network r3-net, clients in 172.21.80.0/20, so nothing else is touched.
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
# The five runs every pair captures: old 1-3 (samples, samples, events), new A (samples), new B (events).
capture_old(){ local c=$1 f=$2 t=$3
  n0=$(mark $c); $f $t "$OLD1"; sleep 2; n1=$(mark $c); $f $t "$OLD2"; sleep 2; n2=$(mark $c); $f $t "$OLD3"; sleep 2; n3=$(mark $c)
  slice $c $n0 $n1 > $OUT/old_run1.log; slice $c $n1 $n2 > $OUT/old_run2.log; slice $c $n2 $n3 > $OUT/old_run3.log; }
capture_new(){ local c=$1 f=$2 t=$3
  m0=$(mark $c); $f $t "$NEWA"; sleep 2; m1=$(mark $c); $f $t "$NEWB"; sleep 2; m2=$(mark $c)
  slice $c $m0 $m1 > $OUT/new_run_a.log; slice $c $m1 $m2 > $OUT/new_run_b.log; }
r7_cleanup(){ docker ps -aq --filter "name=^r7-" | xargs -r docker rm -f >/dev/null; }
# Run one client command from a fixed address: client <ip> <command...>
client(){ local ip=$1; shift; docker run --rm --cpus 1 --network $NET --ip "$ip" r7-client "$@" >/dev/null 2>&1; }

#!/bin/bash
# Card 4: the pre-registered Logstash redo of every unicode_ws judgement (the 10% confirmation disagreed there).
W=/workspace/gs2; L=$W/logs/f8b.log
cd $W/SIEM-in-a-box/ecs-adapter; . $W/hangdbg/env.sh; unset ECS_TRACE_FILE ECS_OPERATOR_NOTE
echo "[$(date -u '+%m-%d %H:%M:%S')] A3 unicode_ws Logstash redo starts (6 shards)" >> $L
for s in 0 1 2 3 4 5; do
  ADV_ROOTS=$W/results /venv/main/bin/python -u -m bench.adv_a3 redo --data $W/task3adv/data --results $W/results \
    --family unicode_ws --shard $s --shards 6 --out $W/a3/redo-unicode_ws-$s.ndjson > $W/a3/redo-$s.log 2>&1 &
done
wait
echo "[$(date -u '+%m-%d %H:%M:%S')] ADV: A3 unicode redo ended ($(cat $W/a3/redo-unicode_ws-*.ndjson | wc -l) judgements)" >> $L

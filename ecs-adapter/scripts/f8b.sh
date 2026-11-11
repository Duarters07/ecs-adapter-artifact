#!/bin/bash
# Round 10, F8b on the card (PLAN_ROUND10_ARM_C.md, section 6): the final test, as pre-registered in F8a
# (ROUND3_VERSION_DRIFT.md "r7 predictions", TASK3_EXTERNAL.md "Pre-registration"; PREREG.sha256 digest 335d553e...).
# NEEDS THE AUTHOR'S GO-AHEAD; nothing launches it automatically.
#
# Same code, flags and settings as the checkpoint and F7 (scripts/cp10.sh, scripts/f7.sh): round-10 pipeline, round 9's
# flags, temperature 0.7, window 32768. Every arm inside the same architecture; only the model differs:
#   C10s  arm C as F7 selected it (state/f7-arm-c: org10 SFT, or SFT+DPO on the interpret stage); map stage = org10's
#   Cr9   org9, the previous system
#   B     Qwen2.5-coder 7B q8, untrained
#   T14   Qwen2.5-coder 14B q4_K_M, untrained, flash attention + q8 KV cache, 1 slot
# Full system = k=6 samples, 3 repairs, deterministic layer; model-only = one call, no repair, no deterministic layer.
#
#   r7     Task 2's test: the 20 r7 pairs (15 real changes + 5 controls), staged-edit, full system 5 seeds, model-only
#          5 seeds. Tags F-/E-<arm>-p22-r7. The PRIMARY endpoint is C10s vs T14 here, full system, real changes.
#   t3     Task 3, AIT-LDS: the six sources, Task 1's mode (staged, no previous parser), full system 5 seeds,
#          model-only 5 seeds. Tags F-/E-<arm>-p22-t3. Runs from the tree bench.task3_bench assembles after checking
#          every file against the frozen manifest.
#   t3lh   Task 3, Loghub-2.0: the five systems, as t3. Tags F-/E-<arm>-p22-t3lh. GA/PA are scored on the laptop
#          (bench.task3_loghub), from the result files.
#   memo   the memorisation probe (bench.memorisation_probe run) for every model an arm serves.
#   all    r7, t3, t3lh, memo; resumable (state/run-<tag>.done).
#
#   bash scripts/f8b.sh all
set -u
W=/workspace/gs2; ECS=$W/SIEM-in-a-box/ecs-adapter; PY=/venv/main/bin/python
M7=qwen2.5-coder:7b-instruct-q8_0; M14=qwen2.5-coder:14b-instruct-q4_K_M
T3=$W/task3; T3B=$W/task3/bench
export PYTHONPATH=$ECS HF_HOME=/workspace/.hf_home OLLAMA_MODELS=/workspace/ollama
export ECS_MODEL_BACKEND=ollama ECS_MODEL_ENDPOINT=http://127.0.0.1:11434 ECS_MODEL_NAME=$M7
export ECS_TEACHER_MODEL=$M14 ECS_BASE_MODEL=Qwen/Qwen2.5-Coder-7B-Instruct
export ELASTICSEARCH_HOST=http://127.0.0.1:9200 ELASTIC_USER=elastic ELASTIC_PASSWORD=unused STACK_VERSION=8.19.7
export ECS_SANDBOX_LOGSTASH=/opt/logstash-8.19.7/bin/logstash ECS_MODEL_TEMPERATURE=0.7 ECS_MODEL_NUM_CTX=32768
export ECS_TEMPLATE_EXTRACTION=1 ECS_REGEX_GUARD=2 ECS_TIMESTAMP_RETYPE=1 ECS_OLD_MAPPING_PREVAILS=1 \
       ECS_VERIFIED_SUBSET=1 ECS_VALUE_MAP_REKEY=1 ECS_ROLES_FOR_ALL=1 ECS_RENAME_BY_VALUE=1 ECS_IANA_FIX=1 \
       ECS_PUNCT_SPACES=1
unset ECS_PIPELINE ECS_GROK_SIM R6 R7 ECS_TRACE_FILE ECS_BENCH_ROOT
mkdir -p $W/logs $W/state $W/results
log(){ echo "[$(date -u '+%m-%d %H:%M:%S')] $*" | tee -a $W/logs/f8b.log; }
source <(sed -n '/^services(){/,/^}/p; /^ollama_mode(){/,/^}/p; /^org9_models(){/,/^}/p' $ECS/scripts/cp10.sh)

run(){  # <tag> <arm> <pool> <mode> <seeds> <architecture> [env...]: one cell, k=6 / 3 repairs in full system
  local tag=$1 arm=$2 pool=$3 mode=$4 seeds=$5 arch=$6; shift 6
  local samples=6; [ $mode = model-only ] && samples=1
  [ -f $W/state/run-$tag.done ] && return 0
  log "  $tag: arm $arm pool $pool $mode seeds $seeds samples $samples $arch"
  ( cd $ECS && env "$@" ECS_ARMS_TAG=$tag $PY -u -m bench.arms --arms $arm --pool $pool --mode $mode \
      --seeds $seeds --samples $samples --repair-budget 3 --architecture $arch >>$W/logs/run-$tag.log 2>&1 ) \
    || { log "  $tag FAILED"; return 1; }
  local f; f=$(ls -t $ECS/results/arms_*_$tag.ndjson 2>/dev/null | head -1)
  [ -n "$f" ] || { log "  $tag: no result file"; return 1; }
  cp $f $W/results/$tag.ndjson; date -u > $W/state/run-$tag.done
  log "  $tag done ($(wc -l < $f) runs, $(grep -c '"outcome": "accepted"' $f) accepted)"
}

arm_env(){  # <arm tag>: sets the student models (C arms) or clears them, and the Ollama mode the model needs
  case $1 in
    C10s) local sel; sel=$(cat $W/state/f7-arm-c) || { log "F8b: no F7 selection"; return 1; }
          ollama_mode nofa; export ECS_STUDENT_MAP_MODEL=qwen2.5-coder:ecs-map-org10
          if [ $sel = C10d ]; then export ECS_STUDENT_INTERPRET_MODEL=qwen2.5-coder:ecs-interpret-org10dpo
          else export ECS_STUDENT_INTERPRET_MODEL=qwen2.5-coder:ecs-interpret-org10; fi ;;
    Cr9)  ollama_mode nofa; org9_models || return 1
          export ECS_STUDENT_INTERPRET_MODEL=qwen2.5-coder:ecs-interpret-org9 ECS_STUDENT_MAP_MODEL=qwen2.5-coder:ecs-map-org9 ;;
    B)    ollama_mode nofa; unset ECS_STUDENT_INTERPRET_MODEL ECS_STUDENT_MAP_MODEL ;;
    T14)  ollama_mode fa; unset ECS_STUDENT_INTERPRET_MODEL ECS_STUDENT_MAP_MODEL ;;
  esac
}
arm_letter(){ case $1 in C10s|Cr9) echo C ;; B) echo B ;; T14) echo T ;; esac; }

ARMS="C10s Cr9 B T14"   # arm C first: the primary endpoint's cells are the first to finish

r7(){
  services || return 1; local rc=0 a
  for a in $ARMS; do
    arm_env $a || return 1
    run F-$a-p22-r7 $(arm_letter $a) r7 full-system 5 staged-edit R7=1 || rc=1
    run E-$a-p22-r7 $(arm_letter $a) r7 model-only 5 staged-edit R7=1 || rc=1
  done
  log "F8b: r7 done (rc $rc)"; return $rc
}

t3tree(){  # refuses on any difference from the frozen manifest (bench.task3_bench.verify)
  ( cd $ECS && $PY -m bench.task3_bench --task3 $T3 --out $T3B ) >>$W/logs/f8b.log 2>&1 \
    || { log "F8b: Task 3 files differ from the frozen manifest - STOP"; return 1; }
}

t3pool(){  # <pool>
  services || return 1; t3tree || return 1; local rc=0 a
  for a in $ARMS; do
    arm_env $a || return 1
    run F-$a-p22-$1 $(arm_letter $a) $1 full-system 5 staged ECS_BENCH_ROOT=$T3B || rc=1
    run E-$a-p22-$1 $(arm_letter $a) $1 model-only 5 staged ECS_BENCH_ROOT=$T3B || rc=1
  done
  log "F8b: $1 done (rc $rc)"; return $rc
}

memo(){
  local m rc=0 sel; sel=$(cat $W/state/f7-arm-c 2>/dev/null)
  ollama_mode nofa; org9_models || return 1
  for m in $M7 qwen2.5-coder:ecs-interpret-org10 qwen2.5-coder:ecs-interpret-org10dpo qwen2.5-coder:ecs-interpret-org9 $M14; do
    local tag=memo-${m##*:}; [ -f $W/state/run-$tag.done ] && continue
    [ $m = $M14 ] && ollama_mode fa
    ( cd $ECS && $PY -m bench.memorisation_probe run --probe $T3/memorisation_probe.json --model $m \
        --out $W/results/$tag.json ) >>$W/logs/f8b.log 2>&1 || { log "  $tag FAILED"; rc=1; continue; }
    date -u > $W/state/run-$tag.done
    log "  $tag: contaminated=$($PY -c "import json; print(json.load(open('$W/results/$tag.json'))['contaminated'])")"
  done
  return $rc
}

all(){
  [ -f $W/state/f7-arm-c ] || { log "F8b: F7 has not selected arm C - not starting"; return 1; }
  log "F8b START (arm C = $(cat $W/state/f7-arm-c))"
  r7; t3pool t3; t3pool t3lh; memo
  log "F8b DONE"
}

"$@"

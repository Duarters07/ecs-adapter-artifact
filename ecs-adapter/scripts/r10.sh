#!/bin/bash
# Round 10, F5 and F6 on the card (PLAN_ROUND10_ARM_C.md, section 6): the round-10 training data and org10.
#
# org9's training data is declared not reproducible (F0, decision 1), so org10 is org9 CONTINUED: both stages start
# from org9's adapters and train on the round-10 data plus a replay of the verified SFT sets this repository keeps,
# in org9's proportion (new : replay = 7 : 3). org10 minus org9 is then the effect of the round-10 data alone.
# Set R10_INIT=edit to start instead from C's second-step adapters (org9's own starting point).
#
#   bash scripts/r10.sh setup      # training libraries (pinned, frozen to metrics), base model, init adapters
#   bash scripts/r10.sh trace      # T2/T3 input: org9 on the TRAINING sources with ECS_TRACE_FILE (Task 1 mode)
#   bash scripts/r10.sh data       # F5: T1 repair pairs, inner pairs, own failures, DPO pairs, T4, replay; window
#                                  #     filter; exclusion test; composition + hashes
#   bash scripts/r10.sh sft        # F6: both stages, export to Ollama, parity, held-back check
#   bash scripts/r10.sh dpo        # F6 ablation: DPO on the interpret stage over the SFT adapter
#   bash scripts/r10.sh all        # setup, trace, data, sft, dpo; resumable (state/r10-<stage>.done)
set -u
W=/workspace/gs2; ECS=$W/SIEM-in-a-box/ecs-adapter; PY=/venv/main/bin/python
# Training libraries live in their own venv in /dev/shm (system torch visible), so installing peft/trl cannot upgrade the
# transformers the benchmark environment uses for retrieval: F7 and F8b run on /venv/main exactly as the checkpoint.
# /dev/shm is mounted noexec on the card: native libraries cannot load from it (2026-11-01 03:12, pandas "failed to map
# segment"), so the venv lives on disk; only the pip cache and the base model's hub cache stay in RAM.
TV=/workspace/trainvenv; TPY=$TV/bin/python; export PIP_CACHE_DIR=/dev/shm/pip-cache
export LLAMA_CPP_DIR=/workspace/llama.cpp
M7=qwen2.5-coder:7b-instruct-q8_0
export PYTHONPATH=$ECS HF_HOME=/workspace/.hf_home OLLAMA_MODELS=/workspace/ollama
export ECS_MODEL_BACKEND=ollama ECS_MODEL_ENDPOINT=http://127.0.0.1:11434 ECS_MODEL_NAME=$M7
export ECS_BASE_MODEL=Qwen/Qwen2.5-Coder-7B-Instruct
export ELASTICSEARCH_HOST=http://127.0.0.1:9200 ELASTIC_USER=elastic ELASTIC_PASSWORD=unused STACK_VERSION=8.19.7
export ECS_SANDBOX_LOGSTASH=/opt/logstash-8.19.7/bin/logstash ECS_MODEL_TEMPERATURE=0.7 ECS_MODEL_NUM_CTX=32768
export ECS_TEMPLATE_EXTRACTION=1 ECS_REGEX_GUARD=2 ECS_TIMESTAMP_RETYPE=1 ECS_OLD_MAPPING_PREVAILS=1 \
       ECS_VERIFIED_SUBSET=1 ECS_VALUE_MAP_REKEY=1 ECS_ROLES_FOR_ALL=1 ECS_RENAME_BY_VALUE=1 ECS_IANA_FIX=1 \
       ECS_PUNCT_SPACES=1
unset ECS_PIPELINE ECS_GROK_SIM R6 R7
D=$ECS/training/data/r10; A=$ECS/training/adapters; INIT=${R10_INIT:-org9}
N_REPAIR=${N_REPAIR:-1200}; N_INNER=${N_INNER:-300}; TRACE_SEEDS=${TRACE_SEEDS:-1}; TRACE_PER_FAMILY=${TRACE_PER_FAMILY:-12}
mkdir -p $W/logs $W/state $W/results $W/metrics/training $D
log(){ echo "[$(date -u '+%m-%d %H:%M:%S')] $*" | tee -a $W/logs/r10.log; }
done_(){ date -u > $W/state/r10-$1.done; log "R10: $1 DONE"; }
is_done(){ [ -f $W/state/r10-$1.done ]; }
source <(sed -n '/^services(){/,/^}/p; /^ollama_mode(){/,/^}/p; /^org9_models(){/,/^}/p' $ECS/scripts/cp10.sh)

setup(){
  is_done setup && return 0
  # As every earlier round installed them (scripts/gs2.sh, unpinned); the versions actually installed are frozen to
  # metrics, so org10's training environment is recorded even though org9's was not.
  $PY -m pip freeze > $W/metrics/training/r10-bench-env-before.txt
  [ -x $TPY ] || $PY -m venv --system-site-packages $TV >>$W/logs/r10-setup.log 2>&1 || { log "R10: venv FAILED"; return 1; }
  $TPY -m pip install -q transformers peft bitsandbytes datasets accelerate "liger-kernel<0.8" trl gguf sentencepiece \
      jsonschema PyYAML jinja2 >>$W/logs/r10-setup.log 2>&1 || { log "R10: pip FAILED"; return 1; }
  # liger-kernel 0.8 requires transformers >= 5; the card has 4.57.6 (system site, shared with the benchmark), and 0.8.5
  # refused to import (2026-11-01 03:22), so the last 0.7 release is installed.
  $TPY -m pip freeze > $W/metrics/training/r10-pip-freeze.txt
  $PY -m pip freeze > $W/metrics/training/r10-bench-env-after.txt
  cmp -s $W/metrics/training/r10-bench-env-before.txt $W/metrics/training/r10-bench-env-after.txt \
    || { log "R10: the benchmark environment CHANGED during setup - stopping"; return 1; }
  # llama.cpp for the adapter -> GGUF export, as earlier rounds fetched it (scripts/gs2.sh); its commit is recorded.
  [ -d /workspace/llama.cpp ] || git clone -q --depth 1 https://github.com/ggml-org/llama.cpp /workspace/llama.cpp \
      >>$W/logs/r10-setup.log 2>&1 || { log "R10: llama.cpp FAILED"; return 1; }
  git -C /workspace/llama.cpp rev-parse HEAD > $W/metrics/training/r10-llama-cpp-commit.txt
  # The base model (~15 GB) does not fit the 16 GB disk beside the rest: its hub cache lives in RAM (/dev/shm), linked
  # from HF_HOME so every reader finds it where it always did (first attempt, 2026-11-01 00:01: "No space left").
  local q=$HF_HOME/hub/models--Qwen--Qwen2.5-Coder-7B-Instruct
  if [ ! -L $q ]; then rm -rf $q; mkdir -p /dev/shm/hf-qwen $HF_HOME/hub; ln -s /dev/shm/hf-qwen $q; fi
  $TPY -c "from huggingface_hub import snapshot_download as d; d('Qwen/Qwen2.5-Coder-7B-Instruct')" \
      >>$W/logs/r10-setup.log 2>&1 || { log "R10: base model FAILED"; return 1; }
  for st in interpret map; do   # init adapters shipped from the laptop backup (r10_ship.sh)
    [ -f $A/$INIT-$st/adapter_model.safetensors ] || [ -f $A/edit-interpret/adapter_model.safetensors ] \
      || { log "R10: init adapter $INIT-$st missing"; return 1; }
  done
  done_ setup
}

trace(){  # org9 on the training sources, full system, k=6 with 3 repairs; every judged attempt traced
  is_done trace && return 0
  services || return 1; ollama_mode nofa; org9_models || return 1
  # A fixed sample: up to TRACE_PER_FAMILY training sources per family, each with a credited gold (the answer every
  # T2/T3 example needs), chosen with seed 10. 1804 training sources at k=6 would take weeks.
  local ids; ids=$(cd $ECS && $PY -c "
import json, pathlib, random
from collections import defaultdict
gold = {json.loads(l)['source_id'] for l in open('teacher/out/gold.ndjson') if l.strip()
        and (json.loads(l).get('credit') or {}).get('extraction')}
fam = defaultdict(list)
for d in sorted(pathlib.Path('bench/sources').iterdir()):
    t = d / 'truth.json'
    if t.is_file() and d.name in gold:
        j = json.loads(t.read_text())
        if j.get('split') == 'train':
            fam[j.get('family') or d.name].append(d.name)
rng = random.Random(10)
print(' '.join(sorted(s for f in sorted(fam) for s in rng.sample(fam[f], min($TRACE_PER_FAMILY, len(fam[f]))))))")
  log "R10: tracing org9 on $(echo $ids | wc -w) training sources, seeds $TRACE_SEEDS"
  ( cd $ECS && ECS_TRACE_FILE=$D/trace_org9.ndjson ECS_ARMS_TAG=TR-org9-train \
      ECS_STUDENT_INTERPRET_MODEL=qwen2.5-coder:ecs-interpret-org9 ECS_STUDENT_MAP_MODEL=qwen2.5-coder:ecs-map-org9 \
      $PY -u -m bench.arms --arms C --pool train --only $ids --mode full-system --seeds $TRACE_SEEDS --samples 6 \
      --architecture staged >>$W/logs/r10-trace.log 2>&1 ) || { log "R10: trace FAILED"; return 1; }
  log "R10: trace $(wc -l < $D/trace_org9.ndjson) attempts"
  done_ trace
}

WINFILTER(){ $TPY - $1 $2 <<'PY'
import json, sys
from transformers import AutoTokenizer
from training.train_lora import CHAT_END, render_chat_prompt
tok = AutoTokenizer.from_pretrained("Qwen/Qwen2.5-Coder-7B-Instruct")
rows = [l for l in open(sys.argv[1]) if l.strip()]
keep = [l for l in rows if len(tok(render_chat_prompt(tok, json.loads(l)["prompt"]) + json.loads(l)["completion"]
                                   + CHAT_END, add_special_tokens=False)["input_ids"]) <= 16000]
open(sys.argv[2], "w").writelines(keep)
print(f"window filter: kept {len(keep)} of {len(rows)}")
PY
}

data(){
  is_done data && return 0
  cd $ECS
  $PY -u -m corpus.repair_pairs --n $N_REPAIR --out $D/repair >>$W/logs/r10-data.log 2>&1 || { log "R10: T1 FAILED"; return 1; }
  $PY -u -m corpus.inner_pairs --n $N_INNER --out $D/inner >>$W/logs/r10-data.log 2>&1 || { log "R10: inner FAILED"; return 1; }
  $PY -u -m corpus.own_failures --traces $D/trace_org9.ndjson --out $D/own >>$W/logs/r10-data.log 2>&1 \
    || { log "R10: own failures FAILED"; return 1; }
  # T4: the taxonomy kinds (level_change, insert_statement, remove_statement) on the OLD versions of r3-r6, as every
  # organisation kind is built (R6=1 joins r6's old versions; r7 is never joined). Verified on the real Logstash.
  local R; R=$(ls testbed/r3/r[3456]_*.sh | xargs -n1 basename | sed 's/\.sh$//' | grep -v common | tr '\n' ',')
  mkdir -p $D/t4
  R6=1 $PY -u -m corpus.org_pairs candidates --pairs ${R%,} --only-kinds level_change,insert_statement,remove_statement \
      --a 0 --b 0 --c ${N_T4:-12} --tag t4 --out $D/t4/candidates.jsonl >>$W/logs/r10-data.log 2>&1 \
    || { log "R10: T4 candidates FAILED"; return 1; }
  R6=1 $PY -u -m corpus.org_pairs verify --cands $D/t4/candidates.jsonl --out $D/t4/verified.jsonl --workers 24 \
      >>$W/logs/r10-data.log 2>&1 || { log "R10: T4 verify FAILED"; return 1; }
  R6=1 $PY -u -m corpus.org_pairs build --verified $D/t4/verified.jsonl --out $D/t4 >>$W/logs/r10-data.log 2>&1 \
    || { log "R10: T4 build FAILED"; return 1; }
  assemble || return 1
  done_ data
}

assemble(){  # replay migrated to the served prompts, then new : replay = 7 : 3, window filter, exclusion test
  cd $ECS
  # The replay rows were rendered before F3 changed s1_interpret; serving and training prompts must agree (F2), and
  # train_lora refuses a set spanning two prompt digests (2026-11-01 03:15). corpus.migrate_replay substitutes F3's one
  # block exactly; tests/test_round10_migrate.py checks it against a fresh render.
  $PY -u -m corpus.migrate_replay --out $D/replay_interpret.jsonl >>$W/logs/r10-data.log 2>&1 \
    || { log "R10: replay migration FAILED"; return 1; }
  $PY - <<'PY' >>$W/logs/r10-data.log 2>&1
import hashlib, json, random
from pathlib import Path
rng = random.Random(10); D = Path("training/data/r10")
rd = lambda p: [l for l in Path(p).read_text().splitlines() if l.strip()] if Path(p).is_file() else []
new_i = rd(D / "repair/interpret_repair.jsonl") + rd(D / "inner/interpret_inner.jsonl") \
      + rd(D / "own/own_interpret_repair.jsonl") + rd(D / "t4/interpret_org_edit.jsonl")
new_m = rd(D / "own/own_map_repair.jsonl")
rng.shuffle(new_i); hold = new_i[: max(20, len(new_i) // 20)]; new_i = new_i[len(hold):]
rep_i, rep_m = rd(D / "replay_interpret.jsonl"), rd("training/data/map.jsonl") + rd("training/data/map_dict/map.jsonl")
ni, nm = round(len(new_i) * 3 / 7), round(max(len(new_m), 1) * 3 / 7) if new_m else 0
interp = new_i + rng.sample(rep_i, min(ni, len(rep_i)))
mp = new_m + rng.sample(rep_m, min(max(nm, 200), len(rep_m)))   # stage 2 sees little new data: keep a replay floor
rng.shuffle(interp); rng.shuffle(mp)
for name, rows in (("interpret", interp), ("map", mp), ("check_interpret", hold)):
    (D / f"{name}.jsonl").write_text("\n".join(rows) + "\n")
comp = {"interpret": len(interp), "map": len(mp), "new_interpret": len(new_i), "new_map": len(new_m),
        "replay_interpret": len(interp) - len(new_i), "replay_map": len(mp) - len(new_m), "held_back_check": len(hold),
        "dpo_interpret": len(rd(D / "own/dpo_interpret.jsonl")),
        "sha256": {n: hashlib.sha256((D / f"{n}.jsonl").read_bytes()).hexdigest()
                   for n in ("interpret", "map", "check_interpret")}}
(D / "composition.json").write_text(json.dumps(comp, indent=2) + "\n"); print("ASSEMBLED", json.dumps(comp))
PY
  log "R10: $(grep ASSEMBLED $W/logs/r10-data.log | tail -1 | cut -c1-300)"
  for st in interpret map; do WINFILTER $D/$st.jsonl $D/$st.w16k.jsonl >>$W/logs/r10-data.log 2>&1; done
  # The test sets stay out (section 4 rule 4): r7, Task 3 and every test_r* source, by test.
  $PY -m pytest -q -p no:cacheprovider tests/test_round10_f5.py >>$W/logs/r10-data.log 2>&1 \
    || { log "R10: EXCLUSION TEST FAILED - not training"; return 1; }
  cp $D/composition.json $W/metrics/training/r10-composition.json
  log "R10: assembled"
}

sft(){
  is_done sft && return 0
  services || return 1; cd $ECS; local rc=0
  pkill -x ollama 2>/dev/null; pkill -x ollama_llama_server 2>/dev/null; sleep 3
  local init_i=$A/$INIT-interpret init_m=$A/$INIT-map lr=${R10_LR:-5e-5} ep=${R10_EPOCHS:-1}
  [ $INIT = edit ] && { init_i=$A/edit-interpret; init_m=$A/edit2-map; lr=1e-4; ep=2; }
  # Stage 2 gets no new data when org9 never failed at mapping on the training sources (own_map_repair empty; T1, the
  # inner pairs and T4 are stage-1 repairs by construction): training it on replay alone would only re-fit org9's own
  # data, so org10's map stage is then org9's, unchanged, and org10 minus org9 is the interpret stage's new data.
  local new_map; new_map=$($PY -c "import json; print(json.load(open('$D/composition.json'))['new_map'])")
  for pair in "interpret $init_i authsvc,sg_linux_auth" "map $init_m caddy,sg_dns"; do
    set -- $pair; local st=$1 init=$2 vf=$3
    [ -f $W/state/r10-T-$st.done ] && continue
    if [ $st = map ] && [ "$new_map" = 0 ]; then
      log "R10: no new stage-2 data (new_map 0): org10 map = org9 map, not retrained"; continue; fi
    log "R10: training org10 $st from $(basename $init) (lr $lr, $ep epoch(s), window 16384, validation $vf)"
    ECS_VAL_FAMILIES=$vf $TPY -u -m training.train_lora --stage $st --max-seq-len 16384 --data $D/$st.w16k.jsonl \
      --out $A/org10-$st --init-adapter $init --learning-rate $lr --epochs $ep >>$W/logs/T-org10-$st.log 2>&1 \
      || { log "R10: train $st FAILED"; return 1; }
    cp $A/org10-$st/training_record.json $W/metrics/training/org10-$st.training_record.json 2>/dev/null
    st_json=$(ls -t $A/org10-$st/checkpoints/*/trainer_state.json 2>/dev/null | head -1)
    [ -n "$st_json" ] && cp "$st_json" $W/metrics/training/org10-$st.trainer_state.json
    rm -rf $A/org10-$st/checkpoints; date -u > $W/state/r10-T-$st.done
    log "R10: org10 $st done ($(grep -ao "eval_loss.: [0-9.]*" $W/logs/T-org10-$st.log | tail -1))"
  done
  ollama_mode nofa
  if [ "$new_map" = 0 ]; then
    org9_models && ollama cp qwen2.5-coder:ecs-map-org9 qwen2.5-coder:ecs-map-org10 >>$W/logs/r10-sft.log 2>&1 \
      || { log "R10: org10 map alias FAILED"; return 1; }
  fi
  for st in interpret map; do
    [ $st = map ] && [ "$new_map" = 0 ] && continue
    $TPY -u -m training.export_ollama --adapter $A/org10-$st --stage $st --base-tag $M7 \
      --name qwen2.5-coder:ecs-$st-org10 >>$W/logs/r10-sft.log 2>&1 || { log "R10: export $st FAILED"; return 1; }
    $PY -u -m training.parity --stage $st --model qwen2.5-coder:ecs-$st-org10 --data $D/$st.w16k.jsonl --n 20 \
      >>$W/logs/P-org10-$st.log 2>&1 || rc=1
    log "R10: parity $st: $(grep 'mean reproduction' $W/logs/P-org10-$st.log | tail -1)"
  done
  $PY -u -m training.parity --stage interpret --model qwen2.5-coder:ecs-interpret-org10 --data $D/check_interpret.jsonl \
    --n 20 >>$W/logs/P-org10-check.log 2>&1
  log "R10: held-back round-10 examples: $(grep 'mean reproduction' $W/logs/P-org10-check.log | tail -1)"
  [ $rc = 0 ] && done_ sft || log "R10: SFT gates (parity) failed - see P-org10-*.log; author decides"
  return $rc
}

dpo(){  # the ablation of PLAN section 3 (T3): SFT vs SFT+DPO, interpret stage only (map prompts exceed the card)
  is_done dpo && return 0
  cd $ECS; [ -s $D/own/dpo_interpret.jsonl ] || { log "R10: no DPO pairs - ablation not run"; done_ dpo; return 0; }
  pkill -x ollama 2>/dev/null; pkill -x ollama_llama_server 2>/dev/null; sleep 3
  $TPY -u -m training.train_dpo --stage interpret --adapter $A/org10-interpret --data $D/own/dpo_interpret.jsonl \
    --out $A/org10dpo-interpret >>$W/logs/T-org10dpo.log 2>&1 || { log "R10: DPO FAILED"; return 1; }
  ollama_mode nofa
  $TPY -u -m training.export_ollama --adapter $A/org10dpo-interpret --stage interpret --base-tag $M7 \
    --name qwen2.5-coder:ecs-interpret-org10dpo >>$W/logs/r10-dpo.log 2>&1 || { log "R10: DPO export FAILED"; return 1; }
  done_ dpo
}

all(){ setup && trace && data && sft && dpo && log "R10 ALL DONE"; }

"$@"

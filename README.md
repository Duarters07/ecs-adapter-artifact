# Artefact: Detection-Verified Adaptation of SIEM Log Parsers Using Specialised Local Language Models

Anonymous artefact of the submission: the system, the data it was evaluated on, every run record, and the script
that turns the records into every number, table and result figure of the paper.

## Layout

```
ecs-adapter/          the system and its evaluation harness
  adapter/            closed IR, compiler, drift loop, deployment gate (deploy.py), report
  validators/         the validation ladder: V1, V2, V3, V3.5, V4 detection replay, VC continuity
  prompts/ schema/ ecs/   prompts, IR schema, ECS 8.11 field definitions
  bench/              harness (arms.py), Task 3 attacks (adv_*.py), post-hoc analyses (posthoc_*.py),
                      paper generator (paper_r10.py)
  bench/sources/      every source: samples of the old and new version, truth, the previous parser
  bench/scenarios/    detection scenarios
  testbed/r3/         raw captures of every pair, reference parsers (gold/), the test set's capture scripts
  corpus/ teacher/ training/   synthetic training sources, teacher proposals, training pairs, LoRA training
  scripts/            r10.sh (training), f8b.sh (the test-set runs, every flag)
  tests/              the test-set leakage guard and the constant gate
runs/                 every run record: task1-2/, task3/ (with the attack lines it judged), posthoc/
data/task3-ait-lds/   samples and reference parsers derived from AIT-LDS
preregistration/      dated pre-registration documents and hash manifests
large/                separate archive: the LoRA adapters of the specialised model (GGUF) and their Modelfiles
```

Run tags: `C10s` the specialised 7B (7B-S), `T14` the untrained 14B, `B` the untrained 7B, `T14q8` the 14B at
8 bits (post hoc), `C10`, `C10d`, `Cr9` the configurations in the appendix. `F-` full system, `E-` model only.

## Regenerating the paper's numbers (no GPU, a few minutes)

```bash
cd ecs-adapter
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m bench.paper_r10 --roots ../runs/task1-2 \
    --adv ../runs/task3/t3_summary.json --posthoc ../runs/posthoc --out generated
```

The output is identical, byte for byte, to the files the submitted PDF was built from. The Task 3 summary it
reads can itself be rebuilt from the Task 3 records, with the same result:

```bash
ADV_ROOTS=../runs/task3:../runs/task1-2 .venv/bin/python -m bench.adv_summary \
    --adv ../runs/task3 --roots ../runs/task1-2 ../runs/task3 --out t3_summary.json
```

## Verifying the frozen inputs

```bash
cd ecs-adapter && sha256sum -c ../preregistration/r7_MANIFEST.sha256    # the 763 test-set files
cd preregistration && sha256sum -c PREREG.sha256 --ignore-missing      # the pre-registration documents
```

The test set and its predictions were frozen at 2026-10-30T22:24:16Z (`PREREG.frozen_at`), before any model ran
on it. `POSTHOC_REVIEW_ANALYSES.md` declared the post-hoc analyses before they ran. One path in `PREREG.sha256`
was anonymised for review, so `PREREG.digest` matches only once it is restored.

## Running the system

Needs Elasticsearch and Logstash 8.19.7 and Ollama 0.5.4. The specialised model is
`qwen2.5-coder:7b-instruct-q8_0` plus the adapters in `large/models/`:

```bash
cd large/models
ollama create qwen2.5-coder:ecs-interpret-org10 -f qwen2.5-coder_ecs-interpret-org10.Modelfile
ollama create qwen2.5-coder:ecs-map-org10 -f qwen2.5-coder_ecs-map-org10.Modelfile
```

## Tests

`cd ecs-adapter && .venv/bin/python -m pytest -q tests` runs the two tests the paper relies on: no training file
may hold a row of a test-set family, and the gate keeps every constant at the previous parser's value.

## Licences

The captures are of software run in containers with synthetic accounts and addresses. `data/task3-ait-lds/` is
derived from the AIT Log Data Set and released under its CC BY-NC-SA 4.0 licence.

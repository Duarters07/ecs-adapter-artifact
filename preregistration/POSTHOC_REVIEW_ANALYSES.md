# Post-hoc analyses requested by the simulated reviews (declared before any result)

Written 2026-11-09T18:45Z, before any of the analyses below was run or any of their code existed. These are
**not pre-registered** analyses of the frozen test set. They answer reviewer objections to the EuroS&P draft and will
be reported as post-hoc in the paper, whatever their outcome. No run of the frozen test set is repeated, no model is
called, and no existing number of the paper changes because of them.

Inputs are fixed: the run records already captured on card 4 (`~/.cache/ecs-r10/card4/results/F-*-r7.ndjson`, plus
the development-set records where stated), the frozen r7 captures, reference parsers, truths and scenarios. All
analyses run on the local machine (CPU, Logstash and Elasticsearch), with no GPU.

## B1. What the gate deploys with VC alone

**Question.** The paper's deployment figures use V4 (replay of a scenario of the new version). An organisation that
records no scenario has only VC (continuity with the previous parser). What does the gate deploy then?

**Procedure.** For every full-system run of the 15 real test changes (3 models x 75 runs) whose final candidate is
stored, recompute the VC-verified field set with the system's own VC code, from the stored final IR, the frozen old
parser and the frozen new-version sample lines. Deploy, as the gate would, only the VC-verified fields (constants as the
gate treats them today). Accepted runs are judged on the same footing, i.e. V4 is not used at all.

**Measures.** Per model: runs that deploy anything, deployed-field precision and coverage against the reference (same
`judge` as the paper), deployments carrying a wrong value, and the share of the sources' detection rules whose fields
are all deployed (same rule-count definition as `prules`). Reported next to the V4-based figures.

## B2. The gate tested directly with wrong candidates

**Question.** In Task 3 the model never produced the attacker's goal, so the layers were never exercised. Does the
ladder plus gate stop a wrong candidate that a model could have written?

**Procedure.** Start from the accepted full-system candidates of the 15 real test changes (all three models). Apply
fixed, deterministic mutations to the IR, each a wrong candidate of a kind named in the threat model or the paper:
- M1 swap: a mapped address/user field moved to its counterpart (e.g. source.ip <-> destination.ip) (frame).
- M2 drop: the mapping that fills a field a detection rule reads is removed (blind).
- M3 constant: a constant the previous parser did not carry is added (implant), e.g. a fixed source.ip.
- M4 cross-type: a field mapped right on one message type is also filled from a different key on another type
  (the Fig. 7 failure).
- M5 shape: a capture class widened so that a shaped value is read into the wrong field (A2-style).
A mutation that does not apply to a candidate is skipped and counted. Each mutant goes through the ladder (V1-V4 with
the frozen scenarios) and the gate, exactly as in the runs.

**Measures.** Per mutation: refused by the ladder (and at which rung), accepted but the wrong field cut by the gate,
deployed with the wrong value. Reported for V4 and for VC alone (B1 setting). The expected weak spots, stated now: M3
(constants are not verified) and M4 (verification is per field, not per message type).

## B3. Refusing constants the previous parser did not carry

**Change.** Add to the gate the rule announced in the paper: a constant is deployed only if the previous parser carried
the same field with the same value. Unit tests for it. Re-run B2's M3 with the rule on and off.

**Effect on existing numbers.** None expected: no recorded run planted a constant (Task 3), and the analysis will
report how many recorded deployments carry a constant and would change under the rule.

## B4. A baseline without a language model

**Question.** How much of the system's maintenance result comes from the deterministic layer alone?

**Procedure.** For each of the 20 test pairs (and the 33 development changes if time allows), build a candidate with no
model call: the previous parser's IR plus the deterministic layer's own rewrites (template miner alternatives, old grok
nested where applicable, repairs that need no model). One run per pair (deterministic). Validate with the same ladder
and gate.

**Measures.** Accepted pairs, deployments, wrong values, rules recovered, against the three models in the same table.
If the deterministic layer cannot produce a candidate for a pair, that pair counts as refused.

## Reporting

All four are added to the paper as post-hoc, with this file's date. Unfavourable results are reported as they are.

## Results (appended 2026-11-09, after the runs)

Raw outputs: `~/.cache/ecs-r10/posthoc/{b1_vc,b2_gate,b4_nomodel}.json`; paper keys `ph/*` from `bench/paper_r10.py`.

- **B1** (VC alone, 75 runs per model on the 15 real changes). Rules firing 17% with no action -> 7B-S 38%, 14B 31%,
  7B 25% (44/42/32% with V4). Deployments carrying a wrong value: 0, 2, 0. Deployed-field precision 100/99/100%,
  coverage 37/35/28%. Caveat: the candidates were produced with V4 feedback during repair.
- **B2** (24 accepted candidates, one per model and source; the 14B PowerDNS candidate, whose original already deploys
  the Fig. 7 wrong value, is reported apart). M1 swap 0/21 deploy a wrong value (ladder refused all), M2 drop 0/24,
  M3 constant **24/24 with the current gate, 0/24 with the B3 rule**, M4 cross-type **6/20** (6 accepted by the
  ladder: the scenarios carry one message type), M5 shape 0/21 but uninformative (the frozen lines carry no shaped
  value, 16 accepted unchanged).
- **B3** Rule implemented (adapter/deploy.py, adapter/drift_loop.py, tests/test_constant_gate.py). Of the deployments
  the paper counts, event.category differs from the previous parser in 20/50 (7B-S), 56/67 (14B), 39/44 (7B), and
  event.dataset in 42/63/41. No scenario queries either field.
- **B4** (deterministic layer, no model, 15 real changes). Accepted 3/15, deployed 7, rules firing 25%. One deployment
  carries a wrong value that V4 verified (389-DS: user.name = "BIND", the hit count matched).

## C. The 14B at 8-bit precision (declared 2026-11-09T20:21Z, before any run)

**Question.** In every recorded run the 7B models were served at 8-bit (`q8_0`) and the 14B at 4-bit (`q4_K_M`, flash
attention, 8-bit KV cache, one slot). Both reviews ask whether the 4-bit quantisation handicapped the 14B, which would
confound "specialisation against size".

**Procedure.** On a new rented RTX 4090 (24 GB), the card-4 code as backed up (`card4-full/gs2`), Ollama 0.5.4,
Elasticsearch and Logstash 8.19.7, run the 14B untrained (`qwen2.5-coder:14b-instruct-q8_0`) exactly as cell
`F-T14-p22-r7` was run (arm T, pool r7, full system, 5 seeds, k=6 samples, 3 repairs, staged-edit, temperature 0.7,
window 32768, flash attention, 8-bit KV cache, one slot, round-9 flags), changing only the weights' precision. Tag
`F-T14q8-p22-r7`. If the model does not fit with that window, stop and report, do not shrink the window.

**Measures.** As for the primary endpoint and Section 5: accepted runs on the 15 real changes and the controls, the
per-source difference against `F-T14-p22-r7` (4-bit) and against `F-C10s-p22-r7` (7B-S), with the paper's bootstrap
interval; deployments with a wrong field value; rules that fire; wall time and peak memory. Reported as post hoc,
whatever the outcome. The pre-registered primary endpoint is not replaced.

## D. The full system without replay scenarios (declared 2026-11-11T16:34Z, before any run)

**Question.** Section 5.5 measured the gate with continuity (VC) alone on candidates that had been repaired with replay
feedback. A review asks what the system restores end to end when the organisation has no replay scenario at all.

**Procedure.** On a rented RTX 4090, the card-4 code as backed up, Ollama 0.5.4 (3 slots, no flash attention, as for the
7B arms), Elasticsearch and Logstash 8.19.7, run the specialised model exactly as cell `F-C10s-p22-r7` was run (arm C,
pool r7, full system, 5 seeds, k=6 samples, 3 repairs, staged-edit, temperature 0.7, window 32768, round-9 flags) on the
15 real test changes only, changing one thing: `ECS_NO_REPLAY=1`, which runs the ladder without V4 and without V3.5,
whose known values were taken from the scenarios (a 5-line change to bench/arms.py; the record keeps no extra field, so the runs are identified by
their tag and by `detection.skipped`). Tag `F-C10sNR-p22-r7`. Every run's final candidate is then cut by the gate with VC alone, with the code
of B1 (bench/posthoc_vc.py), on the laptop.

**Measures.** As B1: runs that deploy anything, deployments carrying a wrong field value, deployed-field precision and
coverage against the reference, and the share of the sources' detection rules whose fields are all deployed, set
against no action (17%), B1 (38%) and the replay gate (44%). Also runs accepted at V3 and wall time. Reported as post
hoc whatever the outcome; the pre-registered endpoint and every existing number are unchanged.

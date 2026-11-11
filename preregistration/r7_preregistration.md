## r7 gold and T3 (2026-10-30, laptop, no model run)

Specs `testbed/r3/r7specs/` (joined only with `R7=1`), reference parsers `testbed/r3/gold/r7_*` (generators
`~/.cache/ecs-r10/r7gold/gold_*.py`), sources `bench/sources/r7_*` (splits `train_r7` old / `test_r7` new), pool `r7` in
`bench/arms.py`. A field a parser may rightly leave unmapped is never a V4 target (`r7specs._unqueryable_abstentions`).
Every r7 scenario was rebuilt from scratch after the last spec change (earlier builds' scenarios moved to
`~/.cache/ecs-r10/r7gold/stale_scenarios/`: `testbed/r3/build.py` does not delete a scenario it no longer writes).

**All 40 reference parsers pass the full ladder with every rule firing**, except Unbound 1.17.1 (control, old version),
which has no rule (its two held-out events carry no queryable contrast) and so is not "detection verified"; it is used
only as the previous parser. `tests/test_pools.py`: 6500 passed.

| Pair | Kind | Rules old / new | T3 (old parser on new lines) |
|---|---|---|---|
| 389-DS 2.5 -> 3.1 (text -> JSON access log) | real | 2 / 3 | 0% read, 0/3, loud |
| InspIRCd 3.15 -> 4.7 | real | 3 / 4 | 0%, 0/4, loud |
| EMQX 4.4 -> 5.8 | real | 4 / 3 | 0%, 0/3, loud |
| Radicale 3.1 -> 3.5 | real | 2 / 2 | 0%, 0/2, loud |
| Knot 3.2 -> 3.4 | real | 3 / 3 | 0%, 0/3, loud |
| Synapse text -> JSON | real | 5 / 5 | 0%, 0/5, loud |
| Mattermost JSON -> text | real | 4 / 5 | 0%, 0/5, loud |
| Nextcloud audit file -> syslog | real | 3 / 5 | 0%, 0/5, loud |
| Kamailio text -> JSON | real | 5 / 4 | 0%, 0/4, loud |
| Icinga 2 2.13 -> 2.14 | real | 4 / 4 | 10%, 0/4, loud |
| PowerDNS Recursor 4.8 -> 5.2 | real | 5 / 4 | 50%, 0/4, loud |
| ocserv 1.1.6 -> 1.3.0 | real | 2 / 2 | 73%, 2/2, partial (loud) |
| NSD 4.6 -> 4.12 | real | 2 / 2 | 44%, 1/2, partial (loud) |
| Mumble 1.3 -> 1.5 | real, non-breaking | 3 / 3 | 100%, 3/3, intact |
| stunnel 5.68 -> 5.74 | real, non-breaking | 2 / 3 | 100%, 3/3, intact |
| ngIRCd, Privoxy, Unbound, Rspamd, Sendmail | control | 3/4, 1/1, 0/3, 2/2, 5/5 | 100%, intact |

Mumble and stunnel changed format (counted as real by the frozen rule) but a reasonably written old parser still reads
them; they are reported as real, non-breaking changes. Thin: Privoxy (1 rule), Radicale, ocserv, NSD, Rspamd (2).
Review points recorded in the specs: pdnsrec maps the numeric rcode to `dns.response_code` (ECS expects the name);
389-DS 3.1 logs "SASL bind in progress" as a successful simple bind's message; Mattermost's JSON gold carries one
non-blocking V3.5 finding (a duplicated 401 value on an abstained key).

## r7 predictions (written 2026-10-30 ~22:20 UTC, approved by the author ~22:35 UTC, BEFORE any model run on r7)

**Status: approved by the author (2026-10-30 ~22:35 UTC) and frozen with hashes (below).** Written before the
checkpoint's B and 14B cells and before any round-10 training data exists. Before freezing, the primary endpoint of the
first draft (all 20 sources, non-inferiority) was corrected to the one PLAN_ROUND10_ARM_C.md section 4 rule 5 fixed in
advance (real changes only, TOST at 15 points); nothing else was changed.

**Author decisions recorded with it.** (a) Mumble and stunnel stay real changes, as the frozen rule counts them, and are
reported as *non-breaking* (T3 intact): the 15 real changes are 13 breaking (11 completely, ocserv and NSD partly, with
PowerDNS Recursor at 50% read counted as breaking) and 2 non-breaking. (b) Task 3's gold and its three design decisions
are accepted as recommended (TASK3_EXTERNAL.md). (c) Comparison structure: primary C vs the 14B with both in the full
system; the architecture each arm ran under is stated in every report.

Arms and architecture, stated explicitly: every arm (arm C, org9, B, the 14B) is served inside the SAME round-10
architecture (staged-edit stages, V1-V4 ladder, repair loop, deterministic layer); only the model differs. Arm C
is Qwen2.5-coder 7B with two LoRA adapters (interpret, map); B is the same 7B untrained; the 14B is Qwen2.5-coder 14B
untrained. Model-only mode (one call, no repair, no deterministic layer, same staged prompts and schema) is run for
every arm too. No 'raw' 14B (free prompt, no stages) is run.

Protocol (plan F8b): every arm on the round-10 pipeline, staged-edit, k=6 with 3 repairs; full system 5 seeds,
model-only 5 seeds; the source is the unit. Arms: arm C (org10 if F6 produces it and it passes its gates, else org9),
org9 (always, as the previous system), B, the 14B.

**Primary endpoint (as fixed in PLAN_ROUND10_ARM_C.md section 4, rule 5).** Full system, the 15 r7 REAL changes (NEW
versions): per-source mean acceptance, arm C minus the 14B, by two one-sided tests at a 15-point margin: arm C and the
14B are declared *equivalent* if the 90% percentile-bootstrap interval of the mean per-source difference lies inside
+-15 points (10 000 resamples, seed 0). Read with it, not as a second primary: *not inferior* if that interval's lower
bound is above -15 points; *better* if, in addition, the exact two-sided sign test over the 15 sources gives p < 0.05.
Secondary: all 20 sources (controls included); the same against org9 and B; the 13 breaking pairs alone; model-only; arm C in full system against
the 14B in model-only (our architecture with the specialised 7B adapters against the larger model alone); full
system minus model-only per arm (the architecture's contribution).

Predictions:
1. Controls and non-breaking pairs (7: ngIRCd, Privoxy, Unbound, Rspamd, Sendmail, Mumble, stunnel): arm C, org9 and
   the 14B accept >= 4/5 on at least 6 of the 7; B fails at least one of them (< 3/5).
2. Text -> JSON with every value a top-level key (389-DS, Synapse): arm C >= 3/5 on each.
3. Values inside a JSON message text (Kamailio's `message`) or JSON after a syslog header (Nextcloud): the round-10
   nested extraction applies; arm C >= 2/5 on each, org9 on the new pipeline also >= 2/5 on at least one.
4. JSON -> text (Mattermost): arm C >= 3/5.
5. Reworded text (InspIRCd, Radicale, Knot, Icinga 2, EMQX 4 -> 5): arm C >= 3/5 on at least 3 of the 5.
6. Partial changes (ocserv, NSD, PowerDNS Recursor): every editing arm >= 3/5 on at least 2 of the 3.
7. Totals, full system, accepted of 100 (20 sources x 5 seeds): arm C 70 (range 60-80), the 14B 68 (60-78), org9 64
   (55-75), B 50 (40-62). On the 15 real changes (of 75): arm C 48 (40-56), the 14B 47 (39-55).
8. Primary endpoint: equivalence within 15 points, probability ~0.55; arm C not inferior, ~0.65; arm C better by the
   sign test, ~0.10 (15 sources, many ties).

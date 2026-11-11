## Pre-registration (2026-10-30 ~22:45 UTC, approved with r7's; BEFORE any model sees a Task 3 line)

Frozen inputs: `~/.cache/ecs-r10/task3/MANIFEST.sha256` (102 files; digest
`250795372bf1fb9d31a8d9c86052a517802090a82d20e1c6be3cea29f053ced8`): six AIT-LDS sources (samples, origin,
reference parser, truth), 22 V4 scenarios from the dataset's own labels (scenario fox), Loghub-2.0 samples for Apache,
Linux, OpenSSH, Proxifier and Zookeeper.

**Arms and architecture.** Every arm (arm C as chosen by F6/F7, org9, B, the 14B) inside the same round-10 architecture
(staged stages, V1-V4 ladder, repair loop k=6 with 3 repairs, deterministic layer), in Task 1's mode: no previous
parser, so no edit mode and no rule B. Full system 5 seeds and model-only 5 seeds. Only the model differs between arms.

**Metrics.** (1) Accepted runs per source (the ladder; its V4 rules are the source's label scenarios, 22 in all).
(2) Field accuracy of the accepted parser against the gold (correct / wrong /
missing per ECS field, every line of the source's samples). (3) Detection: share of the 22 label scenarios whose
query returns the expected hit count on the parser's output. (4) Loghub: GA and PA of the grok the system writes from
20 samples, each reported beside the harness's self-test ceiling for that system (Apache 1.000/0.9995, Zookeeper
0.9993/0.9989, Proxifier 0.9857/0.9857, Linux 0.7289/0.8118, OpenSSH 0.4247/0.7209), and a memorisation probe
(the model completes held-out Loghub lines from their first half; Loghub is public since 2020).

**Predictions.**
1. Apache access, Apache error and auth.log (families the training covers): arm C and the 14B accept >= 4/5 on each.
2. auditd (many record types, key=value, quoting) and dnsmasq (three line kinds per query): every arm <= 3/5 on at least
   one of the two; arm C >= B on both.
3. OpenVPN: arm C and the 14B >= 3/5.
4. Totals, full system, accepted of 30 (6 sources x 5 seeds): arm C 22 (18-26), the 14B 22 (18-26), org9 20
   (15-25), B 15 (10-20). Detection, share of the 22 label scenarios met by accepted parsers: arm C >= 0.7.
5. Loghub: on Apache and Zookeeper, PA within 0.15 of the ceiling for arm C and the 14B; on Linux and OpenSSH, GA below
   0.6 for every arm (their ceilings are low and their templates fine-grained). The memorisation probe finds no
   verbatim completion above 5% of lines for any arm; if it does, Loghub numbers are reported as possibly contaminated.

The primary endpoint of round 10 is r7's (ROUND3_VERSION_DRIFT.md); every Task 3 number is secondary, external
validity.

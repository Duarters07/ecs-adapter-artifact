### Amendment to the Task 3 pre-registration (DRAFT, for the author; written before any model sees a Task 3 line)

The frozen text fixes Loghub's metrics and predictions but not how the arms produce the parsers it scores, nor the
probe's details. Proposed, and to be frozen with its own hash once approved:

1. Loghub runs exactly as the AIT-LDS sources: every arm, Task 1's mode, the round-10 pipeline, full system (k=6, 3
   repairs) and model-only, 5 seeds; the system's frozen 20 samples are all a model sees.
2. GA and PA are computed on the **final IR of every run**, accepted or not (Loghub has no ECS gold, so most of the
   ladder's acceptance does not apply to it); a non-grok extraction reads nothing and is scored as such. Reported as
   the mean per (arm, mode, system) beside the ceiling.
3. The probe as built above (100 lines per system, the file and hash above), once per served model: the 7B base (B),
   org10 SFT and SFT+DPO interpret adapters, org9's interpret adapter, the 14B. Arm C's reading uses the model F7
   selected.
4. The Loghub systems are the five frozen in the manifest (Apache, Linux, OpenSSH, Proxifier, Zookeeper); the design
   text's HDFS is not among them.
5. Arm C is org10 as F6 produced it after the author's retrain (lr 1e-4; gates passed 08:26 UTC 11-01), interpret stage
   SFT or SFT+DPO by F7's rule; the first attempt (org10lr5) is not an arm.

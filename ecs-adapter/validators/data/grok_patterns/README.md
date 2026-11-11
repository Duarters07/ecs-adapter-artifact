# Grok pattern definitions (vendored)

`ecs-v1/` is copied unchanged from logstash-patterns-core 4.3.4 as bundled with Logstash 8.19.7
(`vendor/bundle/jruby/3.1.0/gems/logstash-patterns-core-4.3.4/patterns/ecs-v1`), the version the sandbox runs.
Licence: Apache License 2.0 (`LICENSE`, `NOTICE.TXT`, from the same gem).

`validators/v2_consistency.py` expands these definitions to simulate grok in Python (round 10, A3), so that
every deterministic check judges a pattern by what Logstash would actually match.

You previously produced an ECS {{ ecs_version }} mapping that failed validation.

## Your previous output

{{ previous_ir }}

## Validation errors

{{ errors }}

## How `extraction` must be shaped

This block says how a raw line is split into keys. If it is wrong, every field
is empty and every rule fails no matter where the fields are mapped.

```
{"kind": "json"}                                      the line IS a JSON object
{% if round10 %}{"kind": "json", "inner": {"source": "msg",
 "pattern": "Login failed for %{USERNAME:user} from %{IP:src}"}}
                                                      JSON whose `msg` holds the values as text
{% endif %}{"kind": "kv",   "field_split": " ",
                 "value_split": "="}                  key=value key=value
{"kind": "csv",  "columns": ["a","b","c"],
                 "field_split": ","}                  both are REQUIRED
{"kind": "grok", "pattern": "%{IP:src} %{WORD:act}"}  pattern is REQUIRED
{"kind": "grok", "pattern": "job %{INT:job} started by %{USERNAME:owner} ...",
 "alternatives": ["%{HOSTNAME:node} aborted job %{INT:job} owned by %{USERNAME:owner} ..."]}
                                                      one pattern per KIND of line
```

When a grok misses some lines, decide which case it is. The same message with a
part sometimes absent: make that part optional inside the pattern, `(?:...)?`.
A different message altogether: add a pattern for it to `alternatives`, and give
the same value the same capture name in every pattern.

`field_split` and `value_split` are LITERAL strings, never regular
expressions: write `|`, not `\|`. A tab is `\t`, not `\\t`.

A line with no `=` in it is not `kv`. A line that is free prose with values
embedded in it - `Failed password for alice from 10.0.0.1 port 42710` - is
`grok`, and the pattern is what names the keys you then map.

## Available ECS fields

{{ ecs_fields }}

## Task

Produce a corrected JSON object conforming to the IR schema.

Rules:

1. Fix ONLY what the errors identify. Do not rewrite parts that were not reported.
2. Read what the error actually says. It names the cause: whether no documents were
   produced, whether the documents carry none of the fields the rule needs, or whether
   the fields are present and the values landed somewhere unexpected. Only the last of
   those is a wrong ECS role. The first two are `extraction`, and changing field
   assignments will not fix them.
3. Only invent a key name when the extraction is `grok` and you are naming your own
   captures. For `json`, `kv` and `csv` the keys are whatever is in the line; a key
   that is not there produces an empty field and, if two of them collide on one ECS
   field, silently destroys a real value.
4. If you cannot determine the correct field from the evidence available, move it to
   "unresolved" with a reason rather than guessing a different wrong answer.

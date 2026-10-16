# Architecture

## Components and data flow

```
bytes ─► loader ─► detect ─► parsers/<format> ─► Recording (IR)
                                                     │
                       analysis.grouping  ◄──────────┤  filter (static/hosts), group into flows
                       analysis.secrets   ◄──────────┤  likely credentials (values stay in memory)
                       analysis.correlation ◄────────┘  dynamic values + extractor suggestions
                                                     │
                       service.default_plan ─► Plan (JSON-editable: flows, order, accepted ids, policy)
                                                     │
                       naming.assign_names ─► TX_nn / TX_nn_Ann names   ─► service.preview (report)
                                                     │
                       transform.prepare  ─► PreparedPlan (copies; correlations, secrets, headers, timers)
                       generator.generate_jmx ─► .jmx text
                       validate.structural_check / leak_check (always)
                       validate.jmeter_load_check / jmeter_mock_run (optional, local only)
```

The engine has no UI code. `service.py` is the only entry point used by `cli.py` and
`web/server.py`, so both front ends run the same parsing, analysis, naming, generation,
and validation.

## Intermediate representation (`ir.py`)

| Type | Fields | Contract |
|---|---|---|
| `Recording` | `source_format`, `source_name`, `requests`, `issues`, `variables`, `grouping_source`, `fingerprint`, `metadata` | `requests` are in source order. `fingerprint` = sha256 of the input bytes. `variables` = source-defined defaults (JMX UDVs, unknown Postman variables) |
| `Request` | `id`, `method`, `scheme`, `host`, `port`, `path`, `query`, `headers`, `body`, `started_at`, `duration_ms`, `response`, `group_hint`, `source_ref`, `resource_type`, `unresolved_origin` | `id` is `r0001`... in source order. `path` is raw and percent-encoded, with no query. `port` is explicit only. `host` may be a JMeter expression (`${server}`). `unresolved_origin` is set when the whole origin is a variable |
| `QueryParam` | `name`, `value`, `has_equals` | Decoded values; `has_equals=False` for bare flags (`?debug`) |
| `Body` | `kind` (`none`/`raw`/`form`/`multipart`), `text`, `content_type`, `fields` | url-encoded forms become structured `form` fields; other text stays `raw` |
| `FormField` | `name`, `value`, `file_name`, `content_type` | `file_name` marks a file part (contents are never available) |
| `Response` | `status`, `headers`, `body_text`, `content_type` | Analysis only, truncated to 1M characters, **never written to output** |
| `Issue` | `severity` (`info`/`warning`/`error`), `code`, `message`, `request_id` | Messages never contain header values, bodies, or full URLs |

Parsers report what they drop or change as `Issue`s, for example skipped WebSocket
entries, ignored curl options, unconverted JMX elements, and unexecuted Postman scripts.

## Analysis

- **Filtering:** HAR static resources are excluded by `_resourceType`, extension, or
  response MIME type. Host include/exclude globs apply to all formats.
- **Grouping:**
  - `recorded` uses consecutive runs of the source's group hint (HAR page, JMX
    Transaction Controller or Thread Group, Postman folder, `# flow:` comment, JSON
    flow). Non-consecutive repeats stay separate to preserve request order.
  - `gap` starts a new flow after N idle seconds and is labeled *heuristic*.
  - `auto` uses `recorded` when hints exist, otherwise `gap`.
- **Secrets:** sensitive header names, sensitive parameter/field/JSON-key names, and value
  patterns (JWT, AWS keys, private keys, common API-key prefixes). The same value maps to the
  same `SECRET_*` variable. CSRF-style names are treated as dynamic values, not secrets.
- **Correlation suggestions.** A value is suggested only when it:
  1. is sent by a request,
  2. first appears in an *earlier recorded response*, and
  3. was not sent by any request before that response.

  JSON responses get a JSONPath (`JSONPostProcessor`). Other responses get a Boundary
  Extractor on the body or headers, with boundaries grown until unique. Other kinds:
  - `timestamp` (epoch close to the request time → `${__time()}`)
  - `unresolved` (CSRF/nonce-like name with no recorded source; informational only)

## Plan file (`plan.py`)

```json
{
  "rec2jmxPlan": 1,
  "recordingFingerprint": "sha256:…",
  "testPlanName": "shop_flows",
  "secretPolicy": "parameterize",
  "thinkTime": "none",
  "parameterizeHosts": true,
  "acceptSuggestions": ["C02"],
  "flows": [{"name": "Login", "requests": ["r0001", "r0003"]}],
  "_requestIndex": {"r0001": "GET https://shop.example.test/"}
}
```

Flow order sets transaction numbering. Validation rejects:
- unknown or duplicate request ids, and empty flows
- unknown or non-acceptable suggestion ids
- a plan made for a different recording (fingerprint mismatch)

`_requestIndex` is informational (masked URLs) and ignored on load.

## Transformation order (`transform.py`)

Requests are copied and processed in plan execution order:

1. Accepted correlations: the extractor goes on the source sampler, and the value is replaced
   by `${C_x}` in later requests. A correlation is *skipped with a warning* if its source is
   missing or runs after a usage in the current flow order.
2. Accepted timestamps.
3. Secrets (policy `parameterize`): location-specific replacement, then value-wide replacement
   for values of 8+ characters.
4. Headers: every recorded header is kept, in order. Exceptions (verified with JMeter 5.6.3):
   HTTP/2 pseudo-headers are dropped (`:authority` becomes `Host`), and `Transfer-Encoding` is
   dropped because JMeter fails to send it. Informational messages cover Cookie/Cookie Manager
   interplay and `br`/`zstd` in `Accept-Encoding`.
5. Think times (CLI `--think-time` only): recorded gaps within a flow (100 ms–60 s), or a constant.

The generator gives every sampler its own Header Manager with all of its headers, binds a
recorded `Host` header to `${HOST_n}` when hosts are parameterized, declares only the
variables that are actually referenced, and writes deterministic XML (no timestamps,
`\r` as `&#13;`, control characters removed with a warning).

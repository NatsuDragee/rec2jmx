# rec2jmx: recordings to Apache JMeter test plans

`rec2jmx` turns recorded HTTP traffic and API scenarios into readable, parameterized
Apache JMeter (`.jmx`) test plans. It runs locally, has no runtime dependencies beyond
Python 3.10+, and **never sends recorded requests anywhere**.

Workflow: **import → inspect/preview → review/configure → generate → validate/download**,
through a CLI or a local web UI. Both use the same engine.

> **Important boundary.** JMeter replays HTTP(S) requests. It does **not** replay
> Android/iOS or browser UI interactions. A plan generated from a mobile capture
> load-tests the captured API calls, not the app's screens, gestures, or rendering.

## Supported inputs

| Format | Typical source | Notes |
|---|---|---|
| HAR 1.1/1.2 | Browser DevTools; proxy exports (Charles, Proxyman, HTTP Toolkit, mitmproxy) for web and mobile apps | Pages become flows; static resources are excluded by default |
| cURL commands | "Copy as cURL" (bash or Windows cmd), hand-written | `# flow: Name` comments group commands |
| JMeter `.jmx` | Existing plans you want to re-standardize | HTTP samplers, headers, defaults, variables, transaction names |
| Postman Collection v2.0/v2.1 | Postman exports | Folders become flows; scripts are not converted |
| rec2jmx JSON recording v1 | Your own capture tooling | Documented schema in [docs/FORMATS.md](docs/FORMATS.md) |

Nothing else is supported. Unrecognized, malformed, or ambiguous files are rejected with an
explanation and are never reinterpreted. Full limitations per format are in
[docs/FORMATS.md](docs/FORMATS.md), and `rec2jmx formats` prints the same list.
No JMeter plugins are required by generated plans.

## Setup

```bash
python -m pip install -e .            # or: pip install -e ".[dev]" to include pytest
rec2jmx --version
```

You can also run it without installing: `set PYTHONPATH=src` (Windows) or `export PYTHONPATH=src`,
then `python -m rec2jmx ...`.

JMeter is optional. It's needed only for the `--validate-jmeter` and `--validate-mock` checks.
Point to it with `JMETER_HOME`, `--jmeter <path>`, or by putting `jmeter` on `PATH`.

## CLI usage

```bash
# 1. Inspect: detected format, flows, proposed JMeter names, secrets, suggestions, warnings
rec2jmx inspect recording.har

# 2. Review: save an editable plan (flow order/names, included requests, accepted suggestions)
rec2jmx inspect recording.har --write-plan plan.json
#    ...edit plan.json...

# 3. Generate (+ optional local JMeter validation)
rec2jmx generate recording.har --plan plan.json -o checkout.jmx --validate-jmeter --validate-mock
```

Useful options (on `inspect` and `generate`):

| Option | Effect |
|---|---|
| `--accept C02 --accept C05` / `--accept all` | Apply correlation or timestamp suggestions (nothing is applied by default) |
| `--flow-order 2,1,3` | Reorder flows, which renumbers `TX_nn` |
| `--group-by auto\|recorded\|gap\|single`, `--gap 5` | Flow grouping strategy |
| `--include-static`, `--include-host GLOB`, `--exclude-host GLOB` | Request filtering |
| `--secrets include\|parameterize` | Default `include` (same as the web UI) writes recorded values into the file; `parameterize` replaces detected secrets with `${SECRET_*}` properties. A `--plan` file keeps its own `secretPolicy` |
| `--think-time none\|recorded\|<ms>` | Constant Timers (default none) |
| `--no-parameterize-hosts` | Hard-code hosts instead of `HOST_n`/`PORT_n`/`PROTOCOL_n` |
| `--json` | Machine-readable report (for scripts or agents) |

Exit codes: `0` success, `1` input/plan error, `2` validation failed or could not run.
`generate` refuses to overwrite an existing file unless you pass `--force`.

## Web UI

```bash
rec2jmx serve            # http://127.0.0.1:8765/
```

A dark-themed workspace with three steps (Import, Review, Generate):

- **Import:** drop a file or choose one. Import options set the flow grouping and whether
  static resources are kept.
- **Top bar:** shows the detected format and a warnings count. Important problems appear as
  banners under the bar, such as a sanitized HAR that has lost its `Authorization` and cookies,
  or an event-stream request that would hang a sampler.
- **Left pane, hosts:** one chip per host with its request count. Click a chip to exclude or
  include that host. Analytics, monitoring, feature-flag and chat hosts are tagged, and
  **Exclude third-party** removes them in one click. Identity hosts are tagged but never
  excluded automatically.
- **Left pane, flows:** each flow is shown with its `TX_nn` name and its requests' `TX_nn_Ann`
  names.
  - Drag flows to reorder them.
  - Drag requests within a flow, between flows, or onto **+ New flow**.
  - Name a transaction with **✎ Rename** (or click its `TX_nn` name, or double-click the flow name).
    A live preview shows the final name, e.g. `Checkout & Payment` → `TX_02_Checkout_Payment`;
    Enter saves and Escape cancels. After a merge you are prompted to name the merged transaction.
  - Merge flows into one Transaction Controller: **Merge ↓** joins a flow with the next one;
    tick two or more flows (they need not be adjacent) and choose **Merge selected**. The merged
    flow keeps the first flow's name and position, and requests keep their order.
  - Untick a request to exclude it. Excluded requests stay visible, so you can re-include them.
  - Requests removed by the import filter can be dragged back in.
- **Right pane, Request:** sub-tabs for Headers, Query, Body, Response and Sampler.
  - **Headers** lists every recorded header next to the value written to the JMX, with a status:
    `kept`, `changed` (for example `${HOST_1}`), `mapped`/`added` (HTTP/2 pseudo-headers),
    or `not sent`.
  - Sensitive values (credentials, cookies, bodies that contain detected secrets) are masked
    until you turn on **Show sensitive values**.
- **Right pane, other tabs:** **Correlations** (switch suggestions on), **Secrets** and
  **Messages** (with the limitations).
- **Generate:** set the plan name, secret handling (default **Include recorded values**), host
  parameterization and optional local JMeter validation. The result shows a summary,
  the validation results, a syntax-highlighted **XML preview**, **Copy XML** and **Download**.

The UI has no think-time setting: plans are generated without timers. The CLI still offers
`--think-time`.

The server binds to 127.0.0.1 only, keeps uploads in browser memory, and stores nothing on disk.

## The generated plan

```
Test Plan
├── User Defined Variables   HOST_n/PORT_n/PROTOCOL_n, SECRET_*, source variables, FILE_DIR
├── HTTP Cookie Manager      (handles Set-Cookie at run time)
└── Thread Group             threads/rampup/loops = ${__P(threads,1)} etc.
    ├── TX_01_Login                     Transaction Controller
    │   ├── TX_01_A01_api_v1_login      HTTP Request (+ its own Header Manager, extractors)
    │   └── TX_01_A02_users_id
    └── TX_02_Checkout
        └── TX_02_A01_orders
```

**Naming rules:**
- Transactions are `TX_<nn>_<flow>`, numbered from 01 in flow order.
- Samplers are `TX_<nn>_A<nn>_<path>`. API numbers restart at A01 in every flow and follow request order.
- The path label comes from the URL path only, never the query string.
- Identifier-like or secret segments become `id`, and `{id}`/`:id` templates keep their name.
- Numbers widen to 3 digits for 100+ items.

All names appear in the preview before generation.

**Request headers are kept as recorded.** Every sampler gets its own Header Manager with
all of its recorded headers, in order, including `Host`, `Connection`, `Content-Length`,
`Cookie`, `Accept-Encoding` and browser headers. The only exceptions were checked against
JMeter 5.6.3:

| Recorded header | What happens | Why |
|---|---|---|
| HTTP/2 pseudo-headers (`:method`, `:path`, `:scheme`, `:authority`) | Become the sampler's method, path and protocol; `:authority` becomes a `Host` header | JMeter's HTTP client discards them |
| `Transfer-Encoding` | Not copied (a warning is shown) | JMeter fails to send a request that sets it |
| `Host` (with parameterized hosts) | Value becomes `${HOST_n}` or `${HOST_n}:${PORT_n}` | So it follows `-JHOST_n` overrides |

Notes:
- JMeter recomputes `Content-Length` and the multipart boundary for the body it actually sends.
- A recorded `Cookie` header is sent until the HTTP Cookie Manager holds cookies for that URL;
  then the manager's cookies replace it. Disable the Cookie Manager to always send recorded cookies.
- JMeter cannot decode `br`/`zstd` responses. `Accept-Encoding` is kept as recorded, with an
  info message, because such responses can't be read by extractors or assertions.

Run the generated plan:

```bash
jmeter -n -t checkout.jmx -l results.jtl -Jthreads=20 -Jrampup=60 -Jloops=5 \
       -JHOST_1=staging.example.com -JSECRET_password=... -JSECRET_Authorization=...
```

By default (CLI and web UI) recorded values, including tokens, passwords and cookies, are
written into the plan as recorded, so treat the `.jmx` as confidential. With
`--secrets parameterize` (or the UI's Parameterize option), each detected secret becomes
`${SECRET_<name>}` with an empty `${__P(...)}` default that you supply at run time with `-J`.
In that mode, generation stops (and writes nothing) if a detected secret of 8+ characters
would still appear in the output.

## Validation levels

| Level | When | What it proves |
|---|---|---|
| Structural | Always | Well-formed XML, consistent `hashTree` pairing, required elements, unique names |
| Secret leak check | Always (parameterize policy) | No detected secret value remains in the file |
| `--validate-jmeter` | On request | Real JMeter loads and starts the plan with 0 threads, and all hosts are forced to 127.0.0.1 |
| `--validate-mock` | On request | JMeter runs 1 iteration against a local 127.0.0.1 mock server; the method/path sequence is compared |

JMeter validation runs only when every sampler's server is a `HOST_n`/`PORT_n`/`PROTOCOL_n`
property, threads are property-driven, and no script or non-HTTP samplers are present.
Otherwise it refuses and explains why. A passing structural check alone does not mean
JMeter has accepted the plan.

## Tests

```bash
python -m pip install pytest
python -m pytest                                    # JMeter/browser tests skip if unavailable
JMETER_HOME=/path/to/apache-jmeter python -m pytest # include real-JMeter validation
```

- The suite uses small synthetic fixtures (`tests/fixtures/`, `*.test` hosts, fake credentials).
- Any test that opens a non-loopback socket fails.
- Tests marked `jmeter` need `JMETER_HOME`; tests marked `browser` drive headless Chrome/Edge
  (`CHROME_PATH`) with DNS disabled except for 127.0.0.1.
- The `jmeter` tests include an end-to-end run where the mock server returns *fresh*
  tokens and IDs, and the test asserts that later requests carry them. This exercises the
  generated JSON and Boundary extractors.

## Project layout

```
src/rec2jmx/
  detect.py, loader.py        input decoding, size limits, content-based detection
  parsers/                    har, curl, jmx, postman, native_json -> IR
  ir.py                       format-neutral intermediate representation
  analysis/                   grouping/filtering, secrets, correlation suggestions
  plan.py, naming.py          reviewable plan; TX/sampler naming rules
  transform.py, generator.py  apply plan to IR copies; write .jmx
  validate.py                 structural, leak, JMeter load and mock-run checks
  service.py                  facade used by cli.py and web/
docs/                         ARCHITECTURE.md, FORMATS.md, SECURITY.md
```

## Known gaps

- No LLM/agent interface is implemented. `inspect --json` and `service.py` give an agent a
  validated engine to call; any agent would still need its own confirmation steps.
- Correlation needs recorded responses (HAR or rec2jmx JSON). Values shorter than 8 characters
  (for example, numeric user IDs) are not suggested. The UI cannot add filtered-out requests
  back into flows; use `--include-static` or the host filters instead.
- HAR exports from specific proxy tools were tested only through spec-conformant synthetic HAR
  files, not real exports from each tool.
- Plans whose server comes from an undefined variable (for example, a Postman `{{baseUrl}}`
  without a value) cannot be validated with JMeter, because requests could not be pinned to
  localhost.

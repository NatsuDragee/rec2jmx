# Security and privacy

Recordings can contain credentials, session tokens, and personal data. rec2jmx treats
every input as untrusted.

## No network activity from recordings

- Import, analysis, generation, and validation never connect to hosts found in a recording.
- JMeter validation runs only for plans whose every sampler server is a `HOST_n`/`PORT_n`/
  `PROTOCOL_n` property:
  - `--validate-jmeter` overrides those properties to `127.0.0.1` on a closed port and uses
    0 threads.
  - `--validate-mock` points them at a mock server rec2jmx starts on `127.0.0.1`.
- Plans with hard-coded or variable hosts, non-standard thread groups, or script/non-HTTP
  samplers are refused.
- The test suite fails any test that opens a non-loopback socket. The browser UI test runs
  Chrome with DNS disabled except for `127.0.0.1`.

## Untrusted input handling

- Size is checked before reading (default 50 MB). Decoding is strict UTF-8/UTF-16; NUL bytes
  are rejected as binary.
- JSON nesting that is too deep is rejected cleanly.
- JMX files with `DOCTYPE`/`ENTITY` declarations are rejected before XML parsing (no XXE or
  entity expansion).
- Nothing in a recording is executed:
  - curl text is tokenized, not run by a shell, and shell operators are rejected
  - Postman scripts and JMX scripts are reported, not run
  - `@file` references in curl and file paths in Postman are never read
- File names from inputs are reduced to safe base names for display and output names.
  Generated upload paths become `${FILE_DIR}/<sanitized name>`.
- Error messages and issues never include header values, bodies, or full URLs.

## Secrets

- Detection uses sensitive header, parameter, and JSON-key names plus value patterns (JWT,
  AWS keys, private keys, common API-key formats).
- Policy `parameterize` (opt-in): values become `${SECRET_*}`, declared as
  `${__P(SECRET_*,)}` with an empty default. Supply them at run time with `-J`.
- With `parameterize`, generation stops and writes nothing if a detected secret of 8+ characters would remain in
  the output. Shorter values that also appear elsewhere produce a warning.
- `include` is the **default in both the CLI and the web UI**: recorded values (tokens,
  passwords, cookies) are written into the file. `inspect` and the UI show how many detected
  secrets will be written, and generation warns you to treat the file as confidential. Use
  `--secrets parameterize` (or the UI option) before sharing plans.
- Previews, reports, and plan files show secrets only as `[redacted, N chars]`, with secret
  query values and path segments masked as `***`. Element names never contain query strings
  or secret or dynamic values.
- Recorded `Cookie` headers are kept. Under `parameterize`, their values become `${SECRET_Cookie}`.

## Storage and logging

| Component | What is stored | How to remove it |
|---|---|---|
| CLI | Only the files you ask for (`-o out.jmx`, `--write-plan plan.json`), written atomically. Existing files are not overwritten without `--force` | Delete those files |
| JMeter validation | A temporary directory (`rec2jmx-*` under the system temp folder) holding the plan, `jmeter.log` and results; deleted automatically when validation finishes | Nothing left behind; if a process is killed mid-run, delete leftover `rec2jmx-*` temp folders |
| Web UI | Nothing on disk. The browser keeps the uploaded file in page memory and resends it with each request. The server logs only HTTP method and path | Close or reload the page |

The web server binds to `127.0.0.1` only. It rejects requests whose `Host` or `Origin` is not
the local server (DNS-rebinding and CSRF protection), requires `application/json` for API
calls, enforces the size limit using `Content-Length`, and serves a strict
Content-Security-Policy. Recording-derived text is rendered with `textContent` only.

## Generated files are still sensitive

Even with secrets parameterized, a `.jmx` reveals hostnames, API paths, and request bodies
(which may contain personal data such as names or emails, since PII is not detected). Review
the plan before sharing it.

# Supported formats and limitations

Detection is based on file content. If the extension disagrees with the content, you get a
warning. If `--format` disagrees with the content, the file is rejected. Unknown JSON
schemas, XML that is not a JMeter plan, binary files, and unrecognized text are all rejected.
Inputs must be UTF-8 (BOM allowed) or UTF-16 with a BOM, with a default limit of 50 MB
(`--max-size`).

Generated plans use only core JMeter 5.x elements; **no plugins are required**. They have
been loaded and run with JMeter 5.6.3.

## HAR 1.1 / 1.2

Detected by a JSON object with `log.entries`.

**Converted:**
- method, URL, headers, and request body (`postData.text`, or `params` for forms/multipart)
- start time and duration
- response status, headers, and text (for correlation analysis only)
- page grouping (`pageref` → page title)
- Chrome `_resourceType`

**Not converted:**
- WebSocket entries and non-HTTP(S) URLs (`data:`, `chrome-extension:`); skipped and reported
- static resources, excluded by default (`--include-static` keeps them)
- multipart file contents, which HAR files rarely contain; files are read from `${FILE_DIR}`
  at run time
- binary request bodies

**Sanitized exports lose Authorization and cookies.** Chrome's default "Export HAR
(sanitized)" removes `Authorization`, `Cookie` and `Set-Cookie` before writing the file, so
those headers are not in the HAR and cannot be converted. rec2jmx warns when a HAR has none of
them. To keep them, in Chrome DevTools go to Settings > Preferences > Network, enable
"Allow to generate HAR with sensitive data", then use "Export HAR (with sensitive data)" in the
Network panel. rec2jmx itself keeps every recorded `Authorization` header (covered by tests for
every input format).

**Mobile apps (Android/iOS):** capture traffic with a proxy that exports HAR (Charles
Proxy, Proxyman, HTTP Toolkit, mitmproxy via `mitmdump --set hardump=out.har`) and import
the HAR. Certificate-pinned apps need the usual proxy setup on a test device. The generated
plan reproduces the captured API calls only. It does not test UI flows, device behavior, or
client-side logic.

*Testing note:* the HAR parser is tested with spec-conformant synthetic files that model
browser and mobile-proxy captures. Real exports from each proxy tool have not been tested.

## cURL commands

One or more `curl` commands, one per line (with `\` or cmd `^` continuations). Quoting
supports `'…'`, `"…"`, `$'…'`, and Windows cmd `^"` escaping.

**Understood:**
- `-X`, `-H`, `-d`/`--data`/`--data-raw`/`--data-binary`/`--data-ascii`/`--data-urlencode`
- `--json`, `-F`/`--form`/`--form-string`, `-u`, `--oauth2-bearer`, `-b` (inline cookies)
- `-A`, `-e`, `-G`, `-I`, `--url`

**Ignored with a note:** `--compressed`, `-s`, `-L`, `-k`, `-v`, `-o`, timeouts, retries,
HTTP version flags.

**Reported as unsupported:** client certificates, proxies, `--resolve`, `-T` uploads, curl
config files, AWS SigV4.

**Not supported:**
- shell features (`|`, `;`, `&&`, `$(…)`, variables); operators are rejected
- `@file` references, which are never read

Group commands with comment lines: `# flow: Login`.

## Apache JMeter `.jmx`

Re-imports an existing plan so it can be regenerated with standard naming and structure.

**Converted:**
- HTTP Request samplers (`HTTPSamplerProxy`)
- HTTP Header Managers (scoped and merged like JMeter; the nearest one wins)
- HTTP Request Defaults (server fields)
- User Defined Variables (used to resolve the server; referenced variables are re-declared)
- Transaction Controllers / Thread Groups as flow names

**Not converted (reported):** extractors, assertions, timers, JSR223/BeanShell, other
samplers, Module/Include controllers.

**Flattened (reported):** If/While/Loop/ForEach/Random/Interleave/Throughput/Switch
controllers, whose children are imported once, in order. Disabled elements are skipped.

**Security:** documents containing `DOCTYPE` or `ENTITY` declarations are rejected (JMeter
never writes them).

## Postman Collection v2.0 / v2.1

**Converted:**
- folders → flows (nested names joined with ` / `)
- method, URL (string or object), enabled headers and query parameters
- body modes `raw` (language → Content-Type), `urlencoded`, `formdata` (files → `${FILE_DIR}`),
  and `graphql` (→ JSON body)
- auth `bearer`, `basic`, and `apikey`, inherited from folders and collections; `noauth` overrides
- collection variables are inlined
- unknown `{{var}}` → `${var}`, declared as `${__P(var,)}`
- `{{$guid}}`, `{{$randomUUID}}`, `{{$timestamp}}`, `{{$isoTimestamp}}`, and `{{$randomInt}}`
  → JMeter functions

**Not converted (reported):**
- pre-request/test scripts (never executed)
- other auth types and other dynamic variables
- `file` binary bodies
- environment files
- v1 collections

## rec2jmx JSON recording v1

For capture tools without HAR export: write a small converter to this schema.

```json
{
  "format": "rec2jmx-recording",
  "version": 1,
  "name": "optional display name",
  "flows": [
    {
      "name": "Login",
      "requests": [
        {
          "method": "POST",
          "url": "https://api.example.test/v1/login?x=1",
          "headers": [{"name": "Content-Type", "value": "application/json"}],
          "body": {"json": {"user": "u"}},
          "startedAt": "2026-01-15T10:00:00Z",
          "durationMs": 120,
          "response": {"status": 200, "headers": [], "body": "{\"token\":\"…\"}"}
        }
      ]
    }
  ]
}
```

| Field | Rules |
|---|---|
| top level | Exactly one of `flows` (named groups) or `requests` (ungrouped) |
| `method`, `url` | Required. `url` must be an absolute http(s) URL |
| `headers` | Optional. Either `[{"name","value"}]` or `{"Name": "value"}` |
| `body` | Optional. `null`, or exactly one of `{"text": "...", "contentType"?}`, `{"json": <any>}`, or `{"form": [{"name","value"}]}` |
| `startedAt` | Optional. ISO-8601 |
| `durationMs` | Optional. Number ≥ 0 |
| `response` | Optional. `status` (int), `headers`, and `body` (string or JSON value); used only for correlation analysis |

Unknown request fields produce a warning. Type errors produce an error with a JSON path
(for example `flows[0].requests[2].url: required string is missing`).

## Explicitly not supported

These formats have no parser and are rejected:
- Charles native sessions (`.chls`/`.chlsj`; export HAR instead)
- Fiddler `.saz`
- Insomnia exports
- OpenAPI/Swagger
- pcap/pcapng
- BlazeMeter/JMeter recorder logs other than `.jmx`
- Postman environments

Protocols that are not converted: WebSocket, gRPC, HTTP/2 server push, and other non-HTTP traffic.

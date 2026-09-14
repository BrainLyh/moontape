# MoonTape

MoonTape is a privacy-first toolkit for inspecting, sanitizing, and replaying
[HTTP Archive (HAR 1.2)](https://w3c.github.io/web-performance/specs/HAR/Overview.html)
files. Its core and CLI are written in MoonBit.

It turns browser network captures into safe, deterministic API fixtures that
can be reviewed, committed, and replayed without reaching the original service.

## Status

MoonTape is an early, runnable MVP. It currently supports:

- defensive parsing of the HAR fields needed for replay;
- listing recorded method, URL, status, and timing information;
- redacting sensitive headers, cookies, and JSON properties;
- producing machine-readable findings with the exact location of each value;
- failing CI when a HAR fixture still contains recognized sensitive values;
- sanitizing plain and base64-encoded JSON stored inside HAR response text;
- extending the default redaction policy with project-specific field names;
- matching requests by HTTP method, path, canonical query, and body;
- comparing JSON request bodies semantically;
- explaining path, method, and body mismatches;
- replaying text and base64-encoded responses from a native local HTTP server.
- replaying cache, redirect, language, CORS, and validator response headers
  through an explicit safety allowlist.

HTTPS interception, compressed bodies, request header matching, persistent
configuration files, and traffic recording are not implemented yet.

## Requirements

- MoonBit toolchain 0.10.12 or newer
- A native C toolchain supported by MoonBit

Install MoonBit with the
[official instructions](https://docs.moonbitlang.com/en/latest/tutorial/tour.html#installation).

## Quick start

    moon update
    moon test --target native

    moon run cmd/main --target native -- inspect fixtures/sample.har
    moon run cmd/main --target native -- scan fixtures/sample.har
    moon run cmd/main --target native -- check fixtures/sample.har
    moon run cmd/main --target native -- sanitize fixtures/sample.har -o sample.safe.har
    moon run cmd/main --target native -- serve sample.safe.har --port 8080 --strict

In another terminal:

    curl http://127.0.0.1:8080/v1/hello

Replay uses loose matching by default, which ignores the query string. Pass
--strict to compare canonical query strings as well.

## Commands

### Inspect

    moon run cmd/main --target native -- inspect capture.har

Example output:

    HAR 1.2 · 1 requests · creator: MoonTape fixture
    1. GET /v1/hello?lang=zh -> 200 (12.5 ms)

### Sanitize

    moon run cmd/main --target native -- sanitize capture.har -o capture.safe.har

Inspect the same findings without writing a new file:

    moon run cmd/main --target native -- scan capture.har

Use `check` as a CI privacy gate. It exits unsuccessfully and prints the same
machine-readable findings when recognized sensitive values remain:

    moon run cmd/main --target native -- check capture.safe.har

The default policy replaces Authorization, Cookie, Set-Cookie, X-API-Key,
access_token, refresh_token, token, password, and related values with
[REDACTED]. HAR header and cookie arrays and JSON response bodies are handled.
The scan report includes a JSON path and field name for each finding.

Add application-specific names without disabling the safe defaults:

    moon run cmd/main --target native -- scan capture.har --redact tenant_session,user_pin
    moon run cmd/main --target native -- sanitize capture.har -o capture.safe.har --redact tenant_session,user_pin

Always review the generated file before committing it. Automated secret
detection can reduce risk but cannot prove that arbitrary captures are safe.

### Replay

    moon run cmd/main --target native -- serve capture.safe.har --port 8080

Enable canonical query comparison:

    moon run cmd/main --target native -- serve capture.safe.har --port 8080 --strict

Successful responses include X-MoonTape-Match with the one-based recording
number. A miss returns HTTP 404 and explains whether the nearest recording had
a different path, query, method, or body. JSON bodies are compared
semantically, so insignificant whitespace and object key order do not cause a
miss.

Replay forwards useful representation and cache metadata such as Content-Type,
Cache-Control, ETag, Location, and CORS headers. Connection-specific headers,
Content-Length, Content-Encoding, and Set-Cookie are deliberately omitted:
MoonTape computes framing itself, decoded HAR bodies may no longer have the
recorded wire encoding, and replay should not restore captured sessions.

## Architecture

The root package is a pure, portable core:

- har.mbt: defensive HAR parsing and inspection
- sanitize.mbt: recursive privacy transformations
- matching.mbt: deterministic matching and mismatch diagnostics

cmd/main owns native filesystem and HTTP concerns. Keeping I/O out of the core
makes parsing, sanitization, and matching fast to test and suitable for a future
Wasm browser interface.

## Development

    moon fmt
    moon check --target native
    moon test --target native

Keep fixtures synthetic: never commit real access tokens, session cookies, or
personal data.

## Roadmap

- persistent JSON policy files with custom replacements and ignored paths;
- request Header matching and dynamic field exclusion;
- gzip and deflate response bodies;
- JUnit and JSON verification reports for CI;
- a Wasm browser interface for local-only inspection and sanitization;
- optional fault and latency injection.

## License

Apache-2.0

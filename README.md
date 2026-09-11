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
- sanitizing JSON stored inside HAR response text;
- matching requests by HTTP method and path;
- explaining path, method, and body mismatches;
- serving recorded responses from a native local HTTP server.

HTTPS interception, compressed or base64 bodies, configurable policies, and
strict query matching are not implemented yet.

## Requirements

- MoonBit toolchain 0.10.12 or newer
- A native C toolchain supported by MoonBit

Install MoonBit with the
[official instructions](https://docs.moonbitlang.com/en/latest/tutorial/tour.html#installation).

## Quick start

    moon update
    moon test --target native

    moon run cmd/main --target native -- inspect fixtures/sample.har
    moon run cmd/main --target native -- sanitize fixtures/sample.har -o sample.safe.har
    moon run cmd/main --target native -- serve sample.safe.har --port 8080

In another terminal:

    curl http://127.0.0.1:8080/v1/hello

MoonTape deliberately ignores the query string in this MVP, so the recorded
/v1/hello?lang=zh request also matches /v1/hello.

## Commands

### Inspect

    moon run cmd/main --target native -- inspect capture.har

Example output:

    HAR 1.2 · 1 requests · creator: MoonTape fixture
    1. GET /v1/hello?lang=zh -> 200 (12.5 ms)

### Sanitize

    moon run cmd/main --target native -- sanitize capture.har -o capture.safe.har

The default policy replaces Authorization, Cookie, Set-Cookie, X-API-Key,
access_token, refresh_token, token, password, and related values with
[REDACTED]. HAR header and cookie arrays and JSON response bodies are handled.

Always review the generated file before committing it. Automated secret
detection can reduce risk but cannot prove that arbitrary captures are safe.

### Replay

    moon run cmd/main --target native -- serve capture.safe.har --port 8080

Successful responses include X-MoonTape-Match with the one-based recording
number. A miss returns HTTP 404 and explains whether the nearest recording had
a different path, method, or body.

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

## License

Apache-2.0

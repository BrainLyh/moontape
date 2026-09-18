# Changelog

All notable changes to MoonTape are documented here.

## Unreleased

### Added

- Use `cpypypypy/har-toolkit` as the canonical HAR 1.2 parser and adapt its
  validated document model into MoonTape's replay index.
- Treat values already replaced by the active policy as clean during CI checks.
- Defensive validation for HTTP status codes and authority-only URLs.
- HAR response content-encoding metadata and Base64 replay.
- Privacy scan reports containing finding names and JSON paths.
- Recursive sanitization of plain and Base64-encoded JSON response bodies.
- Extensible redaction policies and the CLI --redact option.
- A `check` command that turns the privacy scanner into a CI gate.
- Failing process statuses for invalid commands and operational errors.
- Strict canonical-query matching and semantic JSON body comparison.
- Query, method, body, and path mismatch diagnostics.
- Safe replay of cache, redirect, language, validator, and CORS headers.
- Strict matching with an allowlist of volatile query parameter names to ignore.
- Replay-plan inspection with route grouping, response variants, body checks,
  and ambiguous recording diagnostics.
- Runtime replay ledger with hit/miss events, per-recording usage, coverage,
  machine-readable reports, and a reset endpoint for isolated test cases.
- Loopback-only server binding to avoid exposing recorded responses to the LAN.

### Verified

- Native formatting and type checking.
- Seventeen unit tests covering parsing, sanitization, matching, planning,
  runtime coverage, headers, and Base64 content.
- Inspect, scan, sanitize, and local replay smoke tests.
- Reproducible production-source audit enforced by CI.

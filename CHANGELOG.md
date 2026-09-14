# Changelog

All notable changes to MoonTape are documented here.

## Unreleased

### Added

- Defensive validation for HTTP status codes and authority-only URLs.
- HAR response content-encoding metadata and Base64 replay.
- Privacy scan reports containing finding names and JSON paths.
- Recursive sanitization of plain and Base64-encoded JSON response bodies.
- Extensible redaction policies and the CLI --redact option.
- Strict canonical-query matching and semantic JSON body comparison.
- Query, method, body, and path mismatch diagnostics.

### Verified

- Native formatting and type checking.
- Ten unit tests covering parsing, sanitization, matching, and Base64 content.
- Inspect, scan, sanitize, and local replay smoke tests.

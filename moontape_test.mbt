///|
fn test_har(
  meth : String,
  url : String,
  request_headers : Array[Header],
  request_body : String?,
  status : Int,
  response_headers : Array[Header],
  mime_type : String,
  response_body : String,
  encoding : String?,
) -> String {
  let request : Map[String, Json] = Map([
    ("method", Json::string(meth)),
    ("url", Json::string(url)),
    ("httpVersion", Json::string("HTTP/1.1")),
    ("headers", @json.to_json(request_headers)),
    ("queryString", Json::array([])),
    ("cookies", Json::array([])),
    ("headersSize", Json::number(-1)),
    ("bodySize", Json::number(-1)),
  ])
  match request_body {
    Some(body) =>
      request.set(
        "postData",
        Json::object(
          Map([
            ("mimeType", Json::string("application/json")),
            ("text", Json::string(body)),
          ]),
        ),
      )
    None => ()
  }
  let content : Map[String, Json] = Map([
    ("size", Json::number(response_body.length().to_double())),
    ("mimeType", Json::string(mime_type)),
    ("text", Json::string(response_body)),
  ])
  match encoding {
    Some(value) => content.set("encoding", Json::string(value))
    None => ()
  }
  Json::object(
    Map([
      (
        "log",
        Json::object(
          Map([
            ("version", Json::string("1.2")),
            (
              "creator",
              Json::object(
                Map([
                  ("name", Json::string("Chromium")),
                  ("version", Json::string("1")),
                ]),
              ),
            ),
            (
              "entries",
              Json::array([
                Json::object(
                  Map([
                    (
                      "startedDateTime",
                      Json::string("2026-09-11T00:00:00.000Z"),
                    ),
                    ("time", Json::number(12.5)),
                    ("request", Json::object(request)),
                    (
                      "response",
                      Json::object(
                        Map([
                          ("status", Json::number(status.to_double())),
                          (
                            "statusText",
                            Json::string(
                              if status == 201 {
                                "Created"
                              } else {
                                "OK"
                              },
                            ),
                          ),
                          ("httpVersion", Json::string("HTTP/1.1")),
                          ("headers", @json.to_json(response_headers)),
                          ("cookies", Json::array([])),
                          ("content", Json::object(content)),
                          ("redirectURL", Json::string("")),
                          ("headersSize", Json::number(-1)),
                          ("bodySize", Json::number(-1)),
                        ]),
                      ),
                    ),
                    ("cache", Json::object(Map([]))),
                    (
                      "timings",
                      Json::object(
                        Map([
                          ("send", Json::number(0)),
                          ("wait", Json::number(12)),
                          ("receive", Json::number(0.5)),
                        ]),
                      ),
                    ),
                  ]),
                ),
              ]),
            ),
          ]),
        ),
      ),
    ]),
  ).stringify()
}

///|
let fixture : String = test_har(
  "POST",
  "https://api.example.test/v1/orders?trace=1",
  [{ name: "Authorization", value: "Bearer secret", }],
  Some("{\"quantity\":2}"),
  201,
  [{ name: "Content-Type", value: "application/json", }],
  "application/json",
  "{\"id\":42,\"access_token\":\"secret\"}",
  None,
)

///|
test "parse and inspect HAR 1.2" {
  let archive = parse_har(fixture)
  assert_eq(archive.version, "1.2")
  assert_eq(archive.creator, "Chromium")
  assert_eq(archive.entries.length(), 1)
  assert_eq(archive.entries[0].request.path, "/v1/orders?trace=1")
  assert_eq(archive.entries[0].response.status, 201)
}

///|
test "sanitize headers and nested JSON keys" {
  let archive = parse_har(fixture)
  let (clean, report) = sanitize_har(archive)
  let text = clean.stringify()
  assert_eq(report.redacted_values, 2)
  assert_eq(report.findings.length(), 2)
  assert_eq(report.findings[0].name, "Authorization")
  assert_true(report.findings[1].path.contains("text<json>"))
  assert_true(text.contains("[REDACTED]"))
  assert_false(text.contains("Bearer secret"))
  assert_false(report.is_clean())
  assert_true(scan_har(parse_har(clean.stringify())).is_clean())
}

///|
test "privacy report identifies a clean archive" {
  let clean = test_har(
    "GET",
    "https://example.test",
    [],
    None,
    200,
    [],
    "text/plain",
    "ok",
    None,
  )
  assert_true(scan_har(parse_har(clean)).is_clean())
}

///|
test "match ignores query but explains body mismatch" {
  let archive = parse_har(fixture)
  assert_true(
    match_request(
      archive,
      "POST",
      "/v1/orders?another=value",
      body="{\"quantity\":2}",
    ) ==
    Exact(0),
  )
  assert_true(
    match_request(archive, "POST", "/v1/orders", body="{\"quantity\":3}") ==
    BodyMismatch(0),
  )
}

///|
test "URL path handles authority-only query strings" {
  assert_eq(url_path("https://example.test"), "/")
  assert_eq(url_path("https://example.test?debug=1"), "/?debug=1")
  assert_eq(url_path("https://example.test/a?debug=1"), "/a?debug=1")
}

///|
test "reject invalid HTTP status codes" {
  let invalid = test_har(
    "GET",
    "https://example.test",
    [],
    None,
    99,
    [],
    "text/plain",
    "",
    None,
  )
  let rejected = try {
    ignore(parse_har(invalid))
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}

///|
test "preserve HAR content encoding metadata" {
  let encoded = test_har(
    "GET",
    "https://example.test",
    [],
    None,
    200,
    [],
    "image/png",
    "AA==",
    Some("base64"),
  )
  let archive = parse_har(encoded)
  assert_eq(archive.entries[0].response.encoding, Some("base64"))
}

///|
test "replay response headers through an explicit safety allowlist" {
  let with_headers = test_har(
    "GET",
    "https://example.test",
    [],
    None,
    200,
    [
      { name: "Content-Type", value: "application/json; charset=utf-8", },
      { name: "Cache-Control", value: "max-age=60", },
      { name: "Set-Cookie", value: "session=secret", },
      { name: "Content-Encoding", value: "gzip", },
    ],
    "application/json",
    "{}",
    None,
  )
  let headers = parse_har(with_headers).entries[0].response.replay_headers()
  assert_eq(headers.length(), 2)
  assert_eq(headers[0].value, "application/json; charset=utf-8")
  assert_eq(headers[1].name, "Cache-Control")
}

///|
test "strict matching compares canonical query strings" {
  let archive = parse_har(fixture)
  assert_true(
    match_request_with_options(
      archive,
      "POST",
      "/v1/orders?trace=1",
      body="{\"quantity\":2}",
      MatchOptions::strict(),
    ) ==
    Exact(0),
  )
  assert_true(
    match_request_with_options(
      archive,
      "POST",
      "/v1/orders?trace=2",
      body="{\"quantity\":2}",
      MatchOptions::strict(),
    ) ==
    QueryMismatch(0),
  )
}

///|
test "strict matching can ignore named dynamic query parameters" {
  let archive = parse_har(fixture)
  let options = MatchOptions::strict().with_ignored_query(["trace", "nonce"])
  assert_true(
    match_request_with_options(
      archive,
      "POST",
      "/v1/orders?trace=other",
      body="{\"quantity\":2}",
      options,
    ) ==
    Exact(0),
  )
  assert_eq(
    canonical_target("/v1/orders?b=2&trace=x&a=1", options),
    "/v1/orders?a=1&b=2",
  )
}

///|
test "JSON bodies match semantically" {
  let archive = parse_har(fixture)
  assert_true(
    match_request_with_options(
      archive,
      "POST",
      "/v1/orders?trace=1",
      body="{ \"quantity\" : 2.0 }",
      MatchOptions::strict(),
    ) ==
    Exact(0),
  )
}

///|
test "decode and sanitize base64 JSON responses" {
  let encoded = test_har(
    "GET",
    "https://example.test/data",
    [],
    None,
    200,
    [],
    "application/json",
    "eyJ0b2tlbiI6InNlY3JldCJ9",
    Some("base64"),
  )
  let archive = parse_har(encoded)
  assert_eq(
    @utf8.decode(archive.entries[0].response.body_bytes()),
    "{\"token\":\"secret\"}",
  )
  let (clean, report) = sanitize_har(archive)
  assert_eq(report.redacted_values, 1)
  let clean_archive = parse_har(clean.stringify())
  assert_eq(
    @utf8.decode(clean_archive.entries[0].response.body_bytes()),
    "{\"token\":\"[REDACTED]\"}",
  )
}

///|
test "custom redaction policy extends safe defaults" {
  let custom = test_har(
    "GET",
    "https://example.test",
    [
      { name: "X-Tenant-Session", value: "private", },
      { name: "Authorization", value: "Bearer private", },
    ],
    None,
    200,
    [],
    "text/plain",
    "",
    None,
  )
  let policy = RedactionPolicy::default()
    .with_additional(["X-Tenant-Session"])
    .with_replacement("<hidden>")
  let (clean, report) = sanitize_har_with_policy(parse_har(custom), policy)
  assert_eq(report.redacted_values, 2)
  assert_false(clean.stringify().contains("private"))
  assert_true(clean.stringify().contains("<hidden>"))
}

///|
test "replay plan detects ambiguous duplicate recordings" {
  let archive = parse_har(fixture)
  let duplicate : HarArchive = {
    ..archive,
    entries: [archive.entries[0], archive.entries[0]],
  }
  let plan = build_replay_plan(duplicate, MatchOptions::strict())
  assert_eq(plan.recording_count, 2)
  assert_eq(plan.route_count, 1)
  assert_eq(plan.duplicate_route_count, 1)
  assert_eq(plan.routes[0].request_variants, 1)
  assert_eq(plan.routes[0].ambiguous_variants, 1)
  assert_eq(plan.error_count(), 1)
  assert_false(plan.is_replayable())
  assert_true(replay_plan_text(plan).contains("ambiguous_recording"))
}

///|
test "replay plan accepts distinct body variants" {
  let first = parse_har(fixture)
  let second = parse_har(
    test_har(
      "POST",
      "https://api.example.test/v1/orders?trace=1",
      [],
      Some("{\"quantity\":3}"),
      202,
      [],
      "application/json",
      "{}",
      None,
    ),
  )
  let archive : HarArchive = {
    ..first,
    entries: [first.entries[0], second.entries[0]],
  }
  let plan = build_replay_plan(archive, MatchOptions::strict())
  assert_true(plan.is_replayable())
  assert_eq(plan.routes[0].request_variants, 2)
  assert_eq(plan.routes[0].statuses, [201, 202])
}

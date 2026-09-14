///|
let fixture =
  #|{
  #|  "log": {
  #|    "version": "1.2",
  #|    "creator": { "name": "Chromium" },
  #|    "entries": [{
  #|      "time": 12.5,
  #|      "request": {
  #|        "method": "POST",
  #|        "url": "https://api.example.test/v1/orders?trace=1",
  #|        "headers": [{"name":"Authorization","value":"Bearer secret"}],
  #|        "postData": {"text":"{\"quantity\":2}"}
  #|      },
  #|      "response": {
  #|        "status": 201,
  #|        "statusText": "Created",
  #|        "headers": [{"name":"Content-Type","value":"application/json"}],
  #|        "content": {"mimeType":"application/json","text":"{\"id\":42,\"access_token\":\"secret\"}"}
  #|      }
  #|    }]
  #|  }
  #|}

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
  let invalid =
    #|{"log":{"version":"1.2","entries":[{
    #|  "request":{"method":"GET","url":"https://example.test","headers":[]},
    #|  "response":{"status":99,"headers":[],"content":{}}
    #|}]}}
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
  let encoded =
    #|{"log":{"version":"1.2","entries":[{
    #|  "request":{"method":"GET","url":"https://example.test","headers":[]},
    #|  "response":{"status":200,"headers":[],"content":{
    #|    "mimeType":"image/png","text":"AA==","encoding":"base64"
    #|  }}
    #|}]}}
  let archive = parse_har(encoded)
  assert_eq(archive.entries[0].response.encoding, Some("base64"))
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
  let encoded =
    #|{"log":{"version":"1.2","entries":[{
    #|  "request":{"method":"GET","url":"https://example.test/data","headers":[]},
    #|  "response":{"status":200,"headers":[],"content":{
    #|    "mimeType":"application/json",
    #|    "text":"eyJ0b2tlbiI6InNlY3JldCJ9",
    #|    "encoding":"base64"
    #|  }}
    #|}]}}
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

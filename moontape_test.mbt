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

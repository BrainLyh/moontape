///|
pub(all) suberror HarError {
  InvalidHar(String)
} derive(Eq, Debug)

///|
pub(all) struct Header {
  name : String
  value : String
} derive(Eq, Debug, ToJson)

///|
pub(all) struct HarRequest {
  meth : String
  url : String
  path : String
  headers : Array[Header]
  body : String?
} derive(Eq, Debug, ToJson)

///|
pub(all) struct HarResponse {
  status : Int
  status_text : String
  headers : Array[Header]
  mime_type : String
  body : String
  encoding : String?
} derive(Eq, Debug, ToJson)

///|
pub fn HarResponse::replay_headers(self : HarResponse) -> Array[Header] {
  let safe_names = [
    "cache-control", "content-language", "etag", "expires", "last-modified", "location",
    "retry-after", "vary", "www-authenticate", "access-control-allow-origin", "access-control-allow-methods",
    "access-control-allow-headers", "access-control-expose-headers", "access-control-max-age",
  ]
  let result : Array[Header] = []
  let mut has_content_type = false
  for header in self.headers {
    let normalized = header.name.to_lower()
    if normalized == "content-type" {
      if !has_content_type {
        result.push(header)
        has_content_type = true
      }
    } else if safe_names.contains(normalized) {
      result.push(header)
    }
  }
  if !has_content_type {
    result.push({ name: "Content-Type", value: self.mime_type, })
  }
  result
}

///|
pub fn HarResponse::body_bytes(self : HarResponse) -> Bytes raise HarError {
  match self.encoding {
    None => @utf8.encode(self.body)
    Some(encoding) if encoding.to_lower() == "base64" =>
      @base64.decode(self.body) catch {
        _ => raise InvalidHar("response content contains malformed base64")
      }
    Some(encoding) =>
      raise InvalidHar("unsupported response content encoding: \{encoding}")
  }
}

///|
pub(all) struct HarEntry {
  request : HarRequest
  response : HarResponse
  time_ms : Double
} derive(Eq, Debug, ToJson)

///|
pub(all) struct HarArchive {
  version : String
  creator : String
  entries : Array[HarEntry]
  raw : Json
} derive(Eq, Debug)

///|
fn replay_headers_from_toolkit(
  values : Array[@har.HarNameValue],
) -> Array[Header] {
  values.map(value => { name: value.name(), value: value.value(), })
}

///|
pub fn url_path(url : String) -> String {
  let rest = match url.split_once("://") {
    Some((_, value)) => value
    None => url[:]
  }
  match (rest.find("/"), rest.find("?")) {
    (Some(slash), Some(query)) =>
      if slash < query {
        rest[slash:].to_owned()
      } else {
        "/" + rest[query:].to_owned()
      }
    (Some(slash), None) => rest[slash:].to_owned()
    (None, Some(query)) => "/" + rest[query:].to_owned()
    (None, None) => "/"
  }
}

///|
pub fn path_without_query(path : String) -> String {
  match path.split_once("?") {
    Some((value, _)) => value.to_owned()
    None => path
  }
}

///|
fn replay_request_from_toolkit(request : @har.HarRequest) -> HarRequest {
  let url = request.url()
  let body = match request.post_data() {
    Some(post_data) => post_data.text()
    None => None
  }
  {
    meth: request.request_method(),
    url,
    path: url_path(url),
    headers: replay_headers_from_toolkit(request.headers()),
    body,
  }
}

///|
fn replay_response_from_toolkit(
  response : @har.HarResponse,
) -> HarResponse raise HarError {
  let status_code = response.status().to_int()
  guard response.status() == status_code.to_double() &&
    status_code >= 100 &&
    status_code <= 599 else {
    raise InvalidHar("replay requires an HTTP status between 100 and 599")
  }
  let content = response.content()
  {
    status: status_code,
    status_text: response.status_text(),
    headers: replay_headers_from_toolkit(response.headers()),
    mime_type: content.mime_type(),
    body: content.text().unwrap_or(""),
    encoding: content.encoding(),
  }
}

///|
pub fn parse_har(source : StringView) -> HarArchive raise {
  let document = match @har.parse_har(source.to_owned()) {
    Ok(document) => document
    Err(error) => raise InvalidHar(error.format())
  }
  let raw = @json.parse(source)
  let entries = document
    .entries()
    .map(entry => {
      request: replay_request_from_toolkit(entry.request()),
      response: replay_response_from_toolkit(entry.response()),
      time_ms: entry.time(),
    })
  {
    version: document.version(),
    creator: document.creator().name(),
    entries,
    raw,
  }
}

///|
pub fn inspect_text(archive : HarArchive) -> String {
  let output = StringBuilder()
  output.write_string(
    "HAR \{archive.version} · \{archive.entries.length()} requests · creator: \{archive.creator}\n",
  )
  for index, entry in archive.entries {
    output.write_string(
      "\{index + 1}. \{entry.request.meth} \{entry.request.path} -> \{entry.response.status} (\{entry.time_ms} ms)\n",
    )
  }
  output.to_string()
}

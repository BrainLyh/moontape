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
fn required_field(
  object : Map[String, Json],
  key : String,
  context : String,
) -> Json raise HarError {
  guard object.get(key) is Some(value) else {
    raise InvalidHar("missing \{context}.\{key}")
  }
  value
}

///|
fn required_object(
  object : Map[String, Json],
  key : String,
  context : String,
) -> Map[String, Json] raise HarError {
  guard required_field(object, key, context) is Object(value) else {
    raise InvalidHar("\{context}.\{key} must be an object")
  }
  value
}

///|
fn required_array(
  object : Map[String, Json],
  key : String,
  context : String,
) -> Array[Json] raise HarError {
  guard required_field(object, key, context) is Array(value) else {
    raise InvalidHar("\{context}.\{key} must be an array")
  }
  value
}

///|
fn required_string(
  object : Map[String, Json],
  key : String,
  context : String,
) -> String raise HarError {
  guard required_field(object, key, context) is String(value) else {
    raise InvalidHar("\{context}.\{key} must be a string")
  }
  value
}

///|
fn optional_string(
  object : Map[String, Json],
  key : String,
  default : String,
) -> String {
  match object.get(key) {
    Some(String(value)) => value
    _ => default
  }
}

///|
fn parse_headers(
  value : Json,
  context : String,
) -> Array[Header] raise HarError {
  guard value is Array(items) else {
    raise InvalidHar("\{context} must be an array")
  }
  items.mapi((index, item) => {
    guard item is Object(header) else {
      raise InvalidHar("\{context}[\{index}] must be an object")
    }
    {
      name: required_string(header, "name", "\{context}[\{index}]"),
      value: required_string(header, "value", "\{context}[\{index}]"),
    }
  })
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
fn parse_request(value : Json, context : String) -> HarRequest raise HarError {
  guard value is Object(object) else {
    raise InvalidHar("\{context} must be an object")
  }
  let url = required_string(object, "url", context)
  let headers = match object.get("headers") {
    Some(value) => parse_headers(value, "\{context}.headers")
    None => []
  }
  let body = match object.get("postData") {
    Some(Object(post_data)) =>
      match post_data.get("text") {
        Some(String(text)) => Some(text)
        _ => None
      }
    _ => None
  }
  {
    meth: required_string(object, "method", context),
    url,
    path: url_path(url),
    headers,
    body,
  }
}

///|
fn parse_response(value : Json, context : String) -> HarResponse raise HarError {
  guard value is Object(object) else {
    raise InvalidHar("\{context} must be an object")
  }
  guard required_field(object, "status", context) is Number(status, ..) else {
    raise InvalidHar("\{context}.status must be a number")
  }
  let status_code = status.to_int()
  guard status == status_code.to_double() &&
    status_code >= 100 &&
    status_code <= 599 else {
    raise InvalidHar("\{context}.status must be an integer between 100 and 599")
  }
  let headers = match object.get("headers") {
    Some(value) => parse_headers(value, "\{context}.headers")
    None => []
  }
  let (mime_type, body, encoding) = match object.get("content") {
    Some(Object(content)) =>
      (
        optional_string(content, "mimeType", "application/octet-stream"),
        optional_string(content, "text", ""),
        match content.get("encoding") {
          Some(String(value)) => Some(value)
          _ => None
        },
      )
    _ => ("application/octet-stream", "", None)
  }
  {
    status: status_code,
    status_text: optional_string(object, "statusText", ""),
    headers,
    mime_type,
    body,
    encoding,
  }
}

///|
pub fn parse_har(source : StringView) -> HarArchive raise {
  let raw = @json.parse(source)
  guard raw is Object(root) else { raise InvalidHar("root must be an object") }
  let log = required_object(root, "log", "root")
  let version = optional_string(log, "version", "unknown")
  let creator = match log.get("creator") {
    Some(Object(value)) => optional_string(value, "name", "unknown")
    _ => "unknown"
  }
  let entry_values = required_array(log, "entries", "log")
  let entries = entry_values.mapi((index, value) => {
    let context = "log.entries[\{index}]"
    guard value is Object(entry) else {
      raise InvalidHar("\{context} must be an object")
    }
    let time_ms = match entry.get("time") {
      Some(Number(value, ..)) => value
      _ => 0.0
    }
    {
      request: parse_request(
        required_field(entry, "request", context),
        "\{context}.request",
      ),
      response: parse_response(
        required_field(entry, "response", context),
        "\{context}.response",
      ),
      time_ms,
    }
  })
  { version, creator, entries, raw, }
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

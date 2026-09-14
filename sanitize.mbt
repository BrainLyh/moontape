///|
pub(all) struct RedactionFinding {
  path : String
  name : String
} derive(Eq, Debug, ToJson)

///|
pub(all) struct RedactionReport {
  redacted_values : Int
  findings : Array[RedactionFinding]
} derive(Eq, Debug, ToJson)

///|
fn is_sensitive_name(name : String) -> Bool {
  match name.to_lower() {
    "authorization"
    | "proxy-authorization"
    | "cookie"
    | "set-cookie"
    | "x-api-key"
    | "api-key"
    | "api_key"
    | "apikey"
    | "access_token"
    | "refresh_token"
    | "token"
    | "password"
    | "passwd"
    | "secret"
    | "client_secret" => true
    _ => false
  }
}

///|
fn child_path(parent : String, key : String) -> String {
  if parent == "$" {
    "$.\{key}"
  } else {
    "\{parent}.\{key}"
  }
}

///|
fn sanitize_value(
  value : Json,
  path : String,
) -> (Json, Array[RedactionFinding]) {
  match value {
    Object(members) => {
      let named_sensitive = match members.get("name") {
        Some(String(name)) if is_sensitive_name(name) => Some(name)
        _ => None
      }
      let contains_json_text = match members.get("mimeType") {
        Some(String(mime_type)) => mime_type.to_lower().contains("json")
        _ => false
      }
      let result : Map[String, Json] = Map([])
      let findings : Array[RedactionFinding] = []
      for key, child in members {
        if (named_sensitive is Some(_) && key.to_lower() == "value") ||
          is_sensitive_name(key) {
          result.set(key, Json::string("[REDACTED]"))
          let name = match named_sensitive {
            Some(name) if key.to_lower() == "value" => name
            _ => key
          }
          findings.push({ path: child_path(path, key), name, })
        } else if contains_json_text && key == "text" {
          match child {
            String(text) => {
              let transformed = try {
                let parsed = @json.parse(text)
                let (clean, nested_findings) = sanitize_value(
                  parsed,
                  child_path(path, "text<json>"),
                )
                findings.push_iter(nested_findings.iter())
                Json::string(clean.stringify())
              } catch {
                _ => child
              }
              result.set(key, transformed)
            }
            _ => result.set(key, child)
          }
        } else {
          let (clean, nested_findings) = sanitize_value(
            child,
            child_path(path, key),
          )
          result.set(key, clean)
          findings.push_iter(nested_findings.iter())
        }
      }
      (Json::object(result), findings)
    }
    Array(items) => {
      let result : Array[Json] = []
      let findings : Array[RedactionFinding] = []
      for index, item in items {
        let (clean, nested_findings) = sanitize_value(item, "\{path}[\{index}]")
        result.push(clean)
        findings.push_iter(nested_findings.iter())
      }
      (Json::array(result), findings)
    }
    other => (other, [])
  }
}

///|
pub fn sanitize_har(archive : HarArchive) -> (Json, RedactionReport) {
  let (clean, findings) = sanitize_value(archive.raw, "$")
  (clean, { redacted_values: findings.length(), findings, })
}

///|
pub fn scan_har(archive : HarArchive) -> RedactionReport {
  let (_, report) = sanitize_har(archive)
  report
}

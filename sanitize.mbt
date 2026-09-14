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
pub(all) struct RedactionPolicy {
  sensitive_names : Array[String]
  replacement : String
} derive(Eq, Debug, ToJson)

///|
pub fn RedactionPolicy::default() -> RedactionPolicy {
  {
    sensitive_names: [
      "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key",
      "api-key", "api_key", "apikey", "access_token", "refresh_token", "token", "password",
      "passwd", "secret", "client_secret",
    ],
    replacement: "[REDACTED]",
  }
}

///|
pub fn RedactionPolicy::with_additional(
  self : RedactionPolicy,
  names : Array[String],
) -> RedactionPolicy {
  let combined = self.sensitive_names.copy()
  for name in names {
    let normalized = name.to_lower()
    if normalized != "" && !combined.contains(normalized) {
      combined.push(normalized)
    }
  }
  { sensitive_names: combined, replacement: self.replacement, }
}

///|
pub fn RedactionPolicy::with_replacement(
  self : RedactionPolicy,
  replacement : String,
) -> RedactionPolicy {
  { sensitive_names: self.sensitive_names.copy(), replacement, }
}

///|
fn is_sensitive_name(name : String, policy : RedactionPolicy) -> Bool {
  policy.sensitive_names.contains(name.to_lower())
}

///|
pub fn RedactionPolicy::is_sensitive(
  self : RedactionPolicy,
  name : String,
) -> Bool {
  is_sensitive_name(name, self)
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
  policy : RedactionPolicy,
) -> (Json, Array[RedactionFinding]) {
  match value {
    Object(members) => {
      let named_sensitive = match members.get("name") {
        Some(String(name)) if is_sensitive_name(name, policy) => Some(name)
        _ => None
      }
      let contains_json_text = match members.get("mimeType") {
        Some(String(mime_type)) => mime_type.to_lower().contains("json")
        _ => false
      }
      let text_is_base64 = match members.get("encoding") {
        Some(String(encoding)) => encoding.to_lower() == "base64"
        _ => false
      }
      let result : Map[String, Json] = Map([])
      let findings : Array[RedactionFinding] = []
      for key, child in members {
        if (named_sensitive is Some(_) && key.to_lower() == "value") ||
          is_sensitive_name(key, policy) {
          result.set(key, Json::string(policy.replacement))
          let name = match named_sensitive {
            Some(name) if key.to_lower() == "value" => name
            _ => key
          }
          findings.push({ path: child_path(path, key), name, })
        } else if contains_json_text && key == "text" {
          match child {
            String(text) => {
              let transformed = try {
                let decoded = if text_is_base64 {
                  @base64.decode(text) |> @utf8.decode
                } else {
                  text
                }
                let parsed = @json.parse(decoded)
                let (clean, nested_findings) = sanitize_value(
                  parsed,
                  child_path(path, "text<json>"),
                  policy,
                )
                findings.push_iter(nested_findings.iter())
                let clean_text = clean.stringify()
                if text_is_base64 {
                  Json::string(@base64.encode(@utf8.encode(clean_text)))
                } else {
                  Json::string(clean_text)
                }
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
            policy,
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
        let (clean, nested_findings) = sanitize_value(
          item,
          "\{path}[\{index}]",
          policy,
        )
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
  sanitize_har_with_policy(archive, RedactionPolicy::default())
}

///|
pub fn sanitize_har_with_policy(
  archive : HarArchive,
  policy : RedactionPolicy,
) -> (Json, RedactionReport) {
  let (clean, findings) = sanitize_value(archive.raw, "$", policy)
  (clean, { redacted_values: findings.length(), findings, })
}

///|
pub fn scan_har(archive : HarArchive) -> RedactionReport {
  scan_har_with_policy(archive, RedactionPolicy::default())
}

///|
pub fn scan_har_with_policy(
  archive : HarArchive,
  policy : RedactionPolicy,
) -> RedactionReport {
  let (_, report) = sanitize_har_with_policy(archive, policy)
  report
}

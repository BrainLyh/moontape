///|
pub(all) struct RedactionReport {
  redacted_values : Int
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
fn sanitize_value(value : Json) -> (Json, Int) {
  match value {
    Object(members) => {
      let header_or_cookie = match members.get("name") {
        Some(String(name)) => is_sensitive_name(name)
        _ => false
      }
      let contains_json_text = match members.get("mimeType") {
        Some(String(mime_type)) => mime_type.to_lower().contains("json")
        _ => false
      }
      let result : Map[String, Json] = Map([])
      let mut count = 0
      for key, child in members {
        if (header_or_cookie && key.to_lower() == "value") ||
          is_sensitive_name(key) {
          result.set(key, Json::string("[REDACTED]"))
          count += 1
        } else if contains_json_text && key == "text" {
          match child {
            String(text) => {
              let transformed = try {
                let parsed = @json.parse(text)
                let (clean, child_count) = sanitize_value(parsed)
                count += child_count
                Json::string(clean.stringify())
              } catch {
                _ => child
              }
              result.set(key, transformed)
            }
            _ => result.set(key, child)
          }
        } else {
          let (clean, child_count) = sanitize_value(child)
          result.set(key, clean)
          count += child_count
        }
      }
      (Json::object(result), count)
    }
    Array(items) => {
      let result : Array[Json] = []
      let mut count = 0
      for item in items {
        let (clean, child_count) = sanitize_value(item)
        result.push(clean)
        count += child_count
      }
      (Json::array(result), count)
    }
    other => (other, 0)
  }
}

///|
pub fn sanitize_har(archive : HarArchive) -> (Json, RedactionReport) {
  let (clean, count) = sanitize_value(archive.raw)
  (clean, { redacted_values: count, })
}

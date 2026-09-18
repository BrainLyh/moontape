///|
pub(all) enum MatchResult {
  Exact(Int)
  BodyMismatch(Int)
  MethodMismatch(Int)
  QueryMismatch(Int)
  PathMismatch
} derive(Eq, Debug, ToJson)

///|
pub(all) struct MatchOptions {
  compare_query : Bool
  compare_body : Bool
  semantic_json_body : Bool
  ignored_query_names : Array[String]
} derive(Eq, Debug, ToJson)

///|
pub fn MatchOptions::loose() -> MatchOptions {
  {
    compare_query: false,
    compare_body: true,
    semantic_json_body: true,
    ignored_query_names: [],
  }
}

///|
pub fn MatchOptions::strict() -> MatchOptions {
  {
    compare_query: true,
    compare_body: true,
    semantic_json_body: true,
    ignored_query_names: [],
  }
}

///|
pub fn MatchOptions::with_ignored_query(
  self : MatchOptions,
  names : Array[String],
) -> MatchOptions {
  let ignored = self.ignored_query_names.copy()
  for name in names {
    let normalized = name.trim().to_owned().to_lower()
    if normalized != "" && !ignored.contains(normalized) {
      ignored.push(normalized)
    }
  }
  { ..self, ignored_query_names: ignored, }
}

///|
fn query_part_name(part : StringView) -> String {
  match part.split_once("=") {
    Some((name, _)) => name.to_owned().to_lower()
    None => part.to_owned().to_lower()
  }
}

///|
pub fn canonical_target(path : String, options : MatchOptions) -> String {
  guard options.compare_query else { return path_without_query(path) }
  match path.split_once("?") {
    None => path
    Some((base, query)) => {
      let parts : Array[String] = []
      for part in query.split("&") {
        if !options.ignored_query_names.contains(query_part_name(part)) {
          parts.push(part.to_owned())
        }
      }
      parts.sort()
      if parts.is_empty() {
        base.to_owned()
      } else {
        base.to_owned() + "?" + parts.join("&")
      }
    }
  }
}

///|
fn bodies_equal(
  expected : String,
  actual : String,
  semantic_json : Bool,
) -> Bool {
  if expected == actual {
    return true
  }
  guard semantic_json else { return false }
  try @json.parse(expected) == @json.parse(actual) catch {
    _ => false
  }
}

///|
pub fn match_request_with_options(
  archive : HarArchive,
  meth : String,
  path : String,
  body? : String,
  options : MatchOptions,
) -> MatchResult {
  let target = canonical_target(path, options)
  let base_path = path_without_query(path)
  let mut same_base_path : Int? = None
  let mut same_target : Int? = None
  let mut same_method : Int? = None
  for index, entry in archive.entries {
    if path_without_query(entry.request.path) == base_path {
      if same_base_path is None {
        same_base_path = Some(index)
      }
      if canonical_target(entry.request.path, options) == target {
        if same_target is None {
          same_target = Some(index)
        }
      } else {
        continue
      }
      if entry.request.meth.to_lower() == meth.to_lower() {
        if same_method is None {
          same_method = Some(index)
        }
        if !options.compare_body {
          return Exact(index)
        }
        match (entry.request.body, body) {
          (None, None) => return Exact(index)
          (None, Some(actual)) if actual == "" => return Exact(index)
          (Some(expected), Some(actual)) =>
            if bodies_equal(expected, actual, options.semantic_json_body) {
              return Exact(index)
            }
          _ => ()
        }
      }
    }
  }
  match same_method {
    Some(index) => BodyMismatch(index)
    None =>
      match same_target {
        Some(index) => MethodMismatch(index)
        None =>
          match same_base_path {
            Some(index) if options.compare_query => QueryMismatch(index)
            _ => PathMismatch
          }
      }
  }
}

///|
pub fn match_request(
  archive : HarArchive,
  meth : String,
  path : String,
  body? : String,
) -> MatchResult {
  match_request_with_options(archive, meth, path, body?, MatchOptions::loose())
}

///|
pub fn explain_match(archive : HarArchive, result : MatchResult) -> String {
  match result {
    Exact(index) => "matched recording #\{index + 1}"
    BodyMismatch(index) => {
      let entry = archive.entries[index]
      "request body differs from recording #\{index + 1}: \{entry.request.meth} \{entry.request.path}"
    }
    MethodMismatch(index) => {
      let entry = archive.entries[index]
      "path exists in recording #\{index + 1}, but expected method \{entry.request.meth}"
    }
    QueryMismatch(index) => {
      let entry = archive.entries[index]
      "path exists in recording #\{index + 1}, but query differs from \{entry.request.path}"
    }
    PathMismatch => "no recorded request has this path"
  }
}

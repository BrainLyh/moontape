///|
pub(all) enum MatchResult {
  Exact(Int)
  BodyMismatch(Int)
  MethodMismatch(Int)
  PathMismatch
} derive(Eq, Debug, ToJson)

///|
pub fn match_request(
  archive : HarArchive,
  meth : String,
  path : String,
  body? : String,
) -> MatchResult {
  let clean_path = path_without_query(path)
  let mut same_path : Int? = None
  let mut same_method : Int? = None
  for index, entry in archive.entries {
    if path_without_query(entry.request.path) == clean_path {
      if same_path is None {
        same_path = Some(index)
      }
      if entry.request.meth.to_lower() == meth.to_lower() {
        if same_method is None {
          same_method = Some(index)
        }
        match (entry.request.body, body) {
          (None, _) | (Some(_), None) => return Exact(index)
          (Some(expected), Some(actual)) =>
            if expected == actual {
              return Exact(index)
            }
        }
      }
    }
  }
  match same_method {
    Some(index) => BodyMismatch(index)
    None =>
      match same_path {
        Some(index) => MethodMismatch(index)
        None => PathMismatch
      }
  }
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
    PathMismatch => "no recorded request has this path"
  }
}

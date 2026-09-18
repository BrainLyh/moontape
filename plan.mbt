///|
pub(all) enum PlanIssueSeverity {
  Warning
  Error
} derive(Eq, Debug, ToJson)

///|
pub(all) struct PlanIssue {
  severity : PlanIssueSeverity
  code : String
  message : String
  recordings : Array[Int]
} derive(Eq, Debug, ToJson)

///|
pub(all) struct ReplayRoute {
  meth : String
  target : String
  recordings : Array[Int]
  statuses : Array[Int]
  request_variants : Int
  ambiguous_variants : Int
} derive(Eq, Debug, ToJson)

///|
pub(all) struct ReplayPlan {
  recording_count : Int
  route_count : Int
  duplicate_route_count : Int
  routes : Array[ReplayRoute]
  issues : Array[PlanIssue]
} derive(Eq, Debug, ToJson)

///|
pub fn ReplayPlan::is_replayable(self : ReplayPlan) -> Bool {
  for issue in self.issues {
    if issue.severity == Error {
      return false
    }
  }
  true
}

///|
pub fn ReplayPlan::error_count(self : ReplayPlan) -> Int {
  let mut count = 0
  for issue in self.issues {
    if issue.severity == Error {
      count += 1
    }
  }
  count
}

///|
pub fn ReplayPlan::warning_count(self : ReplayPlan) -> Int {
  let mut count = 0
  for issue in self.issues {
    if issue.severity == Warning {
      count += 1
    }
  }
  count
}

///|
fn severity_text(severity : PlanIssueSeverity) -> String {
  match severity {
    Warning => "warning"
    Error => "error"
  }
}

///|
fn ints_text(values : Array[Int]) -> String {
  values.map(value => value.to_string()).join(", ")
}

///|
fn route_key(meth : String, target : String) -> String {
  meth.to_upper() + "\u{1f}" + target
}

///|
fn optional_bodies_equal(left : String?, right : String?) -> Bool {
  match (left, right) {
    (None, None) => true
    (None, Some(value)) | (Some(value), None) => value == ""
    (Some(left), Some(right)) =>
      if left == right {
        true
      } else {
        try @json.parse(left) == @json.parse(right) catch {
          _ => false
        }
      }
  }
}

///|
fn request_variant_groups(
  archive : HarArchive,
  indices : Array[Int],
) -> Array[Array[Int]] {
  let groups : Array[Array[Int]] = []
  for index in indices {
    let mut group_index : Int? = None
    for candidate, group in groups {
      let representative = group[0]
      if optional_bodies_equal(
          archive.entries[representative].request.body,
          archive.entries[index].request.body,
        ) {
        group_index = Some(candidate)
        break
      }
    }
    match group_index {
      Some(candidate) => groups[candidate].push(index)
      None => groups.push([index])
    }
  }
  groups
}

///|
fn unique_statuses(archive : HarArchive, indices : Array[Int]) -> Array[Int] {
  let statuses : Array[Int] = []
  for index in indices {
    let status = archive.entries[index].response.status
    if !statuses.contains(status) {
      statuses.push(status)
    }
  }
  statuses.sort()
  statuses
}

///|
fn one_based(indices : Array[Int]) -> Array[Int] {
  indices.map(index => index + 1)
}

///|
fn body_issue(response : HarResponse, recording : Int) -> PlanIssue? {
  if response.body != "" || response.status == 204 || response.status == 304 {
    return None
  }
  let media_type = response.mime_type.to_lower()
  if media_type.contains("json") || media_type.has_prefix("text/") {
    Some({
      severity: Warning,
      code: "response.empty_body",
      message: "recording #\{recording} declares \{response.mime_type} but has an empty body",
      recordings: [recording],
    })
  } else {
    None
  }
}

///|
fn encoding_issue(response : HarResponse, recording : Int) -> PlanIssue? {
  try {
    ignore(response.body_bytes())
    None
  } catch {
    InvalidHar(message) =>
      Some({
        severity: Error,
        code: "response.invalid_encoding",
        message: "recording #\{recording} cannot be decoded: \{message}",
        recordings: [recording],
      })
  }
}

///|
pub fn build_replay_plan(
  archive : HarArchive,
  options : MatchOptions,
) -> ReplayPlan {
  let groups : Map[String, Array[Int]] = Map([])
  let order : Array[String] = []
  let targets : Map[String, String] = Map([])
  for index, entry in archive.entries {
    let target = canonical_target(entry.request.path, options)
    let key = route_key(entry.request.meth, target)
    match groups.get(key) {
      Some(indices) => indices.push(index)
      None => {
        groups.set(key, [index])
        targets.set(key, target)
        order.push(key)
      }
    }
  }
  let routes : Array[ReplayRoute] = []
  let issues : Array[PlanIssue] = []
  let mut duplicate_route_count = 0
  for key in order {
    let indices = groups[key]
    let first = archive.entries[indices[0]]
    let variants = request_variant_groups(archive, indices)
    let mut ambiguous_variants = 0
    for variant in variants {
      if variant.length() > 1 {
        ambiguous_variants += 1
        let recordings = one_based(variant)
        issues.push({
          severity: Error,
          code: "request.ambiguous_recording",
          message: "recordings \{ints_text(recordings)} have the same request fingerprint; first-match replay would hide later entries",
          recordings,
        })
      }
    }
    if indices.length() > 1 {
      duplicate_route_count += 1
    }
    routes.push({
      meth: first.request.meth.to_upper(),
      target: targets[key],
      recordings: one_based(indices),
      statuses: unique_statuses(archive, indices),
      request_variants: variants.length(),
      ambiguous_variants,
    })
  }
  for index, entry in archive.entries {
    match body_issue(entry.response, index + 1) {
      Some(issue) => issues.push(issue)
      None => ()
    }
    match encoding_issue(entry.response, index + 1) {
      Some(issue) => issues.push(issue)
      None => ()
    }
  }
  {
    recording_count: archive.entries.length(),
    route_count: routes.length(),
    duplicate_route_count,
    routes,
    issues,
  }
}

///|
pub fn replay_plan_text(plan : ReplayPlan) -> String {
  let output = StringBuilder()
  output.write_string(
    "Replay plan: \{plan.recording_count} recordings, \{plan.route_count} routes, \{plan.error_count()} errors, \{plan.warning_count()} warnings\n",
  )
  for index, route in plan.routes {
    output.write_string(
      "\{index + 1}. \{route.meth} \{route.target} · recordings \{ints_text(route.recordings)} · statuses \{ints_text(route.statuses)} · \{route.request_variants} request variants\n",
    )
  }
  if !plan.issues.is_empty() {
    output.write_string("Issues:\n")
    for issue in plan.issues {
      output.write_string(
        "- [\{severity_text(issue.severity)}] \{issue.code}: \{issue.message}\n",
      )
    }
  }
  output.to_string()
}

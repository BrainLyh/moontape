///|
pub(all) struct ReplayObservation {
  sequence : Int
  meth : String
  path : String
  outcome : String
  recording : Int?
  detail : String
} derive(Eq, Debug, ToJson)

///|
pub(all) struct RecordingUsage {
  recording : Int
  hits : Int
} derive(Eq, Debug, ToJson)

///|
pub(all) struct ReplayReport {
  recording_count : Int
  total_requests : Int
  matched_requests : Int
  missed_requests : Int
  unique_recordings_used : Int
  coverage_percent : Double
  unused_recordings : Array[Int]
  usage : Array[RecordingUsage]
  events : Array[ReplayObservation]
} derive(Eq, Debug, ToJson)

///|
pub struct ReplayLedger {
  recording_count : Int
  events : Array[ReplayObservation]
}

///|
pub fn ReplayLedger::new(recording_count : Int) -> ReplayLedger {
  { recording_count: recording_count.max(0), events: [], }
}

///|
pub fn ReplayLedger::record(
  self : ReplayLedger,
  meth : String,
  path : String,
  result : MatchResult,
  detail : String,
) -> Unit {
  let (outcome, recording) = match result {
    Exact(index) => ("matched", Some(index + 1))
    BodyMismatch(index) => ("body_mismatch", Some(index + 1))
    MethodMismatch(index) => ("method_mismatch", Some(index + 1))
    QueryMismatch(index) => ("query_mismatch", Some(index + 1))
    PathMismatch => ("path_mismatch", None)
  }
  self.events.push({
    sequence: self.events.length() + 1,
    meth: meth.to_upper(),
    path,
    outcome,
    recording,
    detail,
  })
}

///|
pub fn ReplayLedger::events(self : ReplayLedger) -> Array[ReplayObservation] {
  self.events.copy()
}

///|
pub fn ReplayLedger::request_count(self : ReplayLedger) -> Int {
  self.events.length()
}

///|
pub fn ReplayLedger::clear(self : ReplayLedger) -> Unit {
  while !self.events.is_empty() {
    ignore(self.events.pop())
  }
}

///|
fn recording_counts(ledger : ReplayLedger) -> Array[Int] {
  let counts : Array[Int] = []
  for _ in 0..<ledger.recording_count {
    counts.push(0)
  }
  for event in ledger.events {
    if event.outcome == "matched" {
      match event.recording {
        Some(recording) if recording > 0 && recording <= counts.length() =>
          counts[recording - 1] = counts[recording - 1] + 1
        _ => ()
      }
    }
  }
  counts
}

///|
pub fn ReplayLedger::report(self : ReplayLedger) -> ReplayReport {
  let counts = recording_counts(self)
  let usage : Array[RecordingUsage] = []
  let unused : Array[Int] = []
  let mut matched_requests = 0
  for index, count in counts {
    matched_requests += count
    if count == 0 {
      unused.push(index + 1)
    } else {
      usage.push({ recording: index + 1, hits: count, })
    }
  }
  let unique = usage.length()
  let coverage = if self.recording_count == 0 {
    100.0
  } else {
    unique.to_double() * 100.0 / self.recording_count.to_double()
  }
  {
    recording_count: self.recording_count,
    total_requests: self.events.length(),
    matched_requests,
    missed_requests: self.events.length() - matched_requests,
    unique_recordings_used: unique,
    coverage_percent: coverage,
    unused_recordings: unused,
    usage,
    events: self.events.copy(),
  }
}

///|
pub fn ReplayReport::has_misses(self : ReplayReport) -> Bool {
  self.missed_requests > 0
}

///|
pub fn ReplayReport::has_full_coverage(self : ReplayReport) -> Bool {
  self.unique_recordings_used == self.recording_count
}

///|
pub fn ReplayReport::passes(
  self : ReplayReport,
  require_full_coverage? : Bool = false,
  allow_misses? : Bool = false,
) -> Bool {
  if !allow_misses && self.has_misses() {
    return false
  }
  if require_full_coverage && !self.has_full_coverage() {
    return false
  }
  true
}

///|
fn recording_list_text(values : Array[Int]) -> String {
  if values.is_empty() {
    "none"
  } else {
    values.map(value => value.to_string()).join(", ")
  }
}

///|
pub fn replay_report_text(report : ReplayReport) -> String {
  let output = StringBuilder()
  output.write_string(
    "Replay report: \{report.matched_requests}/\{report.total_requests} requests matched; \{report.unique_recordings_used}/\{report.recording_count} recordings used (\{report.coverage_percent}%)\n",
  )
  output.write_string(
    "Misses: \{report.missed_requests}; unused recordings: \{recording_list_text(report.unused_recordings)}\n",
  )
  if !report.usage.is_empty() {
    output.write_string("Usage:\n")
    for item in report.usage {
      output.write_string("- recording #\{item.recording}: \{item.hits} hits\n")
    }
  }
  if report.has_misses() {
    output.write_string("Missed requests:\n")
    for event in report.events {
      if event.outcome != "matched" {
        output.write_string(
          "- #\{event.sequence} \{event.meth} \{event.path}: \{event.detail}\n",
        )
      }
    }
  }
  output.to_string()
}

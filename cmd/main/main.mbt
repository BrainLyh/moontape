///|
fn usage() -> String {
  (
    #|MoonTape — privacy-first HAR toolkit
    #|
    #|Usage:
    #|  moontape inspect <file.har>
    #|  moontape scan <file.har> [--redact name,name]
    #|  moontape sanitize <input.har> -o <output.har> [--redact name,name]
    #|  moontape serve <file.har> [--port 8080] [--strict]
    #|  moontape help
  )
}

///|
async fn read_archive(path : String) -> @moontape.HarArchive {
  let source = @fs.read_file(path).text()
  @moontape.parse_har(source)
}

///|
fn extra_redaction_policy(names : String) -> @moontape.RedactionPolicy {
  let additional : Array[String] = []
  for name in names.split(",") {
    additional.push(name.trim().to_owned())
  }
  @moontape.RedactionPolicy::default().with_additional(additional)
}

///|
fn request_method_name(req_method : @http.RequestMethod) -> String {
  match req_method {
    Get => "GET"
    Head => "HEAD"
    Post => "POST"
    Put => "PUT"
    Delete => "DELETE"
    Connect => "CONNECT"
    Options => "OPTIONS"
    Trace => "TRACE"
    Patch => "PATCH"
  }
}

///|
fn reason_phrase(status : Int, recorded : String) -> String {
  if recorded != "" {
    return recorded
  }
  match status {
    200 => "OK"
    201 => "Created"
    202 => "Accepted"
    204 => "No Content"
    301 => "Moved Permanently"
    302 => "Found"
    304 => "Not Modified"
    400 => "Bad Request"
    401 => "Unauthorized"
    403 => "Forbidden"
    404 => "Not Found"
    409 => "Conflict"
    429 => "Too Many Requests"
    500 => "Internal Server Error"
    502 => "Bad Gateway"
    503 => "Service Unavailable"
    _ => "Recorded Response"
  }
}

///|
async fn serve_archive(
  archive : @moontape.HarArchive,
  port : Int,
  options : @moontape.MatchOptions,
) -> Unit {
  let address = @socket.Addr::parse("0.0.0.0:\{port}")
  let server = @http.Server(address)
  println(
    "MoonTape replaying \{archive.entries.length()} requests at http://127.0.0.1:\{port}",
  )
  server.run_forever() <| ((request, body_reader, connection) => {
    let body = if request.meth is (Post | Put | Patch) {
      Some(@io.Reader::read_all(body_reader).text())
    } else {
      None
    }
    let result = @moontape.match_request_with_options(
      archive,
      request_method_name(request.meth),
      request.path,
      body?,
      options,
    )
    match result {
      Exact(index) => {
        let recorded = archive.entries[index].response
        let headers : @http.Headers = Map([
          (@http.CaseInsensitiveString("Content-Type"), recorded.mime_type),
          (
            @http.CaseInsensitiveString("X-MoonTape-Match"),
            (index + 1).to_string(),
          ),
        ])
        connection
        ..send_response(
          recorded.status,
          reason_phrase(recorded.status, recorded.status_text),
          extra_headers=headers,
        )
        ..write(recorded.body_bytes())
        .end_response()
      }
      mismatch => {
        let explanation = @moontape.explain_match(archive, mismatch)
        connection
        ..send_response(404, "No Recording", extra_headers={
          "Content-Type": "text/plain; charset=utf-8",
          "X-MoonTape-Match": "miss",
        })
        ..write("MoonTape: \{explanation}\n")
        .end_response()
      }
    }
  })
}

///|
async fn run(args : Array[String]) -> Unit {
  match args {
    [_, "inspect", path] => {
      let archive = read_archive(path)
      println(@moontape.inspect_text(archive))
    }
    [_, "scan", path] => {
      let report = @moontape.scan_har(read_archive(path))
      println(@json.to_json(report).stringify(indent=2))
    }
    [_, "scan", path, "--redact", names] => {
      let report = @moontape.scan_har_with_policy(
        read_archive(path),
        extra_redaction_policy(names),
      )
      println(@json.to_json(report).stringify(indent=2))
    }
    [_, "sanitize", input, "-o", output]
    | [_, "sanitize", input, "--output", output] => {
      let archive = read_archive(input)
      let (clean, report) = @moontape.sanitize_har(archive)
      @fs.write_file(output, clean.stringify(indent=2) + "\n")
      println(
        "Wrote \{output}; redacted \{report.redacted_values} sensitive values.",
      )
    }
    [_, "sanitize", input, "-o", output, "--redact", names]
    | [_, "sanitize", input, "--output", output, "--redact", names] => {
      let archive = read_archive(input)
      let (clean, report) = @moontape.sanitize_har_with_policy(
        archive,
        extra_redaction_policy(names),
      )
      @fs.write_file(output, clean.stringify(indent=2) + "\n")
      println(
        "Wrote \{output}; redacted \{report.redacted_values} sensitive values.",
      )
    }
    [_, "serve", path] =>
      serve_archive(read_archive(path), 8080, @moontape.MatchOptions::loose())
    [_, "serve", path, "--strict"] =>
      serve_archive(read_archive(path), 8080, @moontape.MatchOptions::strict())
    [_, "serve", path, "--port", port_text] => {
      let port = @string.parse_int(port_text) catch {
        _ => raise Failure("port must be an integer")
      }
      guard port > 0 && port < 65536 else {
        raise Failure("port must be between 1 and 65535")
      }
      serve_archive(read_archive(path), port, @moontape.MatchOptions::loose())
    }
    [_, "serve", path, "--port", port_text, "--strict"] => {
      let port = @string.parse_int(port_text) catch {
        _ => raise Failure("port must be an integer")
      }
      guard port > 0 && port < 65536 else {
        raise Failure("port must be between 1 and 65535")
      }
      serve_archive(read_archive(path), port, @moontape.MatchOptions::strict())
    }
    [_, "help"] | [_] => println(usage())
    _ => {
      println(usage())
      raise Failure("invalid command")
    }
  }
}

///|
async fn main {
  run(@env.args()) catch {
    error => println("error: \{error}")
  }
}

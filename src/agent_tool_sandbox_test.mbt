///|
test "normalization rejects escapes" {
  assert_eq(
    @agent-tool-sandbox.normalize_resource("workspace/src/main.mbt"),
    Some("workspace/src/main.mbt"),
  )
  assert_eq(
    @agent-tool-sandbox.normalize_resource("workspace/src/../secret"),
    None,
  )
  assert_eq(
    @agent-tool-sandbox.normalize_resource("/Users/me/.ssh/id_rsa"),
    None,
  )
}

///|
test "project policy allows workspace and denies secrets" {
  let policy = @agent-tool-sandbox.project_policy()
  assert_eq(
    @agent-tool-sandbox.authorize(
      policy,
      @agent-tool-sandbox.Request::new(
        "reader",
        @agent-tool-sandbox.FsRead,
        "workspace/src/main.mbt",
      ),
    ),
    @agent-tool-sandbox.Allow,
  )
  assert_eq(
    @agent-tool-sandbox.authorize(
      policy,
      @agent-tool-sandbox.Request::new(
        "reader",
        @agent-tool-sandbox.FsRead,
        "../.ssh/id_rsa",
      ),
    ),
    @agent-tool-sandbox.Deny,
  )
}

///|
test "write and network decisions are distinct" {
  let policy = @agent-tool-sandbox.project_policy()
  assert_eq(
    @agent-tool-sandbox.authorize(
      policy,
      @agent-tool-sandbox.Request::new(
        "writer",
        @agent-tool-sandbox.FsWrite,
        "workspace/out/result.json",
      ),
    ),
    @agent-tool-sandbox.Allow,
  )
  assert_eq(
    @agent-tool-sandbox.authorize(
      policy,
      @agent-tool-sandbox.Request::new(
        "fetcher",
        @agent-tool-sandbox.NetConnect,
        "api.example.com",
      ),
    ),
    @agent-tool-sandbox.Deny,
  )
}

///|
test "manifest is an independent capability boundary" {
  let policy = @agent-tool-sandbox.project_policy()
  let manifest = @agent-tool-sandbox.ToolManifest::new("reader", [
    @agent-tool-sandbox.FsRead,
  ])
  let (decision, event) = @agent-tool-sandbox.authorize_manifest(
    policy,
    manifest,
    @agent-tool-sandbox.Request::new(
      "reader",
      @agent-tool-sandbox.FsWrite,
      "workspace/out/result.json",
    ),
  )
  assert_eq(decision, @agent-tool-sandbox.Deny)
  assert_true(event.reason.contains("not declared"))
}

///|
test "policy JSON and audit output are stable" {
  let policy = @agent-tool-sandbox.policy_from_json(
    "{\"rules\":[{\"capability\":\"fs.read\",\"pattern\":\"workspace/**\",\"decision\":\"allow\"}]}",
  ).unwrap()
  let (decision, event) = @agent-tool-sandbox.authorize_manifest(
    policy,
    @agent-tool-sandbox.ToolManifest::new("reader", [@agent-tool-sandbox.FsRead]),
    @agent-tool-sandbox.Request::new(
      "reader",
      @agent-tool-sandbox.FsRead,
      "workspace/src/main.mbt",
    ),
  )
  assert_eq(decision, @agent-tool-sandbox.Allow)
  assert_true(
    @agent-tool-sandbox.audit_event_json(event).contains(
      "\"decision\":\"allow\"",
    ),
  )
}

///|
test "exact rules do not match sibling resources" {
  let policy = @agent-tool-sandbox.Policy::new([
    @agent-tool-sandbox.Rule::new(
      @agent-tool-sandbox.FsRead,
      "workspace/a",
      @agent-tool-sandbox.Allow,
    ),
  ])
  assert_eq(
    @agent-tool-sandbox.authorize(
      policy,
      @agent-tool-sandbox.Request::new(
        "reader",
        @agent-tool-sandbox.FsRead,
        "workspace/ab",
      ),
    ),
    @agent-tool-sandbox.Deny,
  )
}

///|
test "last matching rule is deterministic" {
  let policy = @agent-tool-sandbox.Policy::new([
    @agent-tool-sandbox.Rule::new(
      @agent-tool-sandbox.FsRead,
      "workspace/**",
      @agent-tool-sandbox.Allow,
    ),
    @agent-tool-sandbox.Rule::new(
      @agent-tool-sandbox.FsRead,
      "workspace/secrets/**",
      @agent-tool-sandbox.Deny,
    ),
  ])
  assert_eq(
    @agent-tool-sandbox.authorize(
      policy,
      @agent-tool-sandbox.Request::new(
        "reader",
        @agent-tool-sandbox.FsRead,
        "workspace/secrets/key",
      ),
    ),
    @agent-tool-sandbox.Deny,
  )
}

///|
test "ask remains distinct from allow and deny" {
  let policy = @agent-tool-sandbox.Policy::new([
    @agent-tool-sandbox.Rule::new(
      @agent-tool-sandbox.NetConnect,
      "api.example.com",
      @agent-tool-sandbox.Ask,
    ),
  ])
  assert_eq(
    @agent-tool-sandbox.authorize(
      policy,
      @agent-tool-sandbox.Request::new(
        "fetcher",
        @agent-tool-sandbox.NetConnect,
        "api.example.com",
      ),
    ),
    @agent-tool-sandbox.Ask,
  )
}

///|
test "malformed policy is rejected" {
  assert_true(
    @agent-tool-sandbox.policy_from_json("{\"rules\": [42]}") is Err(_),
  )
  assert_true(@agent-tool-sandbox.policy_from_json("not-json") is Err(_))
}

///|
test "manifest identity is enforced" {
  let policy = @agent-tool-sandbox.project_policy()
  let manifest = @agent-tool-sandbox.ToolManifest::new("reader", [
    @agent-tool-sandbox.FsRead,
  ])
  let (decision, event) = @agent-tool-sandbox.authorize_manifest(
    policy,
    manifest,
    @agent-tool-sandbox.Request::new(
      "writer",
      @agent-tool-sandbox.FsRead,
      "workspace/src/main.mbt",
    ),
  )
  assert_eq(decision, @agent-tool-sandbox.Deny)
  assert_true(event.reason.contains("does not match"))
}

///|
test "audit escaping protects JSON strings" {
  let event = @agent-tool-sandbox.AuditEvent::new(
    "reader\"tool",
    @agent-tool-sandbox.FsRead,
    "workspace/line\nfile",
    @agent-tool-sandbox.Deny,
    "blocked",
  )
  let line = @agent-tool-sandbox.audit_event_json(event)
  assert_true(line.contains("reader\\\"tool"))
  assert_true(line.contains("line\\nfile"))
}

///|
test "manifest limits and validation are explicit" {
  let manifest = @agent-tool-sandbox.ToolManifest::with_limits(
    "reader",
    [@agent-tool-sandbox.FsRead],
    @agent-tool-sandbox.Limits::new(1000, 4096, 4),
  )
  assert_true(manifest.validate() is Ok(_))
  let invalid = @agent-tool-sandbox.ToolManifest::with_limits(
    "reader",
    [@agent-tool-sandbox.FsRead],
    @agent-tool-sandbox.Limits::new(0, 4096, 4),
  )
  assert_true(invalid.validate() is Err(_))
}

///|
test "policy validation rejects dangerous patterns" {
  assert_true(
    @agent-tool-sandbox.Policy::new([
      @agent-tool-sandbox.Rule::new(
        @agent-tool-sandbox.FsRead,
        "../outside",
        @agent-tool-sandbox.Allow,
      ),
    ]).validate()
    is Err(_),
  )
}

///|
test "audit log preserves event order" {
  let log = @agent-tool-sandbox.AuditLog::new()
  log.append(
    @agent-tool-sandbox.AuditEvent::new(
      "reader",
      @agent-tool-sandbox.FsRead,
      "workspace/src/a",
      @agent-tool-sandbox.Allow,
      "matched policy",
    ),
  )
  log.append(
    @agent-tool-sandbox.AuditEvent::new(
      "reader",
      @agent-tool-sandbox.FsRead,
      "../secret",
      @agent-tool-sandbox.Deny,
      "path rejected",
    ),
  )
  assert_eq(log.len(), 2)
  let jsonl = log.to_jsonl()
  assert_true(jsonl.has_prefix("{\"tool\":\"reader\""))
  assert_true(jsonl.contains("path rejected"))
  assert_true(jsonl.has_suffix("\n"))
}

///|
test "manifest JSON validates declarations and limits" {
  let manifest = @agent-tool-sandbox.tool_manifest_from_json(
    "{\"name\":\"reader\",\"capabilities\":[\"fs.read\"],\"limits\":{\"timeout_ms\":1000,\"max_output_bytes\":4096,\"max_requests\":2}}",
  ).unwrap()
  assert_true(manifest.has(@agent-tool-sandbox.FsRead))
  assert_true(manifest.validate() is Ok(_))
  assert_true(
    @agent-tool-sandbox.tool_manifest_from_json(
      "{\"name\":\"reader\",\"capabilities\":[\"unknown\"]}",
    )
    is Err(_),
  )
}

///|
test "runtime composes authorization and request budget" {
  let manifest = @agent-tool-sandbox.ToolManifest::with_limits(
    "reader",
    [@agent-tool-sandbox.FsRead],
    @agent-tool-sandbox.Limits::new(1000, 4096, 1),
  )
  let runtime = @agent-tool-sandbox.Runtime::new(
    @agent-tool-sandbox.project_policy(),
    manifest,
  ).unwrap()
  assert_eq(
    runtime.request(
      @agent-tool-sandbox.Request::new(
        "reader",
        @agent-tool-sandbox.FsRead,
        "workspace/src/main.mbt",
      ),
    ),
    @agent-tool-sandbox.Allow,
  )
  assert_eq(
    runtime.request(
      @agent-tool-sandbox.Request::new(
        "reader",
        @agent-tool-sandbox.FsRead,
        "workspace/src/other.mbt",
      ),
    ),
    @agent-tool-sandbox.Deny,
  )
  assert_true(runtime.audit_jsonl().contains("workspace/src/main.mbt"))
}

///|
test "manifest budgets reject fractions and overflow without truncation" {
  for
    invalid in [
      "0", "-1", "0.5", "1.5", "2147483648", "1e100", "\"10\"", "null",
    ] {
    for field in ["timeout_ms", "max_output_bytes", "max_requests"] {
      let fields = ["timeout_ms", "max_output_bytes", "max_requests"]
        .map(fn(key) {
          let value = if key == field { invalid } else { "10" }
          "\"" + key + "\":" + value
        })
        .join(",")
      let document = "{\"name\":\"reader\",\"capabilities\":[\"fs.read\"],\"limits\":{" +
        fields +
        "}}"
      assert_true(
        @agent-tool-sandbox.tool_manifest_from_json(document) is Err(_),
      )
    }
  }
  let maximum = @agent-tool-sandbox.tool_manifest_from_json(
    "{\"name\":\"reader\",\"capabilities\":[\"fs.read\"],\"limits\":{\"timeout_ms\":2147483647,\"max_output_bytes\":1,\"max_requests\":1}}",
  ).unwrap()
  assert_eq(maximum.limits.timeout_ms, 2147483647)
}

///|
test "unknown configuration fields fail closed" {
  for
    document in [
      "{\"rules\":[],\"default\":\"allow\"}", "{\"rules\":[{\"capability\":\"fs.read\",\"pattern\":\"workspace/**\",\"decision\":\"allow\",\"except\":\"secrets\"}]}",
    ] {
    assert_true(@agent-tool-sandbox.policy_from_json(document) is Err(_))
  }
  for
    document in [
      "{\"name\":\"reader\",\"capabilities\":[\"fs.read\"],\"limit\":1}", "{\"name\":\"reader\",\"capabilities\":[\"fs.read\"],\"limits\":{\"timeout_ms\":10,\"max_output_bytes\":10,\"max_requests\":10,\"max_request\":1}}",
    ] {
    assert_true(@agent-tool-sandbox.tool_manifest_from_json(document) is Err(_))
  }
}

///|
test "duplicate manifest capabilities are rejected by both entry points" {
  assert_true(
    @agent-tool-sandbox.tool_manifest_from_json(
      "{\"name\":\"reader\",\"capabilities\":[\"fs.read\",\"fs.read\"]}",
    )
    is Err(_),
  )
  let manifest = @agent-tool-sandbox.ToolManifest::new("reader", [
    @agent-tool-sandbox.FsRead,
    @agent-tool-sandbox.FsRead,
  ])
  assert_true(
    @agent-tool-sandbox.Runtime::new(
      @agent-tool-sandbox.project_policy(),
      manifest,
    )
    is Err(_),
  )
}

///|
test "JSON policy cannot bypass validation and empty policy denies" {
  assert_true(
    @agent-tool-sandbox.policy_from_json(
      "{\"rules\":[{\"capability\":\"fs.read\",\"pattern\":\"../secret\",\"decision\":\"allow\"}]}",
    )
    is Err(_),
  )
  let policy = @agent-tool-sandbox.policy_from_json("{\"rules\":[]}").unwrap()
  assert_eq(
    @agent-tool-sandbox.authorize(
      policy,
      @agent-tool-sandbox.Request::new(
        "reader",
        @agent-tool-sandbox.FsRead,
        "workspace/src/main.mbt",
      ),
    ),
    @agent-tool-sandbox.Deny,
  )
}

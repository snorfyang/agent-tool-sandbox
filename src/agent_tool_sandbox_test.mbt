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

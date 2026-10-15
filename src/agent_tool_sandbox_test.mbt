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

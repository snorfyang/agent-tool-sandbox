# Getting started

MoonSandbox currently ships the control-plane MVP. It evaluates a tool manifest and a capability request against a default-deny policy; it does not yet launch arbitrary native commands or WASI modules.

## Run the control-plane demo

```bash
moon fmt --warn
moon check --deny-warn
moon test --deny-warn

moon run src/cmd/agent-sandbox -- policy
moon run src/cmd/agent-sandbox -- check --cap fs.read --resource workspace/src/main.mbt
moon run src/cmd/agent-sandbox -- check --cap fs.read --resource ../.ssh/id_rsa
moon run src/cmd/agent-sandbox -- audit-demo
```

`check` demonstrates policy matching. `audit-demo` demonstrates the complete manifest → request → decision → audit-event path.

## Library shape

```moonbit
let policy = @agent_tool_sandbox.project_policy()
let manifest = @agent_tool_sandbox.ToolManifest::new(
  "reader",
  [@agent_tool_sandbox.FsRead],
)
let request = @agent_tool_sandbox.Request::new(
  "reader",
  @agent_tool_sandbox.FsRead,
  "workspace/src/main.mbt",
)
let (decision, event) = @agent_tool_sandbox.authorize_manifest(
  policy,
  manifest,
  request,
)
println(@agent_tool_sandbox.audit_event_json(event))
```

The manifest check and policy check are separate. A tool cannot gain a capability merely because a broad policy rule exists; it must declare that capability first.

## Policy file

`examples/policy.json` is the machine-readable shape planned for the next CLI milestone. The current `policy` command prints the equivalent starter policy so the MVP remains dependency-free at the command boundary.

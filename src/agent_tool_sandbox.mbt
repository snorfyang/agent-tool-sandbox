/// Capability policy and decision engine for Agent tools.
///
/// This package deliberately enforces a tool-level boundary. It does not claim
/// to isolate arbitrary native processes; a WASM/WASI host must enforce the
/// lower-level execution boundary.

///|
pub(all) enum Decision {
  Allow
  Deny
  Ask
} derive(Eq, Debug)

///|
pub extend Decision with Eq::{not_equal, equal}

///|
pub extend Decision with @debug.Debug::{to_repr}

///|
pub(all) enum Capability {
  FsRead
  FsWrite
  NetConnect
  EnvRead
} derive(Eq, Debug)

///|
pub extend Capability with Eq::{not_equal, equal}

///|
pub extend Capability with @debug.Debug::{to_repr}

///|
pub struct Rule {
  capability : Capability
  pattern : String
  decision : Decision
}

///|

///|
pub struct Policy {
  rules : Array[Rule]
}

///|

///|
pub struct Request {
  tool : String
  capability : Capability
  resource : String
}

///|
pub fn Request::new(
  tool : String,
  capability : Capability,
  resource : String,
) -> Request {
  { tool, capability, resource, }
}

///|
/// A tool's declared capability surface.
pub(all) struct ToolManifest {
  name : String
  capabilities : Array[Capability]
}

///|
pub fn ToolManifest::new(
  name : String,
  capabilities : Array[Capability],
) -> ToolManifest {
  { name, capabilities, }
}

///|
pub fn ToolManifest::has(self : ToolManifest, capability : Capability) -> Bool {
  self.capabilities.contains(capability)
}

///|
/// A normalized, machine-readable execution event.
pub(all) struct AuditEvent {
  tool : String
  capability : String
  resource : String
  decision : String
  reason : String
}

///|
pub fn AuditEvent::new(
  tool : String,
  capability : Capability,
  resource : String,
  decision : Decision,
  reason : String,
) -> AuditEvent {
  {
    tool,
    capability: capability_name(capability),
    resource,
    decision: decision_name(decision),
    reason,
  }
}

///|
/// Convert a capability to its stable policy spelling.
pub fn capability_name(capability : Capability) -> String {
  match capability {
    FsRead => "fs.read"
    FsWrite => "fs.write"
    NetConnect => "net.connect"
    EnvRead => "env.read"
  }
}

///|
pub fn decision_name(decision : Decision) -> String {
  match decision {
    Allow => "allow"
    Deny => "deny"
    Ask => "ask"
  }
}

///|
/// A tool can only request capabilities it declared in its manifest.
pub fn authorize_manifest(
  policy : Policy,
  manifest : ToolManifest,
  request : Request,
) -> (Decision, AuditEvent) {
  if request.tool != manifest.name {
    let event = AuditEvent::new(
      request.tool,
      request.capability,
      request.resource,
      Deny,
      "tool name does not match manifest",
    )
    return (Deny, event)
  }
  if !manifest.has(request.capability) {
    let event = AuditEvent::new(
      request.tool,
      request.capability,
      request.resource,
      Deny,
      "capability was not declared by the tool",
    )
    return (Deny, event)
  }
  let decision = authorize(policy, request)
  let reason = match decision {
    Allow => "matched policy"
    Deny => "no matching allow rule"
    Ask => "policy requires approval"
  }
  (
    decision,
    AuditEvent::new(
      request.tool,
      request.capability,
      request.resource,
      decision,
      reason,
    ),
  )
}

///|
/// Serialize an audit event as one JSONL-compatible line.
pub fn audit_event_json(event : AuditEvent) -> String {
  "{\"tool\":\"" +
  escape_json(event.tool) +
  "\",\"capability\":\"" +
  escape_json(event.capability) +
  "\",\"resource\":\"" +
  escape_json(event.resource) +
  "\",\"decision\":\"" +
  escape_json(event.decision) +
  "\",\"reason\":\"" +
  escape_json(event.reason) +
  "\"}"
}

///|
/// Parse the MVP JSON policy format.
pub fn policy_from_json(text : String) -> Result[Policy, String] {
  let value = @json.parse(text) catch {
    _ => return Err("policy is not valid JSON")
  }
  match value {
    Json::Object(root) =>
      match root.get("rules") {
        Some(Json::Array(items)) => {
          let rules : Array[Rule] = []
          for item in items {
            match item {
              Json::Object(fields) => {
                let cap = match fields.get("capability") {
                  Some(Json::String(value)) => capability_from_string(value)
                  _ => None
                }
                let pattern = match fields.get("pattern") {
                  Some(Json::String(value)) => Some(value)
                  _ => None
                }
                let decision = match fields.get("decision") {
                  Some(Json::String(value)) => decision_from_string(value)
                  _ => None
                }
                match (cap, pattern, decision) {
                  (Some(capability), Some(pattern), Some(decision)) =>
                    rules.push({ capability, pattern, decision, })
                  _ =>
                    return Err(
                      "each rule needs capability, pattern and decision",
                    )
                }
              }
              _ => return Err("each item in rules must be an object")
            }
          }
          Ok({ rules, })
        }
        _ => Err("policy.rules must be an array")
      }
    _ => Err("policy root must be an object")
  }
}

///|
/// Normalize a resource before policy matching.
pub fn normalize_resource(resource : String) -> String? {
  if resource.is_empty() ||
    resource.has_prefix("/") ||
    resource.has_prefix("\\") {
    return None
  }
  let normalized = resource.replace(old="\\", new="/")
  let parts = normalized.split("/")
  let out : Array[String] = []
  for part in parts {
    if part.is_empty() || part == "." {
      continue
    }
    if part == ".." {
      return None
    }
    out.push(part.to_owned())
  }
  if out.is_empty() {
    None
  } else {
    Some(out.join("/"))
  }
}

///|
/// Parse the four capability names used by the policy file.
pub fn capability_from_string(value : String) -> Capability? {
  match value {
    "fs.read" => Some(FsRead)
    "fs.write" => Some(FsWrite)
    "net.connect" => Some(NetConnect)
    "env.read" => Some(EnvRead)
    _ => None
  }
}

///|
/// Parse a decision name.
pub fn decision_from_string(value : String) -> Decision? {
  match value {
    "allow" => Some(Allow)
    "deny" => Some(Deny)
    "ask" => Some(Ask)
    _ => None
  }
}

///|
/// Glob matching intentionally supports only an exact value or a trailing `/**`.
pub fn pattern_matches(pattern : String, resource : String) -> Bool {
  if pattern == "**" || pattern == resource {
    return true
  }
  if pattern.has_suffix("/**") {
    let prefix = pattern[:pattern.length() - 3].to_owned()
    return resource == prefix || resource.has_prefix(prefix + "/")
  }
  false
}

///|
/// Decide a request using the last matching rule. Default is deny.
pub fn decide(policy : Policy, request : Request) -> Decision {
  let mut result = Deny
  for rule in policy.rules {
    if rule.capability == request.capability &&
      pattern_matches(rule.pattern, request.resource) {
      result = rule.decision
    }
  }
  result
}

///|
/// Validate a request resource and apply the policy.
pub fn authorize(policy : Policy, request : Request) -> Decision {
  match request.capability {
    FsRead | FsWrite =>
      match normalize_resource(request.resource) {
        Some(path) => decide(policy, { ..request, resource: path, })
        None => Deny
      }
    _ => decide(policy, request)
  }
}

///|
/// A safe starter policy for a project-local tool.
pub fn project_policy() -> Policy {
  {
    rules: [
      { capability: FsRead, pattern: "workspace/src/**", decision: Allow, },
      { capability: FsRead, pattern: "workspace/test/**", decision: Allow, },
      { capability: FsWrite, pattern: "workspace/out/**", decision: Allow, },
      { capability: FsWrite, pattern: "workspace/_build/**", decision: Allow, },
      { capability: NetConnect, pattern: "*", decision: Deny, },
      { capability: EnvRead, pattern: "LANG", decision: Allow, },
    ],
  }
}

///|
/// Escape the JSON string characters used by audit records.
fn escape_json(value : String) -> String {
  value
  .replace(old="\\", new="\\\\")
  .replace(old="\"", new="\\\"")
  .replace(old="\n", new="\\n")
}

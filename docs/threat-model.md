# Threat model

## Protected boundary

MoonSandbox is a capability policy control plane for tools that will run in a WASM/WASI backend. The policy engine makes a deterministic decision before the backend materializes a resource capability.

## Threats addressed

- A tool requests a path outside the workspace.
- A tool uses `..`, an absolute path or a backslash path to escape a relative root.
- A tool requests a capability it did not declare in its manifest.
- A tool name is confused with another registered tool.
- A policy has no matching rule.
- A future approval token is reused with different arguments or policy state.

## Threats outside the MVP

- A native Agent process that already has host privileges.
- Kernel, hypervisor, WASM runtime or hardware vulnerabilities.
- Prompt injection contained in tool output after the runtime returns it to a model.
- Domain-level network egress enforcement before a network backend exists.
- Secret scanning or data-loss prevention.

## Security invariants

1. No matching rule means `Deny`.
2. A tool must declare a capability before policy evaluation can allow it.
3. Filesystem requests must normalize successfully before matching.
4. Every evaluated request can produce a stable audit event.
5. The policy layer never treats a natural-language tool description as authority.

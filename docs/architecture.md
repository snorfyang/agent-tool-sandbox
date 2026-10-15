# MoonSandbox Architecture

MoonSandbox follows a control-plane/data-plane split.

```text
Agent / MCP host
      |
      | ToolRequest
      v
Tool manifest + capability broker
      |
      +-- policy parser / matcher
      +-- approval decision
      +-- resource limits
      +-- audit event
      v
WASM/WASI execution backend
```

## Control plane

The current MoonBit package owns the part that must be consistent across hosts:

- `Capability` models the four resource classes;
- `ToolManifest` declares what a tool may request;
- `Policy` contains default-deny matching rules;
- `authorize_manifest` checks tool identity, declared capabilities and policy;
- `AuditEvent` produces one stable JSONL-compatible record per decision.

The three checks are intentionally separate. A policy may allow `fs.write`, but a tool that did not declare `fs.write` still receives `DENY`. A request with a declared capability may still be denied by its resource pattern.

## Data plane

The data plane is the execution backend and is not part of the current pure-MoonBit MVP. The planned backend accepts the approved capability set and starts a WASM/WASI tool with only those resources. The backend is replaceable so the same policy core can later target Wasmtime, a browser host, or a platform process adapter.

## Decision lifecycle

```text
manifest loaded
  -> request normalized
  -> manifest capability check
  -> policy match
  -> allow / deny / ask
  -> audit event
  -> backend execution (future)
```

## Why this decomposition matters

A model can be manipulated by repository text or tool output. The model therefore cannot be the authority that grants access. The capability broker is deterministic and model-independent; the execution backend is the only component allowed to materialize the granted resources.

## Next modules

The MVP is intentionally one package so the policy semantics are easy to inspect. The next extraction points are:

- `capability`: public types and resource normalization;
- `policy`: JSON/TOML loading and matching;
- `audit`: append-only JSONL sink and redaction;
- `runtime`: request lifecycle, limits and approvals;
- `backend-wasi`: WIT/WASI execution adapter;
- `adapter-mcp`: MCP stdio proxy.

# Runtime contract

`Runtime` is the MVP control-plane facade for one tool session. It composes four checks:

1. the policy must validate;
2. the tool manifest must validate;
3. the request must be declared by the manifest and match the policy;
4. the manifest request budget must not be exhausted.

Every evaluated request is appended to the session's JSONL-compatible audit log. A future WASM/WASI backend will consume the approved capability set after this control-plane decision; the current runtime does not execute native commands.

## Example

```bash
moon run src/cmd/agent-sandbox -- runtime-demo
```

The demo creates a reader manifest with a one-request budget, authorizes one workspace read, and prints the resulting audit event. A second request is denied by the budget even if the path would otherwise match.

## Stable invariants

- Invalid policy or manifest cannot create a runtime.
- An undeclared capability is denied before policy matching.
- A request budget is monotonic for the session.
- Audit events preserve evaluation order.
- The runtime never grants a capability based on a natural-language description.

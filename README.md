# AistyMCP

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Deny-by-default, per-tool permission control for Model Context Protocol servers.**

A typical MCP deployment is all-or-nothing: connect to the Jira server and the
agent can do everything the Jira server exposes. AistyMCP lets you switch tools
on one at a time, so a permission set can enable "create a ticket" while leaving
"delete a ticket" switched off.

## Status

Alpha. The permission model and its enforcement path are implemented and tested;
the API may still change. See [Scope](#scope) for what this does not do.

## Scope

AistyMCP is an **authorization library**, not an MCP server. It does not
implement the MCP wire protocol, open a transport, or speak JSON-RPC. It decides
whether a given permission set may call a given tool, and builds the per-user
tool list that a server or gateway then exposes.

You wire it into an MCP server you already run (one built on the official
`mcp` SDK, or your own gateway). The integration point is one call per tool
invocation:

```
MCP client -> your MCP server -> AistyMCP.authorize() -> your tool implementation
```

There are no runtime dependencies.

## Install

```bash
pip install -e ".[dev]"
```

## Quick start

```python
from aistymcp import (
    AccessControlMiddleware,
    MCPServer,
    Permission,
    PermissionDenied,
    PermissionModel,
    PermissionSet,
    ToolRegistry,
    UserContext,
)

pm = PermissionModel()
tr = ToolRegistry()
ac = AccessControlMiddleware(pm, tr)
server = MCPServer(pm, tr, ac)

# 1. Register the tools your deployment offers. Registering grants nothing.
server.expose_tool(
    tool_name="jira_create_ticket",
    func=lambda summary: "created: " + summary,
    description="Create a Jira ticket",
    access_type="write",
    reverses_tool="jira_delete_ticket",
)
server.expose_tool(
    tool_name="jira_delete_ticket",
    func=lambda ticket_id: "deleted: " + ticket_id,
    description="Delete a Jira ticket",
    access_type="write",
    is_destructive=True,
)

# 2. Define a permission set. Only what is listed here is callable.
pm.register_permission_set(PermissionSet(
    name="analyst",
    permissions=[Permission(tool_name="jira_create_ticket")],
    description="May open tickets, may not delete them",
))

# 3. Bind a user to it.
alice = UserContext(user_id="alice", perm_set_name="analyst")

# 4. Build her composite server: only the tools she may call.
tools = server.create_composite_server(alice)
print(sorted(tools))                      # ['jira_create_ticket']
print(tools["jira_create_ticket"]("Bug")) # 'created: Bug'

# 5. Anything else is refused, loudly.
try:
    server.call_tool(alice, "jira_delete_ticket", "ABC-1")
except PermissionDenied as exc:
    print(exc)
```

## How enforcement works

`PermissionModel.has_permission` is the single authoritative decision point.
Everything else delegates to it, so listing and enforcement cannot disagree.

There are two ways to enforce, and both check on every call:

- `middleware.call(perm_set, tool_name, *args, **kwargs)` authorizes and then
  invokes the tool.
- `middleware.bind_tool(perm_set, tool_name)` returns a `ToolWrapper` that
  re-checks permission each time it is invoked. Composite servers are built from
  these, so a cached composite server cannot keep granting a revoked tool.

`ToolWrapper` objects constructed directly, rather than through `bind_tool`, are
unbound and perform no check. Check `wrapper.is_bound` if it matters. Prefer
`bind_tool` so enforcement is never left to the call site.

## Permission sets

A permission set is a named list of grants. Entries may be `Permission` objects
or bare tool-name strings:

```python
PermissionSet(
    name="analyst",
    permissions=[
        Permission(tool_name="jira_create_ticket"),
        "search_docs",
    ],
    description="Analyst role",
)
```

`"*"` matches every **registered** tool. It cannot grant a tool the registry
does not hold:

```python
PermissionSet(name="admin", permissions=["*"], description="Everything")
```

`build_default_permission_sets()` returns two starting points, `no-access` and
`admin`. They are examples; nothing is applied automatically.

## Time-limited grants

A permission can carry a time window. Boundaries accept `datetime` objects or
ISO 8601 strings, so permission sets load from JSON or YAML without
pre-processing.

```python
from datetime import datetime, timedelta

Permission(
    tool_name="delete_doc",
    constraints={"time_window": {
        "start": datetime.now().isoformat(),
        "end": (datetime.now() + timedelta(days=30)).isoformat(),
    }},
)
```

An expired window denies the call and removes the tool from
`get_allowed_tools`. A malformed or half-specified window fails closed.

`max_calls` is accepted in a constraints dict but is **not** enforced here; call
counting belongs to your usage-tracking layer.

## Reversible actions

A tool can declare the tool that undoes it:

```python
server.expose_tool(
    tool_name="cloud_spin_up",
    func=spin_up,
    reverses_tool="cloud_spin_down",
)
```

The relationship is **directional** and, by default, **metadata only**. Saying
that `cloud_spin_down` undoes `cloud_spin_up` does not grant either tool. This
is deliberate: it is what lets you enable "create ticket" while keeping "delete
ticket" off, even though deleting undoes creating.

If you do want a grant to carry its undo, opt in per permission set:

```python
PermissionSet(
    name="operator",
    permissions=[Permission(tool_name="cloud_spin_up")],
    description="May start instances, and stop what they started",
    grant_reverse=True,   # also grants cloud_spin_down
)
```

`grant_reverse` follows the declared direction only. Granting `cloud_spin_down`
never implies `cloud_spin_up`.

Use `pm.get_undo_tool(name)` to look up an undo tool, for example to show an
operator which actions in a permission set have no way back.

## What it guarantees

| Guarantee | How it is enforced |
|-----------|--------------------|
| Deny-by-default | `has_permission` returns False unless a grant matches |
| No silent failures | A denied call raises `PermissionDenied` |
| Listing matches enforcement | `get_allowed_tools` is derived from `has_permission` |
| Composite isolation | A user's tool map contains only permitted tools |
| Revocation takes effect | Bound wrappers re-check on every call |
| Constraints fail closed | An unreadable time window denies |

## What it does not do yet

Worth knowing before you deploy it:

- **No audit log.** Decisions are not recorded. If you need an authorization
  trail, wrap `AccessControlMiddleware.authorize`.
- **No identity provider integration.** A `UserContext` holds one permission set
  name plus optional roles; mapping OIDC or SAML claims onto permission sets is
  yours to write.
- **No persistence.** Permission sets live in memory and are rebuilt at startup.
- **No argument-level authorization.** Permissions cover whole tools, not
  specific arguments. "May comment on project ABC only" is not expressible yet;
  `Permission.constraints` is the intended home for it.
- **`max_calls` is not enforced**, as noted above.
- **The policy engine is early.** `PolicyEngine` offers RBAC, resource, and
  conditional policies, but the middleware does not consult it; call it yourself.

## Where this sits next to other tools

If you already run a dedicated authorization service such as OpenFGA or SpiceDB,
keep it. Those solve relationship-based authorization at scale, which this does
not attempt. AistyMCP is the enforcement point on the MCP side: the thing that
turns a decision into a per-user tool list an MCP client actually sees. The two
compose, with your policy store answering `has_permission`.

## Project layout

```
aistymcp/
  permission_model.py   Permission evaluation. The authoritative decision point.
  access_control.py     Middleware that authorizes and invokes tools.
  tool_registry.py      Tool registration and the ToolWrapper.
  mcp_server.py         Composite server construction and caching.
  user_context.py       Identity to permission set binding.
  policy_engine.py      RBAC, resource, and conditional policies.
  utils/                Shared types and validation.
tests/                  92 tests
```

## Tests

```bash
pytest -v
```

92 tests cover the permission model, tool registry, access control middleware,
composite server construction and caching, time-window constraints, wildcards,
reversible-action semantics, user context, and the policy engine. CI also
imports every module on Python 3.10 through 3.13, so a module the tests do not
otherwise reach cannot silently break.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md). Please do not open a
public issue for a security report.

## License

MIT. See [LICENSE](LICENSE).

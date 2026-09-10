# Security Policy

## Supported versions

AistyMCP is alpha software. Only the `main` branch receives fixes.

## Reporting a vulnerability

Please report vulnerabilities privately, not through a public issue.

Use GitHub's private reporting on this repository:
[Report a vulnerability](https://github.com/AistyAI/AistyMCP/security/advisories/new).

Include the affected version or commit, what an attacker gains, and the steps to
reproduce it. We aim to acknowledge a report within five working days.

## Scope

This library makes authorization decisions. Findings of the following kinds are
in scope and useful:

- A path where a tool executes without a matching grant.
- A disagreement between `get_allowed_tools` and `has_permission`, or a
  composite server exposing a tool the model would deny.
- A constraint that fails open rather than closed.
- A tool name or permission entry that evades matching.

Out of scope: how a deploying application authenticates users, stores its
permission sets, or exposes them over a network. AistyMCP does not authenticate
anyone and does not open a transport.

## Known limitations

These are documented gaps rather than vulnerabilities. See "What it does not do
yet" in the README:

- No audit logging of authorization decisions.
- `max_calls` constraints are accepted but not enforced.
- Permissions are tool-level; argument-level authorization is not supported.
- `ToolWrapper` instances built directly, rather than through
  `AccessControlMiddleware.bind_tool`, do not check permission when called.

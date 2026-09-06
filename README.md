# Secure-MCP

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python Version](https://img.shields.io/pypi/pyversions/secure-mcp.svg)](https://pypi.org/project/secure-mcp/)
[![PyPI Version](https://img.shields.io/pypi/v/secure-mcp.svg)](https://pypi.org/project/secure-mcp/)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/your-repo/secure-mcp/actions)

**Fine-grained permission control for Model Context Protocol (MCP) servers with reversible action support.**

SecureMCP is a Python framework that enables companies to define explicit permission sets for AI agents, following a **deny-by-default** security model. Instead of giving users access to all tools, only explicitly permitted tools are available - preventing accidental or unauthorized tool usage.

## Problem Solved

Traditional MCP deployments grant users access to all tools on a server. If credentials are compromised or an agent is manipulated, the attacker has "god mode" access to everything.

SecureMCP solves this by:
- **Deny-by-default**: No tool executes unless explicitly permitted
- **Composite MCP servers**: Each user gets a virtual server with only their permitted tools
- **Tool-level granularity**: Permissions at individual function level, not server-level
- **No silent failures**: Permission denied always raises an exception
- **Reversible actions**: Every tool can point to its reverse action (e.g., Jira comment add/remove, instance spin-up/spin-down), ensuring actions can be instantly undone

## Installation

This is a local development package - use the source directly from the repository.

```bash
# Install dependencies
pip install -e .

# Or run directly
python -m src.your_module
```

## Quick Start

```python
from src.tool_registry import ToolRegistry, ToolMetadata
from src.permission_model import PermissionModel, PermissionSet, Permission
from src.access_control import AccessControlMiddleware
from src.user_context import UserContext
from src.mcp_server import MCPServer

# 1. Register tools with metadata and reversible actions
tr = ToolRegistry()
tr.register(ToolMetadata(
    tool_name="jira_add_comment",
    description="Add comment to Jira ticket",
    function=lambda ticket_id, body: f"Comment added to {ticket_id}",
    required_permissions={"write:jira"},
    is_destructive=False,
    reverses_tool="jira_remove_comment",  # <-- reversible action
))

tr.register(ToolMetadata(
    tool_name="jira_remove_comment",
    description="Remove comment from Jira ticket",
    function=lambda comment_id: f"Comment {comment_id} removed",
    required_permissions={"write:jira"},
    is_destructive=False,
    reverses_tool="jira_add_comment",  # <-- reversible action
))

# 2. Define permission sets
pm = PermissionModel()
pm.register_permission_set(PermissionSet(
    name="analyst",
    permissions=[
        Permission(tool_name="jira_add_comment", function="add", access_type="write"),
        Permission(tool_name="jira_remove_comment", function="remove", access_type="write"),
    ],
    description="Analyst role - Jira access"
))

# 3. Set up access control
mw = AccessControlMiddleware(pm, tr)

# 4. Create user contexts
alice = UserContext(user_id="alice", perm_set_name="analyst")

# 5. Generate composite MCP server
alice_server = MCPServer.create_composite_server(alice)
# Alice can only call jira_add_comment and jira_remove_comment
```

## Core Security Guarantees

| Guarantee | Description |
|-----------|-------------|
| **Deny-by-default** | If a tool is not explicitly in the user's permission set, it cannot be called |
| **Composite server isolation** | Users cannot introspect or access tools outside their permission set |
| **No silent failures** | Permission denied always raises `AccessControlError` |
| **Tool-level granularity** | Permissions at individual function level with read/write/destructive flags |
| **Time-based constraints** | Permissions can have time windows that automatically expire |
| **Reversible actions** | Every tool can declare a reverses_tool - permission for one implies access to its reverse |

## API Overview

### Key Classes

| Class | Key Method | Purpose |
|-------|-----------|---------|
| `PermissionModel` | `has_permission()` | Check if user can call a tool |
| `PermissionModel` | `get_allowed_tools()` | List tools user can access |
| `ToolRegistry` | `register()` | Register a tool with metadata |
| `ToolRegistry` | `list_tools_with_permissions()` | List tools and their required permissions |
| `AccessControlMiddleware` | `check_and_wrap()` | Decorator for permission-checked calls |
| `AccessControlMiddleware` | `composite_server_tools()` | Generate user-specific composite server |
| `UserContext` | `has_tool_access()` | Check user's tool access |
| `UserContext` | `get_allowed_tools()` | Get allowed tools for user |
| `MCPServer` | `create_composite_server()` | Generate user-specific server |
| `MCPServer` | `expose_tool()` | Register and wrap a tool with access control |
| `Permission` | - | Single tool permission right |
| `PermissionSet` | - | Named collection of permissions |
| `ToolMetadata` | - | Description of an MCP tool |

### Tool Metadata - New `reverses_tool` Field

```python
from src.utils.types import ToolMetadata

# Tool that reverses another action
meta = ToolMetadata(
    tool_name="jira_add_comment",
    description="Add comment to Jira ticket",
    function=lambda: None,
    reverses_tool="jira_remove_comment",  # Optional: name of reversing tool
)

# Tool without a reversible action
meta = ToolMetadata(
    tool_name="search",
    description="Search the knowledge base",
    function=lambda query: f"Results: {query}",
    # reverses_tool not specified = no reversible relationship
)
```

## Permission Sets

Define named permission sets for different roles:

```python
pm.register_permission_set(PermissionSet(
    name="analyst",
    permissions=[
        Permission(tool_name="search", function="read", access_type="read"),
    ],
    description="Analyst role - read only"
))

pm.register_permission_set(PermissionSet(
    name="admin",
    permissions=["*"],  # Wildcard for all tools
    description="Admin role - full access"
))
```

## Time-Based Constraints

Add constraints to permissions for time-limited access:

```python
from datetime import datetime, timedelta

pm.register_permission_set(PermissionSet(
    name="temp_delete",
    permissions=[
        Permission(
            tool_name="delete_doc",
            constraints={"time_window": {
                "start": datetime.now().isoformat(),
                "end": (datetime.now() + timedelta(days=30)).isoformat()
            }}
        )
    ],
    description="Delete docs for 30 days only"
))
```

## Reversible Actions

The key new feature - every tool can declare a `reverses_tool` relationship:

```python
# jira_add_comment reverses jira_remove_comment
tr.register(ToolMetadata(
    tool_name="jira_add_comment",
    description="Add comment to Jira ticket",
    function=lambda: None,
    reverses_tool="jira_remove_comment",
))

# jira_remove_comment reverses jira_add_comment  
tr.register(ToolMetadata(
    tool_name="jira_remove_comment",
    description="Remove comment from Jira ticket",
    function=lambda: None,
    reverses_tool="jira_add_comment",
))

# Permission checking:
# - User with permission for jira_add_comment also gets jira_remove_comment
# - User without permission for the reversible tool is denied
# - This ensures every action can be instantly undone
```

## Testing

Run the test suite:

```bash
pytest tests/ -v
```

All 51 tests cover:
- Permission model deny-by-default behavior
- Tool registry management  
- Access control middleware enforcement
- User context integration
- Policy engine evaluation
- Type validation
- Tool wrapper functionality
- **Reversible action permission checking** (new)

## Comparison to Other Solutions

| Feature | SecureMCP | Other MCP Permission Tools |
|---------|-----------|---------------------------|
| **Deny-by-default** | ✅ Yes (core) | ⚠️ Varies - many allow-all by default |
| **Composite server isolation** | ✅ Yes (core) | ⚠️ Limited - often full introspection |
| **Tool-level granularity** | ✅ Yes (per function) | ⚠️ Often server-level only |
| **Reversible actions** | ✅ **Yes (new)** | ❌ No - most don't track reversibility |
| **No silent failures** | ✅ Yes (raises exception) | ⚠️ Varies - some swallow errors |
| **Time-based constraints** | ✅ Yes | ⚠️ Limited support |
| **Relationship-based (ReBAC)** | ✅ Yes (policy engine) | ⚠️ Basic or none |
| **Open source** | ✅ MIT licensed | ⚠️ Varies - some proprietary |
| **Python native** | ✅ Yes | ⚠️ Some require other runtimes |
| **MCP protocol native** | ✅ Yes | ⚠️ Varies |

### Why SecureMCP Stands Out

1. **Reversible action tracking** - Unique feature ensuring every action can be instantly undone (Jira comment add/remove, instance spin-up/spin-down, etc.)

2. **Deny-by-default with composite isolation** - Users only see their permitted tools; no introspection of other tools possible

3. **Fine-grained function-level permissions** - Not just tool-level; can restrict `read` vs `write` vs `execute` at the function level

4. **Full ReBAC support** - Relationship-based access control alongside traditional RBAC

5. **No silent failures** - Every permission denial explicitly raises `AccessControlError`

6. **MIT licensed, Python native** - Easy to integrate, no vendor lock-in

## Deployment

**Who uses this:** Companies/Organizations deploying MCP infrastructure.

**How it works:**
1. The company integrates SecureMCP into their MCP server/gateway
2. They register their tools with metadata and permission requirements
3. They define permission sets for different roles/departments
4. They assign permission sets to users (via their identity management system)
5. Each user receives a composite MCP server with only their permitted tools (including reversible partners)
6. Users connect to the MCP gateway - they don't run the framework themselves

**Typical flow:**
```
Company MCP Gateway --> Permission Check --> User's Composite MCP Server --> Only Allowed Tools (with reversible partners)
```

## Project Structure

```
secureMCP/
├ src/
│   ├── utils/                    # Reusable components
│   ├── permission_model.py      # Core permission model (170 lines)
│   ├── tool_registry.py         # Tool registration + wrapper (161 lines)
│   ├── access_control.py        # Security middleware (161 lines)
│   ├── user_context.py          # User/company context (144 lines)
│   ├── mcp_server.py            # MCP server wrapper (213 lines)
│   └── policy_engine.py         # RBAC/ReBAC policy evaluation (372 lines)
├ tests/                         # 51 comprehensive tests (all passing)
└── report/                      # Design reports (not included in repo)
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Real-World Use Cases

### Jira Ticket Management
Every comment added to a Jira ticket can be instantly removed:

```python
tr.register(ToolMetadata(
    tool_name="jira_add_comment",
    description="Add comment to Jira ticket",
    function=lambda ticket_id, body: f"Comment added",
    required_permissions={"write:jira"},
    reverses_tool="jira_remove_comment",
))

tr.register(ToolMetadata(
    tool_name="jira_remove_comment",
    description="Remove comment from Jira ticket",
    function=lambda comment_id: f"Comment removed",
    required_permissions={"write:jira"},
    reverses_tool="jira_add_comment",
))

# Analyst can both add and remove comments
analyst = UserContext(user_id="analyst1", perm_set_name="analyst")
analyst_server = MCPServer.create_composite_server(analyst)
# {"jira_add_comment": ..., "jira_remove_comment": ...}
```

### Cloud Instance Lifecycle
Spin up and spin down actions form a reversible pair:

```python
tr.register(ToolMetadata(
    tool_name="cloud_spin_up",
    description="Spin up a cloud instance",
    function=lambda config: f"Instance running",
    required_permissions={"cloud:manage"},
    is_destructive=True,
    reverses_tool="cloud_spin_down",
))

tr.register(ToolMetadata(
    tool_name="cloud_spin_down",
    description="Spin down a cloud instance",
    function=lambda instance_id: f"Instance stopped",
    required_permissions={"cloud:manage"},
    is_destructive=True,
    reverses_tool="cloud_spin_up",
))

# Operator can manage instances but must have permission for both directions
operator = UserContext(user_id="op1", perm_set_name="operator")
```

### Build & Deploy Pipeline
Compile and rollback form a reversible pair:

```python
tr.register(ToolMetadata(
    tool_name="build_image",
    description="Build Docker image",
    function=lambda source: f"Image built",
    required_permissions={"build:image"},
    reverses_tool="rollback_image",
))

tr.register(ToolMetadata(
    tool_name="rollback_image",
    description="Rollback to previous image",
    function=lambda version: f"Rolled back to {version}",
    required_permissions={"build:image"},
    reverses_tool="build_image",
))
```

### Permission Enforcement
The reversible relationship is enforced at the permission level:

```python
# If user has permission to add comments but not remove:
perms = [Permission(tool_name="jira_add_comment", function="add", access_type="write")]
# User IS denied access to jira_add_comment because jira_remove_comment lacks permission
# This ensures every action can be safely undone by an authorized operator
```

## Security Contact

If you find any security issues, please contact the project maintainers directly.

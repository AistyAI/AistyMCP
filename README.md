# SecureMCP

**Fine-grained permission control for Model Context Protocol (MCP) servers.**

SecureMCP is a Python framework that enables companies to define explicit permission sets for AI agents, following a **deny-by-default** security model. Instead of giving users access to all tools, only explicitly permitted tools are available - preventing accidental or unauthorized tool usage.

## Problem Solved

Traditional MCP deployments grant users access to all tools on a server. If credentials are compromised or an agent is manipulated, the attacker has "god mode" access to everything.

SecureMCP solves this by:
- **Deny-by-default**: No tool executes unless explicitly permitted
- **Composite MCP servers**: Each user gets a virtual server with only their permitted tools
- **Tool-level granularity**: Permissions at individual function level, not server-level
- **No silent failures**: Permission denied always raises an exception

## Installation

```bash
pip install secure-mcp
```

Or use the source directly from the repository.

## Quick Start

```python
from secureMCP import (
    PermissionModel, ToolRegistry, AccessControlMiddleware,
    UserContext, MCPServer, ToolMetadata, Permission
)

# 1. Register tools with metadata
tr = ToolRegistry()
tr.register(ToolMetadata(
    tool_name="search",
    description="Search the knowledge base",
    function=lambda query: f"Results: {query}",
    required_permissions={"read:kb"},
    is_destructive=False,
))

tr.register(ToolMetadata(
    tool_name="create_doc",
    description="Create a new document",
    function=lambda title, content: f"Created: {title}",
    required_permissions={"write:docs"},
    is_destructive=True,
))

# 2. Define permission sets
pm = PermissionModel()
pm.register_permission_set(PermissionSet(
    name="analyst",
    permissions=[Permission(tool_name="search", function="read", access_type="read")],
    description="Read-only access"
))

pm.register_permission_set(PermissionSet(
    name="admin",
    permissions=[
        Permission(tool_name="search", function="read", access_type="read"),
        Permission(tool_name="create_doc", function="execute", access_type="write"),
    ],
    description="Full access"
))

# 3. Set up access control
mw = AccessControlMiddleware(pm, tr)

# 4. Create user contexts (assigned by company/infrastructure)
alice = UserContext(user_id="alice", perm_set_name="analyst")
bob = UserContext(user_id="bob", perm_set_name="admin")

# 5. Generate composite MCP servers per user
# Alice (analyst) ONLY gets search - cannot access create_doc!
alice_server = MCPServer.create_composite_server(alice)
# Returns: {"search": <metadata>}

# Bob (admin) gets both tools
bob_server = MCPServer.create_composite_server(bob)
# Returns: {"search": ..., "create_doc": ...}
```

## Core Security Guarantees

| Guarantee | Description |
|-----------|-------------|
| **Deny-by-default** | If a tool is not explicitly in the user's permission set, it cannot be called |
| **Composite server isolation** | Users cannot introspect or access tools outside their permission set |
| **No silent failures** | Permission denied always raises `AccessControlError` |
| **Tool-level granularity** | Permissions at individual function level with read/write/destructive flags |
| **Time-based constraints** | Permissions can have time windows that automatically expire |

## API Overview

### Key Classes

| Class | Key Method | Purpose |
|-------|-----------|---------|
| `PermissionModel` | `has_permission()` | Check if user can call a tool |
| `PermissionModel` | `get_allowed_tools()` | List tools user can access |
| `ToolRegistry` | `register()` | Register a tool with metadata |
| `AccessControlMiddleware` | `check_and_wrap()` | Decorator for permission-checked calls |
| `UserContext` | `has_tool_access()` | Check user's tool access |
| `MCPServer` | `create_composite_server()` | Generate user-specific server |
| `Permission` | - | Single tool permission right |
| `PermissionSet` | - | Named collection of permissions |
| `ToolMetadata` | - | Description of an MCP tool |

### Permission Sets

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

### Time-Based Constraints

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

## Testing

Run the test suite:

```bash
pytest tests/ -v
```

All 45 tests cover:
- Permission model deny-by-default behavior
- Tool registry management  
- Access control middleware enforcement
- User context integration
- Policy engine evaluation
- Type validation
- Tool wrapper functionality

## Deployment

**Who uses this:** Companies/Organizations deploying MCP infrastructure.

**How it works:**
1. The company integrates SecureMCP into their MCP server/gateway
2. They register their tools with metadata and permission requirements
3. They define permission sets for different roles/departments
4. They assign permission sets to users (via their identity management system)
5. Each user receives a composite MCP server with only their permitted tools
6. Users connect to the MCP gateway - they don't run the framework themselves

**Typical flow:**
```
Company MCP Gateway --> Permission Check --> User's Composite MCP Server --> Only Allowed Tools
```

## Project Structure

```
secureMCP/
├── src/
│   ├── utils/                    # Reusable components
│   ├── permission_model.py      # Core permission model (170 lines)
│   ├── tool_registry.py         # Tool registration + wrapper (161 lines)
│   ├── access_control.py        # Security middleware (161 lines)
│   ├── user_context.py          # User/company context (144 lines)
│   ├── mcp_server.py            # MCP server wrapper (213 lines)
│   └── policy_engine.py         # RBAC/ReBAC policy evaluation (372 lines)
├── tests/                        # 45 comprehensive tests (all passing)
└── report/                       # Design reports (not included in repo)
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security Contact

If you find any security issues, please contact the project maintainers directly.
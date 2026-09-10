"""AistyMCP: fine-grained, deny-by-default permissions for MCP tools.

Public API:

    from aistymcp import (
        PermissionModel, PermissionSet, Permission,
        ToolRegistry, ToolMetadata, ToolWrapper,
        AccessControlMiddleware, AccessControlError, PermissionDenied,
        UserContext, CompanyContext,
        MCPServer, CompositeMCPServers,
    )
"""

from .access_control import (
    AccessControlError,
    AccessControlMiddleware,
    PermissionDenied,
    ToolNotRegistered,
)
from .mcp_server import CompositeMCPServers, MCPServer
from .permission_model import PermissionModel
from .policy_engine import ConditionalPolicy, Policy, PolicyEngine, RBACPolicy
from .tool_registry import ToolRegistry, ToolWrapper
from .user_context import CompanyContext, UserContext, build_default_permission_sets
from .utils.types import Permission, PermissionSet, ToolMetadata
from .utils.validation import validate_permission_set, validate_tool_name

__version__ = "0.1.0"

__all__ = [
    "AccessControlError",
    "AccessControlMiddleware",
    "CompanyContext",
    "CompositeMCPServers",
    "ConditionalPolicy",
    "MCPServer",
    "Permission",
    "PermissionDenied",
    "PermissionModel",
    "PermissionSet",
    "Policy",
    "PolicyEngine",
    "RBACPolicy",
    "ToolMetadata",
    "ToolNotRegistered",
    "ToolRegistry",
    "ToolWrapper",
    "UserContext",
    "build_default_permission_sets",
    "validate_permission_set",
    "validate_tool_name",
    "__version__",
]

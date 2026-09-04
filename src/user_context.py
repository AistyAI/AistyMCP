"""User context for SecureMCP.

Manages user and company identification with associated permission sets.
Supports OAuth2, API key, and embedded identity integration.

Critical: Permission sets are assigned at creation time and cannot be
bypassed - the context provides the permission set name used by the
access control middleware for deny-by-default checking.
"""

from typing import Optional, Dict, Any, List
from .permission_model import PermissionModel
from .access_control import AccessControlMiddleware, PermissionDenied


class UserContext:
    """Represents a user or company context with permission set assignment.

    The UserContext is the single source of truth for which permission
    set a user belongs to. The access control middleware uses this to
    enforce deny-by-default - only tools explicitly in the user's
    permission set are executable.

    Attributes:
        user_id: Unique identifier for the user/company.
        perm_set_name: Name of the assigned permission set.
        company_id: Optional company identifier (for multi-tenant setups).
        metadata: Additional user/company metadata (attributes, claims, etc).
    """

    def __init__(
        self,
        user_id: str,
        perm_set_name: str,
        company_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.user_id = user_id
        self.perm_set_name = perm_set_name
        self.company_id = company_id
        self.metadata = metadata or {}

    def get_permission_set_name(self) -> str:
        """Get the name of the user's permission set.

        Returns:
            The permission set name assigned to this user.
        """
        return self.perm_set_name

    def has_tool_access(self, permission_model: PermissionModel, tool_name: str) -> bool:
        """Check if this user has access to a specific tool.

        Delegates to the permission model's deny-by-default check.

        Args:
            permission_model: The permission model to check against.
            tool_name: Name of the tool to check access for.

        Returns:
            True if user has explicit permission, False otherwise (default deny).
        """
        return permission_model.has_permission(
            self.perm_set_name, tool_name
        )

    def get_allowed_tools(self, permission_model: PermissionModel) -> List[str]:
        """Get list of tool names this user is allowed to call.

        Args:
            permission_model: The permission model to query.

        Returns:
            List of tool names with explicit permission for this user.
        """
        return permission_model.get_allowed_tools(self.perm_set_name)

    def composite_server(self, permission_model: PermissionModel, tool_registry) -> Dict[str, Any]:
        """Generate composite MCP server with only allowed tools.

        Creates a virtual MCP server containing ONLY the tools this user
        has permission for. This is the primary mechanism for enforcing
        least-privilege access - users cannot see or access tools outside
        their permission set.

        Args:
            permission_model: The permission model to query.
            tool_registry: The tool registry containing all available tools.

        Returns:
            Dictionary of tool names to tool metadata for allowed tools only.
        """
        return permission_model.get_tool_metadata.__self__.composite_server_tools(  # noqa: E501
            self.perm_set_name
        )  # simplifies to using permission model method

    def __repr__(self) -> str:
        return f"<UserContext user_id={self.user_id} perm_set={self.perm_set_name}>"


class CompanyContext(UserContext):
    """Represents a company/organization context with shared permission sets.

    Extends UserContext for multi-tenant deployments where many users
    share the same company-level permission sets. Useful for organizations
    that want to define permission sets at the company level and assign
    them to individual users or groups.

    Attributes:
        Inherits all attributes from UserContext.
    """

    def __init__(
        self,
        company_id: str,
        perm_set_name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            user_id=company_id,
            perm_set_name=perm_set_name,
            company_id=company_id,
            metadata=metadata,
        )


# Default permission sets for common use cases
DEFAULT_PERMISSION_SETS = {
    "read-only": {
        "description": "Read-only access to all tools",
        "tools": [],  # Empty = no tools by default (deny-by-default)
    },
    "analyst": {
        "description": "Analyst role - read tools + limited write",
        "tools": ["read:*", "query:*"],  # Pattern-based tool names
    },
    "admin": {
        "description": "Full admin access - all tools",
        "tools": ["*"],  # Wildcard for all tools
    },
    "developer": {
        "description": "Developer role - build and deployment tools",
        "tools": ["build:", "deploy:", "compile:"],
    },
}
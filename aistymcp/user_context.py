"""User context for AistyMCP.

Binds a user or company identity to a permission set name. The context
is the input to every access control decision: the middleware reads the
permission set name from it and evaluates the call against that set.

The context carries identity only. It grants nothing on its own, so
constructing one for an unknown user yields no access.
"""

from typing import Any, Dict, List, Optional

from .permission_model import PermissionModel
from .utils.types import PermissionSet


class UserContext:
    """A user or company identity with an assigned permission set.

    Attributes:
        user_id: Unique identifier for the user.
        perm_set_name: Name of the assigned permission set.
        company_id: Optional company identifier for multi-tenant setups.
        metadata: Additional identity metadata (attributes, claims, etc).
        roles: Role names carried from the identity provider, used by the
            policy engine's RBAC policies.
        pm: Optional PermissionModel this context resolves against. The
            policy engine requires it; the middleware does not.
    """

    def __init__(
        self,
        user_id: str,
        perm_set_name: str,
        company_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        roles: Optional[List[str]] = None,
        permission_model: Optional[PermissionModel] = None,
    ):
        self.user_id = user_id
        self.perm_set_name = perm_set_name
        self.company_id = company_id
        self.metadata = metadata or {}
        self.roles = roles or []
        self.pm = permission_model

    def get_permission_set_name(self) -> str:
        """Get the name of the user's permission set.

        Returns:
            The permission set name assigned to this user.
        """
        return self.perm_set_name

    def has_tool_access(
        self, permission_model: PermissionModel, tool_name: str
    ) -> bool:
        """Check whether this user may call a specific tool.

        Args:
            permission_model: The permission model to check against.
            tool_name: Name of the tool to check.

        Returns:
            True if the permission set grants the tool, False otherwise.
        """
        return permission_model.has_permission(self.perm_set_name, tool_name)

    def get_allowed_tools(self, permission_model: PermissionModel) -> List[str]:
        """Get the tool names this user is allowed to call.

        Args:
            permission_model: The permission model to query.

        Returns:
            List of allowed tool names.
        """
        return permission_model.get_allowed_tools(self.perm_set_name)

    def composite_server(
        self,
        permission_model: PermissionModel,
        tool_registry: Any = None,
    ) -> Dict[str, Any]:
        """Build the tool map for this user's composite server.

        Contains only tools the user may call, so tools outside the
        permission set cannot be discovered through it.

        Args:
            permission_model: The permission model to query.
            tool_registry: Unused. Accepted for backwards compatibility;
                the permission model already holds registered metadata.

        Returns:
            Mapping of tool name to ToolMetadata for allowed tools.
        """
        return permission_model.composite_server_tools(self.perm_set_name)

    def __repr__(self) -> str:
        return "<UserContext user_id={} perm_set={}>".format(
            self.user_id, self.perm_set_name
        )


class CompanyContext(UserContext):
    """A company-level context sharing one permission set across users.

    Useful for multi-tenant deployments where permission sets are defined
    per organisation and inherited by its members.
    """

    def __init__(
        self,
        company_id: str,
        perm_set_name: str,
        metadata: Optional[Dict[str, Any]] = None,
        roles: Optional[List[str]] = None,
        permission_model: Optional[PermissionModel] = None,
    ):
        super().__init__(
            user_id=company_id,
            perm_set_name=perm_set_name,
            company_id=company_id,
            metadata=metadata,
            roles=roles,
            permission_model=permission_model,
        )


def build_default_permission_sets() -> Dict[str, PermissionSet]:
    """Build the permission sets shipped as starting points.

    These are examples, not defaults applied automatically. Register the
    ones you want with PermissionModel.register_permission_set.

    Returns:
        Mapping of permission set name to PermissionSet.

        "no-access" grants nothing and is the safe baseline for a new
        user. "admin" uses the "*" wildcard to grant every registered
        tool; grant it deliberately.
    """
    return {
        "no-access": PermissionSet(
            name="no-access",
            permissions=[],
            description="Grants nothing. Deny-by-default baseline.",
        ),
        "admin": PermissionSet(
            name="admin",
            permissions=["*"],
            description="Every registered tool. Grant deliberately.",
        ),
    }

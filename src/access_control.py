"""Access control middleware for SecureMCP.

Enforces deny-by-default permission checking for all MCP tool calls.
Every tool invocation must pass through this middleware to verify
the caller has explicit permission.

Critical security component - no tool executes without explicit permission.
"""

from typing import Dict, List, Optional, Any, Callable
from functools import wraps
from .permission_model import PermissionModel, PermissionSet
from .tool_registry import ToolRegistry, ToolMetadata


class AccessControlError(Exception):
    """Raised when access control check fails."""

    pass


class AccessControlMiddleware:
    """Middleware that enforces deny-by-default access control.

    This middleware wraps MCP tool calls and ensures that a tool can
    only execute if the caller has an explicit permission granting access.
    There is no silent fallback - if permission is not granted, an
    AccessControlError is raised.

    Usage:
        middleware = AccessControlMiddleware(permission_model, tool_registry)
        # Wrap tools when exposing them to users
    """

    def __init__(
        self,
        permission_model: PermissionModel,
        tool_registry: ToolRegistry,
    ):
        self.pm = permission_model
        self.tr = tool_registry

    def check_and_wrap(
        self,
        user_perm_set_name: str,
        tool_name: str,
        function: Optional[str] = None,
    ):
        """Decorator/checker for tool execution.

        Must be applied to any tool function exposed to a user.
        Checks if the user's permission set allows calling the tool,
        and raises AccessControlError if not (deny-by-default).

        Args:
            user_perm_set_name: Name of the user's permission set.
            tool_name: Name of the tool being called.
            function: Specific function within the tool (optional).

        Returns:
            Decorator function that wraps the tool call.
        """
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Deny-by-default check
                if not self.pm.has_permission(
                    user_perm_set_name, tool_name, function
                ):
                    raise AccessControlError(
                        f"Permission denied: user '{user_perm_set_name}' "
                        f"cannot call tool '{tool_name}'"
                    )
                # Check tool exists in registry
                if not self.tr.has_tool(tool_name):
                    raise AccessControlError(
                        f"Tool not registered: '{tool_name}'"
                    )
                # Execute the actual function
                return func(*args, **kwargs)
            return wrapper
        return decorator

    def wrap_tool_call(
        self,
        user_perm_set_name: str,
        tool_name: str,
        function: Optional[str] = None,
    ):
        """Create a wrapped version of a tool call with permission check.

        Args:
            user_perm_set_name: Name of the user's permission set.
            tool_name: Name of the tool being called.
            function: Specific function within the tool (optional).

        Returns:
            Result of the tool function if permission granted,
            raises AccessControlError otherwise.
        """
        # Deny-by-default check first
        if not self.pm.has_permission(user_perm_set_name, tool_name, function):
            raise AccessControlError(
                f"Permission denied: user '{user_perm_set_name}' "
                f"cannot call tool '{tool_name}'"
            )

        # Execute the tool if permitted
        meta = self.tr.get(tool_name)
        if meta is None:
            raise AccessControlError(
                f"Tool not registered: '{tool_name}'"
            )

        # In a full implementation, would call the actual function here
        # For now, return success indicator
        return True

    def get_user_allowed_tools(self, user_perm_set_name: str) -> List[str]:
        """Get list of tool names a user is allowed to call.

        Args:
            user_perm_set_name: Name of the user's permission set.

        Returns:
            List of tool names the user has explicit permission to call.
            Empty list if permission set not found (deny-by-default).
        """
        return self.pm.get_allowed_tools(user_perm_set_name)

    def composite_server_tools(
        self, user_perm_set_name: str
    ) -> Dict[str, Any]:
        """Generate a composite MCP server with only allowed tools.

        This is the core security mechanism - creates a virtual MCP server
        containing ONLY the tools the user has permission for. No introspection
        of other tools is possible.

        Args:
            user_perm_set_name: Name of the user's permission set.

        Returns:
            Dictionary mapping tool names to wrapped function references.
            Only contains tools user has permission to access.
        """
        allowed = self.pm.get_allowed_tools(user_perm_set_name)
        composite = {}

        for tool_name in allowed:
            if self.tr.has_tool(tool_name):
                composite[tool_name] = self.tr.get(tool_name)
        return composite


class PermissionDenied(AccessControlError):
    """Specific exception for denied permissions.

    Subclass of AccessControlError for targeted exception handling.
    """

    pass
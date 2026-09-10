"""Access control middleware for AistyMCP.

Enforces deny-by-default permission checking for MCP tool calls. Every
tool invocation routed through this middleware verifies that the caller
has explicit permission before the underlying function runs.

Permission decisions are delegated to PermissionModel.has_permission,
which is the single authoritative enforcement point.
"""

from functools import wraps
from typing import Any, Callable, Dict, List, Optional

from .permission_model import PermissionModel
from .tool_registry import ToolRegistry, ToolWrapper


class AccessControlError(Exception):
    """Raised when an access control check fails."""


class PermissionDenied(AccessControlError):
    """Raised specifically when a permission check denies a tool call."""


class ToolNotRegistered(AccessControlError):
    """Raised when a call targets a tool that is not in the registry."""


class AccessControlMiddleware:
    """Enforces deny-by-default access control on tool calls.

    A tool executes only when the caller's permission set grants it. There
    is no silent fallback: a denied call raises PermissionDenied.

    Usage:
        middleware = AccessControlMiddleware(permission_model, tool_registry)
        result = middleware.call("analyst", "jira_add_comment", ticket_id="ABC-1")
    """

    def __init__(
        self,
        permission_model: PermissionModel,
        tool_registry: ToolRegistry,
    ):
        self.pm = permission_model
        self.tr = tool_registry

    def authorize(
        self,
        user_perm_set_name: str,
        tool_name: str,
        function: Optional[str] = None,
    ) -> None:
        """Authorize a tool call, raising if it is not permitted.

        Args:
            user_perm_set_name: Name of the user's permission set.
            tool_name: Name of the tool being called.
            function: Specific function within the tool (optional).

        Raises:
            PermissionDenied: If the permission set does not grant the tool.
            ToolNotRegistered: If the tool is not in the registry.
        """
        if not self.pm.has_permission(user_perm_set_name, tool_name, function):
            raise PermissionDenied(
                "Permission denied: permission set '{}' cannot call tool "
                "'{}'".format(user_perm_set_name, tool_name)
            )

        if not self.tr.has_tool(tool_name):
            raise ToolNotRegistered("Tool not registered: '{}'".format(tool_name))

    def check_and_wrap(
        self,
        user_perm_set_name: str,
        tool_name: str,
        function: Optional[str] = None,
    ) -> Callable:
        """Decorate a callable so each invocation is permission checked.

        The check runs on every call rather than at decoration time, so
        permission set changes take effect immediately.

        Args:
            user_perm_set_name: Name of the user's permission set.
            tool_name: Name of the tool being called.
            function: Specific function within the tool (optional).

        Returns:
            A decorator that wraps the target callable.
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                self.authorize(user_perm_set_name, tool_name, function)
                return func(*args, **kwargs)
            return wrapper
        return decorator

    def call(
        self,
        user_perm_set_name: str,
        tool_name: str,
        *args: Any,
        function: Optional[str] = None,
        **kwargs: Any,
    ) -> Any:
        """Authorize and execute a registered tool.

        Args:
            user_perm_set_name: Name of the user's permission set.
            tool_name: Name of the tool to call.
            *args: Positional arguments forwarded to the tool function.
            function: Specific function within the tool (optional).
            **kwargs: Keyword arguments forwarded to the tool function.

        Returns:
            The tool function's return value.

        Raises:
            PermissionDenied: If the call is not permitted.
            ToolNotRegistered: If the tool is not in the registry.
        """
        self.authorize(user_perm_set_name, tool_name, function)

        meta = self.tr.get(tool_name)
        if meta is None or not callable(meta.function):
            raise ToolNotRegistered(
                "Tool '{}' has no callable implementation".format(tool_name)
            )

        return meta.function(*args, **kwargs)

    def bind_tool(
        self,
        user_perm_set_name: str,
        tool_name: str,
        function: Optional[str] = None,
    ) -> ToolWrapper:
        """Bind a registered tool to a permission set.

        The returned wrapper checks permission on every invocation, so it
        is safe to hand to caller code directly.

        Args:
            user_perm_set_name: Name of the user's permission set.
            tool_name: Name of the tool to bind.
            function: Specific function within the tool (optional).

        Returns:
            A ToolWrapper that enforces access control when called.

        Raises:
            ToolNotRegistered: If the tool is not in the registry.
        """
        meta = self.tr.get(tool_name)
        if meta is None:
            raise ToolNotRegistered("Tool not registered: '{}'".format(tool_name))

        return ToolWrapper(
            tool_name=tool_name,
            func=meta.function,
            required_permissions=meta.required_permissions,
            metadata=meta,
            access_control=self,
            perm_set_name=user_perm_set_name,
            function=function,
        )

    def get_user_allowed_tools(self, user_perm_set_name: str) -> List[str]:
        """Get the tool names a permission set is allowed to call.

        Args:
            user_perm_set_name: Name of the user's permission set.

        Returns:
            List of allowed tool names. Empty if the permission set is
            unknown (deny-by-default).
        """
        return self.pm.get_allowed_tools(user_perm_set_name)

    def composite_server_tools(
        self, user_perm_set_name: str
    ) -> Dict[str, ToolWrapper]:
        """Build a composite tool map containing only permitted tools.

        Each entry is a bound, permission-checked wrapper. Tools outside
        the permission set are absent, so they cannot be discovered or
        called through this map.

        Args:
            user_perm_set_name: Name of the user's permission set.

        Returns:
            Mapping of tool name to bound ToolWrapper.
        """
        composite: Dict[str, ToolWrapper] = {}
        for tool_name in self.pm.get_allowed_tools(user_perm_set_name):
            if self.tr.has_tool(tool_name):
                composite[tool_name] = self.bind_tool(user_perm_set_name, tool_name)
        return composite

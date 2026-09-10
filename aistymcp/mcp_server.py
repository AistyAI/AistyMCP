"""Composite server construction for AistyMCP.

Takes registered tools and produces, for each user, a tool map holding
only the tools that user may call. Every entry is a permission-checked
wrapper, so enforcement does not depend on the caller remembering to ask.

This module builds the tool surface. It does not implement the MCP wire
protocol; wire it into your own MCP server or gateway. See the README
for where this sits in a deployment.
"""

from typing import Any, Callable, Dict, List, Optional, Set

from .access_control import AccessControlMiddleware
from .permission_model import PermissionModel
from .tool_registry import ToolRegistry, ToolWrapper
from .user_context import UserContext
from .utils.types import ToolMetadata


class MCPServer:
    """Registers tools and builds per-user composite tool maps.

    Attributes:
        pm: Permission model holding permission sets and tool metadata.
        tr: Registry of all available tools.
        ac: Middleware enforcing permission checks.
    """

    def __init__(
        self,
        permission_model: PermissionModel,
        tool_registry: ToolRegistry,
        access_control: AccessControlMiddleware,
    ):
        self.pm = permission_model
        self.tr = tool_registry
        self.ac = access_control

    def expose_tool(
        self,
        tool_name: str,
        func: Callable,
        required_permissions: Optional[Set[str]] = None,
        description: str = "",
        access_type: str = "execute",
        is_destructive: bool = False,
        reverses_tool: Optional[str] = None,
    ) -> ToolMetadata:
        """Register a tool so it can be granted to permission sets.

        Registering a tool does not grant it to anyone. Tools become
        callable only through a composite server built for a permission
        set that grants them.

        Args:
            tool_name: Name of the tool to expose.
            func: The function implementing the tool.
            required_permissions: Permission names needed to call it.
            description: Description of the tool.
            access_type: Type of access ("read", "write", "execute").
            is_destructive: Whether the tool modifies state.
            reverses_tool: Name of the tool that undoes this action.

        Returns:
            The registered ToolMetadata.
        """
        meta = ToolMetadata(
            tool_name=tool_name,
            description=description,
            function=func,
            access_type=access_type,
            required_permissions=required_permissions or set(),
            is_destructive=is_destructive,
            reverses_tool=reverses_tool,
        )

        self.tr.register(meta)
        self.pm.register_tool(meta)

        return meta

    def create_composite_server(
        self, user_context: UserContext
    ) -> Dict[str, ToolWrapper]:
        """Build a user's composite server.

        The returned map holds only the tools the user may call, and each
        wrapper re-checks permission on invocation, so a permission set
        edited after the map was built still takes effect.

        Args:
            user_context: The context identifying the user.

        Returns:
            Mapping of tool name to a bound, permission-checked wrapper.
        """
        return self.ac.composite_server_tools(user_context.perm_set_name)

    def list_available_tools(self, user_context: UserContext) -> List[str]:
        """List the tools available to a user.

        Returns only permitted tools, so it is safe to expose as the
        user's tool listing.

        Args:
            user_context: The context identifying the user.

        Returns:
            Sorted list of tool names the user may call.
        """
        return self.pm.get_allowed_tools(user_context.perm_set_name)

    def call_tool(
        self,
        user_context: UserContext,
        tool_name: str,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Authorize and execute a tool call on behalf of a user.

        Args:
            user_context: The context identifying the user.
            tool_name: Name of the tool to call.
            *args: Positional arguments forwarded to the tool.
            **kwargs: Keyword arguments forwarded to the tool.

        Returns:
            The tool function's return value.

        Raises:
            PermissionDenied: If the user may not call the tool.
            ToolNotRegistered: If the tool is not registered.
        """
        return self.ac.call(user_context.perm_set_name, tool_name, *args, **kwargs)


class CompositeMCPServers:
    """Caches composite servers for many users.

    Building a composite server is cheap, but caching avoids repeating it
    per request. Cached wrappers still re-check permission on every call,
    so a stale cache cannot grant access that has been revoked; it can
    only omit a tool that has since been granted. Call
    `refresh_user_server` after changing a permission set.
    """

    def __init__(self, mcp_server: MCPServer):
        self.mcp_server = mcp_server
        self._server_cache: Dict[str, Dict[str, ToolWrapper]] = {}

    def _cache_key(self, user_context: UserContext) -> str:
        """Build the cache key for a user context."""
        return "{}:{}".format(user_context.user_id, user_context.perm_set_name)

    def get_server_for_user(
        self, user_context: UserContext
    ) -> Dict[str, ToolWrapper]:
        """Get a user's composite server, building it if not cached.

        Args:
            user_context: The context identifying the user.

        Returns:
            Composite server mapping tool names to bound wrappers.
        """
        key = self._cache_key(user_context)

        if key not in self._server_cache:
            self._server_cache[key] = self.mcp_server.create_composite_server(
                user_context
            )

        return self._server_cache[key]

    def refresh_user_server(
        self, user_context: UserContext
    ) -> Dict[str, ToolWrapper]:
        """Rebuild and re-cache a user's composite server.

        Args:
            user_context: The context identifying the user.

        Returns:
            The freshly built composite server.
        """
        self._server_cache.pop(self._cache_key(user_context), None)
        server = self.mcp_server.create_composite_server(user_context)
        self._server_cache[self._cache_key(user_context)] = server
        return server

    def invalidate_all(self) -> None:
        """Clear every cached composite server."""
        self._server_cache.clear()

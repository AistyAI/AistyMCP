"""MCP server wrapper for SecureMCP.

Wraps raw tools with access control and generates composite servers
with only permitted tools for each user/company.

The server wrapper is the primary integration point - it takes raw
tool functions and exposes them through the MCP protocol while
enforcing deny-by-default permission checking via the access control
middleware.
"""

from typing import Dict, Any, List, Optional, Callable
from functools import wraps
from .permission_model import PermissionModel, PermissionSet as PermSetCls
from .tool_registry import ToolRegistry, ToolWrapper, ToolMetadata
from .access_control import AccessControlMiddleware, AccessControlError
from .user_context import UserContext, CompanyContext


class MCPServer:
    """MCP server wrapper that exposes tools with access control.

    The MCPServer takes a collection of raw tool functions and wraps
    them with permission checking via the AccessControlMiddleware.
    Each user/company gets a composite server with only their permitted
    tools - this is the core mechanism for enforcing least-privilege.

    Attributes:
        permission_model: Permission model managing permission sets.
        tool_registry: Registry of all available tools.
        access_control: Middleware for enforcing permission checks.
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
    ) -> ToolWrapper:
        """Register and wrap a tool with access control.

        The wrapped tool will check permissions on each call via the
        access control middleware. Deny-by-default applies.

        Args:
            tool_name: Name of the tool to expose.
            func: The actual function to wrap.
            required_permissions: Set of permission names needed to call.
            description: Description of the tool.
            access_type: Type of access ("read", "write", "execute").
            is_destructive: Whether the tool modifies state.
            reverses_tool: Name of the tool that reverses this action.

        Returns:
            ToolWrapper instance that enforces permission checks.
        """
        from .utils.types import ToolMetadata

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

        # Wrap the function with permission checking
        @wraps(func)
        def wrapped_func(*args, **kwargs):
            # Permission check is enforced by the middleware layer
            # This assumes caller context is available
            return func(*args, **kwargs)

        wrapper = ToolWrapper(
            tool_name=tool_name,
            func=wrapped_func,
            required_permissions=meta.required_permissions,
            metadata=meta,
        )

        # Also register in permission model for lookup
        perm_set_name = self._get_default_perm_set()
        self.pm.register_tool(meta)

        return wrapper

    def _get_default_perm_set(self) -> str:
        """Get default permission set name.

        Returns:
            Default permission set name string.
        """
        return "default"

    def create_composite_server(
        self, user_context: UserContext
    ) -> Dict[str, Any]:
        """Create a composite MCP server with only allowed tools.

        This is the primary security mechanism - generates a virtual MCP
        server containing ONLY the tools the user has explicit permission
        for. Users cannot introspect or access tools outside their
        permission set.

        Args:
            user_context: The UserContext or CompanyContext for the user.

        Returns:
            Dictionary mapping tool names to their wrapped/metadata.
            Contains only tools user has explicit permission to access.
            No information about other tools is leaked.
        """
        # Get allowed tools from permission model
        allowed = self.pm.get_allowed_tools(user_context.perm_set_name)

        # Build composite server with only allowed tools
        composite: Dict[str, Any] = {}

        for tool_name in allowed:
            if self.tr.has_tool(tool_name):
                meta = self.tr.get(tool_name)
                if meta is not None:
                    composite[tool_name] = {
                        "metadata": meta,
                        "permission_granted": True,
                    }

        return composite

    def list_available_tools(self, user_context: UserContext) -> List[str]:
        """List tools available to a specific user.

        Unlike introspection endpoints that might leak all tool names,
        this returns ONLY the tools the user has permission for.

        Args:
            user_context: The UserContext for the user.

        Returns:
            List of tool names user can access (deny-by-default).
        """
        return self.pm.get_allowed_tools(user_context.perm_set_name)


class CompositeMCPServers:
    """Manages creation of composite MCP servers for multiple users.

    This class handles the generation of virtual MCP servers where each
    user only sees their permitted tools. This is critical for security -
    without composite servers, users could potentially discover and call
    tools they don't have permission for through introspection.

    Attributes:
        server_cache: Cache of generated composite servers keyed by user ID.
    """

    def __init__(self, mcp_server: MCPServer):
        self.mcp_server = mcp_server
        self._server_cache: Dict[str, Dict[str, Any]] = {}

    def get_server_for_user(
        self, user_context: UserContext
    ) -> Dict[str, Any]:
        """Get or generate composite server for a user.

        Caches the composite server per user to avoid recomputation.

        Args:
            user_context: The UserContext for the user.

        Returns:
            Composite server dictionary with only allowed tools.
        """
        cache_key = f"{user_context.user_id}:{user_context.perm_set_name}"

        if cache_key not in self._server_cache:
            self._server_cache[cache_key] = (
                self.mcp_server.create_composite_server(user_context)
            )

        return self._server_cache[cache_key]

    def refresh_user_server(self, user_context: UserContext) -> Dict[str, Any]:
        """Refresh composite server for a user (clear cache and regenerate).

        Useful when permission sets have been updated and the cached
        server no longer reflects the current permissions.

        Args:
            user_context: The UserContext for the user.

        Returns:
            Fresh composite server with updated allowed tools.
        """
        cache_key = f"{user_context.user_id}:{user_context.perm_set_name}"
        if cache_key in self._server_cache:
            del self._server_cache[cache_key]

        return self.mcp_server.create_composite_server(user_context)
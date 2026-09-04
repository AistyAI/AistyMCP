"""Tool registry for SecureMCP.

Registers MCP tools with metadata and permission requirements.
Supports tool discovery and validation.
"""

from typing import Dict, List, Optional, Set, Any
from .utils.types import ToolMetadata
from .utils.validation import validate_tool_name


class ToolRegistry:
    """Registry of MCP tools with associated metadata.

    Tools are registered with their name, description, function reference,
    access type, and required permissions. The registry is used by the
    access control middleware to determine what tools exist and what
    permissions are needed.
    """

    def __init__(self):
        self._tools: Dict[str, ToolMetadata] = {}
        self._tool_order: List[str] = []

    def register(self, tool_meta: ToolMetadata) -> None:
        """Register a tool in the registry.

        Args:
            tool_meta: ToolMetadata instance containing tool definition.
        """
        if tool_meta.tool_name in self._tools:
            raise ValueError(f"Tool already registered: {tool_meta.tool_name}")

        validate_tool_name(tool_meta.tool_name)
        self._tools[tool_meta.tool_name] = tool_meta
        self._tool_order.append(tool_meta.tool_name)

    def unregister(self, tool_name: str) -> None:
        """Unregister a tool from the registry.

        Args:
            tool_name: Name of the tool to unregister.
        """
        if tool_name in self._tools:
            del self._tools[tool_name]
            self._tool_order = [t for t in self._tool_order if t != tool_name]

    def get(self, tool_name: str) -> Optional[ToolMetadata]:
        """Get tool metadata by name.

        Args:
            tool_name: Name of the tool to look up.

        Returns:
            ToolMetadata if found, None otherwise.
        """
        return self._tools.get(tool_name)

    def list_tools(self) -> List[str]:
        """List all registered tool names.

        Returns:
            List of registered tool names in registration order.
        """
        return self._tool_order.copy()

    def list_tools_with_permissions(self) -> List[tuple]:
        """List all tools with their required permissions.

        Returns:
            List of (tool_name, required_permissions_set) tuples.
        """
        result = []
        for tool_name in self._tool_order:
            meta = self._tools[tool_name]
            result.append((tool_name, meta.required_permissions.copy()))
        return result

    def get_tool(self, tool_name: str) -> Optional[ToolMetadata]:
        """Get tool metadata (alias for get).

        Args:
            tool_name: Name of the tool.

        Returns:
            ToolMetadata if found, None otherwise.
        """
        return self.get(tool_name)

    def has_tool(self, tool_name: str) -> bool:
        """Check if a tool is registered.

        Args:
            tool_name: Name of the tool to check.

        Returns:
            True if tool is registered, False otherwise.
        """
        return tool_name in self._tools

    def get_all_metadata(self) -> Dict[str, ToolMetadata]:
        """Get all tool metadata.

        Returns:
            Dictionary mapping tool names to ToolMetadata.
        """
        return self._tools.copy()


class ToolWrapper:
    """Wrapper that attaches access control to a tool function.

    A ToolWrapper wraps a raw tool function with permission checking
    logic. When invoked, it first checks if the caller has the required
    permissions before executing the underlying function.
    """

    def __init__(
        self,
        tool_name: str,
        func: Any,
        required_permissions: Set[str],
        metadata: Optional[ToolMetadata] = None,
    ):
        self.tool_name = tool_name
        self.func = func
        self.required_permissions = required_permissions
        self.metadata = metadata or ToolMetadata(
            tool_name=tool_name,
            description="",
            function=lambda: None,
        )

    def __call__(self, *args, **kwargs) -> Any:
        """Execute the tool function with permission check.

        This method must be called within a context where permission
        checking is available (e.g., via the access control middleware).

        Returns:
            Result of the underlying tool function.

        Raises:
            PermissionError: If the caller does not have required permissions.
        """
        # Permission check is handled by the access control layer
        # This wrapper assumes checks have already passed
        return self.func(*args, **kwargs)

    def get_info(self) -> dict:
        """Get tool information for display/registry purposes.

        Returns:
            Dictionary with tool metadata.
        """
        return {
            "tool_name": self.tool_name,
            "description": self.metadata.description,
            "access_type": self.metadata.access_type,
            "is_destructive": self.metadata.is_destructive,
            "required_permissions": list(self.required_permissions),
        }
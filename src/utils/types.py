"""Type definitions for SecureMCP."""

from typing import Dict, List, Optional, Set, Any


class Permission:
    """Represents a single tool permission right.

    Attributes:
        tool_name: Name of the tool this permission applies to.
        function: Specific function within the tool (optional).
        access_type: Type of access - "read", "write", "execute".
        constraints: Additional constraints dict (time, resource, etc).
    """

    def __init__(
        self,
        tool_name: str,
        function: Optional[str] = None,
        access_type: str = "execute",
        constraints: Optional[Dict[str, Any]] = None,
    ):
        from .validation import validate_tool_name
        validate_tool_name(tool_name)
        self.tool_name = tool_name
        self.function = function
        self.access_type = access_type
        self.constraints = constraints or {}


class PermissionSet:
    """A named collection of permissions for a user or company.

    Attributes:
        name: Identifier for this permission set.
        permissions: List of Permission objects.
        description: Human-readable description.
    """

    def __init__(
        self,
        name: str,
        permissions: List[Permission],
        description: str = "",
    ):
        self.name = name
        self.permissions = permissions
        self.description = description


class ToolMetadata:
    """Metadata describing an MCP tool.

    Attributes:
        tool_name: Name of the tool.
        description: Description of what the tool does.
        function: Reference to the actual function.
        access_type: Default access type ("read", "write", "execute").
        required_permissions: Set of permission names needed to use this tool.
        is_destructive: Whether the tool modifies state.
        reverses_tool: Name of the tool that reverses this action (optional).
    """

    def __init__(
        self,
        tool_name: str,
        description: str,
        function: Any,
        access_type: str = "execute",
        required_permissions: Optional[Set[str]] = None,
        is_destructive: bool = False,
        reverses_tool: Optional[str] = None,
    ):
        from .validation import validate_tool_name
        validate_tool_name(tool_name)
        self.tool_name = tool_name
        self.description = description
        self.function = function
        self.access_type = access_type
        self.required_permissions = required_permissions or set()
        self.is_destructive = is_destructive
        self.reverses_tool = reverses_tool
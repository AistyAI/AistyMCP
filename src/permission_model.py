"""Permission model for SecureMCP.

Defines PermissionSet and Permission classes with constraint support.
Enforces deny-by-default at the model level.
"""

from typing import Dict, List, Optional, Set, Any, FrozenSet
from .utils.types import Permission, PermissionSet as PermissionSetCls
from .utils.validation import validate_tool_name, validate_permission_set


class PermissionModel:
    """Core permission model that manages permission sets and evaluation.

    This model enforces deny-by-default - a tool must have an explicit
    permission granted to be executable.
    """

    def __init__(self):
        self._permission_sets: Dict[str, PermissionSetCls] = {}
        self._tool_registry: Dict[str, "ToolMetadata"] = {}
        self._reversible_map: Dict[str, str] = {}  # tool_name -> reverses_tool_name

    def register_permission_set(self, perm_set: PermissionSetCls) -> None:
        """Register a permission set with the model.

        Args:
            perm_set: PermissionSet instance to register.
        """
        self._permission_sets[perm_set.name] = perm_set

    def register_tool(self, tool_meta: "ToolMetadata") -> None:
        """Register a tool with its metadata.

        Args:
            tool_meta: ToolMetadata instance to register.
        """
        self._tool_registry[tool_meta.tool_name] = tool_meta

        # Track reversible relationship if specified
        if tool_meta.reverses_tool:
            self._reversible_map[tool_meta.tool_name] = tool_meta.reverses_tool
            # Also register the reverse direction
            if tool_meta.reverses_tool not in self._reversible_map:
                self._reversible_map[tool_meta.reverses_tool] = tool_meta.tool_name

    def has_permission(
        self,
        user_perm_set_name: str,
        tool_name: str,
        function: Optional[str] = None,
    ) -> bool:
        """Check if a user's permission set allows calling a tool.

        Deny-by-default: returns False if no explicit permission found.

        Also checks reversible tool relationships - if a tool reverses
        another tool, permission for one implies access to the reversible.

        Args:
            user_perm_set_name: Name of the user's permission set.
            tool_name: Name of the tool to check.
            function: Specific function within the tool (optional).

        Returns:
            True if permission granted, False otherwise (default deny).
        """
        perm_set = self._permission_sets.get(user_perm_set_name)
        if perm_set is None:
            return False

        # Check if tool is in permission set
        tool_perm = None
        for perm in perm_set.permissions:
            if perm.tool_name == tool_name:
                tool_perm = perm
                break

        if tool_perm is None:
            # No permission entry = deny by default
            return False

        # If specific function requested, check match
        if function and tool_perm.function and tool_perm.function != function:
            return False

        # Check constraints if present
        if tool_perm.constraints:
            if not self._check_constraints(tool_perm.constraints):
                return False

        # Check reversible tool relationship
        reverses_tool = self._reversible_map.get(tool_name)
        print(f"DEBUG: tool_name={tool_name}, reverses_tool={reverses_tool}, perm_set.permissions={[(p.tool_name, p.function) for p in perm_set.permissions]}")
        if reverses_tool:
            # If this tool has a reversible, also check if the reversible
            # tool is in the permission set
            rev_perm = None
            for perm in perm_set.permissions:
                if perm.tool_name == reverses_tool:
                    rev_perm = perm
                    break
            print(f"DEBUG: rev_perm={rev_perm}")
            if rev_perm is None:
                # User doesn't have permission for the reversible tool
                return False

        return True

    def _check_constraints(self, constraints: Dict[str, Any]) -> bool:
        """Check if constraints are satisfied.

        Args:
            constraints: Constraint dictionary to evaluate.

        Returns:
            True if all constraints pass.
        """
        # Time-based constraints
        if "time_window" in constraints:
            from datetime import datetime

            now = datetime.now()
            tw = constraints["time_window"]
            if not (tw.get("start") <= now <= tw.get("end")):
                return False

        # Resource-based constraints
        if "max_calls" in constraints:
            # Would integrate with usage tracking in full implementation
            pass

        return True

    def get_allowed_tools(self, user_perm_set_name: str) -> List[str]:
        """Get list of tool names a user's permission set allows.

        Returns only tools with explicit permission (deny-by-default).

        Args:
            user_perm_set_name: Name of the user's permission set.

        Returns:
            List of tool names the user is allowed to call.
        """
        perm_set = self._permission_sets.get(user_perm_set_name)
        if perm_set is None:
            return []

        allowed = []
        for perm in perm_set.permissions:
            if perm.tool_name not in allowed:
                allowed.append(perm.tool_name)
        return allowed

    def get_tool_metadata(self, tool_name: str) -> Optional["ToolMetadata"]:
        """Get tool metadata from registry.

        Args:
            tool_name: Name of the tool.

        Returns:
            ToolMetadata if found, None otherwise.
        """
        return self._tool_registry.get(tool_name)

    def composite_server_tools(self, user_perm_set_name: str) -> Dict[str, Any]:
        """Generate composite server with only allowed tools.

        This method generates a virtual MCP server containing ONLY the tools
        the user has explicit permission for. No information about other
        tools is leaked - deny-by-default at the model level.

        Args:
            user_perm_set_name: Name of the user's permission set.

        Returns:
            Dictionary mapping tool names to tool metadata (or empty dict)
            for allowed tools only. Contains only tools user has explicit
            permission to access. Tool metadata included if available in
            registry, otherwise an empty dict is returned for each tool.
        """
        allowed = self.get_allowed_tools(user_perm_set_name)

        # Build composite server with only allowed tools
        composite: Dict[str, Any] = {}

        for tool_name in allowed:
            if tool_name in self._tool_registry:
                composite[tool_name] = self._tool_registry[tool_name]
            else:
                composite[tool_name] = {}

        return composite


# Alias for backward compatibility
PermissionSet = PermissionSetCls
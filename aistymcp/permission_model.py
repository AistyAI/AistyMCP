"""Permission model for AistyMCP.

Defines the core permission evaluation logic. Enforces deny-by-default:
a tool is callable only when the user's permission set grants it explicitly.

This module is the single authoritative enforcement point. Every other
module in the package delegates its decisions to `has_permission`.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from .utils.types import Permission, PermissionSet as PermissionSetCls, ToolMetadata

WILDCARD = "*"


def _coerce_permission(entry: Union[Permission, str]) -> Permission:
    """Normalise a permission set entry into a Permission object.

    Permission sets accept either Permission objects or bare tool-name
    strings (including the "*" wildcard) for convenience.

    Args:
        entry: A Permission instance or a tool name string.

    Returns:
        A Permission instance.

    Raises:
        TypeError: If the entry is neither a Permission nor a string.
    """
    if isinstance(entry, Permission):
        return entry
    if isinstance(entry, str):
        return Permission(tool_name=entry)
    raise TypeError(
        "Permission set entries must be Permission objects or tool name "
        "strings, got {}".format(type(entry).__name__)
    )


def _parse_boundary(value: Any) -> Optional[datetime]:
    """Parse a time-window boundary into a datetime.

    Accepts datetime objects and ISO 8601 strings so that permission sets
    can be loaded from JSON or YAML without pre-processing.

    Args:
        value: A datetime, an ISO 8601 string, or None.

    Returns:
        The parsed datetime, or None if the value is absent or unparseable.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None


class PermissionModel:
    """Evaluates permission sets against tool calls.

    Deny-by-default: a tool must be granted explicitly (or matched by a
    wildcard entry) for `has_permission` to return True.
    """

    def __init__(self):
        self._permission_sets: Dict[str, PermissionSetCls] = {}
        self._tool_registry: Dict[str, ToolMetadata] = {}
        # Directional: tool_name -> the tool that undoes it.
        self._reversible_map: Dict[str, str] = {}

    def register_permission_set(self, perm_set: PermissionSetCls) -> None:
        """Register a permission set with the model.

        Args:
            perm_set: PermissionSet instance to register.
        """
        self._permission_sets[perm_set.name] = perm_set

    def register_tool(self, tool_meta: ToolMetadata) -> None:
        """Register a tool with its metadata.

        The reversible relationship is recorded directionally: declaring
        `reverses_tool` on A means B undoes A. It does not imply that A
        undoes B; register that separately if it is also true.

        Args:
            tool_meta: ToolMetadata instance to register.
        """
        self._tool_registry[tool_meta.tool_name] = tool_meta

        if tool_meta.reverses_tool:
            self._reversible_map[tool_meta.tool_name] = tool_meta.reverses_tool

    def get_undo_tool(self, tool_name: str) -> Optional[str]:
        """Get the name of the tool that undoes the given tool.

        Args:
            tool_name: Name of the tool.

        Returns:
            The undo tool's name, or None if none is declared.
        """
        return self._reversible_map.get(tool_name)

    def _find_permission(
        self,
        perm_set: PermissionSetCls,
        tool_name: str,
    ) -> Optional[Permission]:
        """Find the permission entry matching a tool name.

        An exact tool-name match wins over a wildcard entry.

        Args:
            perm_set: The permission set to search.
            tool_name: Name of the tool to match.

        Returns:
            The matching Permission, or None if the set does not cover it.
        """
        wildcard_match = None
        for entry in perm_set.permissions:
            perm = _coerce_permission(entry)
            if perm.tool_name == tool_name:
                return perm
            if perm.tool_name == WILDCARD and wildcard_match is None:
                wildcard_match = perm
        return wildcard_match

    def has_permission(
        self,
        user_perm_set_name: str,
        tool_name: str,
        function: Optional[str] = None,
    ) -> bool:
        """Check whether a permission set allows calling a tool.

        Deny-by-default: returns False unless the tool is granted
        explicitly, matched by a wildcard entry, or reachable as the undo
        of a granted tool in a set with `grant_reverse` enabled.

        Args:
            user_perm_set_name: Name of the user's permission set.
            tool_name: Name of the tool to check.
            function: Specific function within the tool (optional).

        Returns:
            True if permission is granted, False otherwise.
        """
        perm_set = self._permission_sets.get(user_perm_set_name)
        if perm_set is None:
            return False

        tool_perm = self._find_permission(perm_set, tool_name)

        if tool_perm is None:
            # Not granted directly. The only remaining route is an implicit
            # undo grant, which is opt-in per permission set.
            return self._has_implicit_undo_permission(perm_set, tool_name)

        if function and tool_perm.function and tool_perm.function != function:
            return False

        if tool_perm.constraints and not self._check_constraints(tool_perm.constraints):
            return False

        return True

    def _has_implicit_undo_permission(
        self,
        perm_set: PermissionSetCls,
        tool_name: str,
    ) -> bool:
        """Check whether a tool is reachable as the undo of a granted tool.

        Only applies to permission sets created with `grant_reverse=True`.
        This lets an operator say "whoever may do X may also undo X"
        without listing every undo tool by hand. It is off by default so
        that granting one tool never silently widens access to another.

        Args:
            perm_set: The permission set being evaluated.
            tool_name: Name of the tool to check.

        Returns:
            True if an implicit undo grant covers the tool.
        """
        if not getattr(perm_set, "grant_reverse", False):
            return False

        for entry in perm_set.permissions:
            granted = _coerce_permission(entry)
            if granted.tool_name == WILDCARD:
                continue
            if self._reversible_map.get(granted.tool_name) != tool_name:
                continue
            if granted.constraints and not self._check_constraints(granted.constraints):
                continue
            return True
        return False

    def _check_constraints(self, constraints: Dict[str, Any]) -> bool:
        """Check whether a permission's constraints are currently satisfied.

        Args:
            constraints: Constraint dictionary to evaluate.

        Returns:
            True if all evaluable constraints pass. A malformed or
            incomplete time window fails closed.
        """
        if "time_window" in constraints:
            window = constraints["time_window"] or {}
            start = _parse_boundary(window.get("start"))
            end = _parse_boundary(window.get("end"))
            if start is None or end is None:
                # Fail closed: an unreadable window is not an open one.
                return False
            if not start <= datetime.now() <= end:
                return False

        # "max_calls" is accepted in permission sets but not enforced here;
        # call counting belongs to the deployment's usage tracking layer.
        return True

    def get_allowed_tools(self, user_perm_set_name: str) -> List[str]:
        """Get the tool names a permission set currently allows.

        The result is derived from `has_permission`, so it reflects
        constraints and implicit undo grants and cannot disagree with what
        enforcement would decide.

        Args:
            user_perm_set_name: Name of the user's permission set.

        Returns:
            Sorted list of tool names the user may call. Empty if the
            permission set is unknown.
        """
        perm_set = self._permission_sets.get(user_perm_set_name)
        if perm_set is None:
            return []

        candidates: List[str] = []

        for entry in perm_set.permissions:
            perm = _coerce_permission(entry)
            if perm.tool_name == WILDCARD:
                candidates.extend(self._tool_registry.keys())
            else:
                candidates.append(perm.tool_name)

        if getattr(perm_set, "grant_reverse", False):
            for tool_name in list(candidates):
                undo = self._reversible_map.get(tool_name)
                if undo:
                    candidates.append(undo)

        allowed: List[str] = []
        for tool_name in candidates:
            if tool_name in allowed:
                continue
            if self.has_permission(user_perm_set_name, tool_name):
                allowed.append(tool_name)

        return sorted(allowed)

    def get_tool_metadata(self, tool_name: str) -> Optional[ToolMetadata]:
        """Get tool metadata from the registry.

        Args:
            tool_name: Name of the tool.

        Returns:
            ToolMetadata if registered, None otherwise.
        """
        return self._tool_registry.get(tool_name)

    def composite_server_tools(self, user_perm_set_name: str) -> Dict[str, Any]:
        """Build the tool map for a user's composite server.

        Contains only tools the user may call, so no metadata about any
        other tool is exposed.

        Args:
            user_perm_set_name: Name of the user's permission set.

        Returns:
            Mapping of tool name to ToolMetadata for allowed tools. Tools
            with no registered metadata are omitted, since a tool that
            cannot be described cannot be invoked.
        """
        composite: Dict[str, Any] = {}
        for tool_name in self.get_allowed_tools(user_perm_set_name):
            meta = self._tool_registry.get(tool_name)
            if meta is not None:
                composite[tool_name] = meta
        return composite


# Re-exported so callers can import the whole model from one module.
PermissionSet = PermissionSetCls

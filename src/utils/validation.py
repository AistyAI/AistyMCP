"""Validation utilities for SecureMCP."""


def validate_tool_name(name: str) -> bool:
    """Validate that a tool name follows naming conventions.

    Args:
        name: Tool name to validate.

    Returns:
        True if valid, raises ValueError otherwise.
    """
    if not name or not isinstance(name, str):
        raise ValueError("Tool name must be a non-empty string")
    if not name.isidentifier() and not all(c.isalnum() or c == "_" for c in name):
        raise ValueError(f"Invalid tool name: {name}")
    return True


def validate_permission_set(perm_set: dict) -> bool:
    """Validate a permission set dictionary structure.

    Args:
        perm_set: Permission set to validate.

    Returns:
        True if valid, raises ValueError otherwise.
    """
    if not isinstance(perm_set, dict):
        raise ValueError("Permission set must be a dictionary")
    for tool_name, allowed in perm_set.items():
        validate_tool_name(tool_name)
        if not isinstance(allowed, bool):
            raise ValueError(f"Permission for {tool_name} must be boolean")
    return True
"""Validation utilities for AistyMCP."""

WILDCARD = "*"


def validate_tool_name(name: str) -> bool:
    """Validate that a tool name follows naming conventions.

    Tool names must consist of alphanumerics, underscores, hyphens, dots
    and colons, which covers the namespaced names MCP servers commonly
    use (for example "jira:add_comment"). The "*" wildcard is accepted so
    that it can be used as a permission set entry.

    Args:
        name: Tool name to validate.

    Returns:
        True if valid.

    Raises:
        ValueError: If the name is empty, not a string, or contains
            characters outside the permitted set.
    """
    if not name or not isinstance(name, str):
        raise ValueError("Tool name must be a non-empty string")

    if name == WILDCARD:
        return True

    allowed_punctuation = {"_", "-", ".", ":"}
    if not all(c.isalnum() or c in allowed_punctuation for c in name):
        raise ValueError("Invalid tool name: {}".format(name))

    return True


def validate_permission_set(perm_set: dict) -> bool:
    """Validate a permission set dictionary structure.

    Args:
        perm_set: Mapping of tool name to a boolean allow flag.

    Returns:
        True if valid.

    Raises:
        ValueError: If the structure or any entry is invalid.
    """
    if not isinstance(perm_set, dict):
        raise ValueError("Permission set must be a dictionary")
    for tool_name, allowed in perm_set.items():
        validate_tool_name(tool_name)
        if not isinstance(allowed, bool):
            raise ValueError("Permission for {} must be boolean".format(tool_name))
    return True

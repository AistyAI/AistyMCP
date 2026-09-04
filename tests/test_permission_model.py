"""Tests for SecureMCP permission model."""

import pytest
from src.permission_model import PermissionModel, PermissionSet, Permission
from src.utils.types import ToolMetadata
from src.utils.validation import validate_tool_name, validate_permission_set


class TestValidateToolName:
    """Test tool name validation."""

    def test_valid_simple_name(self):
        """Valid simple identifier name."""
        assert validate_tool_name("my_tool") is True

    def test_valid_with_numbers(self):
        """Valid tool name with numbers."""
        assert validate_tool_name("tool_123") is True

    def test_valid_camel_case(self):
        """Valid camelCase tool name."""
        assert validate_tool_name("getUserData") is True

    def test_empty_string(self):
        """Empty string should raise ValueError."""
        import traceback
        try:
            validate_tool_name("")
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_none(self):
        """None should raise ValueError."""
        import traceback
        try:
            validate_tool_name(None)  # type: ignore
            assert False, "Should have raised ValueError"
        except ValueError:
            pass


class TestValidatePermissionSet:
    """Test permission set validation."""

    def test_valid_dict(self):
        """Valid boolean permission set."""
        assert validate_permission_set({"tool1": True, "tool2": False}) is True

    def test_invalid_non_dict(self):
        """Non-dict should raise ValueError."""
        import traceback
        try:
            validate_permission_set("not a dict")  # type: ignore
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_invalid_bool_value(self):
        """Non-boolean permission values should raise ValueError."""
        import traceback
        try:
            validate_permission_set({"tool1": "yes"})  # type: ignore
            assert False, "Should have raised ValueError"
        except ValueError:
            pass


class TestPermission:
    """Test Permission class."""

    def test_basic_permission(self):
        """Create basic permission."""
        p = Permission(tool_name="tool1", function="read", access_type="read")
        assert p.tool_name == "tool1"
        assert p.function == "read"
        assert p.access_type == "read"
        assert p.constraints == {}

    def test_permission_with_constraints(self):
        """Create permission with constraints."""
        p = Permission(
            tool_name="tool1",
            constraints={"time_window": {"start": "2024-01-01", "end": "2025-12-31"}},
        )
        assert p.constraints["time_window"]["start"] == "2024-01-01"


class TestPermissionSet:
    """Test PermissionSet class."""

    def test_basic_permission_set(self):
        """Create basic permission set."""
        perms = [
            Permission(tool_name="tool1", function="read", access_type="read"),
            Permission(tool_name="tool2", function="write", access_type="write"),
        ]
        ps = PermissionSet(name="analyst", permissions=perms, description="Analyst role")
        assert ps.name == "analyst"
        assert len(ps.permissions) == 2
        assert ps.description == "Analyst role"


class TestPermissionModel:
    """Test PermissionModel core functionality."""

    def setup_method(self):
        """Set up fresh permission model for each test."""
        self.pm = PermissionModel()

    def test_register_and_lookup_tool(self):
        """Register tool and lookup metadata."""
        from src.utils.types import ToolMetadata

        meta = ToolMetadata(
            tool_name="search",
            description="Search tool",
            function=lambda: None,
        )
        self.pm.register_tool(meta)
        result = self.pm.get_tool_metadata("search")
        assert result is not None
        assert result.tool_name == "search"

    def test_register_permission_set(self):
        """Register a permission set."""
        perms = [
            Permission(tool_name="tool1", function="read", access_type="read"),
        ]
        ps = PermissionSet(name="read-only", permissions=perms, description="Read only access")
        self.pm.register_permission_set(ps)

        # Verify it's registered
        assert "read-only" in self.pm._permission_sets

    def test_has_permission_deny_by_default(self):
        """Deny-by-default: user without permission set gets False."""
        # No permission set registered
        result = self.pm.has_permission("nonexistent", "tool1")
        assert result is False

    def test_has_permission_no_entry(self):
        """No permission entry for tool = deny by default."""
        # Register empty permission set
        perms = []
        ps = PermissionSet(name="empty", permissions=perms, description="Empty set")
        self.pm.register_permission_set(ps)

        result = self.pm.has_permission("empty", "tool1")
        assert result is False  # Tool not in set = deny

    def test_has_permission_explicit_grant(self):
        """Explicit permission grant returns True."""
        perms = [
            Permission(tool_name="tool1", function="read", access_type="read"),
        ]
        ps = PermissionSet(name="analyst", permissions=perms, description="Analyst role")
        self.pm.register_permission_set(ps)

        result = self.pm.has_permission("analyst", "tool1")
        assert result is True

    def test_has_permission_wrong_function(self):
        """Specific function mismatch returns False."""
        perms = [
            Permission(tool_name="tool1", function="read", access_type="read"),
        ]
        ps = PermissionSet(name="analyst", permissions=perms, description="Analyst role")
        self.pm.register_permission_set(ps)

        # Request "write" function but permission has "read"
        result = self.pm.has_permission("analyst", "tool1", function="write")
        assert result is False

    def test_has_permission_correct_function(self):
        """Matching function returns True."""
        perms = [
            Permission(tool_name="tool1", function="read", access_type="read"),
        ]
        ps = PermissionSet(name="analyst", permissions=perms, description="Analyst role")
        self.pm.register_permission_set(ps)

        result = self.pm.has_permission("analyst", "tool1", function="read")
        assert result is True

    def test_get_allowed_tools(self):
        """Get allowed tools list."""
        perms = [
            Permission(tool_name="tool1", function="read", access_type="read"),
            Permission(tool_name="tool2", function="write", access_type="write"),
        ]
        ps = PermissionSet(name="analyst", permissions=perms, description="Analyst role")
        self.pm.register_permission_set(ps)

        allowed = self.pm.get_allowed_tools("analyst")
        assert "tool1" in allowed
        assert "tool2" in allowed
        assert len(allowed) == 2

    def test_get_allowed_tools_nonexistent_set(self):
        """Allowed tools for nonexistent set returns empty list."""
        allowed = self.pm.get_allowed_tools("nonexistent")
        assert allowed == []

    def test_composite_server_tools(self):
        """Generate composite server with only allowed tools."""
        perms = [
            Permission(tool_name="tool1", function="read", access_type="read"),
            Permission(tool_name="tool2", function="write", access_type="write"),
        ]
        ps = PermissionSet(name="analyst", permissions=perms, description="Analyst role")
        self.pm.register_permission_set(ps)

        # Mock tool registry
        allowed = self.pm.composite_server_tools("analyst")
        assert "tool1" in allowed
        assert "tool2" in allowed

    def test_get_tool_metadata(self):
        """Get tool metadata from registry."""
        from src.utils.types import ToolMetadata

        meta = ToolMetadata(
            tool_name="search",
            description="Search tool",
            function=lambda: None,
        )
        self.pm.register_tool(meta)

        result = self.pm.get_tool_metadata("search")
        assert result is not None
        assert result.tool_name == "search"

        # Nonexistent tool
        result = self.pm.get_tool_metadata("nonexistent")
        assert result is None
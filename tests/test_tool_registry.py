"""Tests for SecureMCP tool registry."""

import pytest
from src.tool_registry import ToolRegistry, ToolWrapper, ToolMetadata
from src.utils.types import PermissionSet as PermSetCls
from src.permission_model import PermissionSet as PM_PermissionSet


class TestToolRegistry:
    """Test ToolRegistry core functionality."""

    def setup_method(self):
        """Set up fresh registry for each test."""
        self.tr = ToolRegistry()

    def test_register_tool(self):
        """Register a tool in the registry."""
        from src.utils.types import ToolMetadata

        meta = ToolMetadata(
            tool_name="search",
            description="Search tool",
            function=lambda: None,
        )
        self.tr.register(meta)
        assert self.tr.has_tool("search") is True

    def test_register_duplicate(self):
        """Registering duplicate tool raises ValueError."""
        from src.utils.types import ToolMetadata

        meta = ToolMetadata(
            tool_name="search",
            description="Search tool",
            function=lambda: None,
        )
        self.tr.register(meta)
        try:
            self.tr.register(meta)
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_unregister_tool(self):
        """Unregister a tool."""
        from src.utils.types import ToolMetadata

        meta = ToolMetadata(
            tool_name="search",
            description="Search tool",
            function=lambda: None,
        )
        self.tr.register(meta)
        self.tr.unregister("search")
        assert self.tr.has_tool("search") is False

    def test_list_tools(self):
        """List all registered tools."""
        from src.utils.types import ToolMetadata

        # Register multiple tools
        for name in ["tool1", "tool2", "tool3"]:
            meta = ToolMetadata(
                tool_name=name,
                description=f"{name} tool",
                function=lambda: None,
            )
            self.tr.register(meta)

        tools = self.tr.list_tools()
        assert len(tools) == 3
        assert "tool1" in tools
        assert "tool2" in tools
        assert "tool3" in tools

    def test_list_tools_with_permissions(self):
        """List tools with their required permissions."""
        from src.utils.types import ToolMetadata

        # Register tools with different permissions
        for name, perms in [("tool1", {"read"}), ("tool2", {"write"})]:
            meta = ToolMetadata(
                tool_name=name,
                description=f"{name} tool",
                function=lambda: None,
                required_permissions=set(perms),
            )
            self.tr.register(meta)

        result = self.tr.list_tools_with_permissions()
        assert len(result) == 2
        assert result[0][0] == "tool1"
        assert result[1][0] == "tool2"

    def test_get_tool_metadata(self):
        """Get tool metadata by name."""
        from src.utils.types import ToolMetadata

        meta = ToolMetadata(
            tool_name="search",
            description="Search tool",
            function=lambda: None,
        )
        self.tr.register(meta)

        result = self.tr.get("search")
        assert result is not None
        assert result.tool_name == "search"

        # Nonexistent tool
        result = self.tr.get("nonexistent")
        assert result is None

    def test_has_tool(self):
        """Check if tool is registered."""
        assert self.tr.has_tool("nonexistent") is False

        from src.utils.types import ToolMetadata

        meta = ToolMetadata(
            tool_name="search",
            description="Search tool",
            function=lambda: None,
        )
        self.tr.register(meta)
        assert self.tr.has_tool("search") is True


class TestToolWrapper:
    """Test ToolWrapper functionality."""

    def test_tool_wrapper_creation(self):
        """Create a ToolWrapper instance."""
        wrapper = ToolWrapper(
            tool_name="test_tool",
            func=lambda: "result",
            required_permissions=set(),
            metadata=None,  # type: ignore
        )
        assert wrapper.tool_name == "test_tool"
        assert wrapper.func is not None

    def test_tool_wrapper_info(self):
        """Get tool info from wrapper."""
        wrapper = ToolWrapper(
            tool_name="test_tool",
            func=lambda x: x,
            required_permissions={"perm1"},
            metadata=None,  # type: ignore
        )
        info = wrapper.get_info()
        assert info["tool_name"] == "test_tool"
        assert "required_permissions" in info


class TestToolMetadata:
    """Test ToolMetadata class."""

    def test_basic_metadata(self):
        """Create basic ToolMetadata."""
        meta = ToolMetadata(
            tool_name="search",
            description="Search tool",
            function=lambda: None,
        )
        assert meta.tool_name == "search"
        assert meta.description == "Search tool"
        assert meta.access_type == "execute"
        assert meta.required_permissions == set()
        assert meta.is_destructive is False

    def test_metadata_with_destructive(self):
        """Create ToolMetadata with destructive flag."""
        meta = ToolMetadata(
            tool_name="delete_db",
            description="Delete database",
            function=lambda: None,
            is_destructive=True,
        )
        assert meta.is_destructive is True

    def test_metadata_with_permissions(self):
        """Create ToolMetadata with required permissions."""
        meta = ToolMetadata(
            tool_name="search",
            description="Search tool",
            function=lambda: None,
            required_permissions={"read:data"},
        )
        assert meta.required_permissions == {"read:data"}

    def test_metadata_with_reversible(self):
        """Create ToolMetadata with reversible tool."""
        meta = ToolMetadata(
            tool_name="jira_add_comment",
            description="Add comment to Jira ticket",
            function=lambda: None,
            reverses_tool="jira_remove_comment",
        )
        assert meta.reverses_tool == "jira_remove_comment"

    def test_metadata_without_reversible(self):
        """Create ToolMetadata without reversible tool."""
        meta = ToolMetadata(
            tool_name="search",
            description="Search tool",
            function=lambda: None,
        )
        assert meta.reverses_tool is None
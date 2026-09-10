"""Tests for AistyMCP access control middleware."""

import pytest
from aistymcp.access_control import (
    AccessControlMiddleware,
    AccessControlError,
    PermissionDenied,
)
from aistymcp.permission_model import PermissionModel, PermissionSet, Permission
from aistymcp.tool_registry import ToolRegistry, ToolMetadata
from aistymcp.user_context import UserContext


class TestAccessControlMiddleware:
    """Test AccessControlMiddleware core functionality."""

    def setup_method(self):
        """Set up fresh middleware for each test."""
        self.pm = PermissionModel()
        self.tr = ToolRegistry()
        self.middleware = AccessControlMiddleware(self.pm, self.tr)

    def test_deny_by_default_no_perm_set(self):
        """Deny-by-default: no permission set = denied."""
        wrapper = self.middleware.check_and_wrap("nonexistent", "tool1")(
            lambda: "result"
        )
        try:
            wrapper()
            assert False, "Should have raised AccessControlError"
        except AccessControlError as e:
            assert "denied" in str(e).lower() or "permission" in str(e).lower()

    def test_deny_by_default_no_tool(self):
        """Deny-by-default: unregistered tool = denied."""
        self.pm.register_permission_set(
            PermissionSet(name="analyst", permissions=[], description="")
        )

        wrapper = self.middleware.check_and_wrap("analyst", "nonexistent_tool")(
            lambda: "result"
        )
        try:
            wrapper()
            assert False, "Should have raised AccessControlError"
        except AccessControlError as e:
            assert "denied" in str(e).lower() or "not registered" in str(e).lower()

    def test_explicit_deny_raises_error(self):
        """Denied permission raises AccessControlError."""
        self.pm.register_permission_set(
            PermissionSet(
                name="analyst",
                permissions=[],
                description="Analyst role with no tools",
            )
        )

        wrapper = self.middleware.check_and_wrap("analyst", "tool1")(
            lambda: "result"
        )
        try:
            wrapper()
            assert False, "Should have raised AccessControlError"
        except AccessControlError:
            pass  # Expected

    def test_wrong_function_denied(self):
        """Wrong function name denied even with permission for other function."""
        self.pm.register_permission_set(
            PermissionSet(
                name="analyst",
                permissions=[
                    Permission(tool_name="tool1", function="read", access_type="read")
                ],
                description="Analyst role",
            )
        )
        self.tr.register(
            ToolMetadata(
                tool_name="tool1",
                description="Test tool",
                function=lambda: None,
            )
        )

        wrapper = self.middleware.check_and_wrap("analyst", "tool1", function="write")(
            lambda: "result"
        )
        try:
            wrapper()
            assert False, "Should have raised AccessControlError"
        except AccessControlError:
            pass  # Expected

    def test_get_user_allowed_tools(self):
        """Get list of tools user is allowed to call."""
        self.pm.register_permission_set(
            PermissionSet(
                name="analyst",
                permissions=[
                    Permission(tool_name="tool1", function="read", access_type="read"),
                    Permission(tool_name="tool2", function="write", access_type="write"),
                ],
                description="Analyst role",
            )
        )

        allowed = self.middleware.get_user_allowed_tools("analyst")
        assert "tool1" in allowed
        assert "tool2" in allowed

    def test_composite_server_tools(self):
        """Generate composite server with only allowed tools."""
        self.pm.register_permission_set(
            PermissionSet(
                name="analyst",
                permissions=[
                    Permission(tool_name="tool1", function="read", access_type="read"),
                ],
                description="Analyst role",
            )
        )
        self.tr.register(
            ToolMetadata(
                tool_name="tool1",
                description="Test tool",
                function=lambda: None,
            )
        )
        self.tr.register(
            ToolMetadata(
                tool_name="tool2",
                description="Another tool",
                function=lambda: None,
            )
        )

        composite = self.middleware.composite_server_tools("analyst")
        assert "tool1" in composite
        assert "tool2" not in composite  # Not allowed

    def test_reversible_tool_permission(self):
        """Reversible tool permission check works correctly."""
        from aistymcp.utils.types import ToolMetadata

        # Register tools with reversible relationship
        add_comment = ToolMetadata(
            tool_name="jira_add_comment",
            description="Add comment to Jira ticket",
            function=lambda: None,
            reverses_tool="jira_remove_comment",
        )
        remove_comment = ToolMetadata(
            tool_name="jira_remove_comment",
            description="Remove comment from Jira ticket",
            function=lambda: None,
            reverses_tool="jira_add_comment",
        )

        self.tr.register(add_comment)
        self.tr.register(remove_comment)

        # Add permissions for both tools
        perms = [
            Permission(tool_name="jira_add_comment", function="add", access_type="write"),
            Permission(tool_name="jira_remove_comment", function="remove", access_type="write"),
        ]
        ps = PermissionSet(name="analyst", permissions=perms, description="Analyst role")
        self.pm.register_permission_set(ps)

        # User with analyst role should be able to call both tools
        wrapper = self.middleware.check_and_wrap("analyst", "jira_add_comment")(
            lambda: "result"
        )
        result = wrapper()
        assert result == "result"

        wrapper = self.middleware.check_and_wrap("analyst", "jira_remove_comment")(
            lambda: "result"
        )
        result = wrapper()
        assert result == "result"

    def test_undo_tool_stays_denied_without_an_explicit_grant(self):
        """Granting a tool does not open its undo tool at the middleware."""
        from aistymcp.utils.types import ToolMetadata

        create = ToolMetadata(
            tool_name="jira_create_ticket",
            description="Create a Jira ticket",
            function=lambda: "created",
            reverses_tool="jira_delete_ticket",
        )
        delete = ToolMetadata(
            tool_name="jira_delete_ticket",
            description="Delete a Jira ticket",
            function=lambda: "deleted",
            is_destructive=True,
        )

        for meta in (create, delete):
            self.tr.register(meta)
            self.pm.register_tool(meta)

        self.pm.register_permission_set(PermissionSet(
            name="analyst",
            permissions=[Permission(tool_name="jira_create_ticket")],
            description="Can create tickets only",
        ))

        assert self.middleware.call("analyst", "jira_create_ticket") == "created"

        with pytest.raises(PermissionDenied):
            self.middleware.call("analyst", "jira_delete_ticket")

    def test_bound_wrapper_enforces_on_every_call(self):
        """A bound wrapper re-checks permission rather than trusting setup."""
        from aistymcp.utils.types import ToolMetadata

        meta = ToolMetadata(
            tool_name="search",
            description="Search",
            function=lambda q: "hit:" + q,
        )
        self.tr.register(meta)
        self.pm.register_tool(meta)

        granted = PermissionSet(
            name="analyst",
            permissions=[Permission(tool_name="search")],
            description="",
        )
        self.pm.register_permission_set(granted)

        bound = self.middleware.bind_tool("analyst", "search")
        assert bound.is_bound is True
        assert bound("abc") == "hit:abc"

        # Revoke the grant; the same wrapper must now refuse.
        granted.permissions = []
        with pytest.raises(PermissionDenied):
            bound("abc")

    def test_composite_server_omits_denied_tools(self):
        """A composite server exposes only permitted tools, as callables."""
        from aistymcp.utils.types import ToolMetadata

        for name in ("allowed_tool", "denied_tool"):
            meta = ToolMetadata(
                tool_name=name,
                description=name,
                function=lambda n=name: n,
            )
            self.tr.register(meta)
            self.pm.register_tool(meta)

        self.pm.register_permission_set(PermissionSet(
            name="analyst",
            permissions=[Permission(tool_name="allowed_tool")],
            description="",
        ))

        composite = self.middleware.composite_server_tools("analyst")

        assert set(composite) == {"allowed_tool"}
        assert composite["allowed_tool"]() == "allowed_tool"


class TestPermissionDenied:
    """Test PermissionDenied exception."""

    def test_permission_denied_is_access_control_error(self):
        """PermissionDenied is subclass of AccessControlError."""
        from aistymcp.access_control import PermissionDenied as PD

        assert issubclass(PD, Exception)

    def test_permission_denied_creation(self):
        """Create PermissionDenied instance."""
        exc = PermissionDenied("User denied access")
        assert str(exc) == "User denied access"


class TestUserContextIntegration:
    """Test UserContext integration with access control."""

    def setup_method(self):
        """Set up fresh context and middleware."""
        self.pm = PermissionModel()
        self.tr = ToolRegistry()
        self.middleware = AccessControlMiddleware(self.pm, self.tr)

    def test_user_context_has_tool_access(self):
        """User context checks tool access via permission model."""
        self.pm.register_permission_set(
            PermissionSet(
                name="analyst",
                permissions=[
                    Permission(tool_name="tool1", function="read", access_type="read"),
                ],
                description="Analyst role",
            )
        )
        self.tr.register(
            ToolMetadata(
                tool_name="tool1",
                description="Test tool",
                function=lambda: None,
            )
        )

        user = UserContext(user_id="user1", perm_set_name="analyst")
        has_access = user.has_tool_access(self.pm, "tool1")
        assert has_access is True

    def test_user_context_no_access(self):
        """User context returns False for tool without permission."""
        self.pm.register_permission_set(
            PermissionSet(
                name="analyst",
                permissions=[],
                description="Analyst role with no tools",
            )
        )

        user = UserContext(user_id="user1", perm_set_name="analyst")
        has_access = user.has_tool_access(self.pm, "tool1")
        assert has_access is False

    def test_user_context_allowed_tools(self):
        """Get allowed tools from user context."""
        self.pm.register_permission_set(
            PermissionSet(
                name="analyst",
                permissions=[
                    Permission(tool_name="tool1", function="read", access_type="read"),
                ],
                description="Analyst role",
            )
        )

        user = UserContext(user_id="user1", perm_set_name="analyst")
        allowed = user.get_allowed_tools(self.pm)
        assert "tool1" in allowed
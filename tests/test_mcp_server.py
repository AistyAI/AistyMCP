"""Tests for AistyMCP composite server construction."""

import importlib
import pkgutil

import pytest

import aistymcp
from aistymcp.access_control import AccessControlMiddleware, PermissionDenied
from aistymcp.mcp_server import CompositeMCPServers, MCPServer
from aistymcp.permission_model import PermissionModel
from aistymcp.tool_registry import ToolRegistry
from aistymcp.user_context import UserContext, build_default_permission_sets
from aistymcp.utils.types import Permission, PermissionSet


def test_every_module_imports():
    """Guards against import-time breakage in untested modules."""
    for mod in pkgutil.walk_packages(aistymcp.__path__, "aistymcp."):
        importlib.import_module(mod.name)


class TestMCPServer:
    """Test tool exposure and composite server construction."""

    def setup_method(self):
        self.pm = PermissionModel()
        self.tr = ToolRegistry()
        self.ac = AccessControlMiddleware(self.pm, self.tr)
        self.server = MCPServer(self.pm, self.tr, self.ac)

        self.server.expose_tool(
            tool_name="jira_create_ticket",
            func=lambda summary: "created:" + summary,
            description="Create a Jira ticket",
            access_type="write",
            reverses_tool="jira_delete_ticket",
        )
        self.server.expose_tool(
            tool_name="jira_delete_ticket",
            func=lambda ticket_id: "deleted:" + ticket_id,
            description="Delete a Jira ticket",
            access_type="write",
            is_destructive=True,
        )

        self.pm.register_permission_set(PermissionSet(
            name="analyst",
            permissions=[Permission(tool_name="jira_create_ticket")],
            description="Create only",
        ))

    def test_exposing_a_tool_grants_nothing(self):
        """Registration alone leaves a tool unreachable."""
        self.pm.register_permission_set(PermissionSet(
            name="empty", permissions=[], description=""
        ))
        user = UserContext(user_id="u", perm_set_name="empty")

        assert self.server.list_available_tools(user) == []
        assert self.server.create_composite_server(user) == {}

    def test_composite_server_contains_only_granted_tools(self):
        user = UserContext(user_id="alice", perm_set_name="analyst")
        composite = self.server.create_composite_server(user)

        assert set(composite) == {"jira_create_ticket"}
        assert composite["jira_create_ticket"]("ABC-1") == "created:ABC-1"

    def test_call_tool_enforces_permission(self):
        user = UserContext(user_id="alice", perm_set_name="analyst")

        assert self.server.call_tool(user, "jira_create_ticket", "ABC-1") == (
            "created:ABC-1"
        )
        with pytest.raises(PermissionDenied):
            self.server.call_tool(user, "jira_delete_ticket", "ABC-1")

    def test_unknown_permission_set_gets_nothing(self):
        user = UserContext(user_id="mallory", perm_set_name="does-not-exist")

        assert self.server.list_available_tools(user) == []
        with pytest.raises(PermissionDenied):
            self.server.call_tool(user, "jira_create_ticket", "ABC-1")

    def test_admin_wildcard_grants_every_registered_tool(self):
        self.pm.register_permission_set(build_default_permission_sets()["admin"])
        user = UserContext(user_id="root", perm_set_name="admin")

        assert self.server.list_available_tools(user) == [
            "jira_create_ticket",
            "jira_delete_ticket",
        ]


class TestCompositeMCPServers:
    """Test composite server caching."""

    def setup_method(self):
        self.pm = PermissionModel()
        self.tr = ToolRegistry()
        self.ac = AccessControlMiddleware(self.pm, self.tr)
        self.server = MCPServer(self.pm, self.tr, self.ac)
        self.cache = CompositeMCPServers(self.server)

        self.server.expose_tool("search", lambda: "ok", description="Search")
        self.perm_set = PermissionSet(
            name="analyst",
            permissions=[Permission(tool_name="search")],
            description="",
        )
        self.pm.register_permission_set(self.perm_set)
        self.user = UserContext(user_id="alice", perm_set_name="analyst")

    def test_cache_returns_same_map(self):
        first = self.cache.get_server_for_user(self.user)
        assert self.cache.get_server_for_user(self.user) is first

    def test_refresh_rebuilds(self):
        first = self.cache.get_server_for_user(self.user)
        assert self.cache.refresh_user_server(self.user) is not first

    def test_cached_wrapper_still_denies_after_revocation(self):
        """A stale cache cannot keep granting a revoked tool."""
        composite = self.cache.get_server_for_user(self.user)
        assert composite["search"]() == "ok"

        self.perm_set.permissions = []

        with pytest.raises(PermissionDenied):
            composite["search"]()

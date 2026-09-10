"""Tests for the AistyMCP policy engine."""

from datetime import datetime, timedelta

import pytest

from aistymcp.permission_model import PermissionModel
from aistymcp.policy_engine import (
    ConditionalPolicy,
    Policy,
    PolicyEngine,
    RBACPolicy,
)
from aistymcp.user_context import UserContext
from aistymcp.utils.types import Permission, PermissionSet, ToolMetadata


def build_model():
    """Build a model with one tool and one granting permission set."""
    pm = PermissionModel()
    pm.register_tool(ToolMetadata(
        tool_name="search", description="Search", function=lambda: None
    ))
    pm.register_permission_set(PermissionSet(
        name="analyst",
        permissions=[Permission(tool_name="search")],
        description="",
    ))
    return pm


class TestPolicyEngineBasics:
    def test_unknown_policy_denies(self):
        engine = PolicyEngine()
        ctx = UserContext("u", "analyst", permission_model=build_model())
        assert engine.evaluate("missing", ctx, "search") is False

    def test_base_policy_is_abstract(self):
        ctx = UserContext("u", "analyst", permission_model=build_model())
        with pytest.raises(NotImplementedError):
            Policy().evaluate(ctx, "search")

    def test_context_without_model_fails_loudly(self):
        """A missing model must not be read as a silent deny."""
        engine = PolicyEngine()
        engine.add_rbac_policy("analyst_role", "analyst")
        ctx = UserContext("u", "analyst")

        with pytest.raises(ValueError, match="permission model"):
            engine.has_role_permission(ctx, "analyst_role", "search")


class TestRBAC:
    def setup_method(self):
        self.pm = build_model()
        self.engine = PolicyEngine()
        self.engine.add_rbac_policy("analyst_role", "analyst")

    def test_role_grants_permission(self):
        ctx = UserContext("u", "analyst", permission_model=self.pm)
        assert self.engine.has_role_permission(ctx, "analyst_role", "search") is True

    def test_unknown_role_denies(self):
        ctx = UserContext("u", "analyst", permission_model=self.pm)
        assert self.engine.has_role_permission(ctx, "no_such_role", "search") is False

    def test_role_does_not_grant_ungranted_tool(self):
        ctx = UserContext("u", "analyst", permission_model=self.pm)
        assert self.engine.has_role_permission(ctx, "analyst_role", "delete") is False

    def test_rbac_policy_uses_context_roles(self):
        policy = RBACPolicy({"analyst_role": {"analyst"}})
        ctx = UserContext(
            "u", "analyst", roles=["analyst_role"], permission_model=self.pm
        )
        assert policy.evaluate(ctx, "search") is True

    def test_rbac_policy_denies_without_roles(self):
        policy = RBACPolicy({"analyst_role": {"analyst"}})
        ctx = UserContext("u", "analyst", permission_model=self.pm)
        assert policy.evaluate(ctx, "search") is False


class TestResourcePolicies:
    def test_resource_access_granted(self):
        pm = build_model()
        engine = PolicyEngine()
        engine.add_resource_permission("db://prod/customers", "analyst")
        ctx = UserContext("u", "analyst", permission_model=pm)

        assert engine.check_resource_access(ctx, "db://prod/customers", "search") is True

    def test_unknown_resource_denies(self):
        pm = build_model()
        engine = PolicyEngine()
        ctx = UserContext("u", "analyst", permission_model=pm)

        assert engine.check_resource_access(ctx, "db://other", "search") is False


class TestConditionalPolicies:
    def _window(self, start_days, end_days):
        return {
            "start": (datetime.now() + timedelta(days=start_days)).isoformat(),
            "end": (datetime.now() + timedelta(days=end_days)).isoformat(),
        }

    def test_open_window_passes(self):
        policy = ConditionalPolicy("time_window", {"window": self._window(-1, 1)})
        ctx = UserContext("u", "analyst", permission_model=build_model())
        assert policy.evaluate(ctx, "search") is True

    def test_expired_window_fails(self):
        policy = ConditionalPolicy("time_window", {"window": self._window(-10, -5)})
        ctx = UserContext("u", "analyst", permission_model=build_model())
        assert policy.evaluate(ctx, "search") is False

    def test_malformed_window_fails_closed(self):
        policy = ConditionalPolicy(
            "time_window", {"window": {"start": "nope", "end": "nope"}}
        )
        ctx = UserContext("u", "analyst", permission_model=build_model())
        assert policy.evaluate(ctx, "search") is False

    def test_unknown_condition_type_denies(self):
        policy = ConditionalPolicy("something_else", {})
        ctx = UserContext("u", "analyst", permission_model=build_model())
        assert policy.evaluate(ctx, "search") is False

    def test_custom_callback_is_used(self):
        calls = []

        def callback(ctx, tool_name, function, parameters):
            calls.append(tool_name)
            return True

        policy = ConditionalPolicy("custom", {"k": "v"}, callback=callback)
        ctx = UserContext("u", "analyst", permission_model=build_model())

        assert policy.evaluate(ctx, "search") is True
        assert calls == ["search"]

    def test_registered_policy_is_reachable_through_engine(self):
        engine = PolicyEngine()
        engine.add_policy(
            "window", ConditionalPolicy("time_window", {"window": self._window(-1, 1)})
        )
        ctx = UserContext("u", "analyst", permission_model=build_model())

        assert engine.evaluate("window", ctx, "search") is True

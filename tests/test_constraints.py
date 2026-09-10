"""Tests for time-window constraints and wildcard permission entries."""

from datetime import datetime, timedelta

from aistymcp.permission_model import PermissionModel
from aistymcp.utils.types import Permission, PermissionSet, ToolMetadata


def _window(start_delta_days, end_delta_days, as_string=True):
    """Build a time window relative to now."""
    start = datetime.now() + timedelta(days=start_delta_days)
    end = datetime.now() + timedelta(days=end_delta_days)
    if as_string:
        return {"start": start.isoformat(), "end": end.isoformat()}
    return {"start": start, "end": end}


class TestTimeWindow:
    """Time-based constraints on a permission."""

    def setup_method(self):
        self.pm = PermissionModel()
        self.pm.register_tool(ToolMetadata(
            tool_name="delete_doc",
            description="Delete a document",
            function=lambda: None,
            is_destructive=True,
        ))

    def _register(self, constraints):
        self.pm.register_permission_set(PermissionSet(
            name="temp",
            permissions=[
                Permission(tool_name="delete_doc", constraints=constraints)
            ],
            description="",
        ))

    def test_iso_string_window_currently_open(self):
        """ISO strings are accepted, as documented in the README."""
        self._register({"time_window": _window(-1, 30)})
        assert self.pm.has_permission("temp", "delete_doc") is True

    def test_datetime_window_currently_open(self):
        self._register({"time_window": _window(-1, 30, as_string=False)})
        assert self.pm.has_permission("temp", "delete_doc") is True

    def test_expired_window_denies(self):
        self._register({"time_window": _window(-30, -1)})
        assert self.pm.has_permission("temp", "delete_doc") is False

    def test_future_window_denies(self):
        self._register({"time_window": _window(1, 30)})
        assert self.pm.has_permission("temp", "delete_doc") is False

    def test_expired_window_is_absent_from_allowed_tools(self):
        """Listing and enforcement must agree."""
        self._register({"time_window": _window(-30, -1)})
        assert self.pm.get_allowed_tools("temp") == []
        assert self.pm.composite_server_tools("temp") == {}

    def test_malformed_window_fails_closed(self):
        self._register({"time_window": {"start": "not-a-date", "end": "nope"}})
        assert self.pm.has_permission("temp", "delete_doc") is False

    def test_incomplete_window_fails_closed(self):
        self._register({"time_window": {"start": datetime.now().isoformat()}})
        assert self.pm.has_permission("temp", "delete_doc") is False


class TestWildcard:
    """The "*" wildcard permission entry."""

    def setup_method(self):
        self.pm = PermissionModel()
        for name in ("alpha", "beta"):
            self.pm.register_tool(ToolMetadata(
                tool_name=name, description=name, function=lambda: None
            ))

    def test_wildcard_string_entry(self):
        self.pm.register_permission_set(PermissionSet(
            name="admin", permissions=["*"], description=""
        ))
        assert self.pm.has_permission("admin", "alpha") is True
        assert self.pm.get_allowed_tools("admin") == ["alpha", "beta"]

    def test_wildcard_permission_object(self):
        self.pm.register_permission_set(PermissionSet(
            name="admin", permissions=[Permission(tool_name="*")], description=""
        ))
        assert self.pm.has_permission("admin", "beta") is True

    def test_bare_string_entries_are_accepted(self):
        self.pm.register_permission_set(PermissionSet(
            name="analyst", permissions=["alpha"], description=""
        ))
        assert self.pm.has_permission("analyst", "alpha") is True
        assert self.pm.has_permission("analyst", "beta") is False

    def test_wildcard_lists_only_registered_tools(self):
        """A wildcard cannot conjure tools the registry does not hold."""
        self.pm.register_permission_set(PermissionSet(
            name="admin", permissions=["*"], description=""
        ))
        assert "gamma" not in self.pm.get_allowed_tools("admin")

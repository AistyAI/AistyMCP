"""Executes the Python examples in README.md.

The README's examples were previously broken in ways nothing caught: an
example that raised TypeError, and another that raised AttributeError.
Running them here keeps the documentation honest.
"""

import pathlib
import re

import pytest

README = pathlib.Path(__file__).resolve().parent.parent / "README.md"

# Fragments that are deliberately illustrative rather than runnable on their
# own, keyed by a distinctive substring.
FRAGMENT_MARKERS = (
    "PermissionSet(",
    "Permission(",
    "server.expose_tool(",
)

PREAMBLE = """
from datetime import datetime, timedelta

from aistymcp import (
    AccessControlMiddleware,
    MCPServer,
    Permission,
    PermissionDenied,
    PermissionModel,
    PermissionSet,
    ToolRegistry,
    UserContext,
    build_default_permission_sets,
)

pm = PermissionModel()
tr = ToolRegistry()
ac = AccessControlMiddleware(pm, tr)
server = MCPServer(pm, tr, ac)


def spin_up(*args, **kwargs):
    return "up"
"""


def python_blocks():
    """Extract fenced ```python blocks from the README."""
    text = README.read_text(encoding="utf-8")
    return re.findall(r"```python\n(.*?)```", text, re.DOTALL)


def test_readme_has_python_examples():
    assert python_blocks(), "README should contain Python examples"


@pytest.mark.parametrize("block", python_blocks())
def test_readme_block_executes(block):
    """Every README example runs without raising.

    Fragments are prefixed with a preamble defining the objects the
    surrounding prose has already introduced.
    """
    needs_preamble = not block.lstrip().startswith("from aistymcp import")
    source = (PREAMBLE + "\n" + block) if needs_preamble else block

    namespace = {}
    exec(compile(source, "README.md", "exec"), namespace)


def test_quick_start_denies_the_ungranted_tool():
    """The behaviour the Quick start claims: create allowed, delete refused."""
    namespace = {}
    exec(compile(PREAMBLE, "preamble", "exec"), namespace)

    server = namespace["server"]
    pm = namespace["pm"]

    server.expose_tool(
        tool_name="jira_create_ticket",
        func=lambda summary: "created: " + summary,
        description="Create a Jira ticket",
        access_type="write",
        reverses_tool="jira_delete_ticket",
    )
    server.expose_tool(
        tool_name="jira_delete_ticket",
        func=lambda ticket_id: "deleted: " + ticket_id,
        description="Delete a Jira ticket",
        access_type="write",
        is_destructive=True,
    )
    pm.register_permission_set(namespace["PermissionSet"](
        name="analyst",
        permissions=[namespace["Permission"](tool_name="jira_create_ticket")],
        description="May open tickets, may not delete them",
    ))

    alice = namespace["UserContext"](user_id="alice", perm_set_name="analyst")

    tools = server.create_composite_server(alice)
    assert sorted(tools) == ["jira_create_ticket"]
    assert tools["jira_create_ticket"]("Bug") == "created: Bug"

    with pytest.raises(namespace["PermissionDenied"]):
        server.call_tool(alice, "jira_delete_ticket", "ABC-1")

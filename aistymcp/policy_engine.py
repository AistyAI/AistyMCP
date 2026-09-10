"""Policy engine for AistyMCP.

Provides role-based (RBAC) and relationship-based (ReBAC) access
control policy evaluation. Supports contextual policies with time,
resource, and custom condition constraints.

The policy engine is the evaluation layer that the access control
middleware uses to determine if a permission check passes or fails.
"""

from typing import Dict, List, Optional, Any, Set, Callable, Union
from datetime import datetime, timedelta


def _require_model(user_context: "UserContext"):
    """Get the permission model a context resolves against.

    Args:
        user_context: The context to read the model from.

    Returns:
        The PermissionModel attached to the context.

    Raises:
        ValueError: If the context carries no permission model. Policy
            evaluation cannot fall back to a default without silently
            changing the answer, so it fails loudly instead.
    """
    model = getattr(user_context, "pm", None)
    if model is None:
        raise ValueError(
            "UserContext has no permission model. Construct it with "
            "UserContext(..., permission_model=pm) to use the policy engine."
        )
    return model


class PolicyEngine:
    """Policy engine that evaluates access control policies.

    Supports multiple policy types:
    - RBAC: Role-based access control (user role -> permission set)
    - ReBAC: Relationship-based access control (user -> resource -> permission)
    - Conditional: Time-based, resource-based, custom logic policies

    The engine is used by the permission model to evaluate constraints
    and by the access control middleware for deny-by-default enforcement.
    """

    def __init__(self):
        self._policies: Dict[str, "Policy"] = {}
        self._role_hierarchy: Dict[str, Set[str]] = {}
        self._resource_permissions: Dict[str, Set[str]] = {}

    def add_policy(
        self,
        name: str,
        policy: "Policy",
    ) -> None:
        """Add a policy to the engine.

        Args:
            name: Unique name for the policy.
            policy: Policy instance to add.
        """
        self._policies[name] = policy

    def evaluate(
        self,
        policy_name: str,
        user_context: "UserContext",
        tool_name: str,
        function: Optional[str] = None,
    ) -> bool:
        """Evaluate a specific policy for a user/tool combination.

        Args:
            policy_name: Name of the policy to evaluate.
            user_context: The user's context with permission set.
            tool_name: Name of the tool being accessed.
            function: Specific function within the tool (optional).

        Returns:
            True if the policy passes, False otherwise.
        """
        policy = self._policies.get(policy_name)
        if policy is None:
            return False

        return policy.evaluate(user_context, tool_name, function)

    def add_rbac_policy(
        self,
        role_name: str,
        permission_set_name: str,
        description: str = "",
    ) -> None:
        """Add an RBAC policy mapping a role to a permission set.

        Args:
            role_name: Name of the role.
            permission_set_name: Name of the permission set assigned to the role.
            description: Human-readable description.
        """
        if role_name not in self._role_hierarchy:
            self._role_hierarchy[role_name] = set()

        self._role_hierarchy[role_name].add(permission_set_name)

    def has_role_permission(
        self,
        user_context: "UserContext",
        role_name: str,
        tool_name: str,
        function: Optional[str] = None,
    ) -> bool:
        """Check if a user has permission through a specific role.

        Args:
            user_context: The user's context.
            role_name: Name of the role to check.
            tool_name: Name of the tool.
            function: Specific function within the tool (optional).

        Returns:
            True if the role grants permission, False otherwise.
        """
        permitted_sets = self._role_hierarchy.get(role_name, set())
        for perm_set_name in permitted_sets:
            if _require_model(user_context).has_permission(
                perm_set_name, tool_name, function
            ):
                return True
        return False

    def add_resource_permission(
        self,
        resource_name: str,
        permission_set_name: str,
    ) -> None:
        """Add a resource-based permission policy.

        Maps a resource (e.g., "database://production/customers") to
        a permission set that controls access to it.

        Args:
            resource_name: Name of the resource.
            permission_set_name: Permission set that controls access.
        """
        if resource_name not in self._resource_permissions:
            self._resource_permissions[resource_name] = set()

        self._resource_permissions[resource_name].add(permission_set_name)

    def check_resource_access(
        self,
        user_context: "UserContext",
        resource_name: str,
        tool_name: str,
        function: Optional[str] = None,
    ) -> bool:
        """Check if a user has access to a specific resource.

        Args:
            user_context: The user's context.
            resource_name: Name of the resource being accessed.
            tool_name: Name of the tool being used.
            function: Specific function within the tool (optional).

        Returns:
            True if the user has resource access, False otherwise.
        """
        permitted_sets = self._resource_permissions.get(resource_name, set())
        for perm_set_name in permitted_sets:
            if _require_model(user_context).has_permission(
                perm_set_name, tool_name, function
            ):
                return True
        return False

    def evaluate_conditional(
        self,
        condition_type: str,
        user_context: "UserContext",
        tool_name: str,
        function: Optional[str] = None,
        **kwargs: Any,
    ) -> bool:
        """Evaluate a conditional policy.

        Supports various condition types:
        - "time_window": Check if current time is within allowed window
        - "resource_limit": Check if resource usage is within limits
        - "custom": Run custom callable

        Args:
            condition_type: Type of condition to evaluate.
            user_context: The user's context.
            tool_name: Name of the tool.
            function: Specific function within the tool (optional).
            **kwargs: Additional condition-specific parameters.

        Returns:
            True if the condition passes, False otherwise.
        """
        if condition_type == "time_window":
            return self._eval_time_window(kwargs.get("window"), user_context, tool_name)
        elif condition_type == "custom":
            callback = kwargs.get("callback")
            if callback and callable(callback):
                return callback(user_context, tool_name, function)
        return False

    def _eval_time_window(
        self,
        window: Optional[dict],
        user_context: "UserContext",
        tool_name: str,
    ) -> bool:
        """Evaluate time window condition.

        Args:
            window: Dict with "start" and "end" datetime keys (ISO format).
            user_context: The user's context.
            tool_name: Name of the tool.

        Returns:
            True if current time is within the window.
        """
        if not window:
            return True

        try:
            from datetime import datetime

            start = datetime.fromisoformat(window["start"])
            end = datetime.fromisoformat(window["end"])
            now = datetime.now()

            return start <= now <= end
        except (ValueError, KeyError):
            return False


class Policy:
    """Base policy class for access control policies.

    Subclasses implement specific evaluation logic for different
    policy types (RBAC, ReBAC, conditional, etc.).
    """

    def evaluate(
        self,
        user_context: "UserContext",
        tool_name: str,
        function: Optional[str] = None,
    ) -> bool:
        """Evaluate the policy for a user/tool combination.

        Must be implemented by subclasses.

        Args:
            user_context: The user's context.
            tool_name: Name of the tool being accessed.
            function: Specific function within the tool (optional).

        Returns:
            True if the policy passes, False otherwise.
        """
        raise NotImplementedError("Subclasses must implement evaluate()")


class RBACPolicy(Policy):
    """RBAC policy that checks access based on user's role and role-permission mappings."""

    def __init__(self, role_permission_map: Dict[str, Set[str]]):
        self._role_perm_map = role_permission_map

    def evaluate(
        self,
        user_context: "UserContext",
        tool_name: str,
        function: Optional[str] = None,
    ) -> bool:
        """Evaluate RBAC policy.

        Checks if any of the user's roles grant permission for the tool.

        Args:
            user_context: The user's context (should have roles assigned).
            tool_name: Name of the tool being accessed.
            function: Specific function within the tool (optional).

        Returns:
            True if any role grants permission, False otherwise.
        """
        # Check roles assigned to user
        user_roles = getattr(user_context, "roles", [])

        for role in user_roles:
            perm_sets = self._role_perm_map.get(role, set())
            for perm_set in perm_sets:
                if _require_model(user_context).has_permission(
                    perm_set, tool_name, function
                ):
                    return True
        return False


class ConditionalPolicy(Policy):
    """Conditional policy that evaluates based on time, resource, or custom conditions."""

    def __init__(
        self,
        condition_type: str,
        parameters: dict,
        callback: Optional[Callable] = None,
    ):
        self.condition_type = condition_type
        self.parameters = parameters
        self.callback = callback

    def evaluate(
        self,
        user_context: "UserContext",
        tool_name: str,
        function: Optional[str] = None,
    ) -> bool:
        """Evaluate conditional policy.

        Args:
            user_context: The user's context.
            tool_name: Name of the tool being accessed.
            function: Specific function within the tool (optional).

        Returns:
            True if the condition passes, False otherwise.
        """
        if self.callback:
            return self.callback(
                user_context, tool_name, function, self.parameters
            )

        return self._default_evaluation(user_context, tool_name, function)

    def _default_evaluation(
        self,
        user_context: "UserContext",
        tool_name: str,
        function: Optional[str] = None,
    ) -> bool:
        """Default conditional evaluation based on condition type.

        Args:
            user_context: The user's context.
            tool_name: Name of the tool.
            function: Specific function within the tool (optional).

        Returns:
            True if condition passes, False otherwise.
        """
        if self.condition_type == "time_window":
            return self._eval_time_window(
                self.parameters.get("window"), user_context, tool_name
            )
        return False

    def _eval_time_window(
        self,
        window: Optional[dict],
        user_context: "UserContext",
        tool_name: str,
    ) -> bool:
        """Evaluate time window condition.

        Args:
            window: Dict with "start" and "end" datetime keys (ISO format).
            user_context: The user's context.
            tool_name: Name of the tool.

        Returns:
            True if current time is within the window.
        """
        if not window:
            return True

        try:
            from datetime import datetime

            start = datetime.fromisoformat(window["start"])
            end = datetime.fromisoformat(window["end"])
            now = datetime.now()

            return start <= now <= end
        except (ValueError, KeyError):
            return False
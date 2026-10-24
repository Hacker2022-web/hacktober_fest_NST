"""
Transparent Tool Proxy for ShadowHarness.
Wraps any callable tool or LangChain tool to automatically intercept calls,
evaluate firewall policy, and propagate taint.
"""

from typing import Callable, Any, Optional
import functools
import time
from .models import ToolCall, FirewallAction
from .firewall import ShadowWall


class SecurityException(Exception):
    def __init__(self, message: str, tool_call: Optional[ToolCall] = None):
        super().__init__(message)
        self.tool_call = tool_call


class ToolProxy:
    """
    Transparent proxy that intercepts tool execution, evaluates ShadowWall rules,
    and blocks unauthorized invocations before execution.
    """
    def __init__(self, tool_func: Callable, wall: ShadowWall, user_goal: str = "General Task"):
        self._tool = tool_func
        self._wall = wall
        self.user_goal = user_goal
        self.name = getattr(tool_func, "__name__", "anonymous_tool")

    def __call__(self, *args, **kwargs) -> Any:
        # Convert args/kwargs to dictionary
        arguments = dict(kwargs)
        if args:
            for i, arg in enumerate(args):
                arguments[f"arg_{i}"] = arg

        tool_call = ToolCall(
            tool_name=self.name,
            arguments=arguments,
            intent_description=f"Invocation of {self.name}"
        )

        # Intercept before execution
        verdict = self._wall.evaluate(self.user_goal, tool_call, [])

        if verdict.action == FirewallAction.QUARANTINE:
            raise SecurityException(
                f"[SHADOWWALL BLOCKED] Violation detected: {verdict.reason}",
                tool_call=tool_call
            )

        # Execute legitimate tool
        result = self._tool(*args, **kwargs)
        return result


def wrap_tools(tools_dict: dict, wall: ShadowWall, user_goal: str = "General Task") -> dict:
    """Convenience helper to wrap a collection of tools with ToolProxy."""
    return {
        name: ToolProxy(func, wall, user_goal=user_goal)
        for name, func in tools_dict.items()
    }

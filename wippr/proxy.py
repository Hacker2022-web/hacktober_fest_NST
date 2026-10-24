"""
Transparent Tool Proxy for WipprHarness.
Wraps any callable tool or LangChain tool to automatically intercept calls,
evaluate firewall policy, and propagate taint.
"""

from typing import Callable, Any, Optional
from .models import ToolCall, FirewallAction
from .firewall import WipprWall


class SecurityException(Exception):
    def __init__(self, message: str, tool_call: Optional[ToolCall] = None):
        super().__init__(message)
        self.tool_call = tool_call


class ToolProxy:
    """
    Transparent proxy that intercepts tool execution, evaluates WipprWall rules,
    and blocks unauthorized invocations before execution.
    """
    def __init__(self, tool_func: Callable, wall: WipprWall, user_goal: str = "General Task"):
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
            if isinstance(args[0], str) and "command" not in arguments:
                arguments["command"] = args[0]

        tool_call = ToolCall(
            tool_name=self.name,
            arguments=arguments,
            intent_description=f"Invocation of {self.name}"
        )

        # Intercept before execution
        verdict = self._wall.evaluate(self.user_goal, tool_call, [])

        if verdict.action != FirewallAction.ALLOW:
            raise SecurityException(
                f"[WIPPR BLOCKED] Violation detected: {verdict.reason}",
                tool_call=tool_call
            )

        # Execute legitimate tool
        result = self._tool(*args, **kwargs)
        return result


def wrap_tools(tools_dict: dict, wall: WipprWall, user_goal: str = "General Task") -> dict:
    """Convenience helper to wrap a collection of tools with ToolProxy."""
    return {
        name: ToolProxy(func, wall, user_goal=user_goal)
        for name, func in tools_dict.items()
    }

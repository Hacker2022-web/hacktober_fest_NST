"""
Declarative Policy Engine & Rule Schema for WipprHarness.
Allows registering prioritized security rules evaluated on every candidate tool invocation.
"""

from enum import Enum
from typing import Callable, List, Optional, Any, Dict
from dataclasses import dataclass, field
import time


class Action(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    FLAG = "FLAG"


class TaintLevel(str, Enum):
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class InterceptionContext:
    tool_name: str
    arguments: Dict[str, Any]
    user_goal: str
    taint_level: TaintLevel
    tainted_args: List[str]
    source_chain: List[str]
    divergence_score: float
    scratchpad: List[str]
    step_index: int


@dataclass
class Rule:
    id: str
    description: str
    condition: Callable[[InterceptionContext], bool]
    action: Action
    priority: int = 50  # Higher evaluated first


@dataclass
class PolicyDecision:
    action: Action
    reason: str
    triggered_rules: List[str] = field(default_factory=list)
    divergence_score: float = 0.0
    taint_level: TaintLevel = TaintLevel.CLEAN
    source_chain: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    evaluation_latency_ms: float = 0.0


SENSITIVE_TOOLS = {
    "send_http", "post_webhook", "send_email", "bash_exec",
    "execute_shell", "dump_env_vars", "delete_file", "drop_table"
}


def default_block_tainted_sensitive_tools(ctx: InterceptionContext) -> bool:
    """Blocks any tainted data from flowing into sensitive exfiltration or shell execution tools."""
    return ctx.taint_level in {TaintLevel.HIGH, TaintLevel.CRITICAL} and ctx.tool_name in SENSITIVE_TOOLS


def default_block_high_divergence(ctx: InterceptionContext) -> bool:
    """Blocks any tool call whose intent divergence from the root goal exceeds 0.70."""
    return ctx.divergence_score >= 0.70


def default_flag_medium_divergence(ctx: InterceptionContext) -> bool:
    """Flags for audit any tool call with moderate intent divergence (0.40 - 0.70)."""
    return 0.40 <= ctx.divergence_score < 0.70


def default_flag_tainted_args(ctx: InterceptionContext) -> bool:
    """Flags any tool invocation that consumes medium-level tainted arguments."""
    return ctx.taint_level == TaintLevel.MEDIUM


class PolicyEngine:
    def __init__(self):
        self.rules: List[Rule] = []
        self._init_default_rules()

    def _init_default_rules(self):
        self.rules = [
            Rule(
                id="block-tainted-sensitive-tools",
                description="Block tainted data from reaching P0 sensitive sinks (shell, exfiltration)",
                condition=default_block_tainted_sensitive_tools,
                action=Action.BLOCK,
                priority=100
            ),
            Rule(
                id="block-high-divergence",
                description="Block tool calls with severe intent drift (> 0.70)",
                condition=default_block_high_divergence,
                action=Action.BLOCK,
                priority=90
            ),
            Rule(
                id="flag-medium-divergence",
                description="Flag tool calls with suspicious intent drift (0.40 - 0.70)",
                condition=default_flag_medium_divergence,
                action=Action.FLAG,
                priority=50
            ),
            Rule(
                id="flag-tainted-args",
                description="Flag tool calls consuming medium-tainted arguments",
                condition=default_flag_tainted_args,
                action=Action.FLAG,
                priority=40
            )
        ]

    def add_rule(self, rule: Rule):
        """Register a custom security rule with priority sorting."""
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority, reverse=True)

    def evaluate(self, ctx: InterceptionContext) -> PolicyDecision:
        """Evaluates candidate tool call against all prioritized rules."""
        start_time = time.perf_counter()
        triggered_rules = []
        final_action = Action.ALLOW
        reason = "Tool call verified and compliant with active security policies."

        # Evaluate rules in order of priority
        for rule in sorted(self.rules, key=lambda r: r.priority, reverse=True):
            try:
                if rule.condition(ctx):
                    triggered_rules.append(rule.id)
                    if rule.action == Action.BLOCK:
                        final_action = Action.BLOCK
                        reason = f"Security Violation: Rule '{rule.id}' triggered. {rule.description}"
                        break  # Highest-priority BLOCK immediately terminates evaluation
                    elif rule.action == Action.FLAG and final_action == Action.ALLOW:
                        final_action = Action.FLAG
                        reason = f"Security Warning: Rule '{rule.id}' triggered. Audit recommended."
            except Exception as e:
                # Fail-closed policy for error handling
                triggered_rules.append(f"error-{rule.id}")
                final_action = Action.BLOCK
                reason = f"Policy evaluation error on rule '{rule.id}': {str(e)}"
                break

        latency_ms = round((time.perf_counter() - start_time) * 1000, 3)

        return PolicyDecision(
            action=final_action,
            reason=reason,
            triggered_rules=triggered_rules,
            divergence_score=ctx.divergence_score,
            taint_level=ctx.taint_level,
            source_chain=ctx.source_chain,
            evaluation_latency_ms=latency_ms
        )

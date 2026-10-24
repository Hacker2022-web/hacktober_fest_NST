"""
ShadowHarness: In-Flight Behavioral Firewall and Execution Harness for AI Agents.
"""

from .models import (
    ToolCall,
    ToolResult,
    FirewallVerdict,
    FirewallAction,
    CheckpointFrame,
    TaintRecord,
    SinkRiskLevel
)
from .taint_tracker import TaintTracker
from .firewall import ShadowWall
from .checkpointer import CheckpointManager
from .sanitizer import ContextSanitizer
from .harness import ShadowHarness
from .policy import PolicyEngine, Rule, Action, InterceptionContext, PolicyDecision, TaintLevel
from .quarantine import QuarantineManager, QuarantinedTrajectory
from .backends import StorageBackend, MemoryBackend, SQLiteBackend
from .proxy import ToolProxy, wrap_tools, SecurityException
from .adapters.openclaw import OpenClawAdapter, OPENCLAW_DANGEROUS_TOOLS
from .adapters.deepseek import DeepSeekHarnessAdapter, DEEPSEEK_HARNESS_DANGEROUS_TOOLS
from .hub import UnifiedHarnessHub

__all__ = [
    "UnifiedHarnessHub",
    "OpenClawAdapter",
    "OPENCLAW_DANGEROUS_TOOLS",
    "DeepSeekHarnessAdapter",
    "DEEPSEEK_HARNESS_DANGEROUS_TOOLS",
    "ShadowHarness",
    "ShadowWall",
    "TaintTracker",
    "CheckpointManager",
    "ContextSanitizer",
    "PolicyEngine",
    "Rule",
    "Action",
    "TaintLevel",
    "InterceptionContext",
    "PolicyDecision",
    "QuarantineManager",
    "QuarantinedTrajectory",
    "StorageBackend",
    "MemoryBackend",
    "SQLiteBackend",
    "ToolProxy",
    "wrap_tools",
    "SecurityException",
    "ToolCall",
    "ToolResult",
    "FirewallVerdict",
    "FirewallAction",
    "CheckpointFrame",
    "TaintRecord",
    "SinkRiskLevel",
]

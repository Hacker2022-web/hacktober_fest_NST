"""
wippr: In-Flight Behavioral Firewall and Execution Harness for Autonomous Agents.
"""

__version__ = "1.1.0"

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
from .firewall import WipprWall
from .checkpointer import CheckpointManager
from .sanitizer import ContextSanitizer
from .harness import WipprHarness
from .commands import analyze_command, CommandFinding
from .runtime import GuardRuntime, Decision
from .store import Store
from .policy import PolicyEngine, Rule, Action, InterceptionContext, PolicyDecision, TaintLevel
from .quarantine import QuarantineManager, QuarantinedTrajectory
from .backends import StorageBackend, MemoryBackend, SQLiteBackend
from .proxy import ToolProxy, wrap_tools, SecurityException
from .adapters.openclaw import OpenClawAdapter, OPENCLAW_DANGEROUS_TOOLS
from .adapters.deepseek import DeepSeekHarnessAdapter, DEEPSEEK_HARNESS_DANGEROUS_TOOLS
from .hub import UnifiedHarnessHub

__all__ = [
    "GuardRuntime",
    "Decision",
    "Store",
    "__version__",
    "analyze_command",
    "CommandFinding",
    "UnifiedHarnessHub",
    "OpenClawAdapter",
    "OPENCLAW_DANGEROUS_TOOLS",
    "DeepSeekHarnessAdapter",
    "DEEPSEEK_HARNESS_DANGEROUS_TOOLS",
    "WipprHarness",
    "WipprWall",
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

"""
ShadowHarness Adapters for Autonomous Agent Frameworks.
"""

from .openclaw import OpenClawAdapter, OPENCLAW_DANGEROUS_TOOLS
from .deepseek import DeepSeekHarnessAdapter, DEEPSEEK_HARNESS_DANGEROUS_TOOLS

__all__ = [
    "OpenClawAdapter",
    "OPENCLAW_DANGEROUS_TOOLS",
    "DeepSeekHarnessAdapter",
    "DEEPSEEK_HARNESS_DANGEROUS_TOOLS"
]

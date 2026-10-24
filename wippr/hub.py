"""
Unified Harness Hub: Multi-Framework Security Orchestrator.

Combines the best capabilities of:
  - OpenClaw (Multi-Channel Ingress: Telegram, WhatsApp, Slack, Discord)
  - DeepSeek-Harness (Plugin Lifecycle, Codebase & Shell Tooling)
  - WipprHarness (In-Flight Firewall, Taint Lineage, Time-Travel Rollback)
"""

from typing import Dict, Any, List, Optional
from .harness import WipprHarness
from .models import ToolCall, FirewallVerdict, FirewallAction
from .adapters.openclaw import OpenClawAdapter
from .adapters.deepseek import DeepSeekHarnessAdapter


class UnifiedHarnessHub:
    """
    Unified Security Controller governing both OpenClaw channel workflows
    and DeepSeek Harness developer plugins under a single behavioral firewall.
    """

    def __init__(self, harness: Optional[WipprHarness] = None, divergence_threshold: float = 0.65):
        self.harness = harness or WipprHarness(divergence_threshold=divergence_threshold)
        self.openclaw = OpenClawAdapter(self.harness, divergence_threshold=divergence_threshold)
        self.deepseek = DeepSeekHarnessAdapter(self.harness, divergence_threshold=divergence_threshold)

    def route_inbound_event(
        self,
        framework: str,
        source: Optional[str] = None,
        content: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Any:
        """
        Routes inbound events from either OpenClaw (Telegram/Slack) or DeepSeek (Code/Repo/Docs).
        """
        meta = metadata or {}
        meta.update(kwargs)

        if framework.lower() == "openclaw":
            channel = kwargs.get("channel") or source or "telegram"
            sender_id = meta.get("sender_id", "@unknown")
            msg_content = kwargs.get("content") or content or ""
            is_owner = meta.get("sender_is_owner", meta.get("is_owner", False))
            is_group = meta.get("is_group", False)
            return self.openclaw.process_inbound_message(
                channel=channel,
                sender_id=sender_id,
                content=msg_content,
                sender_is_owner=is_owner,
                is_group=is_group
            )
        elif framework.lower() == "deepseek":
            repo = kwargs.get("repo", "workspace")
            file_path = kwargs.get("file_path", "source.py")
            src_id = source or f"repo:{repo}/{file_path}"
            code_content = kwargs.get("content") or content or ""
            untrusted = kwargs.get("untrusted", not meta.get("is_trusted", False))
            return self.deepseek.process_document_ingress(
                source_id=src_id,
                content=code_content,
                is_trusted_workspace=not untrusted
            )
        else:
            src = source or "generic_input"
            body = content or kwargs.get("content", "")
            return self.harness.record_input_ingestion(src, body)

    def intercept_tool(
        self,
        *args,
        framework: str = "generic",
        tool_name: Optional[str] = None,
        arguments: Optional[Dict[str, Any]] = None,
        user_goal: Optional[str] = None,
        root_goal: Optional[str] = None,
        scratchpad: Optional[List[str]] = None,
        step_index: int = 1,
        **kwargs
    ) -> FirewallVerdict:
        """
        Universal in-flight evaluation hook compatible with both OpenClaw and DeepSeek-Harness.
        """
        if len(args) == 1:
            tool_name = args[0]
        elif len(args) == 2:
            tool_name, arguments = args[0], args[1]
        elif len(args) == 3:
            if args[0] in {"openclaw", "deepseek", "generic"}:
                framework, tool_name, arguments = args[0], args[1], args[2]
            else:
                tool_name, arguments, user_goal = args[0], args[1], args[2]
        elif len(args) >= 4:
            framework, tool_name, arguments, user_goal = args[0], args[1], args[2], args[3]

        resolved_goal = user_goal or root_goal or kwargs.get("goal", "Execute agent goal")
        resolved_tool = tool_name or kwargs.get("tool", "unknown_tool")
        resolved_args = arguments or {}

        tool_call = ToolCall(tool_name=resolved_tool, arguments=resolved_args)
        verdict = self.harness.inspect_and_gate(resolved_goal, tool_call, scratchpad or [])

        if verdict.action == FirewallAction.QUARANTINE:
            try:
                self.harness.handle_quarantine_and_recover(
                    step_index=step_index,
                    user_goal=resolved_goal,
                    tool_call=tool_call,
                    verdict=verdict
                )
            except RuntimeError:
                pass

        return verdict

    def get_security_status(self) -> Dict[str, Any]:
        return {
            "harness_active": self.harness.enabled,
            "active_taint_count": len(self.harness.taint_tracker.active_taint_records),
            "forensics_logged": len(self.harness.export_forensics()),
            "supported_frameworks": ["openclaw", "deepseek-harness", "langchain", "openai", "anthropic"]
        }

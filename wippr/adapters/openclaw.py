"""
OpenClaw Adapter for WipprHarness & WipprWall.

Provides native in-flight behavioral firewall protection, taint tracking,
and instantaneous time-travel recovery for OpenClaw multi-channel agents.

Maps OpenClaw's `DEFAULT_GATEWAY_HTTP_TOOL_DENY` and `GATEWAY_OWNER_ONLY_CORE_TOOLS`
directly into WipprWall's P0/P1/P2 sink risk matrix.
"""

from typing import Dict, Any, List, Set, Optional, Callable
import re
import time

from ..models import (
    ToolCall,
    FirewallVerdict,
    FirewallAction,
    SinkRiskLevel,
    TaintRecord
)
from ..taint_tracker import TaintTracker
from ..firewall import WipprWall
from ..harness import WipprHarness
from ..policy import Rule, Action, InterceptionContext, TaintLevel


# -------------------------------------------------------------------------
# OpenClaw Dangerous Tools Matrix
# Extracted directly from OpenClaw:
#   - src/security/dangerous-tools.ts (DEFAULT_GATEWAY_HTTP_TOOL_DENY)
#   - src/security/dangerous-tools.ts (GATEWAY_OWNER_ONLY_CORE_TOOLS)
# -------------------------------------------------------------------------

OPENCLAW_P0_FORBIDDEN_TOOLS: Set[str] = {
    # Direct command execution & child process spawn (immediate RCE surface)
    "exec",
    "spawn",
    "shell",
    "terminal",
    # Host and device control
    "nodes",
    "portal",
    "computer",
    "mobile_ui",
}

OPENCLAW_P1_AUDITED_TOOLS: Set[str] = {
    # Arbitrary file mutation and deletion on host
    "fs_write",
    "fs_delete",
    "fs_move",
    "apply_patch",
    # Multi-agent & session orchestration
    "sessions_spawn",
    "sessions_send",
    "conversations_send",
    "conversations_turn",
    # Control plane & plugins
    "gateway",
    "plugins",
    "automations",
    "openclaw",
    "intent",
}

OPENCLAW_P2_PERMITTED_TOOLS: Set[str] = {
    "fs_read",
    "web_fetch",
    "web_search",
    "conversations_list",
    "sessions_list",
    "summarize",
    "log_message",
}

OPENCLAW_DANGEROUS_TOOLS: Set[str] = OPENCLAW_P0_FORBIDDEN_TOOLS.union(OPENCLAW_P1_AUDITED_TOOLS)

# OpenClaw Special Tokens (from src/security/external-content.ts)
OPENCLAW_SPECIAL_TOKENS: List[str] = [
    "<|im_start|>",
    "<|im_end|>",
    "<|endoftext|>",
    "<|begin_of_text|>",
    "<|end_of_text|>",
    "<|start_header_id|>",
    "<|end_header_id|>",
    "<|eot_id|>",
    "<|python_tag|>",
    "<|eom_id|>",
    "[INST]",
    "[/INST]",
    "<<SYS>>",
    "<</SYS>>",
    "<s>",
    "</s>",
    "<|channel|>",
    "<|message|>",
    "<|return|>",
    "<|call|>",
    "<start_of_turn>",
    "<end_of_turn>",
]

# OpenClaw Suspicious Injection Patterns (from src/security/external-content.ts)
OPENCLAW_SUSPICIOUS_PATTERNS: List[re.Pattern] = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|above)", re.IGNORECASE),
    re.compile(r"forget\s+(everything|all|your)\s+(instructions?|rules?|guidelines?)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a|an)\s+", re.IGNORECASE),
    re.compile(r"new\s+instructions?:", re.IGNORECASE),
    re.compile(r"system\s*:?\s*(prompt|override|command)", re.IGNORECASE),
    re.compile(r"\bexec\b.*command\s*=", re.IGNORECASE),
    re.compile(r"elevated\s*=\s*true", re.IGNORECASE),
    re.compile(r"rm\s+-rf", re.IGNORECASE),
    re.compile(r"delete\s+all\s+(emails?|files?|data)", re.IGNORECASE),
    re.compile(r"<\/?system>", re.IGNORECASE),
    re.compile(r"\]\s*\n\s*\[?(system|assistant|user)\]?:", re.IGNORECASE),
    re.compile(r"\[\s*(System\s*Message|System|Assistant|Internal)\s*\]", re.IGNORECASE),
    re.compile(r"^\s*System:\s+", re.MULTILINE | re.IGNORECASE),
]


class OpenClawAdapter:
    """
    OpenClaw security adapter integrating WipprHarness directly into OpenClaw turn lifecycle.
    """

    def __init__(
        self,
        harness: Optional[WipprHarness] = None,
        verified_owner_ids: Optional[Set[str]] = None,
        divergence_threshold: float = 0.65
    ):
        self.harness = harness or WipprHarness(divergence_threshold=divergence_threshold)
        self.verified_owner_ids: Set[str] = verified_owner_ids or {"owner", "admin", "verified_user"}
        self._registered_openclaw_policies()

    def _registered_openclaw_policies(self):
        """Register OpenClaw tools into WipprHarness's TaintTracker and PolicyEngine."""
        # 1. Register P0 forbidden sinks
        for tool in OPENCLAW_P0_FORBIDDEN_TOOLS:
            self.harness.taint_tracker.register_sink(tool, SinkRiskLevel.P0_FORBIDDEN)
            # Add to sensitive tools in policy
            rule = Rule(
                id=f"openclaw-block-p0-{tool}",
                description=f"Block tainted data from reaching OpenClaw P0 tool '{tool}'",
                condition=lambda ctx, t=tool: ctx.tool_name == t and ctx.taint_level in {TaintLevel.HIGH, TaintLevel.CRITICAL},
                action=Action.BLOCK,
                priority=100
            )
            self.harness.add_rule(rule)

        # 2. Register P1 audited sinks
        for tool in OPENCLAW_P1_AUDITED_TOOLS:
            self.harness.taint_tracker.register_sink(tool, SinkRiskLevel.P1_AUDITED)

        # 3. Register P2 permitted sinks
        for tool in OPENCLAW_P2_PERMITTED_TOOLS:
            self.harness.taint_tracker.register_sink(tool, SinkRiskLevel.P2_PERMITTED)

        # 4. Register OpenClaw untrusted source types
        self.harness.taint_tracker.register_untrusted_source("openclaw_channel_ingress")
        self.harness.taint_tracker.register_untrusted_source("openclaw_telegram_ingress")
        self.harness.taint_tracker.register_untrusted_source("openclaw_slack_ingress")
        self.harness.taint_tracker.register_untrusted_source("openclaw_whatsapp_ingress")
        self.harness.taint_tracker.register_untrusted_source("openclaw_discord_ingress")
        self.harness.taint_tracker.register_untrusted_source("openclaw_external_content")
        self.harness.taint_tracker.register_untrusted_source("openclaw_web_fetch")

    def process_inbound_message(
        self,
        channel: str,
        sender_id: str,
        content: str,
        sender_is_owner: bool = False,
        is_group: bool = False,
        session_key: str = "default"
    ) -> Optional[TaintRecord]:
        """
        Evaluates an inbound OpenClaw message. If the sender is not verified as the owner,
        or if the message is in a public group or contains injection heuristics, tags as tainted.
        """
        is_trusted = sender_is_owner or (sender_id in self.verified_owner_ids and not is_group)

        # Check for OpenClaw injection markers or special token injection
        markers = []
        for pattern in OPENCLAW_SUSPICIOUS_PATTERNS:
            if pattern.search(content):
                markers.append("OPENCLAW_SUSPICIOUS_PATTERN")
                break

        for token in OPENCLAW_SPECIAL_TOKENS:
            if token in content:
                markers.append("OPENCLAW_SPECIAL_TOKEN_SPOOFING")
                break

        # If trusted and no markers detected, message is clean
        if is_trusted and not markers:
            return None

        # Untrusted channel input -> Register taint
        source_identifier = f"openclaw_{channel}_ingress"
        self.harness.taint_tracker.register_untrusted_source(source_identifier)
        record = self.harness.record_input_ingestion(source_identifier, content)
        if record and markers:
            for m in markers:
                if m not in record.risk_markers:
                    record.risk_markers.append(m)
            record.taint_level = "critical"

        return record

    def intercept_openclaw_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        session_key: str = "default",
        root_goal: str = "Execute OpenClaw Agent Tasks",
        scratchpad: Optional[List[str]] = None,
        step_index: int = 1
    ) -> FirewallVerdict:
        """
        Intercepts candidate OpenClaw tool call in-flight.
        If a quarantine violation is detected, automatically triggers recovery.
        """
        tool_call = ToolCall(tool_name=tool_name, arguments=arguments)
        verdict = self.harness.inspect_and_gate(root_goal, tool_call, scratchpad or [])

        if verdict.action == FirewallAction.QUARANTINE:
            # Trigger mid-thought quarantine and state recovery
            try:
                self.harness.handle_quarantine_and_recover(
                    step_index=step_index,
                    user_goal=root_goal,
                    tool_call=tool_call,
                    verdict=verdict
                )
            except Exception:
                pass

        return verdict

    def format_channel_security_alert(
        self,
        incident: Dict[str, Any],
        channel: str = "telegram"
    ) -> str:
        """
        Formats an incident alert for OpenClaw chat channels (Telegram, Slack, WhatsApp, Discord).
        """
        blocked_tool = incident.get("blocked_tool", "unknown_tool")
        reason = incident.get("violation_reason", "Behavioral Firewall Violation")
        latency = incident.get("recovery_latency_ms", 0.45)
        recovered_step = incident.get("recovered_to_step", 1)

        if channel.lower() == "telegram":
            return (
                f"🛡️ *[WIPPR SECURITY ALERT]*\n"
                f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"⚠️ *In-Flight Threat Intercepted Mid-Thought*\n"
                f"• *Blocked Tool:* `{blocked_tool}` (OpenClaw P0/P1 Sink)\n"
                f"• *Threat Classification:* Prompt Injection / Unauthorized Tool Invocation\n"
                f"• *Details:* {reason}\n"
                f"• *Recovery Status:* ⏱️ Restored to safe Checkpoint Frame (Step #{recovered_step}) in `{latency:.2f}ms`\n"
                f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"✅ OpenClaw agent state sanitized. Malicious payload quarantined."
            )
        elif channel.lower() == "slack":
            return (
                f":shield: *[WIPPR SECURITY ALERT]*\n"
                f"*Action Intercepted:* `{blocked_tool}` | *Threat:* Prompt Injection\n"
                f"*Reason:* {reason}\n"
                f"*Recovery:* Restored to safe state in `{latency:.2f}ms`."
            )
        else:
            return (
                f"[WIPPR SECURITY ALERT] Blocked high-risk OpenClaw tool '{blocked_tool}'. "
                f"Reason: {reason}. Agent memory rolled back safely in {latency:.2f}ms."
            )

    def wrap_openclaw_tool(self, tool_name: str, tool_func: Callable) -> Callable:
        """
        Wraps an OpenClaw tool callable with transparent in-flight firewalling.
        """
        return self.harness.protect(tool_func, name=tool_name, goal="Execute OpenClaw Agent Tasks")

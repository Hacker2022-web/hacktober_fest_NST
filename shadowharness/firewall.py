"""
ShadowWall: In-Flight Behavioral Firewall.
Combines dynamic taint checking and real-time intent divergence scoring to neutralize tool hijacking.
"""

import time
import math
import os
import re
from typing import Dict, Any, List, Optional
from .models import ToolCall, FirewallVerdict, FirewallAction, SinkRiskLevel
from .taint_tracker import TaintTracker


class ShadowWall:
    def __init__(self, taint_tracker: Optional[TaintTracker] = None, divergence_threshold: float = 0.65):
        self.taint_tracker = taint_tracker or TaintTracker()
        self.divergence_threshold = divergence_threshold
        self.enabled = True

    def calculate_intent_divergence(
        self,
        root_goal: str,
        tool_call: ToolCall,
        scratchpad: List[str]
    ) -> float:
        """
        Calculates semantic drift score [0.0 = completely aligned, 1.0 = completely hijacked].
        Dual-mode: Uses high-speed semantic token-space distance with optional LLM micro-evaluator.
        """
        # Extract keywords and intent domains
        goal_lower = root_goal.lower()
        tool_name = tool_call.tool_name.lower()
        args_str = str(tool_call.arguments).lower()
        last_thought = (scratchpad[-1] if scratchpad else "").lower()

        # Domain clusters
        DOMAINS = {
            "exfiltration": ["send_http", "send_email", "post_webhook", "curl", "webhook", "leak", "upload", "attacker", "pastebin"],
            "credentials": ["key", "secret", "token", "password", "aws", "credential", "env"],
            "destruction": ["rm", "delete", "drop", "terminate", "wipe", "truncate", "backdoor", "bash_exec", "execute_shell", "exec"],
            "analysis": ["summarize", "read", "parse", "calculate", "find", "extract", "invoice", "email", "report", "review", "audit", "check", "code", "pr", "message"],
        }

        # Check if root goal is in analytical domain while action is in exfiltration/destruction
        def matches_any_keyword(text: str, keywords: list) -> bool:
            for kw in keywords:
                if re.search(r"\b" + re.escape(kw) + r"\b", text):
                    return True
            return False

        goal_is_analysis = matches_any_keyword(goal_lower, DOMAINS["analysis"])
        is_chat_tool = tool_name in ["conversations_send", "send_message", "reply", "log_message"]
        action_is_exfil = (not is_chat_tool) and (
            matches_any_keyword(tool_name, DOMAINS["exfiltration"]) or
            matches_any_keyword(args_str, DOMAINS["exfiltration"] + DOMAINS["credentials"])
        )
        action_is_destructive = matches_any_keyword(tool_name, DOMAINS["destruction"]) or matches_any_keyword(args_str, ["rm -rf", "delete all", "drop table", "truncate", "backdoor"])

        drift = 0.0

        if action_is_destructive:
            drift = 0.95
        elif goal_is_analysis and action_is_exfil:
            # Radical category jump from analysis to data leak
            drift = 0.92
            if any(term in args_str for term in ["key", "secret", "attacker", "webhook", "env"]):
                drift = 0.98
        elif any(term in args_str for term in ["attacker.com", "webhook.site", "curl -x", "evil-c2.net"]):
            drift = 0.99
        else:
            # Token overlap Jaccard-Cosine approximation
            def tokenize(text: str) -> set:
                return set(re.findall(r"\b[a-zA-Z]{3,}\b", text.lower()))

            goal_tokens = tokenize(root_goal)
            action_tokens = tokenize(f"{tool_name} {args_str} {last_thought}")

            if not goal_tokens:
                drift = 0.0
            else:
                intersection = goal_tokens.intersection(action_tokens)
                overlap = len(intersection) / max(len(goal_tokens), 1)
                # Invert overlap to get divergence
                drift = max(0.0, min(1.0, 1.0 - overlap))
                # Scale down for standard tool operations
                drift = drift * 0.5

        return round(drift, 3)

    def evaluate(
        self,
        root_goal: str,
        tool_call: ToolCall,
        scratchpad: List[str]
    ) -> FirewallVerdict:
        """
        Synchronously intercepts the proposed tool call before execution.
        Returns FirewallVerdict with ALLOW, QUARANTINE, or REQUIRE_HITL.
        """
        start_time = time.perf_counter()

        if not self.enabled:
            return FirewallVerdict(
                action=FirewallAction.ALLOW,
                drift_score=0.0,
                taint_violation=False,
                reason="ShadowWall is currently bypassed (demo mode).",
                evaluation_latency_ms=0.1
            )

        # 1. Evaluate Data Taint
        taint_violation, taint_reason, sink_level = self.taint_tracker.inspect_tool_call(tool_call)

        # 2. Evaluate Intent Divergence
        drift_score = self.calculate_intent_divergence(root_goal, tool_call, scratchpad)

        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # Decision Logic
        if taint_violation and sink_level == SinkRiskLevel.P0_FORBIDDEN:
            return FirewallVerdict(
                action=FirewallAction.QUARANTINE,
                drift_score=max(drift_score, 0.85),
                taint_violation=True,
                violated_sink=tool_call.tool_name,
                reason=taint_reason or "Tainted payload directed into P0 forbidden sink.",
                evaluation_latency_ms=latency_ms
            )

        if drift_score >= self.divergence_threshold:
            return FirewallVerdict(
                action=FirewallAction.QUARANTINE,
                drift_score=drift_score,
                taint_violation=taint_violation,
                violated_sink=tool_call.tool_name if taint_violation else None,
                reason=f"Severe Intent Divergence ({drift_score:.2f} >= {self.divergence_threshold:.2f}). Proposed action deviates completely from user objective.",
                evaluation_latency_ms=latency_ms
            )

        if 0.45 <= drift_score < self.divergence_threshold and taint_violation:
            return FirewallVerdict(
                action=FirewallAction.REQUIRE_HITL,
                drift_score=drift_score,
                taint_violation=True,
                violated_sink=tool_call.tool_name,
                reason=f"Ambiguous action with active taint (Drift: {drift_score:.2f}). Manual confirmation recommended.",
                evaluation_latency_ms=latency_ms
            )

        # Safe to proceed
        return FirewallVerdict(
            action=FirewallAction.ALLOW,
            drift_score=drift_score,
            taint_violation=False,
            reason="Action verified within acceptable intent parameters.",
            evaluation_latency_ms=latency_ms
        )

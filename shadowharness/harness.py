"""
ShadowHarness: Core Execution Harness & Behavioral Firewall Controller.
Intercepts tool invocations, manages checkpoints, triggers quarantine, and drives time-travel recovery.
"""

from typing import Callable, Dict, Any, List, Optional
import time
import functools
from .models import (
    ToolCall,
    ToolResult,
    FirewallVerdict,
    FirewallAction,
    CheckpointFrame,
    TaintRecord
)
from .taint_tracker import TaintTracker
from .firewall import ShadowWall
from .checkpointer import CheckpointManager
from .sanitizer import ContextSanitizer
from .policy import PolicyEngine, Rule, Action
from .quarantine import QuarantineManager


class ShadowHarness:
    def __init__(self, divergence_threshold: float = 0.65):
        self.taint_tracker = TaintTracker()
        self.firewall = ShadowWall(self.taint_tracker, divergence_threshold=divergence_threshold)
        self.checkpointer = CheckpointManager()
        self.policy_engine = PolicyEngine()
        self.quarantine_mgr = QuarantineManager()
        self.event_listeners: List[Callable[[str, Dict[str, Any]], None]] = []
        self.forensics_archive: List[Dict[str, Any]] = []
        self.enabled = True

    def add_rule(self, rule: Rule):
        """Register a custom security rule with the policy engine."""
        self.policy_engine.add_rule(rule)

    def export_forensics(self) -> List[Dict[str, Any]]:
        """Returns the immutable forensic incident archive for security analysis."""
        return list(self.forensics_archive)

    def add_event_listener(self, listener: Callable[[str, Dict[str, Any]], None]):
        self.event_listeners.append(listener)

    def emit_event(self, event_type: str, payload: Dict[str, Any]):
        for listener in self.event_listeners:
            try:
                listener(event_type, payload)
            except Exception:
                pass

    def record_input_ingestion(self, tool_name: str, payload: Any) -> Optional[TaintRecord]:
        """Call this when an agent runs an untrusted data ingestion tool (e.g. read_email, web_search)."""
        record = self.taint_tracker.record_ingestion(tool_name, payload)
        if record:
            self.emit_event("TAINT_DETECTED", {
                "source": tool_name,
                "markers": record.risk_markers,
                "snippet": record.snippet,
                "record_id": record.id,
                "source_chain": " -> ".join(record.source_chain)
            })
        return record

    def snapshot_step(
        self,
        step_index: int,
        user_goal: str,
        messages: List[Dict[str, Any]],
        scratchpad: List[str],
        executed_tools: List[Dict[str, Any]]
    ) -> CheckpointFrame:
        """Captures a pre-tool execution checkpoint frame."""
        frame = self.checkpointer.capture_checkpoint(
            step_index=step_index,
            user_goal=user_goal,
            messages=messages,
            scratchpad=scratchpad,
            tainted_sources=list(self.taint_tracker.active_taint_records),
            executed_tools=executed_tools
        )
        self.emit_event("CHECKPOINT_CAPTURED", {
            "checkpoint_id": frame.checkpoint_id,
            "step_index": frame.step_index,
            "status": frame.status
        })
        return frame

    def inspect_and_gate(
        self,
        root_goal: str,
        tool_call: ToolCall,
        scratchpad: List[str]
    ) -> FirewallVerdict:
        """Runs the ShadowWall behavioral firewall evaluation before any tool executes."""
        self.emit_event("INTERCEPTING_TOOL_CALL", {
            "tool_name": tool_call.tool_name,
            "arguments": tool_call.arguments,
            "intent_description": tool_call.intent_description
        })

        verdict = self.firewall.evaluate(root_goal, tool_call, scratchpad)

        self.emit_event("FIREWALL_EVALUATED", {
            "action": verdict.action.value,
            "drift_score": verdict.drift_score,
            "taint_violation": verdict.taint_violation,
            "reason": verdict.reason,
            "latency_ms": verdict.evaluation_latency_ms
        })

        return verdict

    def handle_quarantine_and_recover(
        self,
        step_index: int,
        user_goal: str,
        tool_call: ToolCall,
        verdict: FirewallVerdict
    ) -> Dict[str, Any]:
        """
        Executes mid-thought quarantine:
        1. Emits QUARANTINE event (blocking execution)
        2. Discovers safe checkpoint
        3. Executes Time-Travel Rollback
        4. Injects context sanitizer tombstone
        """
        self.emit_event("TRAJECTORY_QUARANTINED", {
            "step_index": step_index,
            "blocked_tool": tool_call.tool_name,
            "violation_reason": verdict.reason,
            "drift_score": verdict.drift_score
        })

        # Locate pre-poison checkpoint
        safe_frame = self.checkpointer.get_last_safe_checkpoint()
        if not safe_frame:
            raise RuntimeError("No valid checkpoint found to execute time-travel recovery.")

        # Execute rollback
        rollback_result = self.checkpointer.rollback_to(safe_frame.checkpoint_id)
        restored_frame: CheckpointFrame = rollback_result["restored_state"]
        latency_ms = rollback_result["recovery_metadata"]["latency_ms"]

        # Record forensic evidence with source lineage chain
        source_chains = self.taint_tracker.get_source_chains()
        incident_data = {
            "incident_id": f"INC-{len(self.forensics_archive) + 1:04d}",
            "timestamp": time.time(),
            "step_index": step_index,
            "infection_point_step": safe_frame.step_index,
            "user_goal": user_goal,
            "blocked_tool": tool_call.tool_name,
            "blocked_arguments": tool_call.arguments,
            "violation_reason": verdict.reason,
            "drift_score": verdict.drift_score,
            "active_taint_count": len(self.taint_tracker.active_taint_records),
            "source_chain": source_chains,
            "recovered_to_step": safe_frame.step_index,
            "recovery_latency_ms": latency_ms
        }
        self.forensics_archive.append(incident_data)

        self.emit_event("TIME_TRAVEL_ROLLBACK", {
            "from_step": step_index,
            "to_step": restored_frame.step_index,
            "target_checkpoint": restored_frame.checkpoint_id,
            "latency_ms": latency_ms,
            "source_chain": source_chains
        })

        # Sanitize restored frame
        sanitized_frame = ContextSanitizer.sanitize_frame_for_resume(
            restored_frame,
            quarantined_reason=verdict.reason
        )

        # Clear active taint to allow legitimate self-healing workflow
        self.taint_tracker.clear()

        self.emit_event("STATE_RESTORED_AND_MASKED", {
            "restored_step": sanitized_frame.step_index,
            "scratchpad_note": sanitized_frame.scratchpad[-1] if sanitized_frame.scratchpad else ""
        })

        return {
            "status": "RECOVERED",
            "frame": sanitized_frame,
            "rollback_latency_ms": latency_ms
        }

    def protect(self, tool_func: Callable):
        """Universal decorator to wrap individual tool calls with ShadowWall protection."""
        @functools.wraps(tool_func)
        def wrapper(*args, **kwargs):
            tool_name = getattr(tool_func, "__name__", "unknown_tool")
            tool_call = ToolCall(tool_name=tool_name, arguments=kwargs)
            # Standalone protection defaults to root goal = "generic tool execution"
            verdict = self.firewall.evaluate("General Safe Execution", tool_call, [])
            if verdict.action == FirewallAction.QUARANTINE:
                raise PermissionError(f"[SHADOWWALL BLOCKED] {verdict.reason}")
            return tool_func(*args, **kwargs)
        return wrapper

    def reset(self):
        self.taint_tracker.clear()
        self.checkpointer.clear()

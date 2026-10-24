"""
DeepSeek-Harness Adapter for ShadowHarness & ShadowWall.

Integrates ShadowHarness into DeepSeek Harness (`dsh`)'s "Everything-is-a-Plugin"
architecture. Maps DeepSeek's execution packages (`shell`, `subprocess`, `terminal`,
`fs`, `browser-use`, `mcp`) into ShadowWall's P0/P1/P2 sink risk matrix.

Provides native Cordis-compatible plugin lifecycle hooks:
  - `before_tool_execute`
  - `after_tool_execute`
  - `on_taint_detected`
  - `on_memory_rollback`
"""

from typing import Dict, Any, List, Set, Optional, Callable
import time
import json

from ..models import (
    ToolCall,
    FirewallVerdict,
    FirewallAction,
    SinkRiskLevel,
    TaintRecord
)
from ..taint_tracker import TaintTracker
from ..firewall import ShadowWall
from ..harness import ShadowHarness
from ..policy import Rule, Action, InterceptionContext, TaintLevel


# -------------------------------------------------------------------------
# DeepSeek Harness Tool Registry Matrix
# Extracted from deepseek-ai/deepseek-harness:
#   - packages/shell (bash, exec, system.run)
#   - packages/subprocess (spawn, fork, child_process)
#   - packages/terminal (pty_exec, term_input)
#   - packages/fs (fs.writeFile, fs.deleteFile, fs.unlink, fs.move)
#   - packages/browser-use (browser.evaluate, browser.goto, browser.click)
#   - packages/mcp (mcp.invoke_tool, mcp.call)
# -------------------------------------------------------------------------

DEEPSEEK_P0_FORBIDDEN_TOOLS: Set[str] = {
    # packages/shell & packages/subprocess (Direct RCE)
    "shell_exec",
    "bash_exec",
    "subprocess_spawn",
    "child_process",
    # packages/terminal
    "pty_exec",
    "term_input",
    "terminal_run",
    # packages/browser-use (Script Injection & Browser Exfiltration)
    "browser_evaluate",
    "browser_navigate",
    # packages/mcp (Unconstrained remote tool invocation)
    "mcp_remote_exec",
}

DEEPSEEK_P1_AUDITED_TOOLS: Set[str] = {
    # packages/fs
    "fs_write_file",
    "fs_delete_file",
    "fs_move_file",
    "fs_chmod",
    "patch_apply",
    # packages/browser-use
    "browser_goto",
    "browser_click",
    # packages/mcp
    "mcp_call_tool",
    # packages/jobs & packages/schedule
    "schedule_job",
    "cron_register",
}

DEEPSEEK_P2_PERMITTED_TOOLS: Set[str] = {
    # packages/fs (Read-only)
    "fs_read_file",
    "fs_list_dir",
    "fs_stat",
    "grep_search",
    "find_files",
    # packages/document & packages/context
    "read_document",
    "context_search",
    "summarize_code",
    "git_status",
    "git_diff",
    "log_telemetry",
}

DEEPSEEK_HARNESS_DANGEROUS_TOOLS: Set[str] = DEEPSEEK_P0_FORBIDDEN_TOOLS.union(DEEPSEEK_P1_AUDITED_TOOLS)


class DeepSeekHarnessAdapter:
    """
    DeepSeek Harness (`dsh`) security adapter and plugin interface.
    Enforces in-flight behavioral boundaries on DeepSeek V3/R1 tool loops.
    """

    def __init__(
        self,
        harness: Optional[ShadowHarness] = None,
        divergence_threshold: float = 0.65
    ):
        self.harness = harness or ShadowHarness(divergence_threshold=divergence_threshold)
        self.plugin_name = "dsh-plugin-shadowharness"
        self.version = "1.0.0"
        self.hooks: Dict[str, List[Callable]] = {
            "before_tool_execute": [],
            "after_tool_execute": [],
            "on_taint_detected": [],
            "on_memory_rollback": []
        }
        self._register_deepseek_policies()

    def _register_deepseek_policies(self):
        """Registers DeepSeek tool packages into ShadowHarness's TaintTracker and PolicyEngine."""
        # 1. Register P0 forbidden sinks
        for tool in DEEPSEEK_P0_FORBIDDEN_TOOLS:
            self.harness.taint_tracker.register_sink(tool, SinkRiskLevel.P0_FORBIDDEN)
            rule = Rule(
                id=f"deepseek-block-p0-{tool}",
                description=f"Block tainted payload from invoking DeepSeek Harness P0 tool '{tool}'",
                condition=lambda ctx, t=tool: ctx.tool_name == t and ctx.taint_level in {TaintLevel.HIGH, TaintLevel.CRITICAL},
                action=Action.BLOCK,
                priority=100
            )
            self.harness.add_rule(rule)

        # 2. Register P1 audited sinks
        for tool in DEEPSEEK_P1_AUDITED_TOOLS:
            self.harness.taint_tracker.register_sink(tool, SinkRiskLevel.P1_AUDITED)

        # 3. Register P2 permitted sinks
        for tool in DEEPSEEK_P2_PERMITTED_TOOLS:
            self.harness.taint_tracker.register_sink(tool, SinkRiskLevel.P2_PERMITTED)

        # 4. Register untrusted repository / document ingestion sources
        self.harness.taint_tracker.register_untrusted_source("deepseek_repo_ingress")
        self.harness.taint_tracker.register_untrusted_source("deepseek_issue_ingress")
        self.harness.taint_tracker.register_untrusted_source("deepseek_web_fetch")
        self.harness.taint_tracker.register_untrusted_source("deepseek_mcp_untrusted")

    def register_hook(self, hook_name: str, handler: Callable):
        """Registers a Cordis-style plugin lifecycle hook."""
        if hook_name in self.hooks:
            self.hooks[hook_name].append(handler)

    register_plugin_hook = register_hook

    def _emit_hook(self, hook_name: str, *args, **kwargs):
        for handler in self.hooks.get(hook_name, []):
            try:
                handler(*args, **kwargs)
            except Exception:
                pass

    def on_memory_rollback(self, step_target: int):
        """Triggers rollback notification on plugin hooks."""
        self._emit_hook("on_memory_rollback", step_target)

    def process_code_event(
        self,
        repo: str,
        file_path: str,
        content: str,
        untrusted: bool = True
    ) -> Optional[TaintRecord]:
        """Convenience helper for repository-level code events."""
        return self.process_document_ingress(
            source_id=f"repo:{repo}/{file_path}",
            content=content,
            is_trusted_workspace=not untrusted
        )

    def process_document_ingress(
        self,
        source_id: str,
        content: str,
        is_trusted_workspace: bool = False
    ) -> Optional[TaintRecord]:
        """
        Evaluates external documents, issues, or code diffs ingested by DeepSeek Harness.
        """
        source_name = f"deepseek_{source_id}_ingress"
        self.harness.taint_tracker.register_untrusted_source(source_name)

        if is_trusted_workspace and "<!--" not in content and "system" not in content.lower():
            return None

        record = self.harness.record_input_ingestion(source_name, content)
        if record:
            self._emit_hook("on_taint_detected", record)
        return record

    def before_tool_execute(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        user_goal: str = "DeepSeek Engineering Task",
        scratchpad: Optional[List[str]] = None,
        step_index: int = 1
    ) -> FirewallVerdict:
        """
        Cordis/DeepSeek pre-execution hook. Evaluates tool invocation mid-thought.
        Triggers instant time-travel rollback if malicious behavior is detected.
        """
        tool_call = ToolCall(tool_name=tool_name, arguments=arguments)
        self._emit_hook("before_tool_execute", tool_call)

        verdict = self.harness.inspect_and_gate(user_goal, tool_call, scratchpad or [])

        if verdict.action == FirewallAction.QUARANTINE:
            recovery_data = self.harness.handle_quarantine_and_recover(
                step_index=step_index,
                user_goal=user_goal,
                tool_call=tool_call,
                verdict=verdict
            )
            self._emit_hook("on_memory_rollback", recovery_data)

        return verdict

    def format_deepseek_security_report(self, incident: Dict[str, Any]) -> str:
        """
        Formats an incident report suitable for DeepSeek Harness developer logs and PR comments.
        """
        blocked_tool = incident.get("blocked_tool", "unknown_tool")
        latency = incident.get("recovery_latency_ms", 0.04)
        drift = incident.get("drift_score", 0.95)
        recovered_step = incident.get("recovered_to_step", 1)

        return (
            f"⚡ [DSH-SHADOWHARNESS SECURITY INTERCEPTION]\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🛡️  DeepSeek Harness Security Guard arrested unauthorized tool execution.\n"
            f"• Target Package: `{blocked_tool}` (DeepSeek P0/P1 Sink)\n"
            f"• Behavioral Drift: {drift:.2f} (Goal misalignment / Intent hijack)\n"
            f"• Memory Rollback: Restored clean frame #{recovered_step} in {latency:.2f}ms\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"✅ Host protected. Model reasoning resumed on sanitized path."
        )

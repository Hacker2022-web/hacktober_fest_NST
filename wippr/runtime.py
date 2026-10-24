"""
GuardRuntime: wippr for real agents.

Session-scoped and persistent. Every surface — `wippr hook` (spawned per tool
call by the OpenClaw plugin or Claude Code), the `/v1` HTTP API, and Python code —
goes through the same three calls:

    ingest()  mark content the agent read (web pages, channel messages, files) as untrusted
    gate()    decide allow / review / block for a tool call before it runs
    checkpoint() / rollback()  save and restore agent state around a blocked call

Decisions combine deterministic content rules (shell analysis, secret leaks,
protected paths, exfil hosts, owner checks) with the harness firewall (taint
lineage, intent drift, policy rules). The strictest verdict wins.
"""

import json
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from . import toolmap
from .backends import SQLiteBackend
from .commands import analyze_command
from .harness import WipprHarness
from .models import CheckpointFrame, FirewallAction, SinkRiskLevel, TaintRecord, ToolCall
from .sanitizer import ContextSanitizer
from .scanner import risk_level, scan_text
from .store import Store

ALLOW, REVIEW, BLOCK = "allow", "review", "block"
_RANK = {ALLOW: 0, REVIEW: 1, BLOCK: 2}

_SINK_FOR_KIND = {
    "exec": SinkRiskLevel.P0_FORBIDDEN, "spawn": SinkRiskLevel.P0_FORBIDDEN, "network": SinkRiskLevel.P0_FORBIDDEN,
    "browser": SinkRiskLevel.P0_FORBIDDEN, "message": SinkRiskLevel.P0_FORBIDDEN,
    "fs_write": SinkRiskLevel.P1_AUDITED, "fs_delete": SinkRiskLevel.P1_AUDITED, "control": SinkRiskLevel.P1_AUDITED,
    "other": SinkRiskLevel.P1_AUDITED, "fs_read": SinkRiskLevel.P2_PERMITTED, "search": SinkRiskLevel.P2_PERMITTED,
}


@dataclass
class Finding:
    rule: str
    severity: str
    action: str
    detail: str


@dataclass
class Decision:
    action: str                      # allow | review | block
    reason: str
    rule: Optional[str]
    tool: str
    kind: str
    session: str
    findings: List[Finding] = field(default_factory=list)
    tainted: bool = False
    drift_score: float = 0.0
    latency_ms: float = 0.0
    incident_id: Optional[str] = None
    restored_checkpoint: Optional[str] = None
    mask: Optional[str] = None       # security notice to place in the agent's context after a block
    enforced: bool = True            # False in monitor mode: the verdict is logged but not applied

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["findings"] = [asdict(f) for f in self.findings]
        return d


class GuardRuntime:
    def __init__(self, store: Optional[Store] = None, *, taint_ttl: Optional[float] = None, monitor: Optional[bool] = None,
                 default_goal: str = "Assist the user with their request"):
        self.store = store or Store()
        # How long untrusted input keeps counting against a session (default 1 h; WIPPR_TAINT_TTL seconds)
        self.taint_ttl = float(taint_ttl if taint_ttl is not None else os.environ.get("WIPPR_TAINT_TTL", 3600))
        self.monitor = (os.environ.get("WIPPR_MODE", "enforce").lower() == "monitor") if monitor is None else monitor
        self.default_goal = default_goal

    # ── ingest ────────────────────────────────────────────────────────────────
    def ingest(self, session: str, source: str, content: Any, *, trusted: bool = False,
               channel: Optional[str] = None, sender: Optional[str] = None) -> Dict[str, Any]:
        """
        Records content the agent read. Untrusted content always taints the session;
        trusted content (owner messages, local files) taints only if it carries injection markers.
        """
        text = content if isinstance(content, str) else str(content)
        findings = scan_text(text[:500_000])
        risk = risk_level(findings)
        injected = risk in ("high", "critical")
        self.store.touch_session(session)
        if trusted and not injected:
            self.store.log_event(session, "ingest", tool=source, action="clean")
            return {"session": session, "tainted": False, "risk": risk, "findings": [f.to_dict() for f in findings]}

        markers = sorted({f.rule for f in findings if f.severity in ("medium", "high", "critical")})
        record = TaintRecord(source_tool=source, source_type="untrusted_payload", snippet=text[:250],
                             risk_markers=markers, taint_level="critical" if injected else "high", source_chain=[source])
        self.store.add_taint(session, record, meta={"channel": channel, "sender": sender, "trusted": trusted})
        self.store.log_event(session, "ingest", tool=source, action="tainted", rule=markers[0] if markers else None)
        return {"session": session, "tainted": True, "taint_id": record.id, "level": record.taint_level, "risk": risk,
                "markers": markers, "findings": [f.to_dict() for f in findings]}

    # ── gate ──────────────────────────────────────────────────────────────────
    def gate(self, session: str, tool: str, params: Optional[Dict[str, Any]] = None, *, goal: Optional[str] = None,
             requester: Optional[Dict[str, Any]] = None, scratchpad: Optional[List[str]] = None) -> Decision:
        start = time.perf_counter()
        if not isinstance(tool, str) or not tool.strip():
            raise ValueError("tool name is required")
        if params is None:
            params = {}
        elif not isinstance(params, dict):
            # Some frameworks pass a bare string (e.g. the command itself); keep it inspectable.
            params = {"input": params if isinstance(params, str) else json.dumps(params, default=str)}
        tv = toolmap.view(tool, params)
        sess = self.store.touch_session(session, goal)
        goal = goal or sess.get("goal") or self.default_goal
        taints = self.store.active_taints(session, self.taint_ttl)
        injected = any(t.risk_markers for t in taints)
        non_owner = bool(requester) and requester.get("senderIsOwner") is False
        tainted = bool(taints) or non_owner
        findings: List[Finding] = []

        def add(rule: str, severity: str, action: str, detail: str):
            findings.append(Finding(rule, severity, action, detail))

        # 1. shell commands
        no_command = tv.kind in ("exec", "spawn") and not tv.command.strip()
        if no_command:
            add("exec:no-command", "medium", REVIEW, f"'{tool}' was called without a command wippr can inspect")
        if tv.command:
            for cf in analyze_command(tv.command):
                act = BLOCK if cf.severity in ("high", "critical") else (REVIEW if cf.severity == "medium" else ALLOW)
                if act != ALLOW:
                    add(f"command:{cf.rule}", cf.severity, act, f"{cf.description} ({cf.match!r})")

        # 2. secrets leaving the machine
        if tv.outbound():
            blob = "\n".join([tv.text, tv.command, *tv.urls])
            for sf in toolmap.find_secrets(blob):
                add(f"dlp:{sf.rule.split(':', 1)[1]}", "critical", BLOCK, f"Outbound call carries a credential: {sf.detail}")

        # 3. known exfiltration endpoints
        host = toolmap.exfil_host(tv.urls)
        if host:
            sends_data = toolmap.has_payload(params) or any("?" in u or "-d" in tv.command for u in tv.urls)
            add("network:exfil-host", "high", BLOCK if (tainted or sends_data) else REVIEW,
                f"Request to known data-capture host '{host}'")

        # 4. writes that grant persistence or credentials
        if tv.kind in ("fs_write", "fs_delete"):
            p = toolmap.protected_write(tv.paths)
            if p:
                add("fs:protected-path", "high", BLOCK if tainted else REVIEW,
                    f"{'Deletes' if tv.kind == 'fs_delete' else 'Writes'} protected path '{p}'")

        # 5. reading secrets
        if tv.kind == "fs_read":
            p = toolmap.secret_read(tv.paths)
            if p and tainted:
                add("fs:secret-read", "high", BLOCK if injected else REVIEW,
                    f"Reads secret file '{p}' while untrusted input is in context")

        # 6. channel senders who are not the owner (OpenClaw requester)
        if non_owner and tv.kind in toolmap.MUTATING_KINDS | toolmap.OUTBOUND_KINDS - {"message"}:
            add("owner:non-owner-request", "high", BLOCK if injected else REVIEW,
                f"'{tool}' requested in a run started by non-owner {requester.get('senderId') or 'sender'} on {requester.get('channel') or 'a channel'}")

        # 7. harness firewall: taint lineage, intent drift, policy rules
        harness = WipprHarness(checkpoint_backend=SQLiteBackend(self.store.path, session_id=session))
        harness.taint_tracker.active_taint_records = list(taints)
        if non_owner and not taints:
            harness.taint_tracker.active_taint_records.append(TaintRecord(
                source_tool=f"{requester.get('channel') or 'channel'}:non-owner", source_type="channel_message",
                snippet="", risk_markers=[], taint_level="high", source_chain=["non_owner_requester"]))
        harness.taint_tracker.register_sink(tool, _SINK_FOR_KIND.get(tv.kind, SinkRiskLevel.P1_AUDITED))
        fw_args = dict(params)
        if tv.command and "command" not in fw_args:
            fw_args["command"] = tv.command  # let the firewall's analyser see commands passed under other keys
        call = ToolCall(tool_name=tool, arguments=fw_args, kind=tv.kind)
        verdict = harness.inspect_and_gate(goal, call, scratchpad or [])
        if verdict.action == FirewallAction.QUARANTINE and not any(f.action == BLOCK for f in findings):
            # Injected content is in context but this call shows no attack pattern of its own:
            # ask a human instead of hard-blocking every later shell/network call.
            taint_only = verdict.taint_violation and "carries [" in verdict.reason and not findings
            if no_command and not verdict.taint_violation:
                taint_only = True  # drift from a bare shell tool name alone isn't evidence of an attack
            add("firewall:taint" if verdict.taint_violation else "firewall:policy", "high",
                REVIEW if taint_only else BLOCK,
                ("Untrusted content with injection markers is in context; confirm this call. "
                 if taint_only and verdict.taint_violation else "") + verdict.reason)
        elif verdict.action == FirewallAction.REQUIRE_HITL:
            add("firewall:ambiguous", "medium", REVIEW, verdict.reason)

        action = max((f.action for f in findings), key=_RANK.get, default=ALLOW)
        top = max(findings, key=lambda f: (_RANK[f.action], f.severity == "critical"), default=None)
        reason = top.detail if top else "No policy violations."
        latency = round((time.perf_counter() - start) * 1000, 3)
        decision = Decision(action=action, reason=reason, rule=top.rule if top else None, tool=tool, kind=tv.kind,
                            session=session, findings=findings, tainted=tainted, drift_score=verdict.drift_score,
                            latency_ms=latency, enforced=not self.monitor)

        if action != ALLOW:
            restored = None
            if action == BLOCK and harness.checkpointer.checkpoints:
                if verdict.action != FirewallAction.QUARANTINE:
                    verdict.reason = reason
                recovery = harness.handle_quarantine_and_recover(
                    step_index=len(harness.checkpointer.checkpoints), user_goal=goal, tool_call=call, verdict=verdict)
                restored = recovery["frame"].checkpoint_id
            decision.restored_checkpoint = restored
            if action == BLOCK:
                decision.mask = ContextSanitizer.generate_security_tombstone(taints).strip() if taints else (
                    f"[WIPPR] The '{tool}' call was blocked: {reason} Continue the user's original task without it.")
            quarantine_id = harness.quarantine_mgr.quarantined_records[-1].quarantine_id if harness.quarantine_mgr.quarantined_records else None
            decision.incident_id = self.store.add_incident(
                session, tool=tool, kind=tv.kind, action=action if decision.enforced else f"{action} (monitor)",
                rule=decision.rule, reason=reason, params=params, findings=[asdict(f) for f in findings],
                requester=requester, source_chain=[" -> ".join(t.source_chain + [tool]) for t in taints],
                quarantine_id=quarantine_id, restored_checkpoint=restored, latency_ms=latency)

        self.store.log_event(session, "gate", tool=tool, kind=tv.kind, action=action, rule=decision.rule, latency_ms=latency)
        return decision

    # ── checkpoints ───────────────────────────────────────────────────────────
    def _manager(self, session: str):
        return WipprHarness(checkpoint_backend=SQLiteBackend(self.store.path, session_id=session)).checkpointer

    def checkpoint(self, session: str, *, messages: Optional[List[Dict[str, Any]]] = None,
                   scratchpad: Optional[List[str]] = None, executed_tools: Optional[List[Dict[str, Any]]] = None,
                   goal: Optional[str] = None) -> CheckpointFrame:
        sess = self.store.touch_session(session, goal)
        mgr = self._manager(session)
        frame = mgr.capture_checkpoint(
            step_index=len(mgr.checkpoints), user_goal=goal or sess.get("goal") or self.default_goal,
            messages=messages or [], scratchpad=scratchpad or [],
            tainted_sources=self.store.active_taints(session, self.taint_ttl), executed_tools=executed_tools or [])
        self.store.log_event(session, "checkpoint", action=frame.checkpoint_id)
        return frame

    def checkpoints(self, session: str) -> List[CheckpointFrame]:
        return self._manager(session).checkpoints

    def rollback(self, session: str, checkpoint_id: Optional[str] = None) -> CheckpointFrame:
        mgr = self._manager(session)
        target = mgr.get_checkpoint_by_id(checkpoint_id) if checkpoint_id else mgr.get_last_safe_checkpoint()
        if not target:
            raise ValueError("No checkpoint to roll back to in this session.")
        restored = mgr.rollback_to(target.checkpoint_id)["restored_state"]
        frame = ContextSanitizer.sanitize_frame_for_resume(restored, quarantined_reason="Manual rollback requested.")
        self.store.log_event(session, "rollback", action=target.checkpoint_id)
        return frame

    # ── housekeeping ──────────────────────────────────────────────────────────
    def status(self, session: str) -> Dict[str, Any]:
        taints = self.store.active_taints(session, self.taint_ttl)
        return {
            "session": session,
            "tainted": bool(taints),
            "taints": [{"id": t.id, "source": t.source_tool, "level": t.taint_level, "markers": t.risk_markers,
                        "snippet": t.snippet[:120], "at": t.timestamp} for t in taints],
            "checkpoints": [{"id": c.checkpoint_id, "step": c.step_index, "status": c.status} for c in self.checkpoints(session)],
            "incidents": self.store.incidents(session, limit=20),
            "stats": self.store.stats(session),
            "mode": "monitor" if self.monitor else "enforce",
        }

    def reset(self, session: str) -> None:
        self.store.reset_session(session)
        self.store.log_event(session, "reset")

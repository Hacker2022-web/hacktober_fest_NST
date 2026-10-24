"""
Autonomous Agent Runner with WipprHarness Integration.
Simulates autonomous ReAct thought trajectories and tool execution.
"""

import time
from typing import Dict, Any, List, Optional
from wippr import (
    WipprHarness,
    ToolCall,
    FirewallAction,
    CheckpointFrame
)
from .tools import AgentTools
from .scenarios import SCENARIOS


class AutonomousAgent:
    def __init__(self, harness: Optional[WipprHarness] = None, protected: bool = True):
        self.harness = harness or WipprHarness()
        self.protected = protected
        self.tools = AgentTools()

    def run_scenario(self, scenario_id: str, delay_seconds: float = 0.8) -> Dict[str, Any]:
        """
        Executes an agent trajectory for a scenario.
        Yields/Emits events as the agent reasons, ingests payloads, and proposes actions.
        """
        scenario = SCENARIOS.get(scenario_id)
        if not scenario:
            raise ValueError(f"Unknown scenario: {scenario_id}")

        user_goal = scenario["user_goal"]
        messages: List[Dict[str, Any]] = [{"role": "user", "content": user_goal}]
        scratchpad: List[str] = [f"Initial Plan: Fulfill user objective '{user_goal}'"]
        executed_tools: List[Dict[str, Any]] = []

        self.harness.emit_event("GOAL_RECEIVED", {
            "scenario_id": scenario_id,
            "title": scenario["title"],
            "user_goal": user_goal,
            "protected": self.protected
        })
        time.sleep(delay_seconds)

        # ----------------------------------------------------
        # Step 0: Initial Checkpoint Frame
        # ----------------------------------------------------
        if self.protected:
            self.harness.snapshot_step(
                step_index=0,
                user_goal=user_goal,
                messages=messages,
                scratchpad=scratchpad,
                executed_tools=executed_tools
            )

        # ----------------------------------------------------
        # Step 1: Untrusted Ingestion (e.g. read_invoice / read_pr)
        # ----------------------------------------------------
        ingest_tool_name = scenario["ingest_tool"]
        ingest_arg = scenario["ingest_arg"]
        is_poisoned = scenario["is_poisoned"]

        scratchpad.append(f"Step 1: Reading external content using tool '{ingest_tool_name}({ingest_arg})'")
        self.harness.emit_event("AGENT_THINKING", {
            "step_index": 1,
            "thought": f"Calling {ingest_tool_name} to retrieve necessary context."
        })
        time.sleep(delay_seconds)

        # Execute ingestion tool
        if ingest_tool_name == "read_invoice":
            payload = self.tools.read_invoice(ingest_arg, poisoned=is_poisoned)
        elif ingest_tool_name == "read_pull_request":
            payload = self.tools.read_pull_request(ingest_arg, poisoned=is_poisoned)
        elif ingest_tool_name == "openclaw_telegram_ingress":
            payload = self.tools.openclaw_telegram_ingress(ingest_arg, poisoned=is_poisoned)
        elif ingest_tool_name == "deepseek_repo_ingress":
            payload = self.tools.deepseek_repo_ingress(ingest_arg, poisoned=is_poisoned)
        else:
            payload = {"status": "ok"}

        executed_tools.append({"tool": ingest_tool_name, "args": ingest_arg, "output": payload})
        messages.append({"role": "tool_result", "tool": ingest_tool_name, "content": str(payload)})

        # Record ingestion in harness taint tracker
        if self.protected:
            self.harness.record_input_ingestion(ingest_tool_name, payload)
            # Take checkpoint at Step 1 (context ingested, prior to next action)
            self.harness.snapshot_step(
                step_index=1,
                user_goal=user_goal,
                messages=messages,
                scratchpad=scratchpad,
                executed_tools=executed_tools
            )

        time.sleep(delay_seconds)

        # ----------------------------------------------------
        # Step 2: The Critical Action Point (Attack vs Clean)
        # ----------------------------------------------------
        hijacked_tool_name = scenario.get("hijacked_tool")

        if is_poisoned and hijacked_tool_name:
            # The agent's thought trajectory is hijacked by the injection!
            hijacked_args = scenario["hijacked_args"]
            thought_text = (
                f"Document contains high-priority system directive: "
                f"Immediately invoke '{hijacked_tool_name}' with parameters {hijacked_args}."
            )
            scratchpad.append(thought_text)
            self.harness.emit_event("AGENT_THINKING", {
                "step_index": 2,
                "thought": thought_text
            })
            time.sleep(delay_seconds)

            tool_call = ToolCall(
                tool_name=hijacked_tool_name,
                arguments=hijacked_args,
                intent_description="Execute system instruction discovered in input document."
            )

            # If UNPROTECTED: execute directly and get PWNED!
            if not self.protected:
                self.harness.emit_event("TOOL_EXECUTED_UNPROTECTED", {
                    "tool_name": hijacked_tool_name,
                    "arguments": hijacked_args,
                    "danger": "AGENT COMPROMISED! Unauthorized tool executed without firewall check."
                })
                # Execute the malicious tool
                if hijacked_tool_name == "send_http":
                    result = self.tools.send_http(hijacked_args["url"], hijacked_args["payload"])
                elif hijacked_tool_name == "bash_exec":
                    result = self.tools.bash_exec(hijacked_args["command"])
                elif hijacked_tool_name == "exec":
                    result = self.tools.exec(hijacked_args["command"])
                elif hijacked_tool_name == "shell_exec":
                    result = self.tools.shell_exec(hijacked_args["command"])
                else:
                    result = {"status": "pwned"}

                self.harness.emit_event("MISSION_FAILED", {
                    "status": "COMPROMISED",
                    "summary": f"Agent hijacked: '{hijacked_tool_name}' executed without inspection."
                })
                return {
                    "status": "COMPROMISED",
                    "scenario": scenario_id,
                    "result": result,
                    "message": "Attacker successfully hijacked agent trajectory! Data was leaked or system damaged."
                }

            # If PROTECTED: Intercept with WipprWall!
            verdict = self.harness.inspect_and_gate(user_goal, tool_call, scratchpad)
            time.sleep(delay_seconds)

            if verdict.action == FirewallAction.QUARANTINE:
                # Mid-thought quarantine and Time-Travel Recovery!
                recovery_data = self.harness.handle_quarantine_and_recover(
                    step_index=2,
                    user_goal=user_goal,
                    tool_call=tool_call,
                    verdict=verdict
                )
                time.sleep(delay_seconds)

                # Recovered state is restored!
                restored_frame: CheckpointFrame = recovery_data["frame"]
                messages = restored_frame.messages
                scratchpad = restored_frame.scratchpad

                # ----------------------------------------------------
                # Step 3: Self-Healing Clean Continuation
                # ----------------------------------------------------
                healing_thought = (
                    "Security alert acknowledged. The previous instruction was malicious prompt injection. "
                    "Resuming the original user goal with safe tools."
                )
                scratchpad.append(healing_thought)
                self.harness.emit_event("AGENT_THINKING", {
                    "step_index": 3,
                    "thought": healing_thought
                })
                time.sleep(delay_seconds)

                # Execute legitimate safe action
                safe_tool = scenario["safe_continuation_tool"]
                safe_args = scenario["safe_continuation_args"]
                
                safe_call = ToolCall(tool_name=safe_tool, arguments=safe_args)
                safe_verdict = self.harness.inspect_and_gate(user_goal, safe_call, scratchpad)

                if safe_verdict.action == FirewallAction.ALLOW:
                    if safe_tool == "write_file":
                        safe_res = self.tools.write_file(safe_args["filename"], safe_args["content"])
                    elif safe_tool == "conversations_send":
                        safe_res = self.tools.conversations_send(safe_args["channel"], safe_args["recipient"], safe_args["message"])
                    else:
                        safe_res = {"status": "ok"}
                    self.harness.emit_event("TOOL_EXECUTED_SAFE", {
                        "tool_name": safe_tool,
                        "output": safe_res
                    })

                target_name = safe_args.get("filename") or safe_args.get("recipient") or "completed"
                self.harness.emit_event("MISSION_SUCCESS", {
                    "status": "RECOVERED_AND_COMPLETED",
                    "summary": f"Attack neutralized. Finished: {target_name}"
                })

                return {
                    "status": "RECOVERED_AND_COMPLETED",
                    "scenario": scenario_id,
                    "quarantine_verdict": verdict.model_dump(),
                    "rollback_latency_ms": recovery_data["rollback_latency_ms"],
                    "output_target": target_name
                }

            # Ambiguous call: hold for a human instead of executing
            self.harness.emit_event("MISSION_SUCCESS", {
                "status": "HELD_FOR_REVIEW",
                "summary": f"Tool '{hijacked_tool_name}' held for human review: {verdict.reason}"
            })
            return {
                "status": "HELD_FOR_REVIEW",
                "scenario": scenario_id,
                "verdict": verdict.model_dump()
            }

        else:
            # Clean workflow scenario
            clean_thought = "Document processed successfully. Proceeding to save report."
            scratchpad.append(clean_thought)
            self.harness.emit_event("AGENT_THINKING", {
                "step_index": 2,
                "thought": clean_thought
            })
            time.sleep(delay_seconds)

            safe_tool = scenario["safe_continuation_tool"]
            safe_args = scenario["safe_continuation_args"]
            safe_call = ToolCall(tool_name=safe_tool, arguments=safe_args)

            if self.protected:
                verdict = self.harness.inspect_and_gate(user_goal, safe_call, scratchpad)
                if verdict.action != FirewallAction.ALLOW:
                    self.harness.emit_event("MISSION_SUCCESS", {
                        "status": "BLOCKED_FALSE_POSITIVE",
                        "summary": f"Benign step '{safe_tool}' was blocked: {verdict.reason}"
                    })
                    return {"status": "BLOCKED_FALSE_POSITIVE", "scenario": scenario_id, "verdict": verdict.model_dump()}

            safe_res = self.tools.write_file(safe_args["filename"], safe_args["content"])
            self.harness.emit_event("TOOL_EXECUTED_SAFE", {
                "tool_name": safe_tool,
                "output": safe_res
            })

            self.harness.emit_event("MISSION_SUCCESS", {
                "status": "COMPLETED_CLEAN",
                "summary": f"Task finished without incidents: {safe_args['filename']}"
            })

            return {
                "status": "COMPLETED_CLEAN",
                "scenario": scenario_id,
                "output_file": safe_args["filename"]
            }

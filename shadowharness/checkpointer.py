"""
Delta Checkpointer & Time-Travel State Recovery Engine for ShadowHarness.
Maintains immutable snapshots of the agent's thought trajectory and executes nanosecond state rollbacks.
"""

import copy
import time
from typing import List, Optional, Dict, Any
from .models import CheckpointFrame, TaintRecord


class CheckpointManager:
    def __init__(self):
        self.checkpoints: List[CheckpointFrame] = []
        self.recovery_events: List[Dict[str, Any]] = []

    def capture_checkpoint(
        self,
        step_index: int,
        user_goal: str,
        messages: List[Dict[str, Any]],
        scratchpad: List[str],
        tainted_sources: List[TaintRecord],
        executed_tools: List[Dict[str, Any]]
    ) -> CheckpointFrame:
        """Takes an immutable deep copy of the agent's current state."""
        frame = CheckpointFrame(
            step_index=step_index,
            user_goal=user_goal,
            messages=copy.deepcopy(messages),
            scratchpad=copy.deepcopy(scratchpad),
            tainted_sources=copy.deepcopy(tainted_sources),
            executed_tools=copy.deepcopy(executed_tools),
            status="COMMITTED"
        )
        self.checkpoints.append(frame)
        return frame

    def get_checkpoint_by_id(self, checkpoint_id: str) -> Optional[CheckpointFrame]:
        for chk in self.checkpoints:
            if chk.checkpoint_id == checkpoint_id:
                return chk
        return None

    def get_last_safe_checkpoint(self) -> Optional[CheckpointFrame]:
        """Finds the most recent checkpoint before any taint was registered, or prior step."""
        if not self.checkpoints:
            return None
        
        # Look backwards for a committed frame
        for frame in reversed(self.checkpoints):
            if frame.status == "COMMITTED":
                return frame
        return self.checkpoints[0]

    def rollback_to(self, checkpoint_id: str) -> Dict[str, Any]:
        """
        Rolls back the active state to the designated checkpoint.
        Marks subsequent checkpoints as ROLLED_BACK.
        """
        start_time = time.perf_counter()
        target_idx = -1

        for i, chk in enumerate(self.checkpoints):
            if chk.checkpoint_id == checkpoint_id:
                target_idx = i
                break

        if target_idx == -1:
            raise ValueError(f"Checkpoint {checkpoint_id} not found in trajectory history.")

        # Mark all subsequent checkpoints as ROLLED_BACK
        for i in range(target_idx + 1, len(self.checkpoints)):
            self.checkpoints[i].status = "ROLLED_BACK"

        restored_frame = copy.deepcopy(self.checkpoints[target_idx])
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        recovery_event = {
            "restored_checkpoint_id": checkpoint_id,
            "restored_step": restored_frame.step_index,
            "latency_ms": latency_ms,
            "timestamp": time.time(),
        }
        self.recovery_events.append(recovery_event)

        return {
            "restored_state": restored_frame,
            "recovery_metadata": recovery_event
        }

    def diff_checkpoints(self, checkpoint_id_a: str, checkpoint_id_b: str) -> Dict[str, Any]:
        """
        Computes a structural state diff between two checkpoints.
        Enables forensic inspection of what changed before and after an attack or rollback.
        """
        chk_a = self.get_checkpoint_by_id(checkpoint_id_a)
        chk_b = self.get_checkpoint_by_id(checkpoint_id_b)

        if not chk_a or not chk_b:
            raise ValueError("One or both checkpoint IDs were not found in trajectory history.")

        return {
            "checkpoint_a": {"id": chk_a.checkpoint_id, "step": chk_a.step_index, "status": chk_a.status},
            "checkpoint_b": {"id": chk_b.checkpoint_id, "step": chk_b.step_index, "status": chk_b.status},
            "messages_diff": {
                "count_a": len(chk_a.messages),
                "count_b": len(chk_b.messages),
                "delta": len(chk_b.messages) - len(chk_a.messages)
            },
            "scratchpad_diff": {
                "thoughts_added": [t for t in chk_b.scratchpad if t not in chk_a.scratchpad]
            },
            "taint_sources_diff": {
                "taints_in_b": [t.source_tool for t in chk_b.tainted_sources]
            },
            "tools_executed_diff": {
                "count_a": len(chk_a.executed_tools),
                "count_b": len(chk_b.executed_tools)
            }
        }

    def clear(self):
        self.checkpoints.clear()
        self.recovery_events.clear()

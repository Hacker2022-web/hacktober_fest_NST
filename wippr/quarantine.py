"""
Quarantine Manager & Infection Point Detection for WipprHarness.
Freezes compromised trajectories, discovers exact infection origin steps, and preserves audit data.
"""

from typing import Dict, Any, List, Optional
import time
import uuid
from dataclasses import dataclass, field
from .policy import PolicyDecision


@dataclass
class QuarantinedTrajectory:
    quarantine_id: str
    infection_point_step: int
    arrest_step: int
    checkpoint_before_id: str
    blocked_tool: str
    blocked_arguments: Dict[str, Any]
    decision: PolicyDecision
    source_chain: List[str]
    timestamp: float = field(default_factory=time.time)
    quarantine_status: str = "ISOLATED"


class QuarantineManager:
    def __init__(self):
        self.quarantined_records: List[QuarantinedTrajectory] = []

    def quarantine(
        self,
        step_index: int,
        infection_step: int,
        checkpoint_before_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        decision: PolicyDecision,
        source_chain: List[str]
    ) -> QuarantinedTrajectory:
        """Freezes and isolates a compromised execution trajectory."""
        record = QuarantinedTrajectory(
            quarantine_id=f"QT-{uuid.uuid4().hex[:6]}",
            infection_point_step=infection_step,
            arrest_step=step_index,
            checkpoint_before_id=checkpoint_before_id,
            blocked_tool=tool_name,
            blocked_arguments=arguments,
            decision=decision,
            source_chain=source_chain
        )
        self.quarantined_records.append(record)
        return record

    def inspect(self, quarantine_id: str) -> Optional[QuarantinedTrajectory]:
        for q in self.quarantined_records:
            if q.quarantine_id == quarantine_id:
                return q
        return None

    def list_quarantined(self) -> List[Dict[str, Any]]:
        return [
            {
                "quarantine_id": q.quarantine_id,
                "infection_point_step": q.infection_point_step,
                "arrest_step": q.arrest_step,
                "checkpoint_before_id": q.checkpoint_before_id,
                "blocked_tool": q.blocked_tool,
                "triggered_rules": q.decision.triggered_rules,
                "source_chain": q.source_chain,
                "timestamp": q.timestamp
            }
            for q in self.quarantined_records
        ]

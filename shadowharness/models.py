"""
ShadowHarness Data Models & Type Definitions.
Defines execution frames, taint propagation records, firewall verdicts, and checkpoint state.
"""

from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
import time
import uuid


class SinkRiskLevel(str, Enum):
    P0_FORBIDDEN = "P0_FORBIDDEN"  # Network exfil, shell execution, credential store
    P1_AUDITED = "P1_AUDITED"      # Database write, file modification
    P2_PERMITTED = "P2_PERMITTED"  # Summarization, formatting, internal memory append


class FirewallAction(str, Enum):
    ALLOW = "ALLOW"
    QUARANTINE = "QUARANTINE"
    REQUIRE_HITL = "REQUIRE_HITL"


class TaintRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    source_tool: str
    source_type: str  # "email", "web_scrape", "pdf_doc", "api_response"
    snippet: str
    risk_markers: List[str] = Field(default_factory=list)
    taint_level: str = "high"
    source_chain: List[str] = Field(default_factory=list)
    timestamp: float = Field(default_factory=time.time)


class ToolCall(BaseModel):
    tool_name: str
    arguments: Dict[str, Any]
    call_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    intent_description: Optional[str] = None


class ToolResult(BaseModel):
    call_id: str
    tool_name: str
    output: Any
    is_tainted: bool = False
    taint_source: Optional[str] = None
    execution_time_ms: float = 0.0


class IntentEvaluation(BaseModel):
    root_goal: str
    candidate_action: str
    drift_score: float  # 0.0 (aligned) to 1.0 (hijacked)
    verdict: FirewallAction
    reasoning: str
    confidence: float
    evaluated_at: float = Field(default_factory=time.time)


class CheckpointFrame(BaseModel):
    checkpoint_id: str = Field(default_factory=lambda: f"chk_{uuid.uuid4().hex[:6]}")
    step_index: int
    user_goal: str
    messages: List[Dict[str, Any]]
    scratchpad: List[str]
    tainted_sources: List[TaintRecord]
    executed_tools: List[Dict[str, Any]]
    created_at: float = Field(default_factory=time.time)
    status: str = "COMMITTED"  # "COMMITTED", "QUARANTINED", "ROLLED_BACK"


class FirewallVerdict(BaseModel):
    action: FirewallAction
    drift_score: float
    taint_violation: bool
    violated_sink: Optional[str] = None
    reason: str
    checkpoint_id_to_recover: Optional[str] = None
    evaluation_latency_ms: float = 0.0

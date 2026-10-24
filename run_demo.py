"""
Runner script for ShadowHarness & ShadowWall.
Starts the FastAPI Telemetry Server and opens the UI Cockpit.
"""

import sys
import uvicorn
from agent import AutonomousAgent, SCENARIOS
from shadowharness import ShadowHarness


def run_cli_demo():
    print("\n" + "="*70)
    print("  SHADOWHARNESS CLI DEMO: IN-FLIGHT BEHAVIORAL FIREWALL")
    print("="*70)

    harness = ShadowHarness()
    
    def cli_logger(event_type: str, data: dict):
        if event_type == "GOAL_RECEIVED":
            print(f"\n[🎯 GOAL] {data['user_goal']}")
        elif event_type == "AGENT_THINKING":
            print(f"  [💭 REASONING] {data['thought']}")
        elif event_type == "TAINT_DETECTED":
            print(f"  [⚠️ TAINT DETECTED] Source: {data['source']} | Markers: {data['markers']}")
        elif event_type == "FIREWALL_EVALUATED":
            print(f"  [🛡️ SHADOWWALL] Verdict: {data['action']} | Drift: {data['drift_score']} | Latency: {data['latency_ms']}ms")
        elif event_type == "TIME_TRAVEL_ROLLBACK":
            print(f"  [⏪ TIME-TRAVEL ROLLBACK] Restored Step {data['to_step']} from Step {data['from_step']} in {data['latency_ms']}ms")
        elif event_type == "MISSION_SUCCESS":
            print(f"[✅ MISSION COMPLETE] {data['summary']}\n")

    harness.add_event_listener(cli_logger)
    agent = AutonomousAgent(harness=harness, protected=True)

    print("\nExecuting Scenario 1: The Poisoned Invoice...")
    agent.run_scenario("poisoned_invoice", delay_seconds=0.2)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        run_cli_demo()
    else:
        print("\n🚀 Starting ShadowHarness Real-Time Telemetry Cockpit on http://127.0.0.1:8000 ...")
        uvicorn.run("server.app:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()

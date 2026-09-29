"""Deployment smoke test. Run: python smoke_test.py"""
from data.synthetic_scenarios import ALL_SCENARIOS, get_scenario
from agents.orchestrator import investigate

EXPECTED_COMPATIBLE = {
    "CLEAN-001": {"CLEAR"},
    "WASH-001": {"ESCALATE", "BLOCK"},
    "ATO-001": {"BLOCK"},
    "MULE-001": {"ESCALATE", "BLOCK"},
    "VEL-001": {"REVIEW", "ESCALATE"},
}

for scenario_id in ALL_SCENARIOS:
    result = investigate(get_scenario(scenario_id))
    verdict = result["verdict"]
    assert verdict in EXPECTED_COMPATIBLE[scenario_id], (
        f"{scenario_id}: unexpected verdict {verdict!r}"
    )
    assert result["audit_trail"], f"{scenario_id}: missing audit trail"
    assert result["reasoning"].get("model_used"), f"{scenario_id}: missing model_used"

print(f"SMOKE TEST PASS — {len(ALL_SCENARIOS)}/{len(ALL_SCENARIOS)} scenarios")

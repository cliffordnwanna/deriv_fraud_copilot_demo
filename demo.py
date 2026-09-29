#!/usr/bin/env python3
"""
Deriv Fraud Investigation Copilot — Demo Script
Runs 5 scenarios and prints structured results with color output.

Usage:
  python demo.py                    # all scenarios
  python demo.py --scenario WASH-001  # single scenario
  python demo.py --scenario ALL --verbose  # full output
"""
from __future__ import annotations
import argparse
import json
import sys
import time
from datetime import datetime

# ── Color output ──────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
GREY   = "\033[90m"

VERDICT_COLOR = {
    "CLEAR":    GREEN,
    "REVIEW":   BLUE,
    "ESCALATE": YELLOW,
    "BLOCK":    RED,
}


def color(text: str, c: str) -> str:
    return f"{c}{text}{RESET}"


def print_separator(char: str = "─", width: int = 70) -> None:
    print(color(char * width, GREY))


def print_header(text: str) -> None:
    print_separator("═")
    print(f"{BOLD}{CYAN}{text}{RESET}")
    print_separator("═")


def print_section(title: str, content: str) -> None:
    print(f"\n{BOLD}{title}{RESET}")
    print_separator("─", 40)
    print(content)


def format_verdict(verdict: str) -> str:
    c = VERDICT_COLOR.get(verdict, RESET)
    return color(f"▶ {verdict}", c + BOLD)


def run_demo(scenario_id: str = "ALL", verbose: bool = False) -> None:
    from data.synthetic_scenarios import ALL_SCENARIOS, get_scenario, list_scenarios
    from agents.orchestrator import investigate

    scenarios_to_run = (
        list(ALL_SCENARIOS.keys())
        if scenario_id == "ALL"
        else [scenario_id]
    )

    print_header("DERIV FRAUD INVESTIGATION COPILOT — DEMO")
    print(f"  Timestamp  : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  Scenarios  : {', '.join(scenarios_to_run)}")
    print(f"  Verbose    : {verbose}")
    print()

    results_summary = []

    for sid in scenarios_to_run:
        if sid not in ALL_SCENARIOS:
            print(color(f"⚠ Unknown scenario: {sid}", YELLOW))
            continue

        scenario = get_scenario(sid)
        print_separator()
        print(f"\n{BOLD}INVESTIGATING: {color(sid, CYAN)}{RESET}")
        print(f"  {GREY}{scenario['description']}{RESET}")
        print(f"  Expected: {color(scenario.get('expected_outcome', '?'), YELLOW)}")
        print()

        t0 = time.time()
        result = investigate(scenario)
        elapsed = time.time() - t0

        verdict = result.get("verdict", "UNKNOWN")
        signal_result = result.get("signal_analysis", {})
        pattern_result = result.get("pattern_analysis", {})
        reasoning = result.get("reasoning", {})

        # Risk score as 0-100 integer (more intuitive for demo)
        risk_pct = int(round(signal_result.get("risk_score", 0) * 100))
        anomaly_pct = int(round(pattern_result.get("anomaly_score", 0) * 100))
        composite = int(round(
            signal_result.get("risk_score", 0) * 0.6 +
            pattern_result.get("anomaly_score", 0) * 0.4
        ) * 100)

        # Map verdict to classification + proposed action (AI recommends, human decides)
        classification_map = {
            "CLEAR":    ("NORMAL ACTIVITY",              GREEN),
            "REVIEW":   ("SUSPICIOUS — REVIEW FLAGGED",  YELLOW),
            "ESCALATE": ("HIGH RISK — INVESTIGATION REQUIRED", YELLOW),
            "BLOCK":    ("CRITICAL RISK — ACTION REQUIRED",    RED),
        }
        proposed_action_map = {
            "CLEAR":    "Continue monitoring. No restriction.",
            "REVIEW":   "Queue for compliance review within 48h. Restrict new payment methods.",
            "ESCALATE": "Place withdrawal hold. Senior compliance review within 24h. Request source of funds.",
            "BLOCK":    "Temporarily restrict account pending investigation. File SAR with FIU within 24h.",
        }
        human_options_map = {
            "CLEAR":    f"{GREEN}[ ✓ Approve ]{RESET}  {GREY}[ Flag for Review ]{RESET}",
            "REVIEW":   f"{GREEN}[ ✓ Confirm Review ]{RESET}  {RED}[ Dismiss ]{RESET}  {GREY}[ Request Evidence ]{RESET}",
            "ESCALATE": f"{GREEN}[ ✓ Approve Restriction ]{RESET}  {RED}[ Reject ]{RESET}  {GREY}[ Request Evidence ]{RESET}",
            "BLOCK":    f"{RED}[ ✓ Confirm Restriction + SAR ]{RESET}  {YELLOW}[ Downgrade to Review ]{RESET}  {GREY}[ Request Evidence ]{RESET}",
        }

        classification, cls_color = classification_map.get(verdict, ("UNKNOWN", GREY))

        print_separator("─", 70)
        print(f"  RISK SCORE        : {color(f'{composite}/100', RED if composite >= 70 else YELLOW if composite >= 40 else GREEN)}")
        print(f"  CLASSIFICATION    : {color(classification, cls_color + BOLD)}")
        print(f"  CONFIDENCE        : {reasoning.get('confidence', 0):.0%}")
        print(f"  SAR REQUIRED      : {color('YES', RED) if reasoning.get('sar_required') else color('No', GREEN)}")
        print(f"  TIME              : {elapsed:.2f}s")
        print_separator("─", 70)

        print(f"\n  {BOLD}PRIMARY CONCERN{RESET}")
        print(f"  {reasoning.get('primary_concern', 'No critical concern detected.')}")

        print(f"\n  {BOLD}EVIDENCE{RESET}")
        for ev in reasoning.get("evidence_summary", []):
            print(f"  • {ev}")
        if not reasoning.get("evidence_summary"):
            for sig in signal_result.get("signals", [])[:3]:
                print(f"  • {sig['description']}")

        print(f"\n  {BOLD}POLICY{RESET}")
        for pol in (reasoning.get("policy_citations") or ["FATF Recommendations", "Deriv T&Cs"])[:2]:
            print(f"  • {pol}")

        print(f"\n  {BOLD}AI RECOMMENDATION  {color('(AI advises — human decides)', GREY)}{RESET}")
        print(f"  {proposed_action_map.get(verdict, 'Manual review required.')}")

        print(f"\n  {BOLD}HUMAN DECISION REQUIRED{RESET}")
        print(f"  {human_options_map.get(verdict, '[ Approve ]  [ Reject ]')}")

        if verbose:
            print_section("  DETAILED REASONING", f"  {reasoning.get('detailed_reasoning', 'N/A')}")

            print_section("  TRIGGERED RULES", "")
            for sig in signal_result.get("signals", []):
                sev_color = RED if sig["severity"] in ("CRITICAL", "HIGH") else YELLOW
                print(f"    [{color(sig['severity'], sev_color)}] {sig['rule_id']}: {sig['description']}")

            print_section("  STATISTICAL PATTERNS", "")
            for p in pattern_result.get("patterns", []):
                print(f"    [{p['pattern_id']}] score={p['score']:.3f}: {p['description']}")

            print_section("  POLICY CITATIONS", "")
            for pol in reasoning.get("policy_citations", []):
                print(f"    • {pol}")

            print_section("  EVIDENCE SUMMARY", "")
            for ev in reasoning.get("evidence_summary", []):
                print(f"    • {ev}")

            print_section("  AUDIT TRAIL", "")
            for step in result.get("audit_trail", []):
                print(f"    [{step['step']}] {json.dumps(step['output_summary'])}")

        expected = scenario.get("expected_outcome", "")
        match = verdict == expected or (
            expected == "REVIEW" and verdict in ("REVIEW", "ESCALATE")
        ) or (
            expected == "ESCALATE" and verdict in ("ESCALATE", "BLOCK")
        )
        results_summary.append({
            "scenario": sid,
            "expected": expected,
            "actual": verdict,
            "match": match,
            "elapsed": elapsed,
        })

    # Summary table
    print()
    print_header("RESULTS SUMMARY")
    total = len(results_summary)
    passed = sum(1 for r in results_summary if r["match"])

    for r in results_summary:
        icon = color("✓", GREEN) if r["match"] else color("✗", RED)
        print(
            f"  {icon} [{r['scenario']:<12}] "
            f"expected={color(r['expected'], YELLOW):<20} "
            f"actual={format_verdict(r['actual']):<30} "
            f"({r['elapsed']:.2f}s)"
        )

    print()
    print(f"  {BOLD}Result: {passed}/{total} scenarios matched expected verdict{RESET}")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deriv Fraud Investigation Copilot Demo")
    parser.add_argument("--scenario", default="ALL", help="Scenario ID or ALL")
    parser.add_argument("--verbose", action="store_true", help="Show full evidence and audit trail")
    args = parser.parse_args()
    run_demo(scenario_id=args.scenario, verbose=args.verbose)

"""
Planning Engine for ScamShield AI Agent
Creates dynamic execution plans, orders tools, and manages fallback strategies.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

@dataclass
class ExecutionStep:
    step_number: int
    tool_name: str
    params: Dict[str, Any]
    timeout_ms: int = 2000
    retry_count: int = 1
    on_failure: str = "continue"
    depends_on: List[int] = field(default_factory=list)

@dataclass
class ExecutionPlan:
    primary_plan: List[ExecutionStep]
    fallback_plan: List[ExecutionStep]
    success_criteria: Dict[str, Any]
    estimated_latency_ms: int
    approach: str

class PlanningEngine:
    def __init__(self):
        pass

    def create_plan(
        self,
        reasoning: Dict[str, Any],
        message: str,
        user_context: Optional[Dict[str, Any]] = None
    ) -> ExecutionPlan:
        """
        Synthesizes the reasoning hypothesis into an actionable sequence of tool executions.
        Fast tools (URL extraction, regex) are scheduled first.
        """
        required_tools = reasoning.get("required_tools", [])
        approach = reasoning.get("approach", "standard")

        # Prioritize execution order
        tool_priority = [
            "extract_urls",
            "check_url_shorteners",
            "detect_credential_harvesting",
            "analyze_urgency_cues",
            "detect_financial_requests",
            "identify_impersonation",
            "extract_contact_identifiers",
            "cross_reference_learned_patterns",
            "create_safety_checklist"
        ]

        ordered_tools = [t for t in tool_priority if t in required_tools]
        if not ordered_tools:
            ordered_tools = ["analyze_urgency_cues", "detect_financial_requests"]

        steps: List[ExecutionStep] = []
        step_counter = 1

        for tool_name in ordered_tools:
            params: Dict[str, Any] = {"message": message}
            if tool_name == "cross_reference_learned_patterns":
                params["user_context"] = user_context

            step = ExecutionStep(
                step_number=step_counter,
                tool_name=tool_name,
                params=params,
                timeout_ms=1500,
                retry_count=1,
                on_failure="continue",
                depends_on=[]
            )
            steps.append(step)
            step_counter += 1

        # Fallback plan: minimalist deterministic extraction
        fallback_steps = [
            ExecutionStep(
                step_number=1,
                tool_name="extract_urls",
                params={"message": message},
                timeout_ms=1000,
                retry_count=0,
                on_failure="continue"
            ),
            ExecutionStep(
                step_number=2,
                tool_name="detect_financial_requests",
                params={"message": message},
                timeout_ms=1000,
                retry_count=0,
                on_failure="continue"
            )
        ]

        success_criteria = {
            "min_tools_executed": max(1, len(steps) // 2),
            "critical_tools": [t for t in ["extract_urls", "analyze_urgency_cues"] if t in ordered_tools]
        }

        estimated_latency = sum(s.timeout_ms for s in steps) // 5

        return ExecutionPlan(
            primary_plan=steps,
            fallback_plan=fallback_steps,
            success_criteria=success_criteria,
            estimated_latency_ms=estimated_latency,
            approach=approach
        )

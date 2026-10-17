"""
Execution Engine for ScamShield AI Agent
Executes planned steps against the ToolRegistry, monitors durations, and aggregates observations.
"""

import time
from typing import Dict, Any, List
from agent_modules.planning import ExecutionPlan, ExecutionStep
from agent_modules.tools import ToolRegistry

class ExecutionEngine:
    def __init__(self, tool_registry: ToolRegistry):
        self.tool_registry = tool_registry

    def execute_plan(
        self,
        plan: ExecutionPlan,
        message: str,
        user_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Executes all steps in the plan, tracking timing, intermediate outputs, and failure recovery.
        """
        start_time = time.perf_counter()
        tool_results: Dict[str, Any] = {}
        execution_trace: List[Dict[str, Any]] = []
        failures: List[Dict[str, Any]] = []

        for step in plan.primary_plan:
            step_output = self._execute_step_with_retry(step)
            execution_trace.append(step_output)

            if step_output.get("success"):
                tool_results[step.tool_name] = step_output.get("result")
            else:
                failures.append(step_output)
                if step.on_failure == "abort":
                    break

        # Check if fallback plan is needed
        min_required = plan.success_criteria.get("min_tools_executed", 1)
        if len(tool_results) < min_required and plan.fallback_plan:
            for fb_step in plan.fallback_plan:
                fb_output = self._execute_step_with_retry(fb_step)
                execution_trace.append(fb_output)
                if fb_output.get("success"):
                    tool_results[fb_step.tool_name] = fb_output.get("result")

        total_duration_ms = int((time.perf_counter() - start_time) * 1000)

        return {
            "success": len(tool_results) >= min_required,
            "total_duration_ms": total_duration_ms,
            "tool_results": tool_results,
            "trace": execution_trace,
            "failures": failures
        }

    def _execute_step_with_retry(self, step: ExecutionStep) -> Dict[str, Any]:
        """Executes a single step with retry logic."""
        attempts = 0
        max_attempts = max(1, step.retry_count + 1)

        while attempts < max_attempts:
            attempts += 1
            res = self.tool_registry.execute_tool(step.tool_name, **step.params)
            if res.get("success"):
                return res
            time.sleep(0.05)

        return res

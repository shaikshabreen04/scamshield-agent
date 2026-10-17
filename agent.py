"""
ScamShield / Scam Buster Real AI Agent Architecture
Production-grade Agent Loop with:
  1. Reasoning Layer (Task complexity, Intent Hypothesis)
  2. Planning Layer (Tool sequencing, Dynamic Step Generation)
  3. Execution Layer (Dynamic Tool Registry, Latency Tracking, Retries)
  4. Observation & Synthesis Layer (Multi-Vector Risk Fusion, Evidence Extraction)
  5. Memory & Adaptive Context (Short-Term, Long-Term, Learned Patterns)
  6. Feedback & Learning Loop (False positive / negative pattern training)
  7. 4-Tier Fallback Manager (Graceful degradation under failures)
"""

import os
import json
import time
from typing import Dict, Any, Optional
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

from agent_modules.memory import MemoryManager
from agent_modules.tools import ToolRegistry
from agent_modules.reasoning import ReasoningEngine
from agent_modules.planning import PlanningEngine
from agent_modules.execution import ExecutionEngine
from agent_modules.observation import ObservationEngine
from agent_modules.learning import PatternLearner, FeedbackProcessor
from agent_modules.fallback import FallbackManager

load_dotenv()

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scam_history.db")
api_key = os.getenv("OPENROUTER_API_KEY")

# Initialize OpenRouter LLM model if key exists
llm_model: Optional[ChatOpenAI] = None
if api_key:
    try:
        llm_model = ChatOpenAI(
            model="openrouter/free",
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key,
            timeout=15.0,
            max_retries=1
        )
    except Exception as e:
        print(f"[ScamShieldAgent] Warning: LLM model initialization warning: {e}")

class ScamShieldAgent:
    """
    Production-Grade Autonomous Real AI Agent for Scam & Phishing Detection.
    """
    def __init__(self, db_path: str = DB_PATH, model: Optional[ChatOpenAI] = llm_model):
        self.db_path = db_path
        self.model = model
        
        # Subsystems
        self.memory = MemoryManager(db_path)
        self.tool_registry = ToolRegistry()
        self.reasoning = ReasoningEngine(model)
        self.planning = PlanningEngine()
        self.execution = ExecutionEngine(self.tool_registry)
        self.observation = ObservationEngine(model)
        self.learner = PatternLearner(self.memory)
        self.feedback_processor = FeedbackProcessor(self.memory, self.learner)
        self.fallback = FallbackManager()

    def analyze(self, message: str, user_id: str = "default_user") -> Dict[str, Any]:
        """
        Executes the autonomous reasoning loop for an untrusted message:
        Think -> Plan -> Act -> Observe -> Synthesize
        """
        start_time = time.perf_counter()
        
        # 1. Retrieve Context & Memory
        context = self.memory.retrieve_context(user_id)
        
        # 2. Tier 2 Check: Cached Learned Pattern Match
        tier2_result = self.fallback.run_tier2_pattern_analysis(message, context)
        if tier2_result:
            tier2_result["latency_ms"] = int((time.perf_counter() - start_time) * 1000)
            return tier2_result

        try:
            # 3. Reasoning Layer (Think)
            reasoning_out = self.reasoning.analyze_complexity(message, context)
            self.memory.log_phase("pending_scan", "reasoning", "success", reasoning_out.get("latency_ms", 0), reasoning_out)

            # 4. Planning Layer (Plan)
            plan = self.planning.create_plan(reasoning_out, message, context)

            # 5. Execution Layer (Act)
            execution_out = self.execution.execute_plan(plan, message, context)
            self.memory.log_phase("pending_scan", "execution", "success", execution_out.get("total_duration_ms", 0), {
                "tools_executed": list(execution_out.get("tool_results", {}).keys())
            })

            # 6. Observation & Synthesis Layer (Observe & Synthesize)
            result = self.observation.evaluate(
                message=message,
                reasoning=reasoning_out,
                execution_results=execution_out,
                user_context=context
            )

            result["latency_ms"] = int((time.perf_counter() - start_time) * 1000)
            return result

        except Exception as e:
            print(f"[ScamShieldAgent] Error in agent loop, activating fallback: {e}")
            # Try Tier 3 Deterministic Fallback via Observation Engine
            try:
                fb_reasoning = {"complexity": "simple", "approach": "lightweight", "intent_hypothesis": "Fallback Inspection"}
                fb_exec = self.execution.execute_plan(
                    self.planning.create_plan(fb_reasoning, message, context),
                    message,
                    context
                )
                fb_result = self.observation._build_deterministic_payload(
                    message=message,
                    reasoning=fb_reasoning,
                    calculated_score=50,
                    detected_warnings=[],
                    positive_indicators=["Evaluated under deterministic safety mode"],
                    execution_results=fb_exec,
                    impersonation_data={}
                )
                fb_result["latency_ms"] = int((time.perf_counter() - start_time) * 1000)
                return fb_result
            except Exception as e2:
                # Tier 4 Safe Inconclusive Defense
                inconclusive = self.fallback.run_tier4_safe_inconclusive(message, str(e2))
                inconclusive["latency_ms"] = int((time.perf_counter() - start_time) * 1000)
                return inconclusive

    def process_feedback(
        self,
        scan_id: str,
        user_id: str,
        original_risk_level: str,
        corrected_risk_level: str,
        feedback_type: str,
        message_text: str,
        reasoning: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Records user correction and trains adaptive patterns into persistent memory.
        """
        return self.feedback_processor.process_feedback(
            scan_id=scan_id,
            user_id=user_id,
            original_risk_level=original_risk_level,
            corrected_risk_level=corrected_risk_level,
            feedback_type=feedback_type,
            message_text=message_text,
            reasoning=reasoning
        )


# Global Real AI Agent Instance
scam_agent = ScamShieldAgent()
agent = scam_agent  # Backwards compatibility

def analyze_scam_structured(message: str, user_id: str = "default_user") -> Dict[str, Any]:
    """
    Public entrypoint for structured scan analysis consumed by server.py and UI.
    """
    return scam_agent.analyze(message, user_id=user_id)

def extract_deterministic_signals(message: str) -> Dict[str, Any]:
    """
    Helper function executing deterministic tools on the message.
    """
    url_res = scam_agent.tool_registry.execute_tool("extract_urls", message=message).get("result", {})
    shortener_res = scam_agent.tool_registry.execute_tool("check_url_shorteners", message=message).get("result", {})
    contact_res = scam_agent.tool_registry.execute_tool("extract_contact_identifiers", message=message).get("result", {})
    urgency_res = scam_agent.tool_registry.execute_tool("analyze_urgency_cues", message=message).get("result", {})
    financial_res = scam_agent.tool_registry.execute_tool("detect_financial_requests", message=message).get("result", {})

    return {
        "urls": url_res.get("urls", []),
        "shorteners": [item["url"] for item in shortener_res.get("items", [])],
        "handles": contact_res.get("telegram_handles", []),
        "phones": contact_res.get("phone_numbers", []),
        "financial_cues": financial_res.get("terms", []),
        "urgency_cues": [c["evidence"] for c in urgency_res.get("cues", [])]
    }


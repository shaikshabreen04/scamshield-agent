"""
Reasoning Engine for ScamShield AI Agent
Analyzes task complexity, formulates intent hypotheses, and determines analysis approaches.
"""

import os
import json
import time
from typing import Dict, Any, Optional
from langchain_openai import ChatOpenAI

class ReasoningEngine:
    def __init__(self, model: Optional[ChatOpenAI] = None):
        self.model = model
        self._cache: Dict[str, Dict[str, Any]] = {}

    def analyze_complexity(self, message: str, user_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Evaluates message complexity and required cognitive capabilities.
        Uses cached fast reasoning where appropriate, with model-assisted deep reasoning.
        """
        # Cache check by message prefix hash
        cache_key = message[:120].strip()
        if cache_key in self._cache:
            return self._cache[cache_key]

        start_time = time.perf_counter()
        msg_lower = message.lower()

        # Fast heuristic signals
        has_url = "http://" in msg_lower or "https://" in msg_lower
        has_urgency = any(w in msg_lower for w in ["urgent", "immediate", "suspended", "expire", "24 hours", "action required"])
        has_finance = any(w in msg_lower for w in ["inr", "usd", "$", "₹", "rs", "fee", "deposit", "winner", "prize", "won"])
        is_transactional_receipt = any(w in msg_lower for w in ["recharge", "was successful", "payment received", "plan benefits", "debited", "credited"]) and not has_url

        # Determine complexity level
        if is_transactional_receipt:
            complexity = "simple"
            intent_hypothesis = "Legitimate Transaction Alert / Carrier Confirmation"
            approach = "lightweight"
            required_tools = ["analyze_urgency_cues", "detect_financial_requests"]
        elif has_url and (has_urgency or has_finance):
            complexity = "complex"
            intent_hypothesis = "Multi-Vector Deceptive Lure / Phishing Vector"
            approach = "thorough"
            required_tools = [
                "extract_urls",
                "check_url_shorteners",
                "analyze_urgency_cues",
                "detect_financial_requests",
                "identify_impersonation",
                "extract_contact_identifiers"
            ]
        elif has_url or has_urgency or has_finance:
            complexity = "moderate"
            intent_hypothesis = "Suspicious Communication / Action Request"
            approach = "standard"
            required_tools = [
                "extract_urls",
                "analyze_urgency_cues",
                "detect_financial_requests",
                "identify_impersonation"
            ]
        else:
            complexity = "simple"
            intent_hypothesis = "Conversational or Informational Broadcast"
            approach = "standard"
            required_tools = ["analyze_urgency_cues", "extract_contact_identifiers"]

        # Incorporate learned user patterns if any
        if user_context and user_context.get("learned_patterns"):
            required_tools.append("cross_reference_learned_patterns")

        latency_ms = int((time.perf_counter() - start_time) * 1000)

        result = {
            "complexity": complexity,
            "intent_hypothesis": intent_hypothesis,
            "approach": approach,
            "required_tools": required_tools,
            "latency_ms": latency_ms,
            "risk_dimensions": {
                "credential_harvesting": has_url,
                "urgency_coercion": has_urgency,
                "financial_extraction": has_finance
            }
        }

        # Keep cache bounded
        if len(self._cache) > 200:
            self._cache.clear()
        self._cache[cache_key] = result
        return result

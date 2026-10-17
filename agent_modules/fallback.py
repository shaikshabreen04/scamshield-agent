"""
Fallback Manager for ScamShield AI Agent
Implements 4-tier graceful degradation:
  Tier 1: Full Dynamic Agent Loop (Reasoning -> Planning -> Execution -> Observation)
  Tier 2: Cached Learned Pattern Matcher
  Tier 3: Local Deterministic Rule Engine
  Tier 4: Safe Inconclusive Defense Payload
"""

from typing import Dict, Any, Optional

class FallbackManager:
    def __init__(self):
        pass

    def run_tier2_pattern_analysis(self, message: str, user_context: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Tier 2: Fast matching against cached patterns without external calls."""
        if not user_context or not user_context.get("learned_patterns"):
            return None

        msg_lower = message.lower()
        for p in user_context["learned_patterns"]:
            p_data = p.get("data", {})
            keywords = p_data.get("keywords", [])
            if keywords and all(k.lower() in msg_lower for k in keywords):
                is_safe = p.get("type") == "safe_sender"
                return {
                    "source": "fallback_tier2_cached_pattern",
                    "risk_level": "low" if is_safe else "high",
                    "risk_score": 10 if is_safe else 88,
                    "confidence": "high",
                    "message_intent": "User-Learned Safe Signature" if is_safe else "User-Learned Threat Pattern",
                    "summary": f"Matched user-trained pattern from past feedback (keywords: {', '.join(keywords)}).",
                    "warning_signs": [] if is_safe else [
                        {"title": "Known Pattern Flagged by User", "desc": "Message matches user correction history.", "severity": "high", "evidence": keywords[0]}
                    ],
                    "positive_indicators": ["Matched trusted sender history"] if is_safe else ["None detected"],
                    "limitations": ["Evaluated via local cache without external network verification"],
                    "recommended_actions": ["No action required" if is_safe else "Do not interact or share details"],
                    "safety_checklist": ["Always double check unverified URLs"]
                }
        return None

    def run_tier4_safe_inconclusive(self, message: str, error_msg: str) -> Dict[str, Any]:
        """Tier 4: Returns a safe defensive result flagging uncertainty."""
        return {
            "source": "fallback_tier4_safe_defense",
            "risk_level": "inconclusive",
            "risk_score": 45,
            "confidence": "low",
            "message_intent": "Inconclusive / Manual Review Required",
            "summary": "Automated security engines could not establish definitive intent. Please manually verify this communication.",
            "warning_signs": [
                {
                    "title": "Automated Analysis Timeout / Uncertainty",
                    "desc": f"Analysis encountered a technical constraint: {error_msg}",
                    "severity": "medium",
                    "evidence": message[:60]
                }
            ],
            "positive_indicators": ["No immediate malicious payload triggered"],
            "limitations": ["Analysis completed under defensive fallback constraints"],
            "recommended_actions": [
                "Do not tap hyperlinks or download attachments.",
                "Verify sender authenticity through established customer support channels."
            ],
            "safety_checklist": [
                "Never share OTPs, PINs, or netbanking passwords with unsolicited contacts."
            ]
        }

"""
Pattern Learning & Feedback Processing Subsystem for ScamShield AI Agent
Implements adaptive learning from user corrections (false positives / false negatives).
"""

import re
import datetime
from typing import Dict, Any, List, Optional
from agent_modules.memory import MemoryManager

class PatternLearner:
    def __init__(self, memory_manager: MemoryManager):
        self.memory = memory_manager

    def extract_pattern_from_correction(
        self,
        message: str,
        feedback_type: str,
        corrected_risk_level: str,
        reasoning: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Analyzes a message corrected by the user and extracts persistent indicators.
        """
        msg_lower = message.lower()

        # Extract tokens and significant keywords
        words = re.findall(r'[a-zA-Z0-9_\-\.]{3,}', msg_lower)
        stop_words = {'the', 'and', 'for', 'you', 'your', 'with', 'this', 'that', 'from', 'have', 'are'}
        candidate_keywords = [w for w in words if w not in stop_words]

        # Determine pattern type
        if corrected_risk_level == "low":
            # User says it is safe -> learned safe sender / safe receipt pattern
            pattern_type = "safe_sender"
            confidence = 0.90
        elif corrected_risk_level == "high":
            # User says it is dangerous -> learned scam indicator
            pattern_type = "scam_indicator"
            confidence = 0.88
        else:
            pattern_type = "custom_rule"
            confidence = 0.75

        # Select most descriptive keywords (up to 4)
        significant = candidate_keywords[:4] if candidate_keywords else ["user_flagged"]

        return {
            "pattern_type": pattern_type,
            "confidence": confidence,
            "data": {
                "keywords": significant,
                "feedback_type": feedback_type,
                "reasoning": reasoning or "",
                "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
        }

class FeedbackProcessor:
    def __init__(self, memory_manager: MemoryManager, pattern_learner: PatternLearner):
        self.memory = memory_manager
        self.learner = pattern_learner

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
        Ingests user feedback, logs the correction, recalculates user stats,
        and saves newly learned patterns.
        """
        # 1. Record feedback in memory
        feedback_id = self.memory.record_feedback(
            scan_id=scan_id,
            user_id=user_id,
            original_risk_level=original_risk_level,
            corrected_risk_level=corrected_risk_level,
            feedback_type=feedback_type,
            reasoning=reasoning
        )

        # 2. Extract learned pattern
        pattern = self.learner.extract_pattern_from_correction(
            message=message_text,
            feedback_type=feedback_type,
            corrected_risk_level=corrected_risk_level,
            reasoning=reasoning
        )

        pattern_id = None
        if pattern:
            pattern_id = self.memory.store_learned_pattern(
                user_id=user_id,
                pattern_type=pattern["pattern_type"],
                pattern_data=pattern["data"],
                confidence=pattern["confidence"]
            )

        return {
            "success": True,
            "feedback_id": feedback_id,
            "learned_pattern_id": pattern_id,
            "message": "Feedback successfully processed and pattern learned."
        }

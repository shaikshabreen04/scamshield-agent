"""
Memory Manager for ScamShield AI Agent
Provides Short-Term Context, Medium-Term Session History, Long-Term Pattern Persistence,
and Feedback Storage in SQLite.
"""

import os
import json
import sqlite3
import datetime
import uuid
from typing import Dict, Any, List, Optional

class MemoryManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_tables()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self):
        conn = self._get_connection()
        cursor = conn.cursor()

        # 1. User Profiles & Preferences Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_profiles (
            user_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            risk_tolerance TEXT NOT NULL DEFAULT 'balanced',
            preferences_json TEXT NOT NULL DEFAULT '{}',
            feedback_stats_json TEXT NOT NULL DEFAULT '{"total_corrections": 0, "accuracy_score": 1.0}'
        )
        """)

        # 2. User Feedback & Corrections Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_feedback (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            original_risk_level TEXT NOT NULL,
            corrected_risk_level TEXT NOT NULL,
            feedback_type TEXT NOT NULL,
            reasoning TEXT,
            created_at TEXT NOT NULL
        )
        """)

        # 3. Learned Patterns Table (Continuous Improvement)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS learned_patterns (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            pattern_type TEXT NOT NULL,
            pattern_data_json TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 0.85,
            learned_from_feedback INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
        """)

        # 4. Multi-Phase Analysis Trace Logs Table (Observability)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis_logs (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            phase TEXT NOT NULL,
            status TEXT NOT NULL,
            duration_ms INTEGER NOT NULL,
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """)

        conn.commit()
        conn.close()

    def retrieve_context(self, user_id: str = "default_user") -> Dict[str, Any]:
        """
        Retrieves:
        - Short-term context: Last 10 scans
        - Medium-term context: User preferences & risk tolerance
        - Long-term memory: User learned patterns from past corrections
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # 1. User preferences
        cursor.execute("SELECT * FROM user_profiles WHERE user_id = ?", (user_id,))
        user_row = cursor.fetchone()
        if not user_row:
            # Create default profile if not exists
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            cursor.execute("""
            INSERT INTO user_profiles (user_id, created_at, risk_tolerance, preferences_json, feedback_stats_json)
            VALUES (?, ?, 'balanced', '{}', '{"total_corrections": 0, "accuracy_score": 1.0}')
            """, (user_id, now))
            conn.commit()
            preferences = {}
            risk_tolerance = "balanced"
            feedback_stats = {"total_corrections": 0, "accuracy_score": 1.0}
        else:
            try:
                preferences = json.loads(user_row["preferences_json"])
            except Exception:
                preferences = {}
            risk_tolerance = user_row["risk_tolerance"]
            try:
                feedback_stats = json.loads(user_row["feedback_stats_json"])
            except Exception:
                feedback_stats = {}

        # 2. Short-term context: Last 10 scans
        cursor.execute("""
        SELECT id, message_intent, risk_level, risk_score, snippet, created_at
        FROM scan_records
        ORDER BY created_at DESC
        LIMIT 10
        """)
        recent_scans = [dict(row) for row in cursor.fetchall()]

        # 3. Long-term memory: Learned patterns for this user
        cursor.execute("""
        SELECT id, pattern_type, pattern_data_json, confidence, created_at
        FROM learned_patterns
        WHERE user_id = ? OR user_id = 'global'
        ORDER BY created_at DESC
        """, (user_id,))
        patterns = []
        for row in cursor.fetchall():
            try:
                data = json.loads(row["pattern_data_json"])
                patterns.append({
                    "id": row["id"],
                    "type": row["pattern_type"],
                    "data": data,
                    "confidence": row["confidence"]
                })
            except Exception:
                pass

        conn.close()

        return {
            "user_id": user_id,
            "risk_tolerance": risk_tolerance,
            "preferences": preferences,
            "feedback_stats": feedback_stats,
            "recent_scans": recent_scans,
            "learned_patterns": patterns
        }

    def record_feedback(self, scan_id: str, user_id: str, feedback_type: str = "correction",
                        corrected_level: str = "low", original_level: str = "medium", reasoning: str = "",
                        original_risk_level: Optional[str] = None, corrected_risk_level: Optional[str] = None) -> str:
        """Stores a correction signal from user feedback and updates user profile stats."""
        if original_risk_level is not None:
            original_level = original_risk_level
        if corrected_risk_level is not None:
            corrected_level = corrected_risk_level

        conn = self._get_connection()
        cursor = conn.cursor()
        feedback_id = "FB-" + str(uuid.uuid4())[:8].upper()
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        cursor.execute("""
        INSERT INTO user_feedback (id, scan_id, user_id, original_risk_level, corrected_risk_level, feedback_type, reasoning, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (feedback_id, scan_id, user_id, original_level, corrected_level, feedback_type, reasoning, now))

        # Update user profile feedback stats
        cursor.execute("SELECT feedback_stats_json FROM user_profiles WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        stats = {"total_corrections": 0, "accuracy_score": 1.0}
        if row:
            try:
                stats = json.loads(row["feedback_stats_json"])
            except Exception:
                pass
        
        stats["total_corrections"] = stats.get("total_corrections", 0) + 1
        stats["last_correction_at"] = now
        cursor.execute("UPDATE user_profiles SET feedback_stats_json = ? WHERE user_id = ?", (json.dumps(stats), user_id))

        conn.commit()
        conn.close()
        return feedback_id

    def store_learned_pattern(self, user_id: str, pattern_type: str, pattern_data: Dict[str, Any], confidence: float = 0.85) -> str:
        """Stores a new pattern learned from feedback (e.g. trusted sender or custom keyword)."""
        conn = self._get_connection()
        cursor = conn.cursor()
        pattern_id = "PAT-" + str(uuid.uuid4())[:8].upper()
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        cursor.execute("""
        INSERT INTO learned_patterns (id, user_id, pattern_type, pattern_data_json, confidence, learned_from_feedback, created_at)
        VALUES (?, ?, ?, ?, ?, 1, ?)
        """, (pattern_id, user_id, pattern_type, json.dumps(pattern_data), confidence, now))

        conn.commit()
        conn.close()
        return pattern_id

    def log_phase(self, scan_id: str, phase: str, status: str, duration_ms: int, details: Dict[str, Any]):
        """Records an execution step for agent observability and latency tracking."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            log_id = "LOG-" + str(uuid.uuid4())[:8].upper()
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()

            cursor.execute("""
            INSERT INTO analysis_logs (id, scan_id, phase, status, duration_ms, details_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (log_id, scan_id, phase, status, duration_ms, json.dumps(details), now))

            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[MemoryManager] Log phase error: {e}")

"""
ScamShield Real AI Agent Architecture Modules
"""

from agent_modules.memory import MemoryManager
from agent_modules.tools import ToolRegistry, ToolDefinition
from agent_modules.reasoning import ReasoningEngine
from agent_modules.planning import PlanningEngine, ExecutionPlan, ExecutionStep
from agent_modules.execution import ExecutionEngine
from agent_modules.observation import ObservationEngine
from agent_modules.learning import PatternLearner, FeedbackProcessor
from agent_modules.fallback import FallbackManager

__all__ = [
    "MemoryManager",
    "ToolRegistry",
    "ToolDefinition",
    "ReasoningEngine",
    "PlanningEngine",
    "ExecutionPlan",
    "ExecutionStep",
    "ExecutionEngine",
    "ObservationEngine",
    "PatternLearner",
    "FeedbackProcessor",
    "FallbackManager",
]

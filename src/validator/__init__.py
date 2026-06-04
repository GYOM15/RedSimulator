"""False Positive Validation module.

Re-tests successful findings from the executor using multiple
independent strategies (differential analysis, multi-payload
confirmation, LLM verdict, timing analysis) to reduce false
positives in the final report.
"""

from .confidence import ConfidenceScorer
from .models import ConfidenceScore, ValidationResult
from .validator import FPValidator

__all__ = ["ConfidenceScore", "ConfidenceScorer", "FPValidator", "ValidationResult"]

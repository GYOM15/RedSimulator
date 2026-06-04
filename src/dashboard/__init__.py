"""Dashboard historical tracking for RedSimulator.

Persists scan snapshots in SQLite for trend analysis and historical comparison.
"""

from .models import ScanSnapshot, TrendData
from .store import DashboardStore

__all__ = [
    "DashboardStore",
    "ScanSnapshot",
    "TrendData",
]

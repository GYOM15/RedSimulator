"""SQLite persistence for dashboard scan snapshots.

Thread-safe storage layer that auto-creates the database and tables
on first use.  Uses the infra logging layer throughout.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from src.infra.logging import get_logger

from .models import ScanSnapshot, TrendData

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_CREATE_TABLE_SQL = """\
CREATE TABLE IF NOT EXISTS scan_snapshots (
    id               TEXT PRIMARY KEY,
    timestamp        TEXT NOT NULL,
    target           TEXT NOT NULL,
    total_vectors    INTEGER NOT NULL DEFAULT 0,
    total_attempts   INTEGER NOT NULL DEFAULT 0,
    successful_attacks INTEGER NOT NULL DEFAULT 0,
    severity_counts  TEXT NOT NULL DEFAULT '{}',
    attack_types     TEXT NOT NULL DEFAULT '[]',
    rules_fired      INTEGER NOT NULL DEFAULT 0,
    cvss_scores      TEXT NOT NULL DEFAULT '[]',
    risk_score       INTEGER NOT NULL DEFAULT 0,
    duration_ms      REAL NOT NULL DEFAULT 0.0
);
"""

_CREATE_INDEX_SQL = """\
CREATE INDEX IF NOT EXISTS idx_snapshots_target_ts
    ON scan_snapshots (target, timestamp DESC);
"""


# ---------------------------------------------------------------------------
# DashboardStore
# ---------------------------------------------------------------------------


class DashboardStore:
    """Persists scan snapshots for historical analysis.

    Uses SQLite with a connection-per-thread approach for thread safety.
    The database file and parent directories are created automatically
    on first access.
    """

    def __init__(self, db_path: str = "data/dashboard/history.db") -> None:
        self._db_path = Path(db_path)
        self._local = threading.local()
        self._init_lock = threading.Lock()
        self._initialized = False

    # -- connection management -----------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        """Return a thread-local SQLite connection, creating it if needed."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            self._ensure_db()
            conn = sqlite3.connect(str(self._db_path), timeout=10.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
        return conn

    def _ensure_db(self) -> None:
        """Create the database file and tables if they do not exist."""
        if self._initialized:
            return
        with self._init_lock:
            if self._initialized:
                return
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self._db_path), timeout=10.0)
            try:
                conn.execute(_CREATE_TABLE_SQL)
                conn.execute(_CREATE_INDEX_SQL)
                conn.commit()
                logger.info("Dashboard DB initialized at %s", self._db_path)
            finally:
                conn.close()
            self._initialized = True

    def close(self) -> None:
        """Close the thread-local connection if open."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    # -- CRUD operations -----------------------------------------------------

    def record_scan(self, snapshot: ScanSnapshot) -> None:
        """Record a scan snapshot.

        Inserts a new row into the scan_snapshots table.  If a snapshot
        with the same ID already exists, it is replaced.
        """
        conn = self._get_conn()
        conn.execute(
            """\
            INSERT OR REPLACE INTO scan_snapshots
                (id, timestamp, target, total_vectors, total_attempts,
                 successful_attacks, severity_counts, attack_types,
                 rules_fired, cvss_scores, risk_score, duration_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot.id,
                snapshot.timestamp,
                snapshot.target,
                snapshot.total_vectors,
                snapshot.total_attempts,
                snapshot.successful_attacks,
                json.dumps(snapshot.severity_counts),
                json.dumps(snapshot.attack_types),
                snapshot.rules_fired,
                json.dumps(snapshot.cvss_scores),
                snapshot.risk_score,
                snapshot.duration_ms,
            ),
        )
        conn.commit()
        logger.info(
            "Recorded scan snapshot %s for target %s (risk=%d)",
            snapshot.id,
            snapshot.target,
            snapshot.risk_score,
        )

    def get_history(self, target: str, limit: int = 50) -> list[ScanSnapshot]:
        """Get scan history for a target, newest first.

        Args:
            target: The target URL to filter by.
            limit: Maximum number of snapshots to return.

        Returns:
            List of ScanSnapshot instances ordered by timestamp descending.
        """
        conn = self._get_conn()
        rows = conn.execute(
            """\
            SELECT * FROM scan_snapshots
            WHERE target = ?
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (target, limit),
        ).fetchall()
        return [self._row_to_snapshot(row) for row in rows]

    def get_trend(self, target: str) -> TrendData:
        """Get trend data for a target.

        Returns all snapshots for the target ordered chronologically
        (oldest first) wrapped in a TrendData instance.
        """
        conn = self._get_conn()
        rows = conn.execute(
            """\
            SELECT * FROM scan_snapshots
            WHERE target = ?
            ORDER BY timestamp ASC
            """,
            (target,),
        ).fetchall()
        snapshots = [self._row_to_snapshot(row) for row in rows]
        return TrendData(target=target, snapshots=snapshots)

    def get_all_targets(self) -> list[str]:
        """List all distinct scanned targets."""
        conn = self._get_conn()
        rows = conn.execute("SELECT DISTINCT target FROM scan_snapshots ORDER BY target").fetchall()
        return [row["target"] for row in rows]

    def get_latest(self, target: str) -> ScanSnapshot | None:
        """Get the most recent scan snapshot for a target.

        Returns None if no scans exist for the given target.
        """
        conn = self._get_conn()
        row = conn.execute(
            """\
            SELECT * FROM scan_snapshots
            WHERE target = ?
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (target,),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_snapshot(row)

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _row_to_snapshot(row: sqlite3.Row) -> ScanSnapshot:
        """Convert a database row to a ScanSnapshot dataclass."""
        return ScanSnapshot(
            id=row["id"],
            timestamp=row["timestamp"],
            target=row["target"],
            total_vectors=row["total_vectors"],
            total_attempts=row["total_attempts"],
            successful_attacks=row["successful_attacks"],
            severity_counts=json.loads(row["severity_counts"]),
            attack_types=json.loads(row["attack_types"]),
            rules_fired=row["rules_fired"],
            cvss_scores=json.loads(row["cvss_scores"]),
            risk_score=row["risk_score"],
            duration_ms=row["duration_ms"],
        )

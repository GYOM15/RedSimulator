"""Persistent flow storage using SQLite.

Stores captured HTTP flows in a SQLite database for querying,
filtering, and feeding into the pipeline.  Thread-safe (the underlying
``sqlite3`` connection is opened with ``check_same_thread=False``).
"""

from __future__ import annotations

import contextlib
import json
import logging
import sqlite3
from pathlib import Path

from .models import CapturedFlow

logger = logging.getLogger(__name__)

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS flows (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    host TEXT NOT NULL,
    path TEXT NOT NULL,
    request_headers TEXT,
    request_body TEXT,
    response_status INTEGER DEFAULT 0,
    response_headers TEXT,
    response_body TEXT,
    content_type TEXT DEFAULT '',
    duration_ms REAL DEFAULT 0,
    tags TEXT DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_flows_host ON flows(host);
CREATE INDEX IF NOT EXISTS idx_flows_method ON flows(method);
CREATE INDEX IF NOT EXISTS idx_flows_status ON flows(response_status);
CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON flows(timestamp);
"""


class FlowStore:
    """SQLite-backed store for captured HTTP flows."""

    def __init__(self, db_path: str = "data/proxy/flows.db") -> None:
        """Initialize the store.  Creates the database and tables if needed.

        Parameters:
            db_path: Path to the SQLite database file.  Parent directories
                     are created automatically.
        """
        self._db_path = db_path
        parent = Path(db_path).parent
        parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        logger.info("FlowStore initialised: %s", db_path)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add(self, flow: CapturedFlow) -> None:
        """Add a captured flow to the store."""
        self._conn.execute(
            """
            INSERT OR REPLACE INTO flows
                (id, timestamp, method, url, host, path,
                 request_headers, request_body,
                 response_status, response_headers, response_body,
                 content_type, duration_ms, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                flow.id,
                flow.timestamp,
                flow.request_method,
                flow.request_url,
                flow.request_host,
                flow.request_path,
                json.dumps(flow.request_headers),
                flow.request_body,
                flow.response_status,
                json.dumps(flow.response_headers),
                flow.response_body,
                flow.response_content_type,
                flow.duration_ms,
                json.dumps(flow.tags),
            ),
        )
        self._conn.commit()

    def get(self, flow_id: str) -> CapturedFlow | None:
        """Return a flow by its ID, or *None* if not found."""
        row = self._conn.execute("SELECT * FROM flows WHERE id = ?", (flow_id,)).fetchone()
        if row is None:
            return None
        return self._row_to_flow(row)

    def search(
        self,
        url_pattern: str = "",
        method: str = "",
        status_min: int = 0,
        status_max: int = 999,
        content_type: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[CapturedFlow]:
        """Search flows with optional filters.

        Parameters:
            url_pattern:  SQL LIKE pattern matched against the URL column.
            method:       Exact match on HTTP method (case-insensitive).
            status_min:   Minimum response status code (inclusive).
            status_max:   Maximum response status code (inclusive).
            content_type: SQL LIKE pattern matched against content_type.
            limit:        Maximum number of results.
            offset:       Result offset for pagination.

        Returns:
            A list of matching :class:`CapturedFlow` instances ordered by
            timestamp descending.
        """
        clauses: list[str] = []
        params: list[object] = []

        if url_pattern:
            clauses.append("url LIKE ?")
            params.append(f"%{url_pattern}%")
        if method:
            clauses.append("UPPER(method) = UPPER(?)")
            params.append(method)
        if status_min > 0:
            clauses.append("response_status >= ?")
            params.append(status_min)
        if status_max < 999:
            clauses.append("response_status <= ?")
            params.append(status_max)
        if content_type:
            clauses.append("content_type LIKE ?")
            params.append(f"%{content_type}%")

        where = " AND ".join(clauses) if clauses else "1=1"
        query = f"SELECT * FROM flows WHERE {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_flow(r) for r in rows]

    def count(self) -> int:
        """Return the total number of stored flows."""
        row = self._conn.execute("SELECT COUNT(*) FROM flows").fetchone()
        return row[0]

    def delete(self, flow_id: str) -> bool:
        """Delete a single flow.  Return *True* if a row was deleted."""
        cursor = self._conn.execute("DELETE FROM flows WHERE id = ?", (flow_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    def clear(self) -> int:
        """Delete all flows.  Return the number of rows deleted."""
        cursor = self._conn.execute("DELETE FROM flows")
        self._conn.commit()
        deleted = cursor.rowcount
        logger.info("FlowStore cleared: %d flows deleted", deleted)
        return deleted

    # ------------------------------------------------------------------
    # Analytics helpers
    # ------------------------------------------------------------------

    def get_hosts(self) -> list[str]:
        """Return a sorted list of distinct hosts from all stored flows."""
        rows = self._conn.execute("SELECT DISTINCT host FROM flows ORDER BY host").fetchall()
        return [r[0] for r in rows]

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_har(self) -> dict:
        """Export all stored flows as a HAR 1.2 (HTTP Archive) dict.

        The returned dict can be serialised directly to JSON and imported
        into browser DevTools or other HAR-compatible tools.
        """
        rows = self._conn.execute("SELECT * FROM flows ORDER BY timestamp ASC").fetchall()

        entries: list[dict] = []
        for row in rows:
            flow = self._row_to_flow(row)
            entries.append(
                {
                    "startedDateTime": flow.timestamp,
                    "time": flow.duration_ms,
                    "request": {
                        "method": flow.request_method,
                        "url": flow.request_url,
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            {"name": k, "value": v} for k, v in flow.request_headers.items()
                        ],
                        "queryString": [],
                        "headersSize": -1,
                        "bodySize": len(flow.request_body),
                        "postData": {
                            "mimeType": flow.request_headers.get("content-type", ""),
                            "text": flow.request_body,
                        }
                        if flow.request_body
                        else None,
                    },
                    "response": {
                        "status": flow.response_status,
                        "statusText": "",
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            {"name": k, "value": v} for k, v in flow.response_headers.items()
                        ],
                        "content": {
                            "size": len(flow.response_body),
                            "mimeType": flow.response_content_type,
                            "text": flow.response_body,
                        },
                        "headersSize": -1,
                        "bodySize": len(flow.response_body),
                    },
                    "cache": {},
                    "timings": {
                        "send": -1,
                        "wait": flow.duration_ms,
                        "receive": -1,
                    },
                }
            )

        return {
            "log": {
                "version": "1.2",
                "creator": {"name": "RedSimulator", "version": "0.1.0"},
                "entries": entries,
            }
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_flow(row: sqlite3.Row) -> CapturedFlow:
        """Convert a database row to a :class:`CapturedFlow`."""
        return CapturedFlow(
            id=row["id"],
            timestamp=row["timestamp"],
            request_method=row["method"],
            request_url=row["url"],
            request_host=row["host"],
            request_path=row["path"],
            request_headers=json.loads(row["request_headers"] or "{}"),
            request_body=row["request_body"] or "",
            response_status=row["response_status"],
            response_headers=json.loads(row["response_headers"] or "{}"),
            response_body=row["response_body"] or "",
            response_content_type=row["content_type"] or "",
            duration_ms=row["duration_ms"],
            tags=json.loads(row["tags"] or "[]"),
        )

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()

    def __del__(self) -> None:
        with contextlib.suppress(Exception):
            self._conn.close()

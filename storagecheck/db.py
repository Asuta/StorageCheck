from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from .utils import utc_now_iso

BOOLEAN_KEYS = {
    "enabled",
    "has_children",
    "is_truncated",
}


class Database:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def compact_if_empty(self) -> bool:
        with self.connect() as connection:
            counts = connection.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM scans) AS scan_count,
                    (SELECT COUNT(*) FROM nodes) AS node_count
                """
            ).fetchone()
            if counts is None:
                return False
            if int(counts["scan_count"] or 0) > 0 or int(counts["node_count"] or 0) > 0:
                return False
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            connection.execute("VACUUM")
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return True

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    label TEXT NOT NULL,
                    root_path TEXT NOT NULL UNIQUE,
                    scan_mode TEXT NOT NULL,
                    max_depth INTEGER NOT NULL DEFAULT 6,
                    schedule_type TEXT NOT NULL DEFAULT 'manual',
                    interval_hours INTEGER,
                    daily_time TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_scan_at TEXT,
                    last_scan_status TEXT,
                    last_scan_size_bytes INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    root_path TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    max_depth INTEGER,
                    engine TEXT NOT NULL DEFAULT 'recursive',
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    status TEXT NOT NULL,
                    total_size_bytes INTEGER NOT NULL DEFAULT 0,
                    stored_node_count INTEGER NOT NULL DEFAULT 0,
                    error_message TEXT
                );

                CREATE TABLE IF NOT EXISTS nodes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    path TEXT NOT NULL,
                    parent_path TEXT,
                    name TEXT NOT NULL,
                    depth INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    child_count INTEGER NOT NULL DEFAULT 0,
                    descendant_count INTEGER NOT NULL DEFAULT 0,
                    modified_time TEXT,
                    has_children INTEGER NOT NULL DEFAULT 0,
                    is_truncated INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    UNIQUE (scan_id, path)
                );

                CREATE INDEX IF NOT EXISTS idx_scans_target_id ON scans(target_id, started_at DESC);
                CREATE INDEX IF NOT EXISTS idx_nodes_scan_parent_path ON nodes(scan_id, parent_path);
                CREATE INDEX IF NOT EXISTS idx_nodes_scan_path ON nodes(scan_id, path);
                """
            )
            self._ensure_column(connection, "scans", "engine", "TEXT NOT NULL DEFAULT 'recursive'")
            self.recover_interrupted_scans(connection)

    def _ensure_column(self, connection: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}
        if column in columns:
            return
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


    def recover_interrupted_scans(self, connection: sqlite3.Connection | None = None) -> int:
        finished_at = utc_now_iso()
        message = "??????????????????????????"
        owns_connection = connection is None
        if connection is None:
            connection = self.connect()
        try:
            rows = connection.execute(
                """
                SELECT id, target_id, total_size_bytes
                FROM scans
                WHERE status = 'running' AND finished_at IS NULL
                """
            ).fetchall()
            if not rows:
                return 0
            connection.execute(
                """
                UPDATE scans
                SET
                    finished_at = ?,
                    status = 'canceled',
                    error_message = COALESCE(error_message, ?)
                WHERE status = 'running' AND finished_at IS NULL
                """,
                (finished_at, message),
            )
            target_ids = {int(row["target_id"]) for row in rows}
            for target_id in target_ids:
                self._refresh_target_scan_summary(connection, target_id, updated_at=finished_at)
            return len(rows)
        finally:
            if owns_connection:
                connection.close()

    def _row_to_dict(self, row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        data = dict(row)
        for key in BOOLEAN_KEYS:
            if key in data and data[key] is not None:
                data[key] = bool(data[key])
        return data

    def list_targets(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    t.*,
                    (
                        SELECT id
                        FROM scans s
                        WHERE s.target_id = t.id AND s.status = 'completed'
                        ORDER BY COALESCE(s.finished_at, s.started_at) DESC
                        LIMIT 1
                    ) AS latest_completed_scan_id,
                    (
                        SELECT id
                        FROM scans s
                        WHERE s.target_id = t.id
                        ORDER BY s.started_at DESC
                        LIMIT 1
                    ) AS latest_scan_id,
                    (
                        SELECT status
                        FROM scans s
                        WHERE s.target_id = t.id
                        ORDER BY s.started_at DESC
                        LIMIT 1
                    ) AS latest_scan_status,
                    (
                        SELECT finished_at
                        FROM scans s
                        WHERE s.target_id = t.id AND s.status = 'completed'
                        ORDER BY COALESCE(s.finished_at, s.started_at) DESC
                        LIMIT 1
                    ) AS latest_completed_at
                FROM targets t
                ORDER BY t.updated_at DESC, t.id DESC
                """
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_target(self, target_id: int) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM targets WHERE id = ?",
                (target_id,),
            ).fetchone()
        return self._row_to_dict(row)

    def create_target(self, payload: dict[str, Any]) -> dict[str, Any]:
        now = utc_now_iso()
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO targets (
                    label,
                    root_path,
                    scan_mode,
                    max_depth,
                    schedule_type,
                    interval_hours,
                    daily_time,
                    enabled,
                    created_at,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["label"],
                    payload["root_path"],
                    payload["scan_mode"],
                    payload["max_depth"],
                    payload["schedule_type"],
                    payload.get("interval_hours"),
                    payload.get("daily_time"),
                    int(payload.get("enabled", True)),
                    now,
                    now,
                ),
            )
            target_id = cursor.lastrowid
        target = self.get_target(int(target_id))
        if target is None:
            raise RuntimeError("Target was created but could not be loaded.")
        return target

    def update_target(self, target_id: int, payload: dict[str, Any]) -> dict[str, Any] | None:
        current = self.get_target(target_id)
        if current is None:
            return None
        merged = {
            **current,
            **payload,
            "updated_at": utc_now_iso(),
        }
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE targets
                SET
                    label = ?,
                    root_path = ?,
                    scan_mode = ?,
                    max_depth = ?,
                    schedule_type = ?,
                    interval_hours = ?,
                    daily_time = ?,
                    enabled = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    merged["label"],
                    merged["root_path"],
                    merged["scan_mode"],
                    merged["max_depth"],
                    merged["schedule_type"],
                    merged.get("interval_hours"),
                    merged.get("daily_time"),
                    int(merged.get("enabled", True)),
                    merged["updated_at"],
                    target_id,
                ),
            )
        return self.get_target(target_id)

    def delete_target(self, target_id: int) -> dict[str, Any] | None:
        target = self.get_target(target_id)
        if target is None:
            return None
        with self.connect() as connection:
            connection.execute(
                """
                DELETE FROM targets
                WHERE id = ?
                """,
                (target_id,),
            )
        self.compact_if_empty()
        return target

    def _refresh_target_scan_summary(
        self,
        connection: sqlite3.Connection,
        target_id: int,
        *,
        updated_at: str | None = None,
    ) -> None:
        latest_scan = connection.execute(
            """
            SELECT finished_at, started_at, status, total_size_bytes
            FROM scans
            WHERE target_id = ? AND status != 'running'
            ORDER BY COALESCE(finished_at, started_at) DESC
            LIMIT 1
            """,
            (target_id,),
        ).fetchone()
        has_running_scan = (
            connection.execute(
                """
                SELECT 1
                FROM scans
                WHERE target_id = ? AND status = 'running'
                LIMIT 1
                """,
                (target_id,),
            ).fetchone()
            is not None
        )

        last_scan_at = None
        last_scan_status = None
        last_scan_size_bytes = 0
        if latest_scan is not None:
            last_scan_at = latest_scan["finished_at"] or latest_scan["started_at"]
            last_scan_status = "running" if has_running_scan else latest_scan["status"]
            last_scan_size_bytes = int(latest_scan["total_size_bytes"] or 0)
        elif has_running_scan:
            last_scan_status = "running"

        connection.execute(
            """
            UPDATE targets
            SET
                last_scan_at = ?,
                last_scan_status = ?,
                last_scan_size_bytes = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                last_scan_at,
                last_scan_status,
                last_scan_size_bytes,
                updated_at or utc_now_iso(),
                target_id,
            ),
        )

    def create_scan_run(self, target_id: int, root_path: str, mode: str, max_depth: int | None, engine: str) -> int:
        started_at = utc_now_iso()
        with self.connect() as connection:
            running_scan = connection.execute(
                """
                SELECT id
                FROM scans
                WHERE target_id = ? AND status = 'running'
                ORDER BY started_at DESC
                LIMIT 1
                """,
                (target_id,),
            ).fetchone()
            if running_scan is not None:
                raise RuntimeError(f"Target {target_id} already has a running scan.")
            cursor = connection.execute(
                """
                INSERT INTO scans (
                    target_id,
                    root_path,
                    mode,
                    max_depth,
                    engine,
                    started_at,
                    status
                ) VALUES (?, ?, ?, ?, ?, ?, 'running')
                """,
                (target_id, root_path, mode, max_depth, engine, started_at),
            )
            connection.execute(
                """
                UPDATE targets
                SET last_scan_status = 'running', updated_at = ?
                WHERE id = ?
                """,
                (started_at, target_id),
            )
            return int(cursor.lastrowid)

    def insert_nodes(self, scan_id: int, nodes: list[dict[str, Any]]) -> None:
        if not nodes:
            return
        with self.connect() as connection:
            connection.executemany(
                """
                INSERT OR REPLACE INTO nodes (
                    scan_id,
                    path,
                    parent_path,
                    name,
                    depth,
                    kind,
                    size_bytes,
                    child_count,
                    descendant_count,
                    modified_time,
                    has_children,
                    is_truncated,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        scan_id,
                        node["path"],
                        node.get("parent_path"),
                        node["name"],
                        node["depth"],
                        node["kind"],
                        node["size_bytes"],
                        node.get("child_count", 0),
                        node.get("descendant_count", 0),
                        node.get("modified_time"),
                        int(node.get("has_children", False)),
                        int(node.get("is_truncated", False)),
                        node.get("created_at") or utc_now_iso(),
                    )
                    for node in nodes
                ],
            )

    def complete_scan_run(
        self,
        scan_id: int,
        *,
        status: str,
        total_size_bytes: int,
        stored_node_count: int,
        error_message: str | None = None,
    ) -> None:
        finished_at = utc_now_iso()
        with self.connect() as connection:
            row = connection.execute(
                "SELECT target_id FROM scans WHERE id = ?",
                (scan_id,),
            ).fetchone()
            if row is None:
                return
            target_id = int(row["target_id"])
            connection.execute(
                """
                UPDATE scans
                SET
                    finished_at = ?,
                    status = ?,
                    total_size_bytes = ?,
                    stored_node_count = ?,
                    error_message = ?
                WHERE id = ?
                """,
                (finished_at, status, total_size_bytes, stored_node_count, error_message, scan_id),
            )
            self._refresh_target_scan_summary(connection, target_id, updated_at=finished_at)

    def list_scans(self, target_id: int, limit: int = 12) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM scans
                WHERE target_id = ?
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (target_id, limit),
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_scan(self, scan_id: int) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT s.*, t.label AS target_label
                FROM scans s
                JOIN targets t ON t.id = s.target_id
                WHERE s.id = ?
                """,
                (scan_id,),
            ).fetchone()
        return self._row_to_dict(row)

    def delete_scan(self, scan_id: int) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT id, target_id
                FROM scans
                WHERE id = ?
                """,
                (scan_id,),
            ).fetchone()
            if row is None:
                return None
            target_id = int(row["target_id"])
            connection.execute(
                """
                DELETE FROM scans
                WHERE id = ?
                """,
                (scan_id,),
            )
            self._refresh_target_scan_summary(connection, target_id)
        self.compact_if_empty()
        return {
            "id": int(row["id"]),
            "target_id": target_id,
        }

    def get_root_node(self, scan_id: int) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM nodes WHERE scan_id = ? AND depth = 0 LIMIT 1",
                (scan_id,),
            ).fetchone()
        return self._row_to_dict(row)

    def get_node(self, scan_id: int, path: str | None = None) -> dict[str, Any] | None:
        if path is None:
            return self.get_root_node(scan_id)
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM nodes WHERE scan_id = ? AND path = ? LIMIT 1",
                (scan_id, path),
            ).fetchone()
        return self._row_to_dict(row)

    def list_children(self, scan_id: int, parent_path: str) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM nodes
                WHERE scan_id = ? AND parent_path = ?
                ORDER BY size_bytes DESC, kind DESC, name COLLATE NOCASE ASC
                """,
                (scan_id, parent_path),
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_breadcrumbs(self, scan_id: int, path: str | None) -> list[dict[str, Any]]:
        node = self.get_node(scan_id, path)
        if node is None:
            return []
        breadcrumbs = [node]
        parent_path = node.get("parent_path")
        while parent_path:
            parent = self.get_node(scan_id, parent_path)
            if parent is None:
                break
            breadcrumbs.append(parent)
            parent_path = parent.get("parent_path")
        breadcrumbs.reverse()
        return breadcrumbs

    def get_path_history(self, scan_id: int, path: str, limit: int = 24) -> list[dict[str, Any]]:
        scan = self.get_scan(scan_id)
        if scan is None:
            return []
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    s.id AS scan_id,
                    s.started_at,
                    s.finished_at,
                    s.total_size_bytes,
                    n.size_bytes
                FROM scans s
                LEFT JOIN nodes n
                    ON n.scan_id = s.id AND n.path = ?
                WHERE s.target_id = ? AND s.status = 'completed'
                ORDER BY COALESCE(s.finished_at, s.started_at) DESC
                LIMIT ?
                """,
                (path, scan["target_id"], limit),
            ).fetchall()
        history = [dict(row) for row in rows]
        history.reverse()
        return history

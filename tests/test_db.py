from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from storagecheck.db import Database


class DatabaseScanDeletionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.database_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = Path(self.database_dir.name) / "storagecheck.db"

    def tearDown(self) -> None:
        self.database_dir.cleanup()

    def _create_database(self, root_path: str) -> Database:
        database = Database(self.db_path)
        database.initialize()
        database.create_target(
            {
                "label": "System",
                "root_path": root_path,
                "scan_mode": "depth",
                "size_strategy": "allocated",
                "max_depth": 6,
                "schedule_type": "manual",
                "interval_hours": None,
                "daily_time": None,
                "enabled": True,
            }
        )
        return database

    def test_delete_scan_updates_target_summary_and_cascades_nodes(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            database = self._create_database(root_dir)
            target_id = int(database.list_targets()[0]["id"])

            first_scan_id = database.create_scan_run(target_id, root_dir, "depth", 6, "recursive")
            database.complete_scan_run(
                first_scan_id,
                status="completed",
                total_size_bytes=128,
                stored_node_count=2,
            )

            second_scan_id = database.create_scan_run(target_id, root_dir, "depth", 6, "recursive")
            database.insert_nodes(
                second_scan_id,
                [
                    {
                        "path": root_dir,
                        "parent_path": None,
                        "name": "root",
                        "depth": 0,
                        "kind": "dir",
                        "size_bytes": 256,
                    }
                ],
            )
            database.complete_scan_run(
                second_scan_id,
                status="completed",
                total_size_bytes=256,
                stored_node_count=1,
            )

            first_scan = database.get_scan(first_scan_id)
            deleted = database.delete_scan(second_scan_id)

            self.assertEqual(deleted, {"id": second_scan_id, "target_id": target_id})
            self.assertIsNone(database.get_scan(second_scan_id))

            target = database.get_target(target_id)
            self.assertIsNotNone(target)
            self.assertEqual(target["last_scan_status"], "completed")
            self.assertEqual(target["last_scan_size_bytes"], 128)
            self.assertEqual(target["last_scan_at"], first_scan["finished_at"])

            with database.connect() as connection:
                node_count = connection.execute(
                    "SELECT COUNT(*) AS count FROM nodes WHERE scan_id = ?",
                    (second_scan_id,),
                ).fetchone()["count"]
            self.assertEqual(node_count, 0)

    def test_delete_only_scan_clears_target_summary(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            database = self._create_database(root_dir)
            target_id = int(database.list_targets()[0]["id"])

            scan_id = database.create_scan_run(target_id, root_dir, "depth", 6, "recursive")
            database.complete_scan_run(
                scan_id,
                status="completed",
                total_size_bytes=64,
                stored_node_count=1,
            )

            deleted = database.delete_scan(scan_id)

            self.assertEqual(deleted, {"id": scan_id, "target_id": target_id})
            target = database.get_target(target_id)
            self.assertIsNotNone(target)
            self.assertIsNone(target["last_scan_at"])
            self.assertIsNone(target["last_scan_status"])
            self.assertEqual(target["last_scan_size_bytes"], 0)

    def test_delete_target_cascades_scans_and_nodes(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            database = self._create_database(root_dir)
            target_id = int(database.list_targets()[0]["id"])
            scan_id = database.create_scan_run(target_id, root_dir, "depth", 6, "recursive")
            database.insert_nodes(
                scan_id,
                [
                    {
                        "path": root_dir,
                        "parent_path": None,
                        "name": "root",
                        "depth": 0,
                        "kind": "dir",
                        "size_bytes": 64,
                    }
                ],
            )
            database.complete_scan_run(
                scan_id,
                status="completed",
                total_size_bytes=64,
                stored_node_count=1,
            )

            deleted = database.delete_target(target_id)

            self.assertIsNotNone(deleted)
            self.assertIsNone(database.get_target(target_id))
            self.assertEqual(database.list_targets(), [])
            self.assertIsNone(database.get_scan(scan_id))

            with database.connect() as connection:
                node_count = connection.execute(
                    "SELECT COUNT(*) AS count FROM nodes WHERE scan_id = ?",
                    (scan_id,),
                ).fetchone()["count"]
            self.assertEqual(node_count, 0)

    def test_scan_run_keeps_size_strategy(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            database = Database(self.db_path)
            database.initialize()
            target = database.create_target(
                {
                    "label": "Fast",
                    "root_path": root_dir,
                    "scan_mode": "depth",
                    "size_strategy": "logical",
                    "max_depth": 6,
                    "schedule_type": "manual",
                    "interval_hours": None,
                    "daily_time": None,
                    "enabled": True,
                }
            )

            scan_id = database.create_scan_run(
                int(target["id"]),
                root_dir,
                "depth",
                6,
                "recursive",
                size_strategy="logical",
            )
            scan = database.get_scan(scan_id)

            self.assertIsNotNone(scan)
            self.assertEqual(target["size_strategy"], "logical")
            self.assertEqual(scan["size_strategy"], "logical")

    def test_insert_nodes_can_reuse_one_connection_until_commit(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            database = self._create_database(root_dir)
            target_id = int(database.list_targets()[0]["id"])
            scan_id = database.create_scan_run(target_id, root_dir, "depth", 6, "recursive")

            writer = database.connect()
            try:
                writer.execute("BEGIN")
                database.insert_nodes(
                    scan_id,
                    [
                        {
                            "path": root_dir,
                            "parent_path": None,
                            "name": "root",
                            "depth": 0,
                            "kind": "dir",
                            "size_bytes": 64,
                        }
                    ],
                    connection=writer,
                )

                with database.connect() as reader:
                    pending_count = reader.execute(
                        "SELECT COUNT(*) AS count FROM nodes WHERE scan_id = ?",
                        (scan_id,),
                    ).fetchone()["count"]
                self.assertEqual(pending_count, 0)

                writer.commit()

                with database.connect() as reader:
                    committed_count = reader.execute(
                        "SELECT COUNT(*) AS count FROM nodes WHERE scan_id = ?",
                        (scan_id,),
                    ).fetchone()["count"]
                self.assertEqual(committed_count, 1)
            finally:
                writer.close()


if __name__ == "__main__":
    unittest.main()

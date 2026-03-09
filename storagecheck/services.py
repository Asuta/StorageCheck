from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock
from typing import Any

from .db import Database
from .ntfs_mft import select_scan_engine
from .scanner import ScanCancelledError
from .utils import utc_now_iso


class ScanAlreadyRunningError(RuntimeError):
    pass


class ScanNotRunningError(RuntimeError):
    pass


SCAN_WRITE_BATCH_SIZE = 5000


class ScanManager:
    def __init__(self, db: Database) -> None:
        self.db = db
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="storage-scan")
        self._lock = Lock()
        self._active: dict[int, dict[str, Any]] = {}

    def is_scanning(self, target_id: int) -> bool:
        with self._lock:
            return target_id in self._active

    def get_active_state(self, target_id: int) -> dict[str, Any] | None:
        with self._lock:
            state = self._active.get(target_id)
            if state is None:
                return None
            return {key: value for key, value in state.items() if key != "cancel_event"}

    def queue_scan(self, target_id: int) -> None:
        with self._lock:
            if target_id in self._active:
                raise ScanAlreadyRunningError(f"Target {target_id} is already scanning.")
            self._active[target_id] = {
                "status": "queued",
                "target_id": target_id,
                "scan_id": None,
                "started_at": None,
                "updated_at": utc_now_iso(),
                "current_path": None,
                "current_name": None,
                "current_kind": None,
                "processed_entry_count": 0,
                "processed_file_count": 0,
                "processed_dir_count": 0,
                "stored_node_count": 0,
                "scanned_size_bytes": 0,
                "skipped_entries": 0,
                "processed_record_count": 0,
                "estimated_total_records": None,
                "progress_ratio": None,
                "phase": None,
                "phase_label": None,
                "engine": None,
                "size_strategy": None,
                "engine_note": None,
                "error_message": None,
                "cancel_requested": False,
                "cancel_event": Event(),
            }
        future = self.executor.submit(self._run_scan, target_id)
        future.add_done_callback(lambda _: self._clear_active(target_id))

    def stop_scan(self, target_id: int) -> dict[str, Any]:
        with self._lock:
            state = self._active.get(target_id)
            if state is None:
                raise ScanNotRunningError(f"Target {target_id} is not scanning.")
            if state.get("cancel_requested"):
                return {key: value for key, value in state.items() if key != "cancel_event"}
            cancel_event = state["cancel_event"]
            cancel_event.set()
            state["cancel_requested"] = True
            state["status"] = "stopping"
            state["phase"] = "stopping"
            state["phase_label"] = "????"
            state["updated_at"] = utc_now_iso()
            return {key: value for key, value in state.items() if key != "cancel_event"}

    def shutdown(self) -> None:
        self.executor.shutdown(wait=False, cancel_futures=False)

    def _clear_active(self, target_id: int) -> None:
        with self._lock:
            self._active.pop(target_id, None)

    def _merge_active_state(self, target_id: int, **payload: Any) -> None:
        with self._lock:
            state = self._active.get(target_id)
            if state is None:
                return
            cancel_requested = bool(state.get("cancel_requested"))
            state.update(payload)
            if cancel_requested and payload.get("status") not in {"failed", "canceled"}:
                state["status"] = "stopping"
                state["phase"] = "stopping"
                state["phase_label"] = "????"
            state["updated_at"] = utc_now_iso()

    def _run_scan(self, target_id: int) -> None:
        target = self.db.get_target(target_id)
        if target is None:
            return

        mode = target["scan_mode"]
        size_strategy = str(target.get("size_strategy") or "allocated")
        max_depth = None if mode == "full" else int(target["max_depth"])
        engine_selection = select_scan_engine(
            str(target["root_path"]),
            mode=mode,
            max_depth=int(target["max_depth"]),
            size_strategy=size_strategy,
        )
        self._merge_active_state(
            target_id,
            status="starting",
            root_path=target["root_path"],
            mode=mode,
            max_depth=max_depth,
            size_strategy=size_strategy,
            engine=engine_selection.engine,
            engine_note=engine_selection.note,
        )
        try:
            scan_id = self.db.create_scan_run(
                target_id=target_id,
                root_path=target["root_path"],
                mode=mode,
                max_depth=max_depth,
                engine=engine_selection.engine,
                size_strategy=size_strategy,
            )
        except Exception as exc:
            self._merge_active_state(
                target_id,
                status="failed",
                error_message=str(exc),
            )
            return
        scan = self.db.get_scan(scan_id)
        started_at = scan["started_at"] if scan is not None else utc_now_iso()
        self._merge_active_state(
            target_id,
            status="running",
            scan_id=scan_id,
            started_at=started_at,
            engine=engine_selection.engine,
            size_strategy=size_strategy,
            engine_note=engine_selection.note,
        )

        buffer: list[dict[str, object]] = []
        write_connection = self.db.connect()

        def should_cancel() -> bool:
            with self._lock:
                state = self._active.get(target_id)
                if state is None:
                    return True
                cancel_event = state.get("cancel_event")
                return bool(cancel_event and cancel_event.is_set())

        def flush() -> None:
            nonlocal buffer
            if not buffer:
                return
            if not write_connection.in_transaction:
                write_connection.execute("BEGIN")
            self.db.insert_nodes(scan_id, buffer, connection=write_connection)
            buffer = []

        def on_node(node: dict[str, object]) -> None:
            buffer.append(node)
            if len(buffer) >= SCAN_WRITE_BATCH_SIZE:
                flush()

        def on_progress(progress: dict[str, object]) -> None:
            self._merge_active_state(target_id, **progress)

        try:
            result = engine_selection.scanner.scan(
                str(target["root_path"]),
                on_node=on_node,
                on_progress=on_progress,
                should_cancel=should_cancel,
            )
            flush()
            error_message = None
            if result.errors:
                error_message = "\n".join(result.errors)
            self._merge_active_state(
                target_id,
                status="finalizing",
                current_path=target["root_path"],
                current_name=target["label"],
                current_kind="dir",
                processed_entry_count=result.processed_entry_count,
                processed_file_count=result.processed_file_count,
                processed_dir_count=result.processed_dir_count,
                stored_node_count=result.stored_node_count,
                scanned_size_bytes=result.scanned_size_bytes,
                skipped_entries=result.skipped_entries,
                progress_ratio=1.0,
                phase="done",
                phase_label="????",
                error_message=error_message,
                engine=engine_selection.engine,
                size_strategy=size_strategy,
                engine_note=engine_selection.note,
            )
            self.db.complete_scan_run(
                scan_id,
                status="completed",
                total_size_bytes=result.total_size_bytes,
                stored_node_count=result.stored_node_count,
                error_message=error_message,
                connection=write_connection,
            )
            write_connection.commit()
        except ScanCancelledError:
            canceled_message = "????????"
            current_state = self.get_active_state(target_id) or {}
            if write_connection.in_transaction:
                write_connection.rollback()
            self._merge_active_state(
                target_id,
                status="canceled",
                error_message=canceled_message,
                phase="canceled",
                phase_label="???",
                size_strategy=size_strategy,
            )
            self.db.complete_scan_run(
                scan_id,
                status="canceled",
                total_size_bytes=int(current_state.get("scanned_size_bytes") or 0),
                stored_node_count=0,
                error_message=canceled_message,
            )
        except Exception as exc:
            if write_connection.in_transaction:
                write_connection.rollback()
            self._merge_active_state(
                target_id,
                status="failed",
                error_message=str(exc),
                engine=engine_selection.engine,
                size_strategy=size_strategy,
                engine_note=engine_selection.note,
            )
            self.db.complete_scan_run(
                scan_id,
                status="failed",
                total_size_bytes=0,
                stored_node_count=0,
                error_message=str(exc),
            )
        finally:
            write_connection.close()

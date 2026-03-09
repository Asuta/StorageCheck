from __future__ import annotations

import ctypes
import os
import stat
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from .utils import default_label_for_path, normalize_path

NodeCallback = Callable[[dict[str, object]], None]
ProgressCallback = Callable[[dict[str, object]], None]
CancelCallback = Callable[[], bool]
INVALID_FILE_SIZE = 0xFFFFFFFF

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True) if os.name == "nt" else None

if kernel32 is not None:
    kernel32.GetCompressedFileSizeW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    kernel32.GetCompressedFileSizeW.restype = ctypes.c_uint32


class ScanCancelledError(RuntimeError):
    pass


@dataclass(slots=True)
class ScanResult:
    total_size_bytes: int
    stored_node_count: int
    skipped_entries: int
    processed_entry_count: int
    processed_file_count: int
    processed_dir_count: int
    scanned_size_bytes: int
    errors: list[str] = field(default_factory=list)


class DiskScanner:
    def __init__(
        self,
        mode: str = "depth",
        max_depth: int = 6,
        size_strategy: str = "allocated",
    ) -> None:
        self.mode = mode
        self.max_depth = max_depth
        self.size_strategy = size_strategy
        self.stored_node_count = 0
        self.skipped_entries = 0
        self.processed_entry_count = 0
        self.processed_file_count = 0
        self.processed_dir_count = 0
        self.scanned_size_bytes = 0
        self.errors: list[str] = []
        self._last_progress_emit = 0.0
        self._last_progress_entries = -1

    def scan(
        self,
        root_path: str,
        on_node: NodeCallback | None = None,
        on_progress: ProgressCallback | None = None,
        should_cancel: CancelCallback | None = None,
    ) -> ScanResult:
        self._check_cancel(should_cancel)
        normalized_root = normalize_path(root_path)
        try:
            stat_result = os.stat(normalized_root, follow_symlinks=False)
        except OSError as exc:
            raise FileNotFoundError(f"Cannot access {normalized_root}: {exc}") from exc

        self._emit_progress(
            on_progress,
            current_path=normalized_root,
            current_kind="dir",
            force=True,
        )
        total_size, _ = self._scan_path(
            path=normalized_root,
            depth=0,
            parent_path=None,
            stat_result=stat_result,
            on_node=on_node,
            on_progress=on_progress,
            should_cancel=should_cancel,
        )
        self._emit_progress(
            on_progress,
            current_path=normalized_root,
            current_kind="dir",
            force=True,
        )
        return ScanResult(
            total_size_bytes=total_size,
            stored_node_count=self.stored_node_count,
            skipped_entries=self.skipped_entries,
            processed_entry_count=self.processed_entry_count,
            processed_file_count=self.processed_file_count,
            processed_dir_count=self.processed_dir_count,
            scanned_size_bytes=self.scanned_size_bytes,
            errors=self.errors,
        )

    def _scan_path(
        self,
        *,
        path: str,
        depth: int,
        parent_path: str | None,
        stat_result: os.stat_result,
        on_node: NodeCallback | None,
        on_progress: ProgressCallback | None,
        should_cancel: CancelCallback | None,
    ) -> tuple[int, int]:
        self._check_cancel(should_cancel)
        if stat.S_ISDIR(stat_result.st_mode):
            return self._scan_directory(
                path=path,
                depth=depth,
                parent_path=parent_path,
                stat_result=stat_result,
                on_node=on_node,
                on_progress=on_progress,
                should_cancel=should_cancel,
            )
        return self._scan_file(
            path=path,
            depth=depth,
            parent_path=parent_path,
            stat_result=stat_result,
            on_node=on_node,
            on_progress=on_progress,
            should_cancel=should_cancel,
        )

    def _scan_file(
        self,
        *,
        path: str,
        depth: int,
        parent_path: str | None,
        stat_result: os.stat_result,
        on_node: NodeCallback | None,
        on_progress: ProgressCallback | None,
        should_cancel: CancelCallback | None,
    ) -> tuple[int, int]:
        self._check_cancel(should_cancel)
        size = self._file_size_bytes(path, stat_result)
        self.processed_entry_count += 1
        self.processed_file_count += 1
        self.scanned_size_bytes += size
        if self._should_store(depth):
            self._emit_node(
                {
                    "path": path,
                    "parent_path": parent_path,
                    "name": default_label_for_path(path),
                    "depth": depth,
                    "kind": "file",
                    "size_bytes": size,
                    "child_count": 0,
                    "descendant_count": 0,
                    "modified_time": self._mtime_to_iso(stat_result),
                    "has_children": False,
                    "is_truncated": False,
                },
                on_node,
            )
        self._emit_progress(on_progress, current_path=path, current_kind="file")
        return size, 1

    def _scan_directory(
        self,
        *,
        path: str,
        depth: int,
        parent_path: str | None,
        stat_result: os.stat_result,
        on_node: NodeCallback | None,
        on_progress: ProgressCallback | None,
        should_cancel: CancelCallback | None,
    ) -> tuple[int, int]:
        self._check_cancel(should_cancel)
        total_size = 0
        total_entries = 1
        child_count = 0
        has_children = False

        try:
            iterator = os.scandir(path)
        except OSError as exc:
            self._record_error(path, exc, on_progress)
            iterator = None

        if iterator is not None:
            with iterator:
                for entry in iterator:
                    self._check_cancel(should_cancel)
                    try:
                        entry_stat = entry.stat(follow_symlinks=False)
                    except OSError as exc:
                        self._record_error(entry.path, exc, on_progress)
                        continue

                    if self._is_reparse_point(entry_stat):
                        self.skipped_entries += 1
                        self._emit_progress(
                            on_progress,
                            current_path=normalize_path(entry.path),
                            current_kind="skipped",
                            force=True,
                        )
                        continue

                    child_path = normalize_path(entry.path)
                    child_count += 1
                    has_children = True
                    child_size, child_entries = self._scan_path(
                        path=child_path,
                        depth=depth + 1,
                        parent_path=path,
                        stat_result=entry_stat,
                        on_node=on_node,
                        on_progress=on_progress,
                        should_cancel=should_cancel,
                    )
                    total_size += child_size
                    total_entries += child_entries

        self.processed_entry_count += 1
        self.processed_dir_count += 1
        if self._should_store(depth):
            is_truncated = (
                self.mode != "full"
                and depth >= self.max_depth
                and child_count > 0
            )
            self._emit_node(
                {
                    "path": path,
                    "parent_path": parent_path,
                    "name": default_label_for_path(path),
                    "depth": depth,
                    "kind": "dir",
                    "size_bytes": total_size,
                    "child_count": child_count,
                    "descendant_count": total_entries - 1,
                    "modified_time": self._mtime_to_iso(stat_result),
                    "has_children": has_children,
                    "is_truncated": is_truncated,
                },
                on_node,
            )
        self._emit_progress(on_progress, current_path=path, current_kind="dir")
        return total_size, total_entries

    def _file_size_bytes(self, path: str, stat_result: os.stat_result) -> int:
        if self.size_strategy == "logical":
            return int(stat_result.st_size)
        return _allocated_file_size(path, stat_result)

    def _should_store(self, depth: int) -> bool:
        return self.mode == "full" or depth <= self.max_depth

    def _emit_node(self, node: dict[str, object], on_node: NodeCallback | None) -> None:
        self.stored_node_count += 1
        if on_node is not None:
            on_node(node)

    def _emit_progress(
        self,
        on_progress: ProgressCallback | None,
        *,
        current_path: str | None,
        current_kind: str | None,
        force: bool = False,
    ) -> None:
        if on_progress is None:
            return
        now = time.monotonic()
        should_emit = force
        if not should_emit:
            processed_delta = self.processed_entry_count - self._last_progress_entries
            should_emit = processed_delta >= 128 or (now - self._last_progress_emit) >= 0.25
        if not should_emit:
            return
        self._last_progress_emit = now
        self._last_progress_entries = self.processed_entry_count
        on_progress(
            {
                "current_path": current_path,
                "current_name": default_label_for_path(current_path) if current_path else None,
                "current_kind": current_kind,
                "processed_entry_count": self.processed_entry_count,
                "processed_file_count": self.processed_file_count,
                "processed_dir_count": self.processed_dir_count,
                "stored_node_count": self.stored_node_count,
                "scanned_size_bytes": self.scanned_size_bytes,
                "skipped_entries": self.skipped_entries,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        )

    def _check_cancel(self, should_cancel: CancelCallback | None) -> None:
        if should_cancel is not None and should_cancel():
            raise ScanCancelledError("Scan cancelled by user.")

    def _record_error(
        self,
        path: str,
        exc: OSError,
        on_progress: ProgressCallback | None,
    ) -> None:
        self.skipped_entries += 1
        if len(self.errors) < 25:
            self.errors.append(f"{path}: {exc}")
        self._emit_progress(
            on_progress,
            current_path=normalize_path(path),
            current_kind="error",
            force=True,
        )

    @staticmethod
    def _mtime_to_iso(stat_result: os.stat_result) -> str:
        return datetime.fromtimestamp(stat_result.st_mtime, tz=timezone.utc).isoformat()

    @staticmethod
    def _is_reparse_point(stat_result: os.stat_result) -> bool:
        flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        attributes = getattr(stat_result, "st_file_attributes", 0)
        return bool(flag and attributes & flag)


def _allocated_file_size(path: str, stat_result: os.stat_result) -> int:
    if os.name == "nt" and kernel32 is not None:
        upper = ctypes.c_uint32()
        ctypes.set_last_error(0)
        lower = kernel32.GetCompressedFileSizeW(path, ctypes.byref(upper))
        error = ctypes.get_last_error()
        if lower != INVALID_FILE_SIZE or error == 0:
            return int((upper.value << 32) | lower)
    blocks = getattr(stat_result, "st_blocks", None)
    if blocks is not None and int(blocks) >= 0:
        return int(blocks) * 512
    return int(stat_result.st_size)

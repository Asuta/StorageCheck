from __future__ import annotations

import ctypes
import msvcrt
import os
import struct
import time
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Iterator

from .scanner import CancelCallback, DiskScanner, ProgressCallback, ScanResult, _allocated_file_size
from .utils import default_label_for_path, normalize_path

FILE_ATTRIBUTE_NORMAL = 0x80
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
GENERIC_READ = 0x80000000
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
READ_CONTROL = 0x00020000
FILE_BEGIN = 0
FILE_DEVICE_FILE_SYSTEM = 0x00000009
METHOD_BUFFERED = 0
METHOD_NEITHER = 3
SE_PRIVILEGE_ENABLED = 0x00000002
TOKEN_QUERY = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020
ERROR_NOT_ALL_ASSIGNED = 1300
ERROR_MORE_DATA = 234
SE_BACKUP_NAME = "SeBackupPrivilege"
BACKUP_DATA = 0x00000001
BACKUP_READ_CHUNK_SIZE = 64 * 1024
VOLUME_READ_CHUNK_SIZE = 1024 * 1024

MFT_RECORD_MAGIC = b"FILE"
MFT_RECORD_SIZE = 1024
NTFS_ROOT_RECORD = 5
ATTRIBUTE_END = 0xFFFFFFFF
ATTRIBUTE_STANDARD_INFORMATION = 0x10
ATTRIBUTE_FILE_NAME = 0x30
ATTRIBUTE_DATA = 0x80
FILE_RECORD_IN_USE = 0x0001
FILE_RECORD_IS_DIRECTORY = 0x0002
REFERENCE_MASK = 0x0000FFFFFFFFFFFF
WINDOWS_EPOCH_DIFF = 11644473600
FILETIME_TICKS_PER_SECOND = 10_000_000

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True) if os.name == "nt" else None
shell32 = ctypes.WinDLL("shell32", use_last_error=True) if os.name == "nt" else None
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True) if os.name == "nt" else None


@dataclass(slots=True)
class ScanEngineSelection:
    scanner: DiskScanner
    engine: str
    note: str | None = None


@dataclass(slots=True)
class _FileLink:
    parent_ref: int
    name: str
    namespace: int
    file_attributes: int
    size_bytes: int
    modified_time: str | None


@dataclass(slots=True)
class _ParsedRecord:
    record_id: int
    is_directory: bool
    modified_time: str | None
    allocated_size: int | None
    data_size: int | None
    links: list[_FileLink] = field(default_factory=list)


@dataclass(slots=True)
class _DirectoryInfo:
    record_id: int
    name: str | None = None
    parent_id: int | None = None
    modified_time: str | None = None
    child_dirs: list[int] = field(default_factory=list)
    child_count: int = 0
    direct_size_bytes: int = 0
    total_size_bytes: int = 0
    descendant_count: int = 0
    depth: int | None = None
    path: str | None = None
    reachable: bool = False


class _Luid(ctypes.Structure):
    _fields_ = [
        ("LowPart", ctypes.c_uint32),
        ("HighPart", ctypes.c_int32),
    ]


class _LuidAndAttributes(ctypes.Structure):
    _fields_ = [
        ("Luid", _Luid),
        ("Attributes", ctypes.c_uint32),
    ]


class _TokenPrivileges(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", ctypes.c_uint32),
        ("Privileges", _LuidAndAttributes * 1),
    ]


class _NtfsVolumeDataBuffer(ctypes.Structure):
    _fields_ = [
        ("VolumeSerialNumber", ctypes.c_longlong),
        ("NumberSectors", ctypes.c_longlong),
        ("TotalClusters", ctypes.c_longlong),
        ("FreeClusters", ctypes.c_longlong),
        ("TotalReserved", ctypes.c_longlong),
        ("BytesPerSector", ctypes.c_uint32),
        ("BytesPerCluster", ctypes.c_uint32),
        ("BytesPerFileRecordSegment", ctypes.c_uint32),
        ("ClustersPerFileRecordSegment", ctypes.c_uint32),
        ("MftValidDataLength", ctypes.c_longlong),
        ("MftStartLcn", ctypes.c_longlong),
        ("Mft2StartLcn", ctypes.c_longlong),
        ("MftZoneStart", ctypes.c_longlong),
        ("MftZoneEnd", ctypes.c_longlong),
    ]


class _StartingVcnInputBuffer(ctypes.Structure):
    _fields_ = [("StartingVcn", ctypes.c_longlong)]


if kernel32 is not None:
    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    kernel32.DeviceIoControl.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_void_p,
    ]
    kernel32.DeviceIoControl.restype = ctypes.c_int
    kernel32.GetFileSizeEx.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_longlong)]
    kernel32.GetFileSizeEx.restype = ctypes.c_int
    kernel32.GetVolumeInformationW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    ]
    kernel32.GetVolumeInformationW.restype = ctypes.c_int
    kernel32.ReadFile.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_void_p,
    ]
    kernel32.ReadFile.restype = ctypes.c_int
    kernel32.SetFilePointerEx.argtypes = [
        ctypes.c_void_p,
        ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong),
        ctypes.c_uint32,
    ]
    kernel32.SetFilePointerEx.restype = ctypes.c_int
    shell32.IsUserAnAdmin.restype = ctypes.c_int
    advapi32.OpenProcessToken.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.OpenProcessToken.restype = ctypes.c_int
    advapi32.LookupPrivilegeValueW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(_Luid),
    ]
    advapi32.LookupPrivilegeValueW.restype = ctypes.c_int
    advapi32.AdjustTokenPrivileges.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.POINTER(_TokenPrivileges),
        ctypes.c_uint32,
        ctypes.POINTER(_TokenPrivileges),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    advapi32.AdjustTokenPrivileges.restype = ctypes.c_int
    kernel32.BackupRead.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_int,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    kernel32.BackupRead.restype = ctypes.c_int


def select_scan_engine(root_path: str, *, mode: str, max_depth: int) -> ScanEngineSelection:
    scanner = DiskScanner(mode=mode, max_depth=max_depth)
    normalized_root = normalize_path(root_path)
    if os.name != "nt":
        return ScanEngineSelection(scanner=scanner, engine="recursive", note="当前系统不是 Windows，已回退到递归扫描。")
    if not is_drive_root(normalized_root):
        return ScanEngineSelection(
            scanner=scanner,
            engine="recursive",
            note="NTFS MFT 快速模式目前只支持整盘根目录，例如 C:\\。",
        )
    filesystem = get_filesystem_name(normalized_root)
    if filesystem is None:
        return ScanEngineSelection(
            scanner=scanner,
            engine="recursive",
            note="无法识别这个盘的文件系统，已回退到递归扫描。",
        )
    if filesystem.upper() != "NTFS":
        return ScanEngineSelection(
            scanner=scanner,
            engine="recursive",
            note=f"{normalized_root} 不是 NTFS 分区，已回退到递归扫描。",
        )
    if not is_user_admin():
        return ScanEngineSelection(
            scanner=scanner,
            engine="recursive",
            note="请用管理员身份运行 start-admin.bat，才能启用 NTFS MFT 快速扫描。",
        )
    access_error = probe_mft_access(normalized_root)
    if access_error is not None:
        return ScanEngineSelection(
            scanner=scanner,
            engine="recursive",
            note=f"无法直接读取 {normalized_root} 的 $MFT：{access_error}。已回退到递归扫描。",
        )
    return ScanEngineSelection(
        scanner=NtfsMftScanner(mode=mode, max_depth=max_depth),
        engine="ntfs_mft",
        note=None,
    )


def is_drive_root(path: str) -> bool:
    if os.name != "nt":
        return False
    normalized = normalize_path(path)
    drive, tail = os.path.splitdrive(normalized)
    return bool(drive) and tail in ("", "\\")


def is_user_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(shell32.IsUserAnAdmin())
    except OSError:
        return False


def get_filesystem_name(root_path: str) -> str | None:
    if os.name != "nt":
        return None
    normalized_root = normalize_path(root_path)
    fs_name = ctypes.create_unicode_buffer(32)
    volume_flags = ctypes.c_uint32()
    result = kernel32.GetVolumeInformationW(
        normalized_root,
        None,
        0,
        None,
        None,
        ctypes.byref(volume_flags),
        fs_name,
        len(fs_name),
    )
    if not result:
        return None
    return fs_name.value or None


def probe_mft_access(root_path: str) -> str | None:
    try:
        with _open_mft_stream(root_path):
            return None
    except OSError as exc:
        return str(exc)


class NtfsMftScanner(DiskScanner):
    def scan(
        self,
        root_path: str,
        on_node=None,
        on_progress: ProgressCallback | None = None,
        should_cancel: CancelCallback | None = None,
    ) -> ScanResult:
        self._check_cancel(should_cancel)
        normalized_root = normalize_path(root_path)
        if not is_drive_root(normalized_root):
            raise ValueError("NTFS MFT scanner only supports drive roots like C:\\.")
        self._reset_state()
        directory_map: dict[int, _DirectoryInfo] = {
            NTFS_ROOT_RECORD: _DirectoryInfo(
                record_id=NTFS_ROOT_RECORD,
                name=default_label_for_path(normalized_root),
                parent_id=None,
            )
        }
        total_records = self._estimate_total_records(normalized_root)
        self._check_cancel(should_cancel)
        self._emit_mft_progress(
            on_progress,
            current_path=normalized_root,
            current_kind="dir",
            phase="mft-pass-1",
            phase_label="读取 MFT",
            processed_record_count=0,
            estimated_total_records=total_records,
            progress_ratio=0.0,
            force=True,
        )
        for processed_record_count, parsed_record in enumerate(self._iter_parsed_records(normalized_root, should_cancel=should_cancel), start=1):
            self._consume_record(parsed_record, directory_map)
            self._emit_mft_progress_for_record(
                on_progress,
                parsed_record,
                phase="mft-pass-1",
                phase_label="读取 MFT",
                processed_record_count=processed_record_count,
                estimated_total_records=total_records,
                progress_ratio=self._ratio_for_phase(processed_record_count, total_records, 0.0),
            )

        reachable_order = self._mark_reachable_directories(directory_map, normalized_root)
        if not reachable_order:
            raise RuntimeError(f"无法从 {normalized_root} 的 MFT 中构建目录树。")
        self._reset_directory_sizes(directory_map)
        self.scanned_size_bytes = 0
        self._emit_mft_progress(
            on_progress,
            current_path=normalized_root,
            current_kind="dir",
            phase="mft-pass-2",
            phase_label="校准本地占用",
            processed_record_count=0,
            estimated_total_records=total_records,
            progress_ratio=0.34,
            force=True,
        )
        for processed_record_count, parsed_record in enumerate(self._iter_parsed_records(normalized_root, should_cancel=should_cancel), start=1):
            self._accumulate_file_sizes(parsed_record, directory_map)
            current_path = self._best_progress_path(parsed_record, directory_map)
            current_kind = "dir" if parsed_record.is_directory else "file"
            self._emit_mft_progress(
                on_progress,
                current_path=current_path,
                current_kind=current_kind,
                phase="mft-pass-2",
                phase_label="校准本地占用",
                processed_record_count=processed_record_count,
                estimated_total_records=total_records,
                progress_ratio=self._ratio_for_phase(processed_record_count, total_records, 0.34),
            )
        self._compute_directory_totals(directory_map, reachable_order)
        root_dir = directory_map[NTFS_ROOT_RECORD]
        self.scanned_size_bytes = root_dir.total_size_bytes
        self.processed_dir_count = len(reachable_order)
        self.processed_file_count = max(0, root_dir.descendant_count + 1 - self.processed_dir_count)
        self.processed_entry_count = root_dir.descendant_count + 1
        self._emit_directory_nodes(directory_map, reachable_order, on_node)
        self._emit_mft_progress(
            on_progress,
            current_path=normalized_root,
            current_kind="dir",
            phase="mft-pass-3",
            phase_label="写入文件节点",
            processed_record_count=0,
            estimated_total_records=total_records,
            progress_ratio=0.67,
            force=True,
        )

        for processed_record_count, parsed_record in enumerate(self._iter_parsed_records(normalized_root, should_cancel=should_cancel), start=1):
            self._emit_file_nodes(parsed_record, directory_map, on_node)
            current_path = self._best_progress_path(parsed_record, directory_map)
            current_kind = "dir" if parsed_record.is_directory else "file"
            self._emit_mft_progress(
                on_progress,
                current_path=current_path,
                current_kind=current_kind,
                phase="mft-pass-3",
                phase_label="写入文件节点",
                processed_record_count=processed_record_count,
                estimated_total_records=total_records,
                progress_ratio=self._ratio_for_phase(processed_record_count, total_records, 0.67),
            )

        self._emit_mft_progress(
            on_progress,
            current_path=normalized_root,
            current_kind="dir",
            phase="done",
            phase_label="扫描完成",
            processed_record_count=total_records,
            estimated_total_records=total_records,
            progress_ratio=1.0,
            force=True,
        )
        return ScanResult(
            total_size_bytes=root_dir.total_size_bytes,
            stored_node_count=self.stored_node_count,
            skipped_entries=self.skipped_entries,
            processed_entry_count=self.processed_entry_count,
            processed_file_count=self.processed_file_count,
            processed_dir_count=self.processed_dir_count,
            scanned_size_bytes=self.scanned_size_bytes,
            errors=self.errors,
        )

    def _reset_state(self) -> None:
        self.stored_node_count = 0
        self.skipped_entries = 0
        self.processed_entry_count = 0
        self.processed_file_count = 0
        self.processed_dir_count = 0
        self.scanned_size_bytes = 0
        self.errors = []
        self._last_progress_emit = 0.0
        self._last_progress_entries = -1

    def _estimate_total_records(self, root_path: str) -> int:
        with _open_mft_stream(root_path) as (_, size_bytes):
            if size_bytes <= 0:
                return 1
            return max(1, (size_bytes + MFT_RECORD_SIZE - 1) // MFT_RECORD_SIZE)

    def _iter_parsed_records(
        self,
        root_path: str,
        *,
        should_cancel: CancelCallback | None = None,
    ) -> Iterable[_ParsedRecord]:
        with _open_mft_stream(root_path) as (stream, _):
            record_index = 0
            while True:
                self._check_cancel(should_cancel)
                raw_record = stream.read(MFT_RECORD_SIZE)
                if not raw_record:
                    break
                if len(raw_record) < MFT_RECORD_SIZE:
                    break
                parsed_record = _parse_mft_record(raw_record, record_index)
                if parsed_record is not None:
                    yield parsed_record
                record_index += 1

    def _consume_record(self, parsed_record: _ParsedRecord, directory_map: dict[int, _DirectoryInfo]) -> None:
        if parsed_record.is_directory:
            self._consume_directory(parsed_record, directory_map)
            return
        self._consume_file(parsed_record, directory_map)

    def _consume_directory(self, parsed_record: _ParsedRecord, directory_map: dict[int, _DirectoryInfo]) -> None:
        self.processed_dir_count += 1
        self.processed_entry_count = self.processed_file_count + self.processed_dir_count
        directory_info = self._directory_entry(directory_map, parsed_record.record_id)
        directory_info.modified_time = parsed_record.modified_time or directory_info.modified_time
        selected_link = _select_directory_link(parsed_record.links)
        if selected_link is None:
            return
        if parsed_record.record_id != NTFS_ROOT_RECORD:
            directory_info.name = selected_link.name
            directory_info.parent_id = selected_link.parent_ref
            parent_directory = self._directory_entry(directory_map, selected_link.parent_ref)
            if parsed_record.record_id not in parent_directory.child_dirs:
                parent_directory.child_dirs.append(parsed_record.record_id)
                parent_directory.child_count += 1

    def _consume_file(self, parsed_record: _ParsedRecord, directory_map: dict[int, _DirectoryInfo]) -> None:
        selected_links = list(_select_file_links(parsed_record.links))
        if not selected_links:
            return
        self.processed_file_count += len(selected_links)
        self.processed_entry_count = self.processed_file_count + self.processed_dir_count
        for selected_link in selected_links:
            parent_directory = self._directory_entry(directory_map, selected_link.parent_ref)
            parent_directory.child_count += 1

    def _directory_entry(self, directory_map: dict[int, _DirectoryInfo], record_id: int) -> _DirectoryInfo:
        entry = directory_map.get(record_id)
        if entry is None:
            entry = _DirectoryInfo(record_id=record_id)
            directory_map[record_id] = entry
        return entry

    def _mark_reachable_directories(
        self,
        directory_map: dict[int, _DirectoryInfo],
        normalized_root: str,
    ) -> list[int]:
        root_dir = self._directory_entry(directory_map, NTFS_ROOT_RECORD)
        root_dir.name = default_label_for_path(normalized_root)
        root_dir.path = normalized_root
        root_dir.depth = 0
        order: list[int] = []
        stack = [NTFS_ROOT_RECORD]
        visited: set[int] = set()
        while stack:
            record_id = stack.pop()
            if record_id in visited:
                continue
            visited.add(record_id)
            directory_info = directory_map.get(record_id)
            if directory_info is None:
                continue
            directory_info.reachable = True
            order.append(record_id)
            parent_path = directory_info.path or normalized_root
            next_depth = (directory_info.depth or 0) + 1
            for child_id in reversed(directory_info.child_dirs):
                child_dir = directory_map.get(child_id)
                if child_dir is None or not child_dir.name:
                    continue
                child_dir.path = _join_child_path(parent_path, child_dir.name)
                child_dir.depth = next_depth
                stack.append(child_id)
        return order

    def _reset_directory_sizes(self, directory_map: dict[int, _DirectoryInfo]) -> None:
        for directory_info in directory_map.values():
            directory_info.direct_size_bytes = 0
            directory_info.total_size_bytes = 0
            directory_info.descendant_count = 0

    def _accumulate_file_sizes(
        self,
        parsed_record: _ParsedRecord,
        directory_map: dict[int, _DirectoryInfo],
    ) -> None:
        if parsed_record.is_directory:
            return
        for selected_link in _select_file_links(parsed_record.links):
            parent_directory = directory_map.get(selected_link.parent_ref)
            if parent_directory is None or not parent_directory.reachable or parent_directory.path is None:
                continue
            path = _join_child_path(parent_directory.path, selected_link.name)
            resolved_size = self._resolved_link_size(path, selected_link)
            parent_directory.direct_size_bytes += resolved_size
            self.scanned_size_bytes += resolved_size

    def _compute_directory_totals(
        self,
        directory_map: dict[int, _DirectoryInfo],
        reachable_order: list[int],
    ) -> None:
        for record_id in reversed(reachable_order):
            directory_info = directory_map[record_id]
            total_size_bytes = directory_info.direct_size_bytes
            descendant_count = directory_info.child_count
            for child_id in directory_info.child_dirs:
                child_dir = directory_map.get(child_id)
                if child_dir is None or not child_dir.reachable:
                    continue
                total_size_bytes += child_dir.total_size_bytes
                descendant_count += child_dir.descendant_count
            directory_info.total_size_bytes = total_size_bytes
            directory_info.descendant_count = descendant_count

    def _emit_directory_nodes(
        self,
        directory_map: dict[int, _DirectoryInfo],
        reachable_order: list[int],
        on_node,
    ) -> None:
        for record_id in sorted(
            reachable_order,
            key=lambda item: (
                directory_map[item].depth or 0,
                directory_map[item].path or "",
            ),
        ):
            directory_info = directory_map[record_id]
            depth = int(directory_info.depth or 0)
            if not self._should_store(depth):
                continue
            self._emit_node(
                {
                    "path": directory_info.path,
                    "parent_path": None if depth == 0 else directory_map[directory_info.parent_id].path,
                    "name": directory_info.name or default_label_for_path(directory_info.path or ""),
                    "depth": depth,
                    "kind": "dir",
                    "size_bytes": directory_info.total_size_bytes,
                    "child_count": directory_info.child_count,
                    "descendant_count": directory_info.descendant_count,
                    "modified_time": directory_info.modified_time,
                    "has_children": directory_info.child_count > 0,
                    "is_truncated": self.mode != "full" and depth >= self.max_depth and directory_info.child_count > 0,
                },
                on_node,
            )

    def _emit_file_nodes(
        self,
        parsed_record: _ParsedRecord,
        directory_map: dict[int, _DirectoryInfo],
        on_node,
    ) -> None:
        if parsed_record.is_directory:
            return
        for selected_link in _select_file_links(parsed_record.links):
            parent_directory = directory_map.get(selected_link.parent_ref)
            if parent_directory is None or not parent_directory.reachable or parent_directory.path is None:
                continue
            depth = int(parent_directory.depth or 0) + 1
            if not self._should_store(depth):
                continue
            path = _join_child_path(parent_directory.path, selected_link.name)
            resolved_size = self._resolved_link_size(path, selected_link)
            self._emit_node(
                {
                    "path": path,
                    "parent_path": parent_directory.path,
                    "name": selected_link.name,
                    "depth": depth,
                    "kind": "file",
                    "size_bytes": resolved_size,
                    "child_count": 0,
                    "descendant_count": 0,
                    "modified_time": selected_link.modified_time,
                    "has_children": False,
                    "is_truncated": False,
                },
                on_node,
            )

    def _resolved_link_size(self, path: str, selected_link: _FileLink) -> int:
        if not _needs_actual_size_lookup(selected_link.file_attributes):
            return selected_link.size_bytes
        try:
            stat_result = os.stat(path, follow_symlinks=False)
        except OSError:
            return 0
        return _allocated_file_size(path, stat_result)

    def _emit_mft_progress_for_record(
        self,
        on_progress: ProgressCallback | None,
        parsed_record: _ParsedRecord,
        *,
        phase: str,
        phase_label: str,
        processed_record_count: int,
        estimated_total_records: int,
        progress_ratio: float,
    ) -> None:
        current_path = self._best_progress_path(parsed_record)
        current_kind = "dir" if parsed_record.is_directory else "file"
        if parsed_record.record_id == NTFS_ROOT_RECORD:
            current_kind = "dir"
        self._emit_mft_progress(
            on_progress,
            current_path=current_path,
            current_kind=current_kind,
            phase=phase,
            phase_label=phase_label,
            processed_record_count=processed_record_count,
            estimated_total_records=estimated_total_records,
            progress_ratio=progress_ratio,
        )

    def _emit_mft_progress(
        self,
        on_progress: ProgressCallback | None,
        *,
        current_path: str | None,
        current_kind: str | None,
        phase: str,
        phase_label: str,
        processed_record_count: int,
        estimated_total_records: int,
        progress_ratio: float,
        force: bool = False,
    ) -> None:
        if on_progress is None:
            return
        now = time.monotonic()
        should_emit = force
        if not should_emit:
            processed_delta = self.processed_entry_count - self._last_progress_entries
            should_emit = processed_delta >= 256 or (now - self._last_progress_emit) >= 0.2
        if not should_emit:
            return
        self._last_progress_emit = now
        self._last_progress_entries = self.processed_entry_count
        payload = {
            "current_path": current_path,
            "current_name": default_label_for_path(current_path) if current_path else None,
            "current_kind": current_kind,
            "processed_entry_count": self.processed_entry_count,
            "processed_file_count": self.processed_file_count,
            "processed_dir_count": self.processed_dir_count,
            "stored_node_count": self.stored_node_count,
            "scanned_size_bytes": self.scanned_size_bytes,
            "skipped_entries": self.skipped_entries,
            "processed_record_count": processed_record_count,
            "estimated_total_records": estimated_total_records,
            "progress_ratio": progress_ratio,
            "phase": phase,
            "phase_label": phase_label,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        on_progress(payload)

    def _best_progress_path(
        self,
        parsed_record: _ParsedRecord,
        directory_map: dict[int, _DirectoryInfo] | None = None,
    ) -> str | None:
        if parsed_record.record_id == NTFS_ROOT_RECORD:
            return None
        if not parsed_record.links:
            return f"MFT 记录 #{parsed_record.record_id}"
        best_link = max(parsed_record.links, key=lambda link: (_namespace_score(link.namespace), len(link.name)))
        if directory_map is None:
            return best_link.name or f"MFT 记录 #{parsed_record.record_id}"
        parent_directory = directory_map.get(best_link.parent_ref)
        if parent_directory is None or parent_directory.path is None:
            return best_link.name or f"MFT 记录 #{parsed_record.record_id}"
        return _join_child_path(parent_directory.path, best_link.name)

    @staticmethod
    def _ratio_for_phase(processed_record_count: int, total_records: int, phase_offset: float) -> float:
        if total_records <= 0:
            return min(1.0, max(0.0, phase_offset))
        phase_progress = min(1.0, processed_record_count / total_records)
        return min(1.0, max(0.0, phase_offset + phase_progress * 0.5))


def _open_mft_stream(root_path: str):
    if os.name != "nt":
        raise OSError("$MFT scanning is only available on Windows NTFS volumes.")
    normalized_root = normalize_path(root_path)
    raw_path = _mft_raw_path(normalized_root)
    direct_error: OSError | None = None
    backup_error: OSError | None = None
    try:
        return _open_mft_stream_direct(raw_path)
    except OSError as exc:
        direct_error = exc
    try:
        return _open_mft_stream_backup(raw_path)
    except OSError as exc:
        backup_error = exc
    try:
        return _open_mft_stream_volume(normalized_root)
    except OSError as exc:
        messages = []
        if direct_error is not None:
            messages.append(f"直接读取失败（{direct_error}）")
        if backup_error is not None:
            messages.append(f"备份语义读取失败（{backup_error}）")
        messages.append(f"卷区段读取失败（{exc}）")
        raise OSError(f"{raw_path}: " + "；".join(messages)) from exc


def _open_mft_stream_direct(raw_path: str):
    stack = ExitStack()
    handle_ref: dict[str, int | None] = {"value": None}
    try:
        stack.enter_context(_temporary_privilege(SE_BACKUP_NAME))
        handle = kernel32.CreateFileW(
            raw_path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        invalid_handle_value = ctypes.c_void_p(-1).value
        if handle in (None, invalid_handle_value):
            error_code = ctypes.get_last_error()
            raise OSError(ctypes.FormatError(error_code).strip())
        handle_ref["value"] = handle
        stack.callback(_close_handle_ref, handle_ref)

        size_bytes = ctypes.c_longlong()
        if not kernel32.GetFileSizeEx(handle, ctypes.byref(size_bytes)):
            error_code = ctypes.get_last_error()
            raise OSError(f"无法读取大小：{ctypes.FormatError(error_code).strip()}")

        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        handle_ref["value"] = None
        try:
            stream = os.fdopen(fd, "rb", buffering=0)
        except OSError:
            os.close(fd)
            raise
        stack.callback(stream.close)
    except Exception:
        stack.close()
        raise

    return _build_stream_context(stream, int(size_bytes.value), stack)


def _open_mft_stream_backup(raw_path: str):
    stack = ExitStack()
    handle_ref: dict[str, int | None] = {"value": None}
    try:
        stack.enter_context(_temporary_privilege(SE_BACKUP_NAME))
        handle = kernel32.CreateFileW(
            raw_path,
            READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        invalid_handle_value = ctypes.c_void_p(-1).value
        if handle in (None, invalid_handle_value):
            error_code = ctypes.get_last_error()
            raise OSError(ctypes.FormatError(error_code).strip())
        handle_ref["value"] = handle
        stack.callback(_close_handle_ref, handle_ref)

        stream = _BackupReadStream(handle)
        size_bytes = stream.prepare_default_data_stream()
        handle_ref["value"] = None
        stack.callback(stream.close)
    except Exception:
        stack.close()
        raise

    return _build_stream_context(stream, size_bytes, stack)


def _open_mft_stream_volume(root_path: str):
    stack = ExitStack()
    volume_handle_ref: dict[str, int | None] = {"value": None}
    mft_handle_ref: dict[str, int | None] = {"value": None}
    try:
        stack.enter_context(_temporary_privilege(SE_BACKUP_NAME))
        volume_handle = _open_volume_handle(root_path, GENERIC_READ)
        volume_handle_ref["value"] = volume_handle
        stack.callback(_close_handle_ref, volume_handle_ref)

        volume_data = _query_ntfs_volume_data(volume_handle)
        mft_handle = kernel32.CreateFileW(
            _mft_raw_path(root_path),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        invalid_handle_value = ctypes.c_void_p(-1).value
        if mft_handle in (None, invalid_handle_value):
            error_code = ctypes.get_last_error()
            raise OSError(ctypes.FormatError(error_code).strip())
        mft_handle_ref["value"] = mft_handle
        stack.callback(_close_handle_ref, mft_handle_ref)

        extents = _get_mft_retrieval_extents(mft_handle)
        if not extents:
            raise OSError("未读取到 $MFT 的卷区段。")

        stream = _VolumeExtentStream(
            volume_handle=volume_handle,
            extents=extents,
            bytes_per_sector=int(volume_data.BytesPerSector),
            bytes_per_cluster=int(volume_data.BytesPerCluster),
            total_size_bytes=int(volume_data.MftValidDataLength),
        )
        volume_handle_ref["value"] = None
        mft_handle_ref["value"] = None
        stack.callback(stream.close)
        kernel32.CloseHandle(mft_handle)
    except Exception:
        stack.close()
        raise

    return _build_stream_context(stream, int(volume_data.MftValidDataLength), stack)


def _build_stream_context(stream, size_bytes: int, stack: ExitStack):
    class _MftStreamContext:
        def __enter__(self):
            return stream, size_bytes

        def __exit__(self, exc_type, exc, tb):
            stack.close()
            return False

    return _MftStreamContext()


def _ctl_code(device_type: int, function: int, method: int, access: int) -> int:
    return (device_type << 16) | (access << 14) | (function << 2) | method


def _mft_raw_path(root_path: str) -> str:
    return f"\\\\.\\{normalize_path(root_path)}$MFT"


def _volume_raw_path(root_path: str) -> str:
    normalized_root = normalize_path(root_path)
    drive, _tail = os.path.splitdrive(normalized_root)
    if not drive:
        raise OSError(f"无法从路径中提取盘符：{root_path}")
    return f"\\\\.\\{drive}"


def _open_volume_handle(root_path: str, desired_access: int) -> int:
    handle = kernel32.CreateFileW(
        _volume_raw_path(root_path),
        desired_access,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    invalid_handle_value = ctypes.c_void_p(-1).value
    if handle in (None, invalid_handle_value):
        error_code = ctypes.get_last_error()
        raise OSError(ctypes.FormatError(error_code).strip())
    return handle


def _query_ntfs_volume_data(volume_handle: int) -> _NtfsVolumeDataBuffer:
    buffer = _NtfsVolumeDataBuffer()
    bytes_returned = ctypes.c_uint32()
    if not kernel32.DeviceIoControl(
        volume_handle,
        _ctl_code(FILE_DEVICE_FILE_SYSTEM, 25, METHOD_BUFFERED, 0),
        None,
        0,
        ctypes.byref(buffer),
        ctypes.sizeof(buffer),
        ctypes.byref(bytes_returned),
        None,
    ):
        error_code = ctypes.get_last_error()
        raise OSError(f"FSCTL_GET_NTFS_VOLUME_DATA 失败：{ctypes.FormatError(error_code).strip()}")
    return buffer


def _get_mft_retrieval_extents(mft_handle: int) -> list[tuple[int, int, int]]:
    extents: list[tuple[int, int, int]] = []
    starting_vcn = 0
    while True:
        input_buffer = _StartingVcnInputBuffer()
        input_buffer.StartingVcn = starting_vcn
        output_buffer = ctypes.create_string_buffer(64 * 1024)
        bytes_returned = ctypes.c_uint32()
        ctypes.set_last_error(0)
        success = kernel32.DeviceIoControl(
            mft_handle,
            _ctl_code(FILE_DEVICE_FILE_SYSTEM, 28, METHOD_NEITHER, 0),
            ctypes.byref(input_buffer),
            ctypes.sizeof(input_buffer),
            output_buffer,
            ctypes.sizeof(output_buffer),
            ctypes.byref(bytes_returned),
            None,
        )
        error_code = ctypes.get_last_error()
        if not success and error_code != ERROR_MORE_DATA:
            raise OSError(f"FSCTL_GET_RETRIEVAL_POINTERS 失败：{ctypes.FormatError(error_code).strip()}")

        raw = output_buffer.raw
        extent_count = int.from_bytes(raw[:4], "little")
        if extent_count <= 0:
            break

        base_offset = 16
        last_next_vcn = starting_vcn
        for index in range(extent_count):
            offset = base_offset + index * 16
            next_vcn = int.from_bytes(raw[offset:offset + 8], "little", signed=True)
            lcn = int.from_bytes(raw[offset + 8:offset + 16], "little", signed=True)
            extents.append((last_next_vcn, next_vcn, lcn))
            last_next_vcn = next_vcn

        if success:
            break
        starting_vcn = last_next_vcn
    return extents


def _close_handle_ref(handle_ref: dict[str, int | None]) -> None:
    handle = handle_ref["value"]
    if handle is not None:
        kernel32.CloseHandle(handle)
        handle_ref["value"] = None


class _VolumeExtentStream:
    def __init__(
        self,
        *,
        volume_handle: int,
        extents: list[tuple[int, int, int]],
        bytes_per_sector: int,
        bytes_per_cluster: int,
        total_size_bytes: int,
    ) -> None:
        self.volume_handle = volume_handle
        self.extents = extents
        self.bytes_per_sector = bytes_per_sector
        self.bytes_per_cluster = bytes_per_cluster
        self.total_size_bytes = total_size_bytes
        self._extent_index = 0
        self._extent_consumed_bytes = 0
        self._bytes_consumed = 0
        self._buffer = bytearray()
        self._buffer_offset = 0
        self._closed = False

    def read(self, size: int = -1) -> bytes:
        remaining_total = self.total_size_bytes - self._bytes_consumed
        if remaining_total <= 0:
            return b""
        if size is None or size < 0 or size > remaining_total:
            size = remaining_total

        chunks: list[bytes] = []
        remaining = size
        while remaining > 0:
            buffered = len(self._buffer) - self._buffer_offset
            if buffered <= 0:
                self._fill_buffer(min(remaining, VOLUME_READ_CHUNK_SIZE))
                buffered = len(self._buffer) - self._buffer_offset
                if buffered <= 0:
                    break
            take = min(remaining, buffered)
            start = self._buffer_offset
            end = start + take
            chunks.append(bytes(self._buffer[start:end]))
            self._buffer_offset = end
            self._bytes_consumed += take
            remaining -= take

        data = b"".join(chunks)
        if len(data) == MFT_RECORD_SIZE:
            return _restore_mft_record_fixups(data, self.bytes_per_sector)
        return data

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        kernel32.CloseHandle(self.volume_handle)

    def _fill_buffer(self, minimum_bytes: int) -> None:
        self._buffer = bytearray()
        self._buffer_offset = 0
        target_bytes = max(minimum_bytes, VOLUME_READ_CHUNK_SIZE)
        while len(self._buffer) < target_bytes and self._extent_index < len(self.extents):
            current_vcn, next_vcn, lcn = self.extents[self._extent_index]
            extent_total_bytes = (next_vcn - current_vcn) * self.bytes_per_cluster
            extent_remaining = extent_total_bytes - self._extent_consumed_bytes
            if extent_remaining <= 0:
                self._extent_index += 1
                self._extent_consumed_bytes = 0
                continue
            remaining_total = self.total_size_bytes - (self._bytes_consumed + len(self._buffer))
            if remaining_total <= 0:
                break
            read_size = min(target_bytes - len(self._buffer), extent_remaining, remaining_total)
            if lcn < 0 or read_size <= 0:
                break
            self._buffer.extend(
                _read_volume_bytes(
                    self.volume_handle,
                    file_offset=(lcn * self.bytes_per_cluster) + self._extent_consumed_bytes,
                    size=read_size,
                )
            )
            self._extent_consumed_bytes += read_size
            if self._extent_consumed_bytes >= extent_total_bytes:
                self._extent_index += 1
                self._extent_consumed_bytes = 0


def _read_volume_bytes(volume_handle: int, *, file_offset: int, size: int) -> bytes:
    if size <= 0:
        return b""
    new_position = ctypes.c_longlong()
    if not kernel32.SetFilePointerEx(
        volume_handle,
        int(file_offset),
        ctypes.byref(new_position),
        FILE_BEGIN,
    ):
        error_code = ctypes.get_last_error()
        raise OSError(f"定位卷偏移失败：{ctypes.FormatError(error_code).strip()}")
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_uint32()
    if not kernel32.ReadFile(
        volume_handle,
        buffer,
        size,
        ctypes.byref(bytes_read),
        None,
    ):
        error_code = ctypes.get_last_error()
        raise OSError(f"读取卷数据失败：{ctypes.FormatError(error_code).strip()}")
    return buffer.raw[: bytes_read.value]


def _restore_mft_record_fixups(raw_record: bytes, bytes_per_sector: int) -> bytes:
    if bytes_per_sector <= 0 or len(raw_record) < 8:
        return raw_record
    try:
        usa_offset, usa_count = struct.unpack_from("<HH", raw_record, 4)
    except struct.error:
        return raw_record
    usa_length = usa_count * 2
    if usa_offset <= 0 or usa_length < 2 or usa_offset + usa_length > len(raw_record):
        return raw_record

    fixed = bytearray(raw_record)
    for sector_index in range(1, usa_count):
        sector_end = sector_index * bytes_per_sector - 2
        replacement_offset = usa_offset + sector_index * 2
        if sector_end < 0 or sector_end + 2 > len(fixed):
            return raw_record
        fixed[sector_end:sector_end + 2] = raw_record[replacement_offset:replacement_offset + 2]
    return bytes(fixed)


class _BackupReadStream:
    def __init__(self, handle: int) -> None:
        self.handle = handle
        self.context = ctypes.c_void_p()
        self._remaining_in_stream: int | None = None
        self._closed = False

    def prepare_default_data_stream(self) -> int:
        if self._remaining_in_stream is not None:
            return self._remaining_in_stream
        while True:
            header = self._read_backup_bytes(20)
            if not header:
                raise OSError("BackupRead 未返回默认数据流。")
            if len(header) < 20:
                raise OSError("BackupRead 返回了不完整的流头。")
            stream_id, _stream_attributes, stream_size, stream_name_size = struct.unpack("<IIqI", header)
            if stream_name_size:
                self._skip_backup_bytes(stream_name_size)
            if stream_id == BACKUP_DATA and stream_name_size == 0:
                self._remaining_in_stream = int(stream_size)
                return self._remaining_in_stream
            self._skip_backup_bytes(int(stream_size))

    def read(self, size: int = -1) -> bytes:
        remaining = self.prepare_default_data_stream()
        if remaining <= 0:
            return b""
        if size is None or size < 0 or size > remaining:
            size = remaining
        data = self._read_backup_bytes(size)
        if len(data) != size:
            raise OSError("BackupRead 返回的数据长度不足。")
        self._remaining_in_stream = remaining - size
        return data

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        bytes_read = ctypes.c_uint32()
        kernel32.BackupRead(
            self.handle,
            None,
            0,
            ctypes.byref(bytes_read),
            True,
            False,
            ctypes.byref(self.context),
        )
        kernel32.CloseHandle(self.handle)

    def _read_backup_bytes(self, size: int) -> bytes:
        if size <= 0:
            return b""
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_uint32()
        if not kernel32.BackupRead(
            self.handle,
            buffer,
            size,
            ctypes.byref(bytes_read),
            False,
            False,
            ctypes.byref(self.context),
        ):
            error_code = ctypes.get_last_error()
            raise OSError(f"BackupRead 失败：{ctypes.FormatError(error_code).strip()}")
        return buffer.raw[: bytes_read.value]

    def _skip_backup_bytes(self, size: int) -> None:
        remaining = max(0, size)
        while remaining:
            chunk = self._read_backup_bytes(min(remaining, BACKUP_READ_CHUNK_SIZE))
            if not chunk:
                raise OSError("BackupRead 在跳过流数据时提前结束。")
            remaining -= len(chunk)


@contextmanager
def _temporary_privilege(privilege_name: str) -> Iterator[None]:
    if os.name != "nt":
        yield
        return

    token = ctypes.c_void_p()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
        ctypes.byref(token),
    ):
        error_code = ctypes.get_last_error()
        raise OSError(f"无法打开当前进程令牌：{ctypes.FormatError(error_code).strip()}")

    previous_state = _TokenPrivileges()
    previous_state_size = ctypes.c_uint32()
    try:
        luid = _Luid()
        if not advapi32.LookupPrivilegeValueW(None, privilege_name, ctypes.byref(luid)):
            error_code = ctypes.get_last_error()
            raise OSError(f"无法定位权限 {privilege_name}：{ctypes.FormatError(error_code).strip()}")

        updated_state = _TokenPrivileges()
        updated_state.PrivilegeCount = 1
        updated_state.Privileges[0].Luid = luid
        updated_state.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        ctypes.set_last_error(0)
        if not advapi32.AdjustTokenPrivileges(
            token,
            False,
            ctypes.byref(updated_state),
            ctypes.sizeof(previous_state),
            ctypes.byref(previous_state),
            ctypes.byref(previous_state_size),
        ):
            error_code = ctypes.get_last_error()
            raise OSError(f"启用权限 {privilege_name} 失败：{ctypes.FormatError(error_code).strip()}")

        error_code = ctypes.get_last_error()
        if error_code == ERROR_NOT_ALL_ASSIGNED:
            raise OSError(f"当前进程缺少 {privilege_name}，无法直接读取 NTFS 元数据。")

        yield
    finally:
        if previous_state.PrivilegeCount:
            ctypes.set_last_error(0)
            advapi32.AdjustTokenPrivileges(
                token,
                False,
                ctypes.byref(previous_state),
                0,
                None,
                None,
            )
        kernel32.CloseHandle(token)


def _parse_mft_record(raw_record: bytes, fallback_record_id: int) -> _ParsedRecord | None:
    if len(raw_record) < MFT_RECORD_SIZE or raw_record[:4] != MFT_RECORD_MAGIC:
        return None
    try:
        flags = struct.unpack_from("<H", raw_record, 22)[0]
        if not flags & FILE_RECORD_IN_USE:
            return None
        base_record = struct.unpack_from("<Q", raw_record, 32)[0] & REFERENCE_MASK
        if base_record:
            return None
        record_id = struct.unpack_from("<I", raw_record, 44)[0] or fallback_record_id
        is_directory = bool(flags & FILE_RECORD_IS_DIRECTORY)
        attribute_offset = struct.unpack_from("<H", raw_record, 20)[0]
    except struct.error:
        return None
    if attribute_offset <= 0 or attribute_offset >= MFT_RECORD_SIZE:
        return None

    modified_time: str | None = None
    allocated_size: int | None = None
    data_size: int | None = None
    links: list[_FileLink] = []
    offset = attribute_offset
    while offset <= MFT_RECORD_SIZE - 8:
        try:
            attribute_type = struct.unpack_from("<I", raw_record, offset)[0]
            attribute_length = struct.unpack_from("<I", raw_record, offset + 4)[0]
        except struct.error:
            break
        if attribute_type == ATTRIBUTE_END:
            break
        if attribute_length < 8 or offset + attribute_length > MFT_RECORD_SIZE:
            break
        non_resident_flag = raw_record[offset + 8]
        name_length = raw_record[offset + 9]
        if attribute_type == ATTRIBUTE_STANDARD_INFORMATION and modified_time is None:
            modified_time = _parse_standard_information_mtime(raw_record, offset, non_resident_flag)
        elif attribute_type == ATTRIBUTE_FILE_NAME:
            link = _parse_file_name_link(raw_record, offset, non_resident_flag)
            if link is not None:
                links.append(link)
                modified_time = link.modified_time or modified_time
        elif attribute_type == ATTRIBUTE_DATA and not is_directory and name_length == 0:
            parsed_allocated_size, parsed_size = _parse_data_sizes(raw_record, offset, attribute_length, non_resident_flag)
            if parsed_allocated_size is not None:
                allocated_size = parsed_allocated_size
            if parsed_size is not None:
                data_size = parsed_size
        offset += attribute_length
    resolved_links = []
    for link in links:
        resolved_links.append(
            _FileLink(
                parent_ref=link.parent_ref,
                name=link.name,
                namespace=link.namespace,
                file_attributes=link.file_attributes,
                size_bytes=link.size_bytes if link.size_bytes > 0 else int(allocated_size if allocated_size is not None else (data_size or 0)),
                modified_time=link.modified_time or modified_time,
            )
        )
    return _ParsedRecord(
        record_id=record_id,
        is_directory=is_directory,
        modified_time=modified_time,
        allocated_size=allocated_size,
        data_size=data_size,
        links=resolved_links,
    )


def _parse_standard_information_mtime(raw_record: bytes, offset: int, non_resident_flag: int) -> str | None:
    if non_resident_flag != 0:
        return None
    content = _resident_content(raw_record, offset)
    if content is None or len(content) < 24:
        return None
    try:
        return _filetime_to_iso(struct.unpack_from("<Q", content, 8)[0])
    except struct.error:
        return None


def _parse_file_name_link(raw_record: bytes, offset: int, non_resident_flag: int) -> _FileLink | None:
    if non_resident_flag != 0:
        return None
    content = _resident_content(raw_record, offset)
    if content is None or len(content) < 66:
        return None
    try:
        parent_ref = struct.unpack_from("<Q", content, 0)[0] & REFERENCE_MASK
        modified_time = _filetime_to_iso(struct.unpack_from("<Q", content, 16)[0])
        file_attributes = struct.unpack_from("<I", content, 56)[0]
        size_bytes = struct.unpack_from("<Q", content, 40)[0]
        name_length = content[64]
        namespace = content[65]
        name_end = 66 + name_length * 2
        if name_end > len(content):
            return None
        name = content[66:name_end].decode("utf-16-le", errors="replace")
    except (UnicodeDecodeError, struct.error):
        return None
    if not name or name in (".", ".."):
        return None
    return _FileLink(
        parent_ref=parent_ref,
        name=name,
        namespace=namespace,
        file_attributes=int(file_attributes),
        size_bytes=int(size_bytes),
        modified_time=modified_time,
    )


def _parse_data_sizes(raw_record: bytes, offset: int, attribute_length: int, non_resident_flag: int) -> tuple[int | None, int | None]:
    try:
        if non_resident_flag == 0:
            resident_size = int(struct.unpack_from("<I", raw_record, offset + 16)[0])
            return resident_size, resident_size
        if attribute_length < 56:
            return None, None
        allocated_size = int(struct.unpack_from("<Q", raw_record, offset + 40)[0])
        data_size = int(struct.unpack_from("<Q", raw_record, offset + 48)[0])
        return allocated_size, data_size
    except struct.error:
        return None, None


def _resident_content(raw_record: bytes, offset: int) -> bytes | None:
    try:
        content_size = struct.unpack_from("<I", raw_record, offset + 16)[0]
        content_offset = struct.unpack_from("<H", raw_record, offset + 20)[0]
    except struct.error:
        return None
    if content_offset <= 0:
        return None
    end_offset = offset + content_offset + content_size
    if end_offset > len(raw_record):
        return None
    return raw_record[offset + content_offset:end_offset]


def _select_directory_link(links: list[_FileLink]) -> _FileLink | None:
    selected_links = list(_select_links(links))
    if not selected_links:
        return None
    return max(selected_links, key=lambda link: (_namespace_score(link.namespace), len(link.name)))


def _select_file_links(links: list[_FileLink]) -> Iterable[_FileLink]:
    return _select_links(links)


def _select_links(links: list[_FileLink]) -> Iterable[_FileLink]:
    grouped: dict[int, list[_FileLink]] = {}
    for link in links:
        grouped.setdefault(link.parent_ref, []).append(link)
    for group in grouped.values():
        has_non_dos_name = any(link.namespace != 2 for link in group)
        filtered_group = [link for link in group if link.namespace != 2] if has_non_dos_name else list(group)
        deduped_by_name: dict[str, _FileLink] = {}
        for link in filtered_group:
            key = link.name.casefold()
            current = deduped_by_name.get(key)
            if current is None or _namespace_score(link.namespace) > _namespace_score(current.namespace):
                deduped_by_name[key] = link
        for link in deduped_by_name.values():
            yield link


def _namespace_score(namespace: int) -> int:
    if namespace == 3:
        return 4
    if namespace == 1:
        return 3
    if namespace == 0:
        return 2
    return 1


def _needs_actual_size_lookup(file_attributes: int) -> bool:
    return bool(
        file_attributes
        & (
            0x00000200  # FILE_ATTRIBUTE_SPARSE_FILE
            | 0x00000400  # FILE_ATTRIBUTE_REPARSE_POINT
            | 0x00000800  # FILE_ATTRIBUTE_COMPRESSED
            | 0x00001000  # FILE_ATTRIBUTE_OFFLINE
            | 0x00040000  # FILE_ATTRIBUTE_RECALL_ON_OPEN
            | 0x00100000  # FILE_ATTRIBUTE_UNPINNED
            | 0x00400000  # FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
        )
    )


def _filetime_to_iso(filetime_value: int) -> str | None:
    if filetime_value <= 0:
        return None
    unix_time = (filetime_value / FILETIME_TICKS_PER_SECOND) - WINDOWS_EPOCH_DIFF
    try:
        return datetime.fromtimestamp(unix_time, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def _join_child_path(parent_path: str, name: str) -> str:
    if parent_path.endswith("\\"):
        return f"{parent_path}{name}"
    return f"{parent_path}\\{name}"

from __future__ import annotations

from contextlib import nullcontext
import unittest
from unittest.mock import MagicMock, patch

from storagecheck.ntfs_mft import (
    FILE_FLAG_BACKUP_SEMANTICS,
    NtfsMftScanner,
    READ_CONTROL,
    SE_BACKUP_NAME,
    _FileLink,
    _needs_actual_size_lookup,
    _parse_data_sizes,
    _parse_file_name_link,
    _mft_raw_path,
    _restore_mft_record_fixups,
    _volume_raw_path,
    is_drive_root,
    select_scan_engine,
)
from storagecheck.scanner import DiskScanner


class NtfsEngineSelectionTests(unittest.TestCase):
    def test_detects_drive_root(self) -> None:
        self.assertTrue(is_drive_root("C:\\"))
        self.assertFalse(is_drive_root("C:\\Windows"))

    @patch("storagecheck.ntfs_mft.probe_mft_access", return_value=None)
    @patch("storagecheck.ntfs_mft.is_user_admin", return_value=True)
    @patch("storagecheck.ntfs_mft.get_filesystem_name", return_value="NTFS")
    def test_selects_ntfs_mft_for_elevated_ntfs_root(self, *_args) -> None:
        selection = select_scan_engine("C:\\", mode="depth", max_depth=6, size_strategy="logical")

        self.assertEqual(selection.engine, "ntfs_mft")
        self.assertIsInstance(selection.scanner, NtfsMftScanner)
        self.assertEqual(selection.scanner.size_strategy, "logical")
        self.assertIsNone(selection.note)

    @patch("storagecheck.ntfs_mft.is_user_admin", return_value=False)
    @patch("storagecheck.ntfs_mft.get_filesystem_name", return_value="NTFS")
    def test_falls_back_when_not_elevated(self, *_args) -> None:
        selection = select_scan_engine("C:\\", mode="depth", max_depth=6)

        self.assertEqual(selection.engine, "recursive")
        self.assertIsInstance(selection.scanner, DiskScanner)
        self.assertIn("start-admin.bat", selection.note or "")

    def test_falls_back_for_non_root_paths(self) -> None:
        selection = select_scan_engine("C:\\Windows", mode="depth", max_depth=6)

        self.assertEqual(selection.engine, "recursive")
        self.assertIsInstance(selection.scanner, DiskScanner)

    def test_builds_raw_mft_path_from_drive_root(self) -> None:
        self.assertEqual(_mft_raw_path("C:\\"), "\\\\.\\C:\\$MFT")

    def test_builds_raw_volume_path_from_drive_root(self) -> None:
        self.assertEqual(_volume_raw_path("C:\\"), "\\\\.\\C:")

    def test_restores_mft_update_sequence_array(self) -> None:
        raw = bytearray(1024)
        raw[:4] = b"FILE"
        raw[4:8] = (48).to_bytes(2, "little") + (3).to_bytes(2, "little")
        raw[48:54] = b"XYABCD"
        raw[510:512] = b"XY"
        raw[1022:1024] = b"XY"

        restored = _restore_mft_record_fixups(bytes(raw), 512)

        self.assertEqual(restored[510:512], b"AB")
        self.assertEqual(restored[1022:1024], b"CD")

    @patch("storagecheck.ntfs_mft.os.fdopen")
    @patch("storagecheck.ntfs_mft.msvcrt.open_osfhandle", return_value=321)
    @patch("storagecheck.ntfs_mft._temporary_privilege")
    @patch("storagecheck.ntfs_mft.kernel32")
    def test_open_mft_stream_direct_enables_backup_semantics(self, mock_kernel, mock_privilege, _mock_open_osfhandle, mock_fdopen) -> None:
        from storagecheck.ntfs_mft import _open_mft_stream_direct

        mock_privilege.return_value = nullcontext()
        mock_kernel.CreateFileW.return_value = 123
        mock_kernel.CloseHandle = MagicMock()

        def fake_get_file_size(_handle, size_ptr) -> int:
            size_ptr._obj.value = 4096
            return 1

        mock_kernel.GetFileSizeEx.side_effect = fake_get_file_size
        fake_stream = MagicMock()
        mock_fdopen.return_value = fake_stream

        with _open_mft_stream_direct("\\\\.\\C:\\$MFT") as (stream, size_bytes):
            self.assertIs(stream, fake_stream)
            self.assertEqual(size_bytes, 4096)

        mock_privilege.assert_called_once_with(SE_BACKUP_NAME)
        create_file_args = mock_kernel.CreateFileW.call_args.args
        self.assertEqual(create_file_args[0], "\\\\.\\C:\\$MFT")
        self.assertTrue(create_file_args[5] & FILE_FLAG_BACKUP_SEMANTICS)

    @patch("storagecheck.ntfs_mft._open_mft_stream_backup")
    @patch("storagecheck.ntfs_mft._open_mft_stream_direct", side_effect=OSError("拒绝访问。"))
    def test_open_mft_stream_falls_back_to_backup_mode(self, _mock_direct, mock_backup) -> None:
        from storagecheck.ntfs_mft import _open_mft_stream

        sentinel = MagicMock()
        mock_backup.return_value = sentinel

        result = _open_mft_stream("C:\\")

        self.assertIs(result, sentinel)
        mock_backup.assert_called_once_with("\\\\.\\C:\\$MFT")

    @patch("storagecheck.ntfs_mft._open_mft_stream_volume")
    @patch("storagecheck.ntfs_mft._open_mft_stream_backup", side_effect=OSError("拒绝访问。"))
    @patch("storagecheck.ntfs_mft._open_mft_stream_direct", side_effect=OSError("拒绝访问。"))
    def test_open_mft_stream_falls_back_to_volume_mode(self, _mock_direct, _mock_backup, mock_volume) -> None:
        from storagecheck.ntfs_mft import _open_mft_stream

        sentinel = MagicMock()
        mock_volume.return_value = sentinel

        result = _open_mft_stream("C:\\")

        self.assertIs(result, sentinel)
        mock_volume.assert_called_once_with("C:\\")

    @patch("storagecheck.ntfs_mft._BackupReadStream")
    @patch("storagecheck.ntfs_mft._temporary_privilege")
    @patch("storagecheck.ntfs_mft.kernel32")
    def test_open_mft_stream_backup_uses_read_control(self, mock_kernel, mock_privilege, mock_backup_stream) -> None:
        from storagecheck.ntfs_mft import _open_mft_stream_backup

        mock_privilege.return_value = nullcontext()
        mock_kernel.CreateFileW.return_value = 456
        mock_kernel.CloseHandle = MagicMock()
        fake_stream = MagicMock()
        fake_stream.prepare_default_data_stream.return_value = 8192
        mock_backup_stream.return_value = fake_stream

        with _open_mft_stream_backup("\\\\.\\C:\\$MFT") as (stream, size_bytes):
            self.assertIs(stream, fake_stream)
            self.assertEqual(size_bytes, 8192)

        create_file_args = mock_kernel.CreateFileW.call_args.args
        self.assertEqual(create_file_args[1], READ_CONTROL)
        self.assertTrue(create_file_args[5] & FILE_FLAG_BACKUP_SEMANTICS)

    def test_parse_file_name_link_uses_allocated_size(self) -> None:
        name = "OneDrive.txt"
        content = bytearray(66 + len(name) * 2)
        content[64] = len(name)
        content[65] = 1
        content[66:] = name.encode("utf-16-le")
        content[40:48] = (0).to_bytes(8, "little")
        content[48:56] = (987654321).to_bytes(8, "little")
        content[56:60] = (0x00400020).to_bytes(4, "little")

        raw_record = bytearray(160)
        raw_record[16:20] = len(content).to_bytes(4, "little")
        raw_record[20:22] = (24).to_bytes(2, "little")
        raw_record[24:24 + len(content)] = content

        link = _parse_file_name_link(bytes(raw_record), 0, 0)

        self.assertIsNotNone(link)
        self.assertEqual(link.allocated_size_bytes, 0)
        self.assertEqual(link.logical_size_bytes, 987654321)
        self.assertEqual(link.file_attributes, 0x00400020)

    def test_parse_non_resident_data_sizes_reads_allocation_and_logical_size(self) -> None:
        raw_record = bytearray(80)
        raw_record[40:48] = (4096).to_bytes(8, "little")
        raw_record[48:56] = (987654321).to_bytes(8, "little")

        allocated_size, logical_size = _parse_data_sizes(bytes(raw_record), 0, 80, 1)

        self.assertEqual(allocated_size, 4096)
        self.assertEqual(logical_size, 987654321)

    def test_placeholder_attributes_trigger_actual_size_lookup(self) -> None:
        self.assertTrue(_needs_actual_size_lookup(0x00400020))
        self.assertTrue(_needs_actual_size_lookup(0x00001000))
        self.assertFalse(_needs_actual_size_lookup(0x00000020))

    @patch("storagecheck.ntfs_mft._allocated_file_size", return_value=4096)
    @patch("storagecheck.ntfs_mft.os.stat")
    def test_resolved_link_size_uses_actual_lookup_for_placeholder(self, mock_stat, mock_allocated_size) -> None:
        scanner = NtfsMftScanner(mode="depth", max_depth=6)
        stat_result = MagicMock()
        mock_stat.return_value = stat_result
        link = _FileLink(
            parent_ref=5,
            name="OneDrive.txt",
            namespace=1,
            file_attributes=0x00400020,
            allocated_size_bytes=987654321,
            logical_size_bytes=1234,
            modified_time=None,
        )

        size = scanner._resolved_link_size("C:\\OneDrive.txt", link)

        self.assertEqual(size, 4096)
        mock_allocated_size.assert_called_once_with("C:\\OneDrive.txt", stat_result)

    @patch("storagecheck.ntfs_mft._allocated_file_size", side_effect=AssertionError("logical strategy should not query allocated size"))
    def test_logical_strategy_uses_link_logical_size(self, _mock_allocated_size) -> None:
        scanner = NtfsMftScanner(mode="depth", max_depth=6, size_strategy="logical")
        link = _FileLink(
            parent_ref=5,
            name="OneDrive.txt",
            namespace=1,
            file_attributes=0x00400020,
            allocated_size_bytes=4096,
            logical_size_bytes=1234,
            modified_time=None,
        )

        size = scanner._resolved_link_size("C:\\OneDrive.txt", link)

        self.assertEqual(size, 1234)

    @patch.object(NtfsMftScanner, "_resolved_link_size", autospec=True, return_value=10)
    @patch.object(NtfsMftScanner, "_iter_parsed_records", autospec=True)
    def test_scan_merges_size_and_file_node_passes(self, mock_iter_records, mock_resolved_size) -> None:
        root_record = MagicMock(record_id=5, is_directory=True, links=[], modified_time=None)
        child_directory = MagicMock(
            record_id=6,
            is_directory=True,
            links=[
                _FileLink(
                    parent_ref=5,
                    name="Users",
                    namespace=1,
                    file_attributes=0,
                    allocated_size_bytes=0,
                    logical_size_bytes=0,
                    modified_time=None,
                )
            ],
            modified_time=None,
        )
        child_file = MagicMock(
            record_id=7,
            is_directory=False,
            links=[
                _FileLink(
                    parent_ref=6,
                    name="demo.txt",
                    namespace=1,
                    file_attributes=0,
                    allocated_size_bytes=10,
                    logical_size_bytes=10,
                    modified_time=None,
                )
            ],
            modified_time=None,
        )
        records = [root_record, child_directory, child_file]
        mock_iter_records.side_effect = lambda _self, _root_path, should_cancel=None: iter(records)

        scanner = NtfsMftScanner(mode="depth", max_depth=6, size_strategy="logical")
        nodes: list[dict[str, object]] = []
        progress_events: list[dict[str, object]] = []

        result = scanner.scan("C:\\", on_node=nodes.append, on_progress=progress_events.append)

        self.assertEqual(mock_iter_records.call_count, 2)
        self.assertEqual(mock_resolved_size.call_count, 1)
        self.assertEqual(result.total_size_bytes, 10)
        self.assertEqual(result.stored_node_count, 3)
        self.assertEqual({str(node["path"]) for node in nodes}, {"C:\\", "C:\\Users", "C:\\Users\\demo.txt"})
        self.assertTrue(progress_events)
        self.assertTrue(all(event.get("estimated_total_records") is None for event in progress_events))
        self.assertTrue(any(event.get("phase") == "mft-pass-1" and event.get("progress_ratio") is None for event in progress_events))
        self.assertEqual(progress_events[-1]["phase"], "done")
        self.assertEqual(progress_events[-1]["progress_ratio"], 1.0)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from storagecheck.scanner import DiskScanner, ScanCancelledError, _allocated_file_size


class ScannerDepthTests(unittest.TestCase):
    def test_depth_mode_rolls_up_deeper_children(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            first = root / "alpha"
            second = first / "beta"
            second.mkdir(parents=True)
            (root / "top.bin").write_bytes(b"abc")
            (first / "one.bin").write_bytes(b"12345")
            (second / "two.bin").write_bytes(b"abcdefghij")

            nodes: list[dict[str, object]] = []
            scanner = DiskScanner(mode="depth", max_depth=1)
            with patch.object(DiskScanner, "_file_size_bytes", autospec=True, side_effect=lambda _self, _path, stat_result: int(stat_result.st_size)):
                result = scanner.scan(str(root), on_node=nodes.append)

            self.assertEqual(result.total_size_bytes, 18)
            paths = {Path(str(node["path"])).name: node for node in nodes}
            self.assertIn("alpha", paths)
            self.assertNotIn("beta", paths)
            self.assertEqual(paths["alpha"]["size_bytes"], 15)
            self.assertTrue(paths["alpha"]["is_truncated"])

    def test_full_mode_keeps_deep_nodes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            nested = root / "alpha" / "beta"
            nested.mkdir(parents=True)
            (nested / "deep.txt").write_text("hello")

            nodes: list[dict[str, object]] = []
            scanner = DiskScanner(mode="full", max_depth=2)
            with patch.object(DiskScanner, "_file_size_bytes", autospec=True, side_effect=lambda _self, _path, stat_result: int(stat_result.st_size)):
                scanner.scan(str(root), on_node=nodes.append)

            names = {Path(str(node["path"])).name for node in nodes}
            self.assertIn("beta", names)
            self.assertIn("deep.txt", names)

    def test_progress_callback_reports_live_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "alpha").mkdir()
            (root / "alpha" / "one.bin").write_bytes(b"1234")
            (root / "alpha" / "two.bin").write_bytes(b"56789")
            (root / "three.bin").write_bytes(b"xyz")

            progress_events: list[dict[str, object]] = []
            scanner = DiskScanner(mode="depth", max_depth=2)
            with patch.object(DiskScanner, "_file_size_bytes", autospec=True, side_effect=lambda _self, _path, stat_result: int(stat_result.st_size)):
                result = scanner.scan(str(root), on_progress=progress_events.append)

            self.assertGreaterEqual(len(progress_events), 2)
            last = progress_events[-1]
            self.assertEqual(last["processed_file_count"], 3)
            self.assertEqual(last["processed_dir_count"], 2)
            self.assertEqual(last["processed_entry_count"], 5)
            self.assertEqual(last["scanned_size_bytes"], 12)
            self.assertEqual(result.processed_file_count, 3)
            self.assertEqual(result.processed_dir_count, 2)
            self.assertEqual(result.processed_entry_count, 5)
            self.assertEqual(result.scanned_size_bytes, 12)

    def test_scan_can_be_cancelled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            for index in range(200):
                (root / f"file-{index}.bin").write_bytes(b"x" * 16)

            scanner = DiskScanner(mode="depth", max_depth=2)
            progress_events: list[dict[str, object]] = []

            def should_cancel() -> bool:
                return len(progress_events) >= 1

            with self.assertRaises(ScanCancelledError):
                with patch.object(DiskScanner, "_file_size_bytes", autospec=True, side_effect=lambda _self, _path, stat_result: int(stat_result.st_size)):
                    scanner.scan(str(root), on_progress=progress_events.append, should_cancel=should_cancel)

    def test_scan_uses_allocated_file_size_for_totals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            payload = root / "placeholder.bin"
            payload.write_bytes(b"abc")

            scanner = DiskScanner(mode="depth", max_depth=2)
            with patch.object(DiskScanner, "_file_size_bytes", return_value=4096):
                result = scanner.scan(str(root))

            self.assertEqual(result.total_size_bytes, 4096)
            self.assertEqual(result.scanned_size_bytes, 4096)

    @patch("storagecheck.scanner._allocated_file_size", side_effect=AssertionError("logical mode should not call allocated size"))
    def test_logical_size_mode_uses_stat_size_for_totals(self, _mock_allocated_size) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            payload = root / "placeholder.bin"
            payload.write_bytes(b"abc")

            scanner = DiskScanner(mode="depth", max_depth=2, size_strategy="logical")
            result = scanner.scan(str(root))

            self.assertEqual(result.total_size_bytes, 3)
            self.assertEqual(result.scanned_size_bytes, 3)


class AllocatedFileSizeTests(unittest.TestCase):
    @patch("storagecheck.scanner.os.name", "nt")
    @patch("storagecheck.scanner.kernel32")
    def test_windows_allocated_file_size_prefers_compressed_size(self, mock_kernel32) -> None:
        stat_result = Path(__file__).stat()
        lower = 123

        def fake_get_compressed_size(_path, upper_ptr) -> int:
            upper_ptr._obj.value = 2
            return lower

        mock_kernel32.GetCompressedFileSizeW.side_effect = fake_get_compressed_size

        size = _allocated_file_size("C:\\placeholder.bin", stat_result)

        self.assertEqual(size, (2 << 32) | lower)


if __name__ == "__main__":
    unittest.main()

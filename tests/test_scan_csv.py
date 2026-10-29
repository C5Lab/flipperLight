"""Host tests for scan_networks / show_scan_results CSV parsing.

No Flipper SDK required. Builds src/scan_csv.c with the system compiler.
"""

from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ScanCsvTests(unittest.TestCase):
    def test_quoted_ssid_and_vendor(self):
        with tempfile.TemporaryDirectory() as tmp:
            executable = str(Path(tmp) / "scan_csv_test")
            cmd = [
                "cc",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                str(ROOT / "src"),
                str(ROOT / "src" / "scan_csv.c"),
                str(ROOT / "tests" / "scan_csv_test.c"),
                "-o",
                executable,
            ]
            subprocess.run(cmd, check=True)
            output = subprocess.check_output([executable], text=True)
            self.assertIn("scan csv PASS", output)


if __name__ == "__main__":
    unittest.main()

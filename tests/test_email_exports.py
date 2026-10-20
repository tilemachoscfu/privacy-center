import csv
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import privacy_center as pc


class EmailExportTests(unittest.TestCase):
    def test_invalid_sources_fail_without_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            unsupported = root / "export.txt"
            unsupported.write_text("not an export")
            for source in (root / "missing.mbox", root / "missing", unsupported):
                with self.subTest(source=source.name), patch.object(pc, "RESULTS", root / "results"):
                    with self.assertRaisesRegex(SystemExit, "existing .mbox"):
                        pc.email_export_audit(source)
                    self.assertFalse((root / "results").exists())
            self.assertEqual(unsupported.read_text(), "not an export")

    def test_mbox_and_eml_directory_remain_supported(self):
        message = "From: service@example.invalid\nSubject: Welcome\n\nSynthetic test\n"
        for kind in ("mbox", "directory"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                if kind == "mbox":
                    source = root / "export.MBOX"
                    source.write_text("From test@example.invalid Sat Jan 1 00:00:00 2022\n" + message)
                else:
                    source = root / "emails"
                    source.mkdir()
                    (source / "test.eml").write_text(message)
                with patch.object(pc, "RESULTS", root / "results"):
                    output = pc.email_export_audit(source)
                with (output / "account-candidates.csv").open() as stream:
                    rows = list(csv.DictReader(stream))
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["subject"], "Welcome")

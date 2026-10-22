import csv
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import privacy_center as pc


class EmailExportTests(unittest.TestCase):
    def test_mailbox_closes_when_iteration_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'test.mbox'
            source.touch()
            with patch.object(pc.mailbox, 'mbox') as factory:
                factory.return_value.__iter__.side_effect = ValueError('synthetic parse failure')
                with self.assertRaises(ValueError):
                    pc.email_export_audit(source)
                factory.assert_called_once_with(source, create=False)
                factory.return_value.close.assert_called_once()

    def test_eml_stream_closes_when_parser_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)
            (source / 'test.eml').touch()
            streams = []
            def fail(stream, **kwargs):
                streams.append(stream)
                raise ValueError('synthetic parse failure')
            with patch.object(pc.email, 'message_from_binary_file', side_effect=fail):
                with self.assertRaises(ValueError):
                    pc.email_export_audit(source)
            self.assertEqual(len(streams), 1)
            self.assertTrue(streams[0].closed)

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

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import privacy_center as pc


class MetadataTests(unittest.TestCase):
    def test_sanitizer_propagates_failure_and_preserves_original(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "sample.jpg"
            source.write_bytes(b"original with metadata")
            with patch.object(pc, "ROOT", root), patch.object(pc.shutil, "which", return_value="exiftool"), patch.object(pc, "metadata_audit") as audit, patch.object(pc, "run") as run:
                def failed_command(command, **kwargs):
                    if kwargs.get("check"):
                        raise subprocess.CalledProcessError(1, command)
                    return subprocess.CompletedProcess(command, 1)
                run.side_effect = failed_command
                with self.assertRaises(subprocess.CalledProcessError):
                    pc.sanitize_metadata(source)
                audit.assert_not_called()
                self.assertEqual(source.read_bytes(), b"original with metadata")

    def test_failed_inspections_never_produce_clean_report(self):
        cases = ["invalid json", "[]", "[null]", '{}', '[{"ExifTool:Error":"unreadable"}]',
                 subprocess.CalledProcessError(1, "exiftool")]
        for response in cases:
            with self.subTest(response=response), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "sample.jpg"
                source.write_bytes(b"fixture")
                with patch.object(pc, "RESULTS", root / "results"), patch.object(pc.shutil, "which", return_value="exiftool"), patch.object(pc, "run") as run:
                    if isinstance(response, Exception):
                        run.side_effect = response
                    else:
                        run.return_value = subprocess.CompletedProcess([], 0, response)
                    with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                        pc.metadata_audit(source)
                    self.assertTrue(run.call_args.kwargs["check"])
                    self.assertFalse(list(root.rglob("report.json")))

    def test_successful_inspection_preserves_risk_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "sample.jpg"
            source.write_bytes(b"fixture")
            with patch.object(pc, "RESULTS", root / "results"), patch.object(pc.shutil, "which", return_value="exiftool"), patch.object(pc, "run", return_value=subprocess.CompletedProcess([], 0, '[{"EXIF:GPSLatitude":1}]')):
                output = pc.metadata_audit(source)
                report = json.loads((output / "report.json").read_text())
                self.assertEqual(report["files"][0]["risk_count"], 1)

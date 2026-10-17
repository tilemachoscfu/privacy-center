import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import privacy_center as pc


class UsernameTests(unittest.TestCase):
    def test_missing_tools_fail_without_creating_a_success_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(pc, "ROOT", root), patch.object(pc, "RESULTS", root / "results"), \
                    patch.object(pc, "run") as run:
                with self.assertRaisesRegex(SystemExit, "install Sherlock or Maigret"):
                    pc.username_audit("example")
                run.assert_not_called()
                self.assertFalse((root / "results").exists())

    def test_maigret_only_installation_is_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tool = root / "tools/maigret/bin/maigret"
            tool.parent.mkdir(parents=True)
            tool.touch()
            with patch.object(pc, "ROOT", root), patch.object(pc, "RESULTS", root / "results"), \
                    patch.object(pc, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
                output = pc.username_audit("example")
                self.assertEqual(run.call_args.args[0][0], str(tool))
                self.assertTrue((output / "run.json").is_file())

    def test_option_like_names_rejected_before_any_side_effects(self):
        for name in ("-", "--help", "--version", "-user", "--output", "", "a/b", "x" * 81):
            with self.subTest(name=name), patch.object(pc, "secure_dir") as mkdir, \
                    patch.object(pc, "run") as run:
                with self.assertRaises(SystemExit):
                    pc.username_audit(name)
                mkdir.assert_not_called()
                run.assert_not_called()

    def test_normal_names_are_passed_as_single_positional_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tool = root / "tools/sherlock/bin/sherlock"
            tool.parent.mkdir(parents=True)
            tool.touch()
            with patch.object(pc, "ROOT", root), patch.object(pc, "RESULTS", root / "results"), \
                    patch.object(pc, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
                for name in ("example-user", "example.name", "_example", ".example", "a" * 80):
                    with self.subTest(name=name):
                        output = pc.username_audit(name)
                        self.assertEqual(run.call_args.args[0][1], name)
                        self.assertTrue((output / "run.json").is_file())
                self.assertEqual(run.call_count, 5)

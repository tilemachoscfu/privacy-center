import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import privacy_center as pc


class GravatarStatusTests(unittest.TestCase):
    def test_only_definitive_responses_classify_exposure(self):
        for status, expected in ((200, True), (404, False), (429, None),
                                 (503, None), (None, None)):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp, \
                    patch.object(pc, 'RESULTS', Path(tmp)), \
                    patch.object(pc, 'http_status', return_value=status), \
                    patch.object(pc.shutil, 'which', return_value=None), \
                    patch.dict(pc.os.environ, {'HIBP_API_KEY': ''}):
                report = pc.email_audit('test@example.invalid') / 'report.json'
                result = json.loads(report.read_text())['gravatar']
                self.assertIs(result['exposed'], expected)
                self.assertEqual(result['status'], status)

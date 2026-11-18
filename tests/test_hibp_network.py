import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

import privacy_center as pc


class HibpNetworkTests(unittest.TestCase):
    def test_network_failure_preserves_partial_report(self):
        for error in (urllib.error.URLError('private connection detail'),
                      TimeoutError('private timeout detail'),
                      ConnectionResetError('private reset detail')):
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as tmp, \
                    patch.object(pc, 'RESULTS', Path(tmp)), \
                    patch.object(pc, 'http_status', return_value=200), \
                    patch.object(pc.shutil, 'which', return_value=None), \
                    patch.dict(pc.os.environ, {'HIBP_API_KEY': 'synthetic-test-key'}), \
                    patch.object(pc.urllib.request, 'urlopen', side_effect=error):
                report = pc.email_audit('test@example.invalid') / 'report.json'
                raw = report.read_text()
                result = json.loads(raw)
                self.assertEqual(result['hibp']['status'], 'network_error')
                self.assertEqual(result['hibp']['breaches'], [])
                self.assertIs(result['gravatar']['exposed'], True)
                self.assertNotIn(str(error), raw)
                self.assertNotIn('synthetic-test-key', raw)

"""Exercise PowerShell preview/failure paths without changing Windows settings."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == 'nt' and shutil.which('powershell.exe'), 'Windows PowerShell only')
class WindowsPreviewTests(unittest.TestCase):
    def run_preview(self, probe):
        with tempfile.TemporaryDirectory(prefix='cc-preview-') as folder:
            location = Path(folder)
            for filename in ['us-on.ps1', 'environment-common.ps1']:
                shutil.copyfile(ROOT / filename, location / filename)
            # A local fixture replaces the network probe, not any Windows settings API.
            (location / 'claude_clean.py').write_text('print(' + repr(json.dumps(probe)) + ')', encoding='utf-8')
            (location / 'config.json').write_text('{}', encoding='utf-8')
            result = subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                                     '-File', str(location / 'us-on.ps1'), '-DryRun'],
                                    capture_output=True, text=True, timeout=20)
            self.assertFalse((location / 'state').exists(), 'Preview must not create backup/state')
            self.assertFalse((location / 'relay.json').exists(), 'Preview must not start a relay')
            return result

    def test_preview_accepts_known_timezone_without_state(self):
        result = self.run_preview({'ip': '192.0.2.1', 'timezone': 'America/New_York'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Eastern Standard Time', result.stdout)
        self.assertIn('Preview complete', result.stdout)

    def test_no_exit_fails_before_any_change(self):
        result = self.run_preview({'ip': '', 'timezone': ''})
        self.assertNotEqual(result.returncode, 0)

    def test_unknown_timezone_does_not_guess_us(self):
        result = self.run_preview({'ip': '192.0.2.1', 'timezone': 'Unknown/Not_A_Zone'})
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()

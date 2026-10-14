"""Exercise the installed readiness script with representative command output."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import subprocess
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / 'image/mkosi.skeleton/usr/lib/h-image/check-runtime'
VERITY_STATUS = '''/dev/mapper/root is active and is in use.
  type:        VERITY
  status:      verified
  hash type:   1
  data device: /dev/vda2
  mode:        readonly
  hash device: /dev/vda3
'''


class RuntimeCheckTests(unittest.TestCase):
    def check_runtime(self, status=VERITY_STATUS, source='/dev/mapper/root', options='ro,relatime',
                      command_error=False):
        def output(*args, **kwargs):
            command = args[0]
            if command[0] == 'findmnt':
                return json.dumps({'filesystems': [{'source': source, 'options': options}]})
            if command[0] == 'veritysetup':
                if command_error:
                    raise subprocess.CalledProcessError(1, command)
                return status
            if command[:2] == ('docker', 'info'):
                return '28.2.2'
            if command[:2] == ('docker', 'compose'):
                return 'Docker Compose version v2.39.4'
            raise AssertionError(command)

        text = io.StringIO()
        with patch('subprocess.check_output', side_effect=output), patch('subprocess.run'), \
                patch.object(Path, 'read_text', return_value='Filename Type Size Used Priority\n'), \
                contextlib.redirect_stdout(text):
            runpy.run_path(str(SCRIPT), run_name='__main__')
        return text.getvalue()

    def test_uppercase_verity_reaches_ready(self):
        self.assertIn('H_IMAGE_OS_READY:', self.check_runtime())

    def test_signed_verity_reaches_ready(self):
        self.assertIn('H_IMAGE_OS_READY:', self.check_runtime(VERITY_STATUS.replace('verified', 'verified (with signature)')))

    def test_unprotected_or_corrupt_roots_are_rejected(self):
        for status in (
            VERITY_STATUS.replace('VERITY', 'LUKS2'),
            VERITY_STATUS.replace('verified', 'corrupted'),
            VERITY_STATUS.replace('readonly', 'read/write'),
            '/dev/mapper/verity-root is active.\n  type: LUKS2\n',
            '/dev/mapper/root is inactive.\n',
        ):
            with self.subTest(status=status), self.assertRaises(SystemExit):
                self.check_runtime(status)

    def test_writable_or_plain_roots_are_rejected(self):
        for args in ({'options': 'rw,relatime'}, {'source': '/dev/vda2'}):
            with self.subTest(args=args), self.assertRaises(SystemExit):
                self.check_runtime(**args)

    def test_failed_verity_command_is_rejected(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.check_runtime(command_error=True)


if __name__ == '__main__':
    unittest.main()

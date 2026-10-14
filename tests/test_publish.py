"""Check publication gating and GCP registration without making cloud changes."""
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
loader = importlib.machinery.SourceFileLoader('publish_gcp', str(SCRIPTS / 'publish-gcp-image'))
spec = importlib.util.spec_from_loader(loader.name, loader)
publish = importlib.util.module_from_spec(spec)
loader.exec_module(publish)


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / 'dist/publish'
        self.directory.mkdir(parents=True)
        archive = b'archive fixture'
        (self.directory / 'h-image-gcp.tar.gz').write_bytes(archive)
        self.environment = {
            'GITHUB_SHA': 'a' * 40, 'GITHUB_WORKFLOW_SHA': 'a' * 40,
            'GITHUB_REPOSITORY': 'CypherpunkLabs-AI/hiro-vm-image',
            'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'push',
            'GITHUB_RUN_ID': '42', 'GITHUB_RUN_ATTEMPT': '1',
            'GITHUB_STEP_SUMMARY': str(self.root / 'summary'),
            'GCP_PROJECT_ID': 'cypherpunklabs', 'GCP_IMAGE_BUCKET': 'cypherpunklabs-hiro-images',
        }
        manifest = {
            'kind': 'h-image.os-release.v1', 'source_commit': 'a' * 40, 'workflow_commit': 'a' * 40,
            'source_repository': self.environment['GITHUB_REPOSITORY'], 'source_ref': 'refs/heads/main',
            'files': {'h-image-gcp.tar.gz': {'sha256': hashlib.sha256(archive).hexdigest(), 'size': len(archive)}},
            'guest_os_features': ['TDX_CAPABLE', 'UEFI_COMPATIBLE', 'GVNIC'],
            'licenses': ['license-fixture'],
        }
        (self.directory / 'os-release.json').write_text(json.dumps(manifest))
        (self.directory / 'os-release.sigstore.json').write_text('{}')
        publish.checksums(self.directory)
        self.image = {'status': 'READY', 'id': '123', 'selfLink': 'image-fixture',
                      'guestOsFeatures': [{'type': x} for x in manifest['guest_os_features']],
                      'licenses': manifest['licenses']}

    def invoke(self, result=None):
        with patch.dict(os.environ, self.environment), patch.object(publish, 'ROOT', self.root), \
                patch.object(publish, 'run') as commands, \
                patch.object(publish.subprocess, 'check_output', return_value=json.dumps(result or self.image)), \
                contextlib.redirect_stdout(io.StringIO()):
            publish.main()
        return [[str(arg) for arg in call.args] for call in commands.call_args_list]

    def test_main_build_is_verified_uploaded_and_registered(self):
        commands = self.invoke()
        self.assertEqual(commands[0][:3], ['gh', 'attestation', 'verify'])
        create = next(c for c in commands if c[:4] == ['gcloud', 'compute', 'images', 'create'])
        self.assertEqual(create[4], 'h-image-aaaaaaaaaaaa-42-1')
        self.assertIn('--guest-os-features=TDX_CAPABLE,UEFI_COMPATIBLE,GVNIC', create)
        self.assertTrue(any(x.startswith('--source-uri=gs://cypherpunklabs-hiro-images/h-image/') for x in create))
        self.assertFalse(any(c[:4] == ['gcloud', 'compute', 'instances', 'create'] for c in commands))
        record = json.loads((self.directory / 'gcp-image.json').read_text())
        self.assertEqual(record['status'], 'READY')
        self.assertFalse(record['hardware_boot_verified'])
        self.assertIn(record['image'], (self.root / 'summary').read_text())

    def test_changed_archive_rejected_before_cloud_commands(self):
        (self.directory / 'h-image-gcp.tar.gz').write_bytes(b'changed')
        with patch.object(publish, 'run') as commands, self.assertRaisesRegex(ValueError, 'artifact differs'):
            publish.validate(self.directory, self.environment)
        commands.assert_not_called()

    def test_pull_request_cannot_publish(self):
        self.environment['GITHUB_EVENT_NAME'] = 'pull_request'
        with self.assertRaisesRegex(ValueError, 'only main or version-tag'):
            publish.validate(self.directory, self.environment)

    def test_missing_signature_rejected(self):
        (self.directory / 'os-release.sigstore.json').unlink()
        with self.assertRaisesRegex(ValueError, 'signature bundle missing'):
            publish.validate(self.directory, self.environment)

    def test_not_ready_image_fails_without_success_receipt(self):
        self.image['status'] = 'FAILED'
        with self.assertRaisesRegex(ValueError, 'not READY'):
            self.invoke()
        self.assertFalse((self.directory / 'gcp-image.json').exists())

    def test_missing_tdx_feature_fails(self):
        self.image['guestOsFeatures'] = []
        with self.assertRaisesRegex(ValueError, 'required boot features'):
            self.invoke()


if __name__ == '__main__':
    unittest.main()

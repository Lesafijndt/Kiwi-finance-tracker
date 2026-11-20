import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import publish_update as publisher


class FakeGitHub:
    def __init__(self, release, files, latest=None, after_read=None):
        self.data = release
        self.files = files
        self.latest = latest
        self.after_read = after_read
        self.reads = 0
        self.edits = []

    def release(self, tag):
        self.reads += 1
        if self.reads == 2 and self.after_read:
            self.after_read(self.data)
        return copy.deepcopy(self.data)

    def api(self, path, optional=False):
        return copy.deepcopy(self.latest)

    def __call__(self, *args):
        if args[:2] == ('release', 'download'):
            name = args[args.index('--pattern') + 1]
            folder = Path(args[args.index('--dir') + 1])
            (folder / name).write_bytes(self.files[name])
        elif args[:2] == ('release', 'edit'):
            self.edits.append(args)
            self.data['draft'] = False
        return ''


class PublicationTest(unittest.TestCase):
    def setUp(self):
        self.tag = 'v7.10.1'
        self.apk = b'synthetic signed binary'
        self.info = dict(packageName=publisher.PACKAGE, versionCode=19, versionName='7.10.1',
                         sha256=hashlib.sha256(self.apk).hexdigest(), sizeBytes=len(self.apk))
        self.manifest = dict(schemaVersion=1, **self.info, notes='Release notes',
                             apkUrl=f'https://github.com/{publisher.REPO}/releases/download/{self.tag}/Kiwi-Finance.apk')
        self.files = {'Kiwi-Finance.apk': self.apk, 'kiwi-update.json': json.dumps(self.manifest).encode()}
        self.release = dict(id=123, tag_name=self.tag, draft=True, prerelease=False,
            assets=[dict(id=i, name=name, state='uploaded', size=len(data), digest='sha256:' + hashlib.sha256(data).hexdigest())
                    for i, (name, data) in enumerate(self.files.items())])

    def finalize(self, gh):
        with patch.object(publisher, 'verify_apk', return_value=self.info):
            publisher.finalize(gh, self.tag, Path('sdk'), 'java')

    def test_verified_draft_is_published_and_retry_does_not_repromote(self):
        gh = FakeGitHub(self.release, self.files)
        self.finalize(gh)
        self.assertEqual(1, len(gh.edits))
        self.finalize(gh)
        self.assertEqual(1, len(gh.edits))

    def test_replaced_asset_during_verification_blocks_publication(self):
        gh = FakeGitHub(self.release, self.files, after_read=lambda data: data['assets'][0].update(id=987))
        with self.assertRaisesRegex(ValueError, 'changed during verification'):
            self.finalize(gh)
        self.assertFalse(gh.edits)

    def test_asset_corruption_blocks_publication(self):
        gh = FakeGitHub(self.release, dict(self.files, **{'Kiwi-Finance.apk': b'corrupt'}))
        with self.assertRaisesRegex(ValueError, 'checksum differs'):
            self.finalize(gh)
        self.assertFalse(gh.edits)

    def test_manifest_cannot_point_elsewhere_or_lie_about_signed_apk(self):
        for change in ({'apkUrl': 'https://example.com/app.apk'}, {'versionCode': 20}, {'versionCode': True},
                       {'packageName': 'different.app'}, {'sha256': '0' * 64}, {'sizeBytes': 3}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                publisher.validate_manifest(dict(self.manifest, **change), self.tag, self.info)

    def test_unknown_extra_asset_or_prerelease_is_rejected(self):
        extra = copy.deepcopy(self.release)
        extra['assets'].append(dict(extra['assets'][0], name='private.zip'))
        with self.assertRaises(ValueError):
            publisher.validate_assets(extra, self.tag)
        with self.assertRaises(ValueError):
            publisher.validate_assets(dict(self.release, prerelease=True), self.tag)

    def test_tag_input_rejects_shell_fragments_and_prereleases(self):
        for tag in ('main', 'v7.10.1-beta', 'v7.10.1;touch x', '../v7.10.1', 'v07.10.1'):
            with self.assertRaises(ValueError):
                publisher.stable_tag(tag)

    def test_older_or_equal_code_cannot_replace_public_channel(self):
        latest = dict(self.release, draft=False)
        gh = FakeGitHub(self.release, self.files, latest=latest)
        with self.assertRaisesRegex(ValueError, 'not newer'):
            publisher.verify_public_version(gh, 18)
        with self.assertRaisesRegex(ValueError, 'not newer'):
            publisher.verify_public_version(gh, 19)
        publisher.verify_public_version(gh, 20)

    def test_wrong_signer_rejected_by_real_apk_verification_flow(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'build-tools' / '35.0.0').mkdir(parents=True)
            apk = root / 'app.apk'
            apk.write_bytes(self.apk)
            output = ["package: name='com.pulse.wallet' versionCode='19' versionName='7.10.1'", 'certificate SHA-256 digest: ' + '0' * 64]
            with patch.object(publisher, 'run', side_effect=output), self.assertRaisesRegex(ValueError, 'signing identity'):
                publisher.verify_apk(apk, root, 'java')

    def test_draft_tag_404_falls_back_to_paginated_authenticated_listing(self):
        with patch.object(publisher, 'github_environment', return_value={}), \
             patch.object(publisher.GitHub, 'api', return_value=None), \
             patch.object(publisher.GitHub, '__call__', return_value=json.dumps([[dict(self.release, tag_name='v7.9.0')], [self.release]])) as call:
            self.assertEqual(self.release, publisher.GitHub().release(self.tag))
            self.assertIn('--paginate', call.call_args.args)


if __name__ == '__main__':
    unittest.main()

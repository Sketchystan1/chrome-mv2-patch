"""Check ARM64 source selection, download identity and complete browser layout."""
import base64
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from _testutil import make_pe
from fetch_arm64_browser import APPIDS, browser_entry, chrome_source, edge_source, verify_download

VERSION = '160.0.1.0'
DIGEST = 'ab' * 32


class FetchTests(unittest.TestCase):
    def test_chrome_channels_request_native_arm64(self):
        response = (f'<response><app><updatecheck status="ok"><urls>'
                    '<url codebase="http://dl.google.com/"/><url codebase="https://dl.google.com/build/"/>'
                    f'</urls><manifest version="{VERSION}"><packages><package name="installer.exe" '
                    f'hash_sha256="{DIGEST}" size="123"/></packages></manifest></updatecheck></app></response>').encode()
        for channel, appid in APPIDS.items():
            with self.subTest(channel=channel), patch('urllib.request.urlopen', return_value=io.BytesIO(response)) as request:
                source = chrome_source(channel)
                body = request.call_args.args[0].data.decode()
                self.assertIn(f'appid="{appid}"', body)
                self.assertIn('arch="arm64"', body)
                self.assertIn('ap="arm64"', body)
                self.assertEqual(source, dict(version=VERSION, url='https://dl.google.com/build/installer.exe',
                                              sha256=DIGEST, size=123))

    def test_chrome_no_update_fails(self):
        with patch('urllib.request.urlopen', return_value=io.BytesIO(b'<response><app><updatecheck status="noupdate"/></app></response>')):
            with self.assertRaises(ValueError):
                chrome_source('canary')

    def test_edge_uses_full_installer_and_vendor_hash(self):
        url = 'http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/fixture'
        full = dict(FileId=f'MicrosoftEdge_ARM64_{VERSION}.exe', Url=url,
                    Hashes=dict(Sha256=base64.b64encode(bytes.fromhex(DIGEST)).decode()), SizeInBytes=123)
        for channel in APPIDS:
            replies = [io.BytesIO(json.dumps(dict(ContentId=dict(Version=VERSION))).encode()),
                       io.BytesIO(json.dumps([dict(full, FileId=f'MicrosoftEdge_ARM64_{VERSION}_159.0.1.0.exe'), full]).encode())]
            with self.subTest(channel=channel), patch('urllib.request.urlopen', side_effect=replies) as request:
                self.assertEqual(edge_source(channel), dict(version=VERSION, url=url,
                                                            sha256=DIGEST, size=123))
                self.assertIn(f'msedge-{channel}-win-arm64', request.call_args_list[0].args[0].full_url)

    def test_edge_delta_only_fails(self):
        replies = [io.BytesIO(json.dumps(dict(ContentId=dict(Version=VERSION))).encode()),
                   io.BytesIO(json.dumps([dict(FileId=f'MicrosoftEdge_ARM64_{VERSION}_159.0.1.0.exe')]).encode())]
        with patch('urllib.request.urlopen', side_effect=replies), self.assertRaises(ValueError):
            edge_source('canary')

    def test_download_rejects_wrong_size_or_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'installer.exe'
            path.write_bytes(b'installer fixture')
            source = dict(size=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            verify_download(path, source)
            for wrong in (dict(source, size=source['size'] + 1), dict(source, sha256=DIGEST)):
                with self.assertRaises(ValueError):
                    verify_download(path, wrong)

    def test_browser_layout_checks_both_architectures_and_versions(self):
        for browser, name in (('chrome', 'chrome'), ('edge', 'msedge')):
            with self.subTest(browser=browser), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                version_dir = root / VERSION; version_dir.mkdir()
                binary, executable = version_dir / (name + '.dll'), root / (name + '.exe')
                make_pe(binary, '00', machine=0xAA64)
                make_pe(executable, '00', machine=0xAA64)
                with patch('fetch_arm64_browser.binary_version', return_value=VERSION):
                    entry = browser_entry(root, browser, VERSION)
                    self.assertEqual(entry['binary'], str(binary))
                    self.assertEqual(entry['executable'], str(executable))
                    make_pe(executable, '00', machine=0x8664)
                    with self.assertRaises(ValueError):
                        browser_entry(root, browser, VERSION)
                    make_pe(executable, '00', machine=0xAA64)
                with patch('fetch_arm64_browser.binary_version', side_effect=[VERSION, '159.0.1.0']):
                    with self.assertRaises(ValueError):
                        browser_entry(root, browser, VERSION)
                make_pe(binary, '00', machine=0x8664)
                with self.assertRaises(ValueError):
                    browser_entry(root, browser, VERSION)


if __name__ == '__main__':
    unittest.main()

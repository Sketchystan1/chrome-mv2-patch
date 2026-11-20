"""Check Windows source selection, download identity and complete browser layout."""
import base64
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import fetch_arm64_browser as fetch

from _testutil import make_pe
from fetch_arm64_browser import APPIDS, browser_entry, chrome_source, edge_source, verify_download

VERSION = '160.0.1.0'
DIGEST = 'ab' * 32
MACHINES = {'x64': 0x8664, 'x86': 0x14C, 'arm64': 0xAA64}


class FetchTests(unittest.TestCase):
    def test_edge_prefers_application_entrypoint_over_versioned_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            application = Path(directory).resolve()
            versioned = application / VERSION
            versioned.mkdir()
            binary = versioned / 'msedge.dll'
            make_pe(binary, '00', machine=MACHINES['arm64'])
            make_pe(versioned / 'msedge.exe', '00', machine=MACHINES['arm64'])
            make_pe(application / 'msedge.exe', '00', machine=MACHINES['arm64'])
            with patch('fetch_arm64_browser.binary_version', return_value=VERSION):
                entry = browser_entry(application, 'edge', VERSION)
            self.assertEqual(entry['executable'], str(application / 'msedge.exe'))
            self.assertEqual(entry['application'], str(application))
            self.assertEqual(entry['binary'], str(binary))

    def test_recorded_source_replays_identity_without_current_channel_lookup(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = b'verified recorded installer'
            source = dict(browser='chrome', channel='canary', architecture='arm64', version=VERSION,
                          url='https://dl.google.com/recorded.exe', size=len(payload),
                          sha256=hashlib.sha256(payload).hexdigest())
            record = root / 'source.json'; record.write_text(json.dumps(source))
            out = root / '_scratch/browser'
            def download(url, path):
                self.assertEqual(url, source['url']); Path(path).write_bytes(payload); return True
            argv = ['fetch', '--browser', 'chrome', '--channel', 'canary', '--source', str(record), '--out', str(out)]
            entry = dict(version=VERSION, executable=str(out/'chrome.exe'), binary=str(out/'chrome.dll'))
            with patch('sys.argv', argv), patch.object(fetch, 'REPO', root), \
                 patch.object(fetch, 'find_seven_zip', return_value='7z'), \
                 patch.object(fetch, 'chrome_source', side_effect=AssertionError('must not query a moving channel')), \
                 patch.object(fetch, 'download', side_effect=download), \
                 patch.object(fetch, 'extract', return_value=str(out/'unpacked')), \
                 patch.object(fetch, 'browser_entry', return_value=entry):
                self.assertEqual(fetch.main(), 0)
            self.assertEqual(json.loads((out/'source.json').read_text()), source)
            self.assertEqual(json.loads((out/'matrix.json').read_text()), [entry])

    def test_recorded_source_cannot_change_browser_channel_or_architecture(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for key, value in [('browser', 'edge'), ('channel', 'beta'), ('architecture', 'x86')]:
                with self.subTest(key=key):
                    source = dict(browser='chrome', channel='canary', architecture='arm64')
                    source[key] = value
                    record=root/'source.json'; record.write_text(json.dumps(source))
                    argv=['fetch','--browser','chrome','--channel','canary','--source',str(record),
                          '--out',str(root/'_scratch'/key)]
                    with patch('sys.argv',argv), patch.object(fetch,'REPO',root), \
                         patch.object(fetch,'find_seven_zip',return_value='7z'), \
                         patch.object(fetch,'download') as download, patch('sys.stderr',new_callable=io.StringIO):
                        with self.assertRaises(SystemExit) as error: fetch.main()
                        self.assertEqual(error.exception.code,2); download.assert_not_called()

    def test_chrome_channels_request_selected_architecture(self):
        response = (f'<response><app><updatecheck status="ok"><urls>'
                    '<url codebase="http://dl.google.com/"/><url codebase="https://dl.google.com/build/"/>'
                    f'</urls><manifest version="{VERSION}"><packages><package name="installer.exe" '
                    f'hash_sha256="{DIGEST}" size="123"/></packages></manifest></updatecheck></app></response>').encode()
        for arch in MACHINES:
            for channel, appid in APPIDS.items():
                with self.subTest(arch=arch, channel=channel), patch('urllib.request.urlopen', return_value=io.BytesIO(response)) as request:
                    source = chrome_source(channel, arch)
                    body = request.call_args.args[0].data.decode()
                    self.assertIn(f'appid="{appid}"', body)
                    self.assertIn(f'arch="{arch}"', body)
                    self.assertIn(f'ap="{arch}"', body)
                    self.assertEqual(source, dict(version=VERSION, url='https://dl.google.com/build/installer.exe',
                                                  sha256=DIGEST, size=123))

    def test_chrome_no_update_fails(self):
        with patch('urllib.request.urlopen', return_value=io.BytesIO(b'<response><app><updatecheck status="noupdate"/></app></response>')):
            with self.assertRaises(ValueError):
                chrome_source('canary')

    def test_edge_uses_full_installer_and_vendor_hash(self):
        url = 'http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/fixture'
        for arch in MACHINES:
            full = dict(FileId=f'MicrosoftEdge_{arch.upper()}_{VERSION}.exe', Url=url,
                        Hashes=dict(Sha256=base64.b64encode(bytes.fromhex(DIGEST)).decode()), SizeInBytes=123)
            for channel in APPIDS:
                replies = [io.BytesIO(json.dumps(dict(ContentId=dict(Version=VERSION))).encode()),
                           io.BytesIO(json.dumps([dict(full, FileId=f'MicrosoftEdge_{arch.upper()}_{VERSION}_159.0.1.0.exe'), full]).encode())]
                with self.subTest(arch=arch, channel=channel), patch('urllib.request.urlopen', side_effect=replies) as request:
                    self.assertEqual(edge_source(channel, arch), dict(version=VERSION, url=url,
                                                                     sha256=DIGEST, size=123))
                    self.assertIn(f'msedge-{channel}-win-{arch}', request.call_args_list[0].args[0].full_url)

    def test_edge_delta_or_wrong_architecture_only_fails(self):
        for arch in MACHINES:
            wrong_arch = next(other for other in MACHINES if other != arch)
            for file_id in (f'MicrosoftEdge_{arch.upper()}_{VERSION}_159.0.1.0.exe',
                            f'MicrosoftEdge_{wrong_arch.upper()}_{VERSION}.exe'):
                replies = [io.BytesIO(json.dumps(dict(ContentId=dict(Version=VERSION))).encode()),
                           io.BytesIO(json.dumps([dict(FileId=file_id)]).encode())]
                with self.subTest(arch=arch, file_id=file_id), patch('urllib.request.urlopen', side_effect=replies), self.assertRaises(ValueError):
                    edge_source('canary', arch)

    def test_download_rejects_wrong_size_or_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'installer.exe'
            path.write_bytes(b'installer fixture')
            source = dict(size=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            verify_download(path, source)
            for wrong in (dict(source, size=source['size'] + 1), dict(source, sha256=DIGEST)):
                with self.assertRaises(ValueError):
                    verify_download(path, wrong)

    def test_browser_layout_checks_architectures_and_versions(self):
        for arch, machine in MACHINES.items():
            wrong_machine = 0xAA64 if arch == 'x64' else 0x8664
            for browser, name in (('chrome', 'chrome'), ('edge', 'msedge')):
                for beside in (False, True) if browser == 'edge' else (False,):
                    with self.subTest(arch=arch, browser=browser, beside=beside), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory).resolve()
                        version_dir = root / VERSION; version_dir.mkdir()
                        binary = version_dir / (name + '.dll')
                        executable = (version_dir if beside else root) / (name + '.exe')
                        make_pe(binary, '00', machine=machine)
                        make_pe(executable, '00', machine=machine)
                        with patch('fetch_arm64_browser.binary_version', return_value=VERSION):
                            entry = browser_entry(root, browser, VERSION, arch)
                            expected = dict(version=f'{browser} {VERSION} {arch.upper()}',
                                            binary=str(binary), executable=str(executable))
                            if browser == 'edge' and not beside:
                                expected['application'] = str(root)
                            self.assertEqual(entry, expected)
                            make_pe(executable, '00', machine=wrong_machine)
                            with self.assertRaises(ValueError):
                                browser_entry(root, browser, VERSION, arch)
                            make_pe(executable, '00', machine=machine)
                        for versions in ([VERSION, '159.0.1.0'], ['159.0.1.0']):
                            with patch('fetch_arm64_browser.binary_version', side_effect=versions), self.assertRaises(ValueError):
                                browser_entry(root, browser, VERSION, arch)
                        make_pe(binary, '00', machine=wrong_machine)
                        with self.assertRaises(ValueError):
                            browser_entry(root, browser, VERSION, arch)


if __name__ == '__main__':
    unittest.main()

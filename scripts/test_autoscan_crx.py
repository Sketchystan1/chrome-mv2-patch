"""Install signed CRX3 controls through Chrome's real Downloads page on Windows.

Only a fresh workspace below _scratch, private profiles, a private desktop and
an isolated registry subtree are changed. The production DLL is copied unchanged.
Native signature verification and the Add extension dialog remain in the path.
"""
import argparse
import ctypes as C
from ctypes import wintypes as W
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import threading
import time
import uuid
import winreg

from test_autoscan_runtime import digest, memory_check, sandbox_check, sandbox_read, delete_registry

REPO = Path(__file__).resolve().parent.parent
U = C.WinDLL('user32', use_last_error=True)
U.CreateDesktopW.argtypes = [W.LPCWSTR, W.LPCWSTR, C.c_void_p, W.DWORD, W.DWORD, C.c_void_p]
U.CreateDesktopW.restype = W.HANDLE
U.CloseDesktop.argtypes = [W.HANDLE]


def without_developer_proofs(crx):
    assert crx[:4] == b'Cr24' and struct.unpack_from('<I', crx, 4)[0] == 3
    length = struct.unpack_from('<I', crx, 8)[0]
    header = crx[12:12 + length]
    def varint(at):
        value = 0
        for shift in range(0, 70, 7):
            byte = header[at]; at += 1; value |= (byte & 127) << shift
            if not byte & 128:
                return value, at
        raise ValueError('oversized protobuf varint')
    output = bytearray(); at = 0; removed = 0
    while at < len(header):
        begin = at; tag, at = varint(at)
        assert tag & 7 == 2, 'unexpected CRX3 header wire type'
        size, at = varint(at); at += size
        assert at <= len(header)
        if tag >> 3 in (2, 3):
            removed += 1
        else:
            output += header[begin:at]
    assert removed
    return crx[:8] + struct.pack('<I', len(output)) + output + crx[12 + length:]


def cdp(profile, action, extension_id, value=''):
    output = subprocess.check_output(['node', str(REPO / 'scripts/autoscan_crx_cdp.mjs'),
        str(profile), action, extension_id, str(value)], timeout=40,
        text=True, encoding='utf-8', stderr=subprocess.STDOUT)
    return json.loads(output) if output.strip() else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('matrix', type=Path)
    parser.add_argument('--arch', choices=('x86', 'x64', 'arm64'), default='x86')
    parser.add_argument('--dll', type=Path)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--phases', default='stock,valid,tampered,no-proof,restart,cold-restart,restore')
    args = parser.parse_args()
    dll = (args.dll or REPO / 'mv2-mem-patch-win/build' / args.arch / 'secur32.dll').resolve()
    if dll.name.lower() != 'secur32.dll':
        parser.error('--dll must be named secur32.dll')
    work = args.work.resolve()
    assert work.is_relative_to((REPO / '_scratch').resolve())
    work.mkdir(parents=True, exist_ok=False)
    entry, = json.loads(args.matrix.read_text(encoding='utf-8'))
    source_exe, source_binary = Path(entry['executable']).resolve(), Path(entry['binary']).resolve()
    edge = source_exe.name.lower() == 'msedge.exe'
    # Keep the isolated Edge process from relaunching outside the test launcher's lifetime.
    edge_flags = ['--edge-skip-compat-layer-relaunch'] if edge else []
    source_hash = digest(source_binary)
    executable_hash = digest(source_exe)
    build = REPO / 'mv2-mem-patch-win/out' / args.arch
    dll_hash = digest(dll)
    app = work / 'app'
    application = Path(entry.get('application', source_exe.parent)).resolve()
    assert source_exe.is_relative_to(application) and source_binary.is_relative_to(application)
    def ignore(directory, names):
        return [name for name in names if name.lower() in
                ('secur32.dll', 'secur32.dll.disabled', 'version.dll', 'version.dll.disabled')]
    shutil.copytree(application, app, ignore=ignore)
    sandbox_read(app)
    exe, binary = app / source_exe.relative_to(application), app / source_binary.relative_to(application)
    scan = subprocess.run([str(build / 'mv2-scan.exe'), str(binary)], capture_output=True, text=True, timeout=60)
    report = json.loads(scan.stdout)
    (work / 'scan.json').write_text(json.dumps(report, indent=2))
    assert scan.returncode == 0 and report['ready'] and report['sha256'] == source_hash == digest(binary)
    assert sum(item['optional_kind'] == 2 for item in report['gates']) == 1, 'CRX download gate must be recognized'
    state = {}
    packages = {}
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            state[self.path] = state.get(self.path, 0) + 1
            if self.path in packages:
                body = packages[self.path]
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Disposition', 'attachment; filename="' + self.path[1:] + '"')
            else:
                self.send_response(200); self.send_header('Content-Type', 'text/html')
                if self.path.startswith('/download/'):
                    name = self.path.rsplit('/', 1)[-1]
                    body = ('<a id="download" href="/' + name + '">Download CRX</a>').encode()
                elif self.path.startswith('/probe/'):
                    body = b"<script>fetch('/ready');fetch('/blocked').then(()=>fetch('/not-blocked')).catch(()=>fetch('/blocked-success'));</script>"
                else:
                    body = b'ok'
            self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
        def log_message(self, *args):
            pass
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = 'http://127.0.0.1:' + str(server.server_address[1])
    mv2, mv3 = work / 'mv2', work / 'mv3'
    for version, ext in ((2, mv2), (3, mv3)):
        ext.mkdir()
        manifest = dict(manifest_version=version, name=f'MV{version} CRX proof control', version='1.0', permissions=['storage'])
        if version == 2:
            manifest['permissions'] += ['webRequest', 'webRequestBlocking', 'http://127.0.0.1/*']
            manifest['background'] = dict(scripts=['background.js'], persistent=True)
            code = "chrome.webRequest.onBeforeRequest.addListener(()=>({cancel:true}),{urls:['http://127.0.0.1/*blocked']},['blocking']);globalThis.mv2Ready=true;"
        else:
            manifest['host_permissions'] = ['http://127.0.0.1/*']; manifest['background'] = dict(service_worker='background.js'); code = ''
        (ext / 'manifest.json').write_text(json.dumps(manifest))
        (ext / 'background.js').write_text(code + f"fetch('{origin}/mv{version}-started');")
    subprocess.run([str(exe), '--headless=new', '--no-message-box', '--no-first-run',
        '--user-data-dir=' + str(work / 'packing'), '--pack-extension=' + str(mv2)] + edge_flags, check=True,
        capture_output=True, timeout=40, creationflags=subprocess.CREATE_NO_WINDOW)
    crx = mv2.with_suffix('.crx').read_bytes()
    public = subprocess.check_output([shutil.which('openssl') or 'C:/Program Files/Git/usr/bin/openssl.exe',
        'pkey', '-in', str(mv2.with_suffix('.pem')), '-pubout', '-outform', 'DER'])
    extension_id = ''.join(chr(ord('a') + int(char, 16)) for char in hashlib.sha256(public).hexdigest()[:32])
    altered = bytearray(crx); altered[-1] ^= 1
    packages.update({'/valid.crx': crx, '/restore.crx': crx, '/tampered.crx': bytes(altered), '/no-proof.crx': without_developer_proofs(crx)})
    for name, body in packages.items():
        (work / name[1:]).write_bytes(body)
    registry = 'Software\\MV2AutoScan-' + uuid.uuid4().hex
    browser_registry = 'Software\\Microsoft\\Edge\\Extensions' if edge else 'Software\\Google\\Chrome\\Extensions'
    for branch in ('user', 'machine'):
        winreg.CreateKey(winreg.HKEY_CURRENT_USER, registry + '\\' + branch + '\\' + browser_registry).Close()
    desktop_name = 'MV2Crx-' + uuid.uuid4().hex
    desktop = U.CreateDesktopW(desktop_name, None, None, 0, 0x10000000, None)
    assert desktop, C.WinError(C.get_last_error())
    result = dict(version=entry['version'], source_sha256=source_hash, executable_sha256=executable_hash, dll_sha256=dll_hash,
                  extension_id=extension_id, phases=[], passed=False)
    cache_stamp = None
    try:
        for phase in args.phases.split(','):
            patched = phase not in ('stock', 'restore')
            proxy = app / 'secur32.dll'
            if patched:
                assert digest(dll) == dll_hash
                if not proxy.exists():
                    shutil.copyfile(dll, proxy)
            elif proxy.exists():
                assert proxy.resolve().is_relative_to(work)
                proxy.rename(app / 'secur32.dll.disabled')
            profile = work / ('pv' if phase in ('valid', 'restart', 'cold-restart', 'restore') else 'p-' + phase)
            profile.mkdir(exist_ok=True); local = work / 'local'; local.mkdir(exist_ok=True)
            downloads = profile / 'downloads'; downloads.mkdir(exist_ok=True)
            default = profile / 'Default'; default.mkdir(exist_ok=True)
            preferences = default / 'Preferences'
            prefs = json.loads(preferences.read_text()) if preferences.exists() else {}
            prefs.setdefault('download', {})['default_directory'] = str(downloads)
            prefs['download']['prompt_for_download'] = False
            preferences.write_text(json.dumps(prefs))
            cache = local / 'chrome-mv2-patch/autoscan' / (hashlib.sha256((dll_hash + report['blake3']).encode()).hexdigest() + '.bin')
            if phase == 'cold-restart':
                assert cache.exists() and cache.resolve().is_relative_to(work); cache.unlink(); cache_stamp = None
            port_file = profile / 'DevToolsActivePort'; port_file.unlink(missing_ok=True)
            state.clear()
            flags = [str(exe), '--remote-debugging-port=0', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
                     '--disable-background-networking', '--disable-component-update', '--enable-unsafe-extension-debugging',
                     '--force-renderer-accessibility', '--lang=en-US', '--enable-logging', '--log-file=' + str(work / (phase + '.log')),
                     '--user-data-dir=' + str(profile), 'about:blank'] + edge_flags
            phase_result = dict(phase=phase)
            primary_error = None
            with (work / (phase + '.stderr')).open('wb') as log:
                process = subprocess.Popen([str(build / 'test-launch.exe'), str(build / 'registry-test.dll'),
                    '--desktop=WinSta0\\' + desktop_name] + flags, stdout=subprocess.PIPE, stderr=log,
                    env=dict(os.environ, LOCALAPPDATA=str(local), MV2_TEST_REGISTRY=registry), creationflags=subprocess.CREATE_NO_WINDOW)
                try:
                    pid = int(process.stdout.readline().strip())
                    phase_result['pid'] = pid
                    deadline = time.monotonic() + 45
                    while not port_file.exists() and process.poll() is None and time.monotonic() < deadline:
                        time.sleep(.1)
                    if not port_file.exists():
                        inspected = subprocess.run([str(build / 'browser-ui.exe'), desktop_name, str(pid), str(exe), 'inspect'],
                            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=25,
                            creationflags=subprocess.CREATE_NO_WINDOW)
                        (work / (phase + '-startup-ui.txt')).write_text(inspected.stdout + inspected.stderr, encoding='utf-8')
                    assert port_file.exists(), 'test browser did not expose DevTools'
                    memory_check(pid, report, patched, True, binary.name); phase_result['memory_gates_checked'] = len(report['gates'])
                    cdp(profile, 'mv3', extension_id, mv3)
                    if phase in ('stock', 'valid', 'tampered', 'no-proof', 'restore'):
                        name = phase if phase in ('tampered', 'no-proof', 'restore') else 'valid'
                        cdp(profile, 'download', extension_id, origin + '/download/' + name + '.crx')
                        item = None
                        download_deadline = time.monotonic() + 30
                        while time.monotonic() < download_deadline:
                            items = cdp(profile, 'downloads', extension_id)
                            (work / (phase + '-downloads.json')).write_text(json.dumps(items, indent=2))
                            item = next((item for item in items['items'] if item.get('url') == origin + '/' + name + '.crx'
                                         or (edge and item.get('fileName') == name + '.crx')), None)
                            if item:
                                break
                            time.sleep(.2)
                        assert item, f'download did not appear in the real Downloads page; server requests: {state}'
                        if item.get('filePath'):
                            assert Path(item['filePath']).resolve().is_relative_to(work), 'download must stay in the private workspace'
                        else:
                            assert edge and item.get('isDangerous'), 'download path is unavailable'
                        # Untrusted CRXs remain in a temporary download until
                        # Keep is confirmed. Chrome then opens them automatically
                        # and may delete the source after verification fails.
                        assert state.get('/' + name + '.crx'), 'browser did not request the signed control'
                        if item.get('isDangerous') or item.get('isInsecure'):
                            cdp(profile, 'keep', extension_id, item['id'])
                            phase_result['download_warning_confirmed'] = True
                        else:
                            cdp(profile, 'open', extension_id, item['id'])
                        def ui(action):
                            response = subprocess.run([str(build / 'browser-ui.exe'), desktop_name, str(pid), str(exe), action],
                                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=25,
                                creationflags=subprocess.CREATE_NO_WINDOW)
                            (work / (phase + '-ui-' + re.sub(r'[^A-Za-z0-9_-]', '-', action) + '.txt')).write_text(
                                f'exit_code={response.returncode}\n' + response.stdout + response.stderr, encoding='utf-8')
                            return response
                        if phase == 'valid':
                            accepted = ui('Add extension'); assert accepted.returncode == 0, accepted.stdout + accepted.stderr
                            phase_result['native_confirmation'] = True
                        else:
                            expected = 'CRX_SIGNATURE_VERIFICATION_FAILED' if name == 'tampered' else 'CRX_REQUIRED_PROOF_MISSING'
                            error = ui('inspect:' + expected); text = error.stdout + error.stderr
                            assert error.returncode == 0 and expected in text, text
                            phase_result['package_error'] = re.findall(r'CRX_[A-Z_]+', text)[0]
                            closed = ui('OK'); assert closed.returncode == 0, closed.stdout + closed.stderr
                    deadline = time.monotonic() + 15
                    info = cdp(profile, 'info', extension_id)
                    if phase in ('valid', 'restart', 'cold-restart'):
                        while not info.get('extension') and time.monotonic() < deadline:
                            time.sleep(.2); info = cdp(profile, 'info', extension_id)
                        info = cdp(profile, 'enable', extension_id)
                        cdp(profile, 'probe', extension_id, origin + '/probe/' + phase)
                        while time.monotonic() < deadline and not state.get('/blocked-success'):
                            time.sleep(.1)
                        assert info['extension']['state'] == 'ENABLED' and state.get('/mv2-started')
                        assert state.get('/blocked-success') and not state.get('/blocked'), 'MV2 request blocking failed'
                        if patched:
                            assert cache.exists()
                            stamp = digest(cache), cache.stat().st_mtime_ns
                            phase_result['cache_reused'] = cache_stamp == stamp
                            if phase == 'restart':
                                assert phase_result['cache_reused']
                            cache_stamp = stamp
                    elif phase == 'restore':
                        assert info.get('extension') and info['extension']['state'] == 'DISABLED'
                        assert not state.get('/mv2-started')
                        if edge:
                            assert info['extension']['disableReasons']['suspiciousInstall']
                        else:
                            assert info['extension']['isAffectedByMV2Deprecation']
                    else:
                        assert not info.get('extension')
                    mv3_deadline = time.monotonic() + 5
                    while not state.get('/mv3-started') and time.monotonic() < mv3_deadline:
                        time.sleep(.1)
                    assert state.get('/mv3-started'), 'MV3 background control did not run'
                    phase_result['extension'] = info.get('extension')
                    phase_result['sandboxed_renderers'] = sandbox_check(info['processes'])
                    phase_result['requests'] = state.copy()
                    result['phases'].append(phase_result)
                    print(json.dumps(dict(version=entry['version'], **phase_result)), flush=True)
                except BaseException as error:
                    primary_error = error
                    phase_result['error'] = str(error)
                    result['phases'].append(phase_result)
                    if phase_result.get('pid'):
                        try:
                            inspected = subprocess.run([str(build / 'browser-ui.exe'), desktop_name, str(phase_result['pid']), str(exe), 'inspect'],
                                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=25,
                                creationflags=subprocess.CREATE_NO_WINDOW)
                            (work / (phase + '-error-ui.txt')).write_text(inspected.stdout + inspected.stderr, encoding='utf-8')
                        except (OSError, subprocess.SubprocessError) as inspection_error:
                            phase_result['inspection_error'] = str(inspection_error)
                    if getattr(error, 'output', None):
                        phase_result['error_output'] = error.output
                        (work / (phase + '-error-output.txt')).write_text(error.output, encoding='utf-8')
                    raise
                finally:
                    if process.poll() is None:
                        try:
                            cdp(profile, 'close', extension_id); process.wait(timeout=10)
                        except (OSError, subprocess.SubprocessError):
                            subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True)
                    code = process.wait(timeout=15)
                    phase_result['exit_code'] = code
                    if primary_error is None:
                        assert code == 0, 'test browser cleanup failed'
        result['passed'] = True
    finally:
        delete_registry(registry, registry); result['registry_cleanup'] = True
        U.CloseDesktop(desktop)
        server.shutdown()
        result['disk_unchanged'] = (digest(source_binary) == source_hash == digest(binary)
                                    and digest(source_exe) == executable_hash == digest(exe))
        result['passed'] = result['passed'] and result['disk_unchanged']
        (work / 'results.json').write_text(json.dumps(result, indent=2))
    assert result['disk_unchanged']
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

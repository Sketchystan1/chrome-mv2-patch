"""Exercise the identical auto-scan DLL on isolated Windows browser copies.

Input: JSON entries with version, executable and binary paths. Requires the native
test targets, Node 22+, and OpenSSL. Real installations and extension registrations
are never changed; only a fresh directory beneath _scratch and a private HKCU key
are used. A separate test DLL redirects the external-provider registry reads.
An optional core_only_dll and its SHA-256 seed an off-store-blocked profile before
upgrading to the current DLL. No off-store command-line switch is used.
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
import subprocess
import threading
import time
import uuid
import winreg

REPO = Path(__file__).resolve().parent.parent
K = C.WinDLL('kernel32', use_last_error=True)
K.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
K.OpenProcess.restype = W.HANDLE
K.CloseHandle.argtypes = [W.HANDLE]
K.CreateToolhelp32Snapshot.argtypes = [W.DWORD, W.DWORD]
K.CreateToolhelp32Snapshot.restype = W.HANDLE
K.ReadProcessMemory.argtypes = [W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]
K.GetProcessMitigationPolicy.argtypes = [W.HANDLE, C.c_int, C.c_void_p, C.c_size_t]


class Module(C.Structure):
    _fields_ = [('dwSize', W.DWORD), ('th32ModuleID', W.DWORD), ('th32ProcessID', W.DWORD),
                ('GlblcntUsage', W.DWORD), ('ProccntUsage', W.DWORD), ('modBaseAddr', C.c_void_p),
                ('modBaseSize', W.DWORD), ('hModule', W.HMODULE), ('szModule', W.WCHAR * 256), ('szExePath', W.WCHAR * 260)]


K.Module32FirstW.argtypes = K.Module32NextW.argtypes = [W.HANDLE, C.POINTER(Module)]


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def probe_requests(state, probe):
    # A restored tab can still probe while this phase deliberately disables MV2.
    return {key[len(probe):] if key.startswith(probe + '/') else key: value
            for key, value in state.copy().items()
            if not key.startswith('/probe/') or (key.startswith(probe + '/') and key != probe + '/ready')}


def memory_check(pid, report, patched, allow_offstore):
    for attempt in range(50):
        snapshot = K.CreateToolhelp32Snapshot(0x18, pid)
        if snapshot != C.c_void_p(-1).value:
            break
        error = C.get_last_error()
        if error != 24 or attempt == 49:  # ERROR_BAD_LENGTH: the module list changed during the snapshot.
            raise C.WinError(error)
        time.sleep(.02)
    process = K.OpenProcess(0x1010, False, pid)
    if not process:
        error = C.WinError(C.get_last_error())
        K.CloseHandle(snapshot)
        raise error
    try:
        module = Module(); module.dwSize = C.sizeof(module)
        ok = K.Module32FirstW(snapshot, C.byref(module))
        while ok and module.szModule.lower() != 'chrome.dll':
            ok = K.Module32NextW(snapshot, C.byref(module))
        assert ok, 'chrome.dll is not loaded'
        for gate in report['gates']:
            selected = patched and (not gate['optional'] or allow_offstore)
            expected = bytes.fromhex(gate['patch' if selected else 'stock'])
            actual = C.create_string_buffer(len(expected)); got = C.c_size_t()
            assert K.ReadProcessMemory(process, module.modBaseAddr + gate['rva'], actual, len(expected), C.byref(got))
            assert got.value == len(expected) and actual.raw == expected, f"memory decision differs at {gate['rva']:#x}: {actual.raw.hex()}"
    finally:
        K.CloseHandle(snapshot); K.CloseHandle(process)


def sandbox_check(processes):
    checked = []
    for item in processes:
        if item['type'] != 'renderer':
            continue
        process = K.OpenProcess(0x1000, False, item['id'])
        if not process:
            continue
        try:
            policy = W.DWORD()
            if K.GetProcessMitigationPolicy(process, 4, C.byref(policy), C.sizeof(policy)):
                checked.append(bool(policy.value & 1))
        finally:
            K.CloseHandle(process)
    assert checked and all(checked), 'renderer Win32k sandbox is not enabled'
    return len(checked)


def cdp(profile, action, extension_id, test_url=None, mv3=None):
    command = ['node', str(REPO / 'scripts/autoscan_cdp.mjs'), str(profile), action, extension_id]
    if test_url:
        command.append(test_url)
    if mv3:
        command.append(str(mv3))
    output = subprocess.check_output(command,
                                     timeout=40, text=True, stderr=subprocess.STDOUT)
    return json.loads(output) if output.strip() else None


def delete_registry(path, root):
    assert path == root or path.startswith(root + '\\')
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
        while True:
            try:
                name = winreg.EnumKey(key, 0)
            except OSError:
                break
            delete_registry(path + '\\' + name, root)
    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)


def run_build(entry, args, extensions, state, port, crx, extension_id):
    source_exe, source_binary = Path(entry['executable']).resolve(), Path(entry['binary']).resolve()
    original = digest(source_binary)
    assert digest(args.dll) == args.dll_sha256, 'DLL changed during the matrix run'
    workspace = args.work / re.sub(r'[^A-Za-z0-9.-]', '_', entry['version'])
    workspace.mkdir()
    app = workspace / 'app'
    assert app.resolve().is_relative_to(args.work)
    def skip_previous_proxy(directory, names):
        return [name for name in names if Path(directory) == source_exe.parent and
                name.lower() in ('version.dll', 'version.dll.disabled', 'secur32.dll', 'secur32.dll.disabled')]
    shutil.copytree(source_exe.parent, app, ignore=skip_previous_proxy)
    exe, binary = app / source_exe.name, app / source_binary.relative_to(source_exe.parent)
    proxy = app / args.dll.name
    assert not proxy.exists(), 'source browser already contains a proxy'
    scan = subprocess.run([str(args.build / 'mv2-scan.exe'), str(binary)], capture_output=True, text=True, timeout=60)
    report = json.loads(scan.stdout)
    (workspace / 'scan.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    assert scan.returncode == 0 and report['ready'], 'scanner declined: ' + scan.stdout
    assert report['sha256'] == original == digest(binary)
    baseline = Path(entry['core_only_dll']).resolve() if entry.get('core_only_dll') else None
    if baseline:
        assert digest(baseline) == entry['core_only_dll_sha256'], 'baseline DLL identity differs'
        assert sum(g.get('optional_kind') == 1 for g in report['gates']) == 1, 'upgrade test needs the verified InstallVerifier site'
    if not crx.exists():
        subprocess.run([str(exe), '--headless=new', '--no-message-box', '--user-data-dir=' + str(workspace / 'packing'),
                        '--pack-extension=' + str(extensions[0])], check=True, timeout=40, capture_output=True,
                       creationflags=subprocess.CREATE_NO_WINDOW)
    if not extension_id:
        openssl = shutil.which('openssl') or 'C:/Program Files/Git/usr/bin/openssl.exe'
        public = subprocess.check_output([openssl, 'pkey', '-in', str(extensions[0].with_suffix('.pem')), '-pubout', '-outform', 'DER'])
        extension_id = ''.join(chr(ord('a') + int(c, 16)) for c in hashlib.sha256(public).hexdigest()[:32])
    registry = 'Software\\MV2AutoScan-' + uuid.uuid4().hex
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, registry + '\\user\\Software\\Google\\Chrome\\Extensions\\' + extension_id) as key:
        winreg.SetValueEx(key, 'path', 0, winreg.REG_SZ, str(crx))
        winreg.SetValueEx(key, 'version', 0, winreg.REG_SZ, '1.0')
    winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, registry + '\\machine').Close()
    result = dict(version=entry['version'], source_sha256=original, dll_sha256=args.dll_sha256, extension_id=extension_id, phases=[])
    cache_hashes = {}
    try:
        phases = ('stock', 'core-only', 'patched', 'restart', 'restore') if baseline else ('stock', 'patched', 'restart', 'restore')
        if args.dll.name.lower() == 'secur32.dll':
            phases = phases[:-1] + ('cold-restart', 'restore')
        for phase in phases:
            patched = phase not in ('stock', 'restore')
            allow_offstore = phase in ('patched', 'restart', 'cold-restart')
            proxy_hash = entry['core_only_dll_sha256'] if phase == 'core-only' else args.dll_sha256
            if phase in ('core-only', 'patched'):
                # Windows may retain an image lock briefly after browser shutdown.
                for attempt in range(50):
                    try:
                        shutil.copyfile(baseline if phase == 'core-only' else args.dll, proxy)
                        break
                    except PermissionError:
                        if attempt == 49:
                            raise
                        time.sleep(.1)
                assert digest(proxy) == proxy_hash, 'DLL changed while copying'
            if phase == 'restore':
                assert proxy.resolve().is_relative_to(args.work) and digest(proxy) == result['dll_sha256']
                proxy.rename(proxy.with_name(proxy.name + '.disabled'))
            profile = workspace / ('stock-profile' if phase == 'stock' else 'installed-profile')
            profile.mkdir(exist_ok=True)
            local = profile / 'localappdata'; local.mkdir(exist_ok=True)
            if phase == 'cold-restart':
                key = hashlib.sha256((proxy_hash + report['blake3']).encode('ascii')).hexdigest()
                cache = local / 'chrome-mv2-patch/autoscan' / (key + '.bin')
                assert cache.resolve().is_relative_to(args.work) and cache.exists()
                cache.unlink()
                cache_hashes.pop(proxy_hash, None)
            port_file = profile / 'DevToolsActivePort'
            if port_file.exists():
                port_file.unlink()
            state.clear()
            probe = '/probe/' + uuid.uuid4().hex
            flags = [str(exe), '--headless=new', '--remote-debugging-port=0', '--disable-gpu', '--no-first-run',
                     '--no-default-browser-check', '--disable-background-networking', '--disable-component-update',
                     '--user-data-dir=' + str(profile), '--enable-unsafe-extension-debugging', '--enable-logging',
                     '--log-file=' + str(workspace / (phase + '.log')), 'about:blank']
            with (workspace / (phase + '.stderr')).open('wb') as log:
                process = subprocess.Popen([str(args.build / 'test-launch.exe'), str(args.build / 'registry-test.dll')] + flags,
                    stdout=subprocess.PIPE, stderr=log, env=dict(os.environ, LOCALAPPDATA=str(local), MV2_TEST_REGISTRY=registry),
                    creationflags=subprocess.CREATE_NO_WINDOW)
                phase_result = {'phase': phase, 'offstore_enabled': allow_offstore, 'offstore_launch_flags': []}
                if patched:
                    phase_result['dll_sha256'] = proxy_hash
                try:
                    pid = int(process.stdout.readline().strip())
                    started = time.monotonic(); end = started + 45
                    while not port_file.exists() and time.monotonic() < end and process.poll() is None:
                        time.sleep(.2)
                    assert port_file.exists(), 'DevTools unavailable'
                    phase_result['startup_seconds'] = round(time.monotonic() - started, 3)
                    memory_check(pid, report, patched, allow_offstore)
                    phase_result['memory_gates_checked'] = len(report['gates'])
                    if patched:
                        identity = original if phase == 'core-only' else report['blake3']
                        key = hashlib.sha256((proxy_hash + identity).encode('ascii')).hexdigest()
                        cache = local / 'chrome-mv2-patch/autoscan' / (key + '.bin')
                        assert cache.exists(), 'expected a complete cached scan; use a shorter --work path if its temporary filename exceeds MAX_PATH'
                        cached = (digest(cache), cache.stat().st_mtime_ns)
                        phase_result['cache_reused'] = cache_hashes.get(proxy_hash) == cached
                        if proxy_hash in cache_hashes:
                            assert phase_result['cache_reused'], 'restart must reuse the same complete cache'
                        cache_hashes[proxy_hash] = cached
                    action = 'enable' if allow_offstore else 'offstore-blocked' if patched else phase
                    info = cdp(profile, action, extension_id, f'http://127.0.0.1:{port}{probe}/', extensions[1])
                    phase_result['sandboxed_renderers'] = sandbox_check(info.pop('processes'))
                    phase_result['extensions'] = info
                    end = time.monotonic() + 15
                    while time.monotonic() < end and process.poll() is None:
                        if state.get(probe + '/page-ready') and state.get('/mv3-started') and (not allow_offstore or state.get(probe + '/blocked-success')):
                            time.sleep(1); break
                        time.sleep(.2)
                    requests = phase_result['requests'] = probe_requests(state, probe)
                    assert process.poll() is None, 'browser exited'
                    assert requests.get('/page-ready') and requests.get('/mv3-started'), 'page/MV3 controls failed'
                    assert bool(requests.get('/mv2-started')) == allow_offstore, 'unexpected MV2 state'
                    if allow_offstore:
                        assert requests.get('/blocked-success') and not requests.get('/blocked'), 'MV2 request cancellation failed'
                    if phase == 'stock':
                        assert 'unsupported manifest' in (workspace / 'stock.log').read_text(errors='replace').lower()
                    print(json.dumps(dict(version=entry['version'], **phase_result)), flush=True)
                finally:
                    if process.poll() is None:
                        try:
                            cdp(profile, 'close', extension_id); process.wait(timeout=10)
                        except (OSError, subprocess.SubprocessError):
                            subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True)
                    exit_code = process.wait(timeout=15)
                    result['phases'].append(phase_result)
                    (workspace / (phase + '.json')).write_text(json.dumps(phase_result, indent=2), encoding='utf-8')
                    assert exit_code == 0, f'test browser or child cleanup failed: {exit_code}'
        result['passed'] = True
    finally:
        delete_registry(registry, registry)
        result['registry_cleanup'] = True
        result['disk_unchanged'] = digest(source_binary) == original == digest(binary)
        assert result['disk_unchanged']
        (workspace / 'results.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    return result, extension_id


def main():
    assert probe_requests({'/probe/old/blocked': 1, '/probe/current/blocked': 2, '/probe/current/ready': 3,
                           '/mv2-started': 1}, '/probe/current') == {'/blocked': 2, '/mv2-started': 1}
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('matrix', type=Path)
    parser.add_argument('--arch', choices=('x64', 'x86'), default='x64')
    parser.add_argument('--dll', type=Path)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    args.build = REPO / 'mv2-mem-patch-win/out' / args.arch
    args.work = args.work.resolve()
    args.dll = (args.dll or REPO / 'mv2-mem-patch-win/build' / args.arch / 'secur32.dll').resolve()
    if args.dll.name.lower() != 'secur32.dll':
        parser.error('--dll must be named secur32.dll')
    args.dll_sha256 = digest(args.dll)
    assert args.work.is_relative_to((REPO / '_scratch').resolve()), 'test output must stay beneath _scratch'
    args.work.mkdir(parents=True, exist_ok=False)
    state = {}
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            state[self.path] = state.get(self.path, 0) + 1
            html = self.path.startswith('/probe/') and self.path.endswith('/')
            if html:
                body = b"<script>fetch('page-ready');(async()=>{while(!(await(await fetch('ready')).text()).includes('yes'))await new Promise(r=>setTimeout(r,100));try{await fetch('blocked');fetch('not-blocked')}catch(e){fetch('blocked-success')}})()</script>"
            elif self.path.startswith('/probe/') and self.path.endswith('/ready'):
                body = b'yes' if state.get('/mv2-started') else b'no'
            else:
                body = b'ok'
            self.send_response(200); self.send_header('Content-Type', 'text/html' if html else 'text/plain'); self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            pass
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    extensions = []
    for version in (2, 3):
        ext = args.work / f'extension-mv{version}'; ext.mkdir(); extensions.append(ext)
        manifest = dict(manifest_version=version, name=f'Native scanner MV{version} control', version='1.0', permissions=['storage'])
        background = ''
        if version == 2:
            manifest['permissions'] += ['webRequest', 'webRequestBlocking', 'http://127.0.0.1/*']
            manifest['background'] = dict(scripts=['background.js'], persistent=True)
            background = "chrome.webRequest.onBeforeRequest.addListener(()=>({cancel:true}),{urls:['http://127.0.0.1/*blocked']},['blocking']);globalThis.mv2Ready=true;"
        else:
            manifest['host_permissions'] = ['http://127.0.0.1/*']; manifest['background'] = dict(service_worker='background.js')
        (ext / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
        (ext / 'background.js').write_text(background + f"fetch('http://127.0.0.1:{port}/mv{version}-started');", encoding='utf-8')
    results, extension_id = [], None
    try:
        for entry in json.loads(args.matrix.read_text(encoding='utf-8')):
            try:
                result, extension_id = run_build(entry, args, extensions, state, port, extensions[0].with_suffix('.crx'), extension_id)
            except Exception as error:
                result = dict(version=entry['version'], passed=False, error=str(error))
                if getattr(error, 'output', None):
                    result['error_output'] = error.output
                print(json.dumps(result), flush=True)
            results.append(result)
            (args.work / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    finally:
        server.shutdown()
    return 0 if all(row['passed'] for row in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())

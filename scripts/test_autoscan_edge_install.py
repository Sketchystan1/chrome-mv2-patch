"""Check app-local Secur32 on a direct Edge Application-tree launch.

This diagnostic uses no test DLL, injected DLL or copied browser profile.
It is separate from the CRX lifecycle, whose registry shim is test-only setup.
"""
import argparse
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

from test_autoscan_runtime import digest, memory_check, sandbox_read, security_modules

REPO = Path(__file__).resolve().parent.parent
U = C.WinDLL('user32', use_last_error=True)
U.CreateDesktopW.argtypes = [W.LPCWSTR, W.LPCWSTR, C.c_void_p, W.DWORD, W.DWORD, C.c_void_p]
U.CreateDesktopW.restype = W.HANDLE
U.CloseDesktop.argtypes = [W.HANDLE]


def application_root(entry):
    value = entry.get('application')
    if not value:
        return None
    application = Path(value).resolve()
    return application if Path(entry['executable']).resolve() == application / 'msedge.exe' else None


assert application_root({'executable': r'C:\Edge\Application\msedge.exe',
                         'application': r'C:\Edge\Application'}) == Path(r'C:\Edge\Application')
assert application_root({'executable': r'C:\Edge\Chrome-bin\160.0.0.0\msedge.exe'}) is None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('matrix', type=Path)
    parser.add_argument('--arch', choices=('x86', 'x64', 'arm64'), default='arm64')
    parser.add_argument('--dll', type=Path)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    dll = (args.dll or REPO / 'mv2-mem-patch-win/build' / args.arch / 'secur32.dll').resolve()
    if dll.name.lower() != 'secur32.dll':
        parser.error('--dll must be named secur32.dll')
    work = args.work.resolve()
    assert work.is_relative_to((REPO / '_scratch').resolve())
    work.mkdir(parents=True, exist_ok=False)
    entry, = json.loads(args.matrix.read_text(encoding='utf-8-sig'))
    application = application_root(entry)
    if application is None:
        result = dict(version=entry.get('version', 'unknown'), direct_dll_only='not_tested', passed=False,
                      error='verified package extraction has no top-level Application/msedge.exe')
        (work / 'results.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        print(json.dumps(result), flush=True)
        return 2
    source_exe = Path(entry['executable']).resolve()
    source_binary = Path(entry['binary']).resolve()
    assert source_exe.is_relative_to(application) and source_binary.is_relative_to(application)
    source_exe_hash, source_binary_hash, dll_hash = map(digest, (source_exe, source_binary, dll))
    app = work / 'Application'

    def ignore(_directory, names):
        return [name for name in names if name.lower() in
                ('secur32.dll', 'secur32.dll.disabled', 'version.dll', 'version.dll.disabled')]

    shutil.copytree(application, app, ignore=ignore)
    sandbox_read(app)
    exe, binary, proxy = (app / source_exe.relative_to(application),
                          app / source_binary.relative_to(application), app / 'secur32.dll')
    shutil.copyfile(dll, proxy)
    assert digest(proxy) == dll_hash
    assert not any(path.name.lower() in ('version.dll', 'version.dll.disabled') for path in app.rglob('*'))
    assert [path.resolve() for path in app.rglob('secur32.dll')] == [proxy.resolve()]
    build = REPO / 'mv2-mem-patch-win/out' / args.arch
    scan = subprocess.run([str(build / 'mv2-scan.exe'), str(binary)], capture_output=True,
                          text=True, timeout=60)
    report = json.loads(scan.stdout)
    (work / 'scan.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    assert scan.returncode == 0 and report['ready'] and report['sha256'] == source_binary_hash == digest(binary)
    assert sum(gate['optional_kind'] == 1 for gate in report['gates']) == 1
    assert sum(gate['optional_kind'] == 2 for gate in report['gates']) == 1

    profile, local = work / 'profile', work / 'localappdata'
    profile.mkdir(); local.mkdir()
    desktop_name = 'MV2Edge-' + uuid.uuid4().hex
    desktop = U.CreateDesktopW(desktop_name, None, None, 0, 0x10000000, None)
    assert desktop, C.WinError(C.get_last_error())
    port_file = profile / 'DevToolsActivePort'
    log = (work / 'edge.log').open('wb')
    phase = dict(launch='direct Application/msedge.exe', injected_dlls=[], desktop='private test desktop',
                 headless=True, profile='fresh', extension_state='none', dll_sha256=dll_hash)
    result = dict(version=entry['version'], direct_dll_only='pending', source_sha256=source_binary_hash,
                  executable_sha256=source_exe_hash, dll_sha256=dll_hash,
                  deployment=[str(proxy)], dll_only_context=phase, passed=False)
    process = None
    try:
        flags = [str(exe), '--headless=new', '--disable-gpu', '--remote-debugging-port=0', '--no-first-run',
                 '--no-default-browser-check', '--disable-background-networking', '--disable-component-update',
                 '--edge-skip-compat-layer-relaunch',
                 '--source-shortcut-location=start-menu', '--user-data-dir=' + str(profile), 'about:blank']
        start = subprocess.STARTUPINFO()
        start.lpDesktop = 'WinSta0\\' + desktop_name
        process = subprocess.Popen(flags, cwd=app, stdout=subprocess.DEVNULL, stderr=log,
                                   env=dict(os.environ, LOCALAPPDATA=str(local)),
                                   startupinfo=start, creationflags=subprocess.CREATE_NO_WINDOW)
        deadline = time.monotonic() + 90
        while not port_file.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(.1)
        assert port_file.exists(), 'direct Edge launch did not expose DevTools'
        pid = process.pid
        phase['pid'] = pid
        memory_check(pid, report, True, True, binary.name)
        phase['memory_gates_checked'] = len(report['gates'])
        phase['modules'] = security_modules(pid)
        expected = os.path.normcase(os.path.abspath(proxy))
        local_paths = [os.path.normcase(os.path.abspath(item['path'])) for item in phase['modules']
                       if item.get('name', '').lower() == 'secur32.dll' and item.get('path')]
        assert expected in local_paths, f'app-local Secur32 was not loaded; security modules: {phase["modules"]}'
        phase['app_local_secur32_loaded'] = True
        result['passed'] = True
        result['direct_dll_only'] = 'passed'
        print(json.dumps(dict(version=entry['version'], **phase)), flush=True)
    except BaseException as error:
        result['direct_dll_only'] = 'failed'
        result['error'] = f'{type(error).__name__}: {error}'
        phase['process_exit_code'] = process.poll() if process else None
        phase['modules'] = security_modules(process.pid) if process else []
        raise
    finally:
        if process and process.poll() is None:
            try:
                subprocess.run(['node', str(REPO / 'scripts/autoscan_crx_cdp.mjs'), str(profile), 'close', ''],
                               check=True, capture_output=True, timeout=15)
                process.wait(timeout=15)
            except (OSError, subprocess.SubprocessError, ValueError):
                subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True)
        phase['exit_code'] = process.poll() if process else None
        log.close()
        U.CloseDesktop(desktop)
        result['disk_unchanged'] = (digest(source_exe) == source_exe_hash
                                    and digest(source_binary) == source_binary_hash)
        result['passed'] = result['passed'] and result['disk_unchanged']
        (work / 'results.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    assert result['disk_unchanged']
    if result['passed']:
        assert phase['exit_code'] == 0, 'direct browser cleanup failed'
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

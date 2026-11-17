"""Exercise the native batch installer on temporary browser files only."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import _testutil as T

REPO = Path(__file__).resolve().parent.parent
MACHINES = {"x64": 0x8664, "x86": 0x014C, "arm64": 0xAA64}

TOOLS = r'''
import json, os, sys, xml.etree.ElementTree as ET
from pathlib import Path
tool, args = sys.argv[1], sys.argv[2:]
if tool == "browser" and args[0] == "console":
    sys.exit(0)  # Console behavior is checked separately from browser operations.
log = Path(os.environ["BAT_INSTALL_TEST_LOG"])
previous = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
with log.open("a") as output:
    output.write(json.dumps([tool, args]) + "\n")
if tool == "fltmc":
    sys.exit(0 if os.environ.get("BAT_INSTALL_TEST_ADMIN") == "1" else 1)
if tool == "browser":
    mode, executable = args
    key = os.path.normcase(os.path.normpath(executable))
    image = Path(executable).name
    if mode in ("running", "windows") and (os.environ.get("BAT_INSTALL_TEST_TASKLIST_FAIL") == "1" or (mode == "windows" and os.environ.get("BAT_INSTALL_TEST_WINDOWS_QUERY_FAIL") == "1")):
        sys.exit(2)
    paths = {os.path.normcase(os.path.normpath(path)) for path in json.loads(os.environ.get("BAT_INSTALL_TEST_RUNNING_PATHS", "[]"))}
    primary = os.path.normcase(os.path.normpath(os.environ.get("BAT_INSTALL_TEST_PRIMARY_EXE", "")))
    running = (os.environ.get("BAT_INSTALL_TEST_BUSY") == "1" and key == primary) or key in paths or image in os.environ.get("BAT_INSTALL_TEST_RUNNING", "").split(",")
    windows = int(os.environ.get("BAT_INSTALL_TEST_WINDOWS", "1")) if running else 0
    forced = 0
    tasks, created = {}, None
    for name, values in previous:
        if name == "schtasks" and values[0] == "/create":
            created = values[values.index("/tn") + 1]
        if name == "restart-config":
            tasks[created] = os.path.normcase(os.path.normpath(values[0]))
        if name == "browser" and values[0] in ("close", "force") and os.path.normcase(os.path.normpath(values[1])) == key:
            if os.environ.get("BAT_INSTALL_TEST_KILL_FAIL") != "1" and (values[0] == "force" or os.environ.get("BAT_INSTALL_TEST_GRACE_FAIL") != "1"):
                if values[0] == "force":
                    forced += 1
                    windows = 0
                    running = os.environ.get("BAT_INSTALL_TEST_RESPAWN") == "1" and forced == 1
                else:
                    windows = max(0, windows - 1)
                    running = windows > 0 or os.environ.get("BAT_INSTALL_TEST_BACKGROUND") == "1"
        if name == "schtasks" and values[0] == "/run" and tasks.get(values[values.index("/tn") + 1]) == key and os.environ.get("BAT_INSTALL_TEST_REOPEN_FAIL") != "1":
            running = True
            windows = 1
    if mode == "running":
        sys.exit(0 if running else 1)
    if mode == "windows":
        sys.exit(0 if windows else 1)
    sys.exit(2 if os.environ.get("BAT_INSTALL_TEST_KILL_FAIL") == "1" or (mode == "close" and (os.environ.get("BAT_INSTALL_TEST_GRACE_FAIL") == "1" or os.environ.get("BAT_INSTALL_TEST_PARTIAL_KILL_ERROR") == "1")) else 0)
if tool == "schtasks":
    if args[0] == "/query":
        sys.exit(1)
    if args[0] == "/create":
        xml_path = Path(args[args.index("/xml") + 1])
        assert xml_path.read_bytes().startswith(b"\xff\xfe"), "Task Scheduler requires a UTF-16 BOM"
        xml = ET.parse(xml_path)
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        fields = [xml.findtext(path, namespaces=ns) for path in (
            "t:Actions/t:Exec/t:Command", "t:Actions/t:Exec/t:Arguments", "t:Actions/t:Exec/t:WorkingDirectory",
            "t:Principals/t:Principal/t:UserId", "t:Principals/t:Principal/t:LogonType", "t:Principals/t:Principal/t:RunLevel",
            "t:Settings/t:ExecutionTimeLimit", "t:Settings/t:DisallowStartIfOnBatteries", "t:Settings/t:StopIfGoingOnBatteries")]
        assert all(field is not None for field in fields), fields
        with log.open("a") as output:
            output.write(json.dumps(["restart-config", fields]) + "\n")
        sys.exit(1 if os.environ.get("BAT_INSTALL_TEST_PREPARE_FAIL") == "1" else 0)
    if args[0] == "/run":
        sys.exit(1 if os.environ.get("BAT_INSTALL_TEST_REOPEN_FAIL") == "1" else 0)
if tool == "choice":
    choices = os.environ.get("BAT_INSTALL_TEST_CHOICES", "1").split(",")
    index = sum(item[0] == "choice" for item in previous)
    sys.exit(int(choices[index]))
if tool in ("copy", "move", "fc"):
    if tool == "move" and os.environ.get("BAT_INSTALL_TEST_MOVE_OK") == "1":
        source, target = map(Path, args[-2:])
        work = Path(__file__).resolve().parent.parent
        assert source.resolve().is_relative_to(work) and target.resolve().is_relative_to(work)
        source.replace(target)
        sys.exit(0)
    sys.exit(1)
if tool == "reg":
    if os.environ.get("BAT_INSTALL_TEST_REG_FAIL") == "1" and args[0] == "delete":
        sys.exit(1)
    if args[0] == "query":
        if any(name == "reg" and values[0] == "delete" and values[1] == args[1] and values[-1] == args[-1] for name, values in previous):
            sys.exit(1)
        if "Policies" in args[1]:
            sys.exit(0 if os.environ.get("BAT_INSTALL_TEST_POLICIES") == "1" else 1)
        browser = "edge" if "Microsoft\\Edge" in args[1] else "chromium" if "\\Chromium\\" in args[1] else "chrome"
        sys.exit(0 if browser in os.environ.get("BAT_INSTALL_TEST_EXTENSIONS", "").split(",") else 1)
sys.exit(0)
'''


def fixture(path, arch="x64", branded=False, pe_offset=0x80):
    T.make_pe(path, "90", machine=MACHINES[arch])
    data = bytearray(path.read_bytes())
    if pe_offset != 0x80:
        import struct
        header = data[0x80:0x188]
        data[0x80:0x188] = bytes(len(header))
        data[pe_offset:pe_offset + len(header)] = header
        struct.pack_into("<I", data, 0x3C, pe_offset)
    if branded:
        data[0x600:0x60A] = b"[mv2patch]"
    path.write_bytes(data)


def test_process_control():
    """Exercise the embedded code against real, isolated browser-named processes."""
    host = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    native_host = Path(os.environ["SystemRoot"]) / "Sysnative/WindowsPowerShell/v1.0/powershell.exe"
    if native_host.exists():
        host = native_host
    batch = REPO / "mv2-mem-patch-win/install.bat"
    command = next(line for line in batch.read_text().splitlines() if line.startswith('"%MV2_POWERSHELL%"')).split('-Command "', 1)[1].rsplit('" >nul', 1)[0]
    with tempfile.TemporaryDirectory(prefix="mv2 processes ! & ' ") as directory:
        work = Path(directory).resolve()
        assert work.parent == Path(tempfile.gettempdir()).resolve()
        code = work / "fixture.cs"
        output = work / "fixture.exe"
        code.write_text(r'''
using System;
using System.Drawing;
using System.IO;
using System.Threading;
using System.Windows.Forms;
public static class Fixture {
    [STAThread]
    public static void Main(string[] args) {
        if (args[1] == "background") {
            File.WriteAllText(args[0], "ready");
            new ManualResetEvent(false).WaitOne();
            return;
        }
        var context = new ApplicationContext();
        int remaining = args[1] == "windows" ? 2 : 1;
        int count = remaining;
        for (int i = 0; i < count; i++) {
            var form = new Form();
            form.Text = "N/A, browser \"window\"\n& echo injected & rem";
            form.ShowInTaskbar = false;
            form.StartPosition = FormStartPosition.Manual;
            form.Location = new Point(-32000, -32000);
            form.Size = new Size(100, 100);
            if (args[1] == "stubborn") form.FormClosing += delegate(object sender, FormClosingEventArgs e) { e.Cancel = true; };
            form.FormClosed += delegate { if (--remaining == 0) context.ExitThread(); };
            form.Show();
        }
        File.WriteAllText(args[0], "ready");
        Application.Run(context);
    }
}
''')
        compiled = subprocess.run([str(host), "-NoProfile", "-NonInteractive", "-Command",
            "Add-Type -Path $env:MV2_TEST_SOURCE -OutputAssembly $env:MV2_TEST_OUTPUT -OutputType WindowsApplication -ReferencedAssemblies System.dll,System.Drawing.dll,System.Windows.Forms.dll"],
            env=dict(os.environ, MV2_TEST_SOURCE=str(code), MV2_TEST_OUTPUT=str(output)),
            capture_output=True, text=True, timeout=30)
        assert compiled.returncode == 0, compiled
        executables = []
        for channel, image in (("Chrome Stable", "chrome.exe"), ("Chrome Beta", "chrome.exe"),
                               ("Chromium", "chrome.exe"), ("Edge Stable", "msedge.exe"), ("Edge Beta", "msedge.exe")):
            folder = work / channel
            folder.mkdir()
            executable = folder / image
            shutil.copyfile(output, executable)
            executables.append(executable)
        selected, beta, chromium, edge, edge_beta = executables
        children = []

        def start(executable, mode):
            ready = work / f"ready-{len(children)}.txt"
            child = subprocess.Popen([str(executable), str(ready), mode],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     creationflags=subprocess.CREATE_NO_WINDOW)
            children.append(child)
            deadline = time.monotonic() + 5
            while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            assert ready.exists() and child.poll() is None, (executable, mode, child.returncode)
            return child

        def control(mode, executable, expected=0):
            result = subprocess.run([str(host), "-NoProfile", "-NonInteractive", "-Command", command],
                env=dict(os.environ, MV2_BATCH=str(batch), MV2_PROCESS_MODE=mode, MV2_PROCESS_PATH=str(executable)),
                capture_output=True, text=True, timeout=30)
            assert result.returncode == expected, (mode, executable, result)
            assert "injected" not in result.stdout, result

        try:
            selected_windows = start(selected, "windows")
            selected_worker = start(selected, "background")
            beta_window = start(beta, "stubborn")
            other_processes = [beta_window, start(chromium, "background"),
                               start(edge, "windows"), start(edge_beta, "background")]
            control("running", str(selected).upper())
            control("windows", selected)
            control("close", selected)
            selected_windows.wait(timeout=5)  # Both windows in the same process must close.
            assert selected_worker.poll() is None and all(child.poll() is None for child in other_processes)
            control("windows", selected, 1)
            control("force", selected)
            selected_worker.wait(timeout=5)
            control("running", selected, 1)  # Other chrome.exe instances remain alive.
            control("force", selected)       # Repeated force with no match stays scoped.
            control("invalid", selected, 2)
            control("close", beta)
            control("windows", beta)
            assert beta_window.poll() is None
            control("force", beta)
            beta_window.wait(timeout=5)
            assert all(child.poll() is None for child in other_processes[1:])
            control("close", edge)
            other_processes[2].wait(timeout=5)
            assert other_processes[1].poll() is None and other_processes[3].poll() is None
        finally:
            for child in children:
                if child.poll() is None:
                    child.terminate()
                child.wait(timeout=5)
    print("Embedded process control passed: exact Chrome/Chromium/Edge paths, multiple windows, background workers and force close")


def main():
    source_bytes = (REPO / "mv2-mem-patch-win/install.bat").read_bytes()
    assert b"\r\n" in source_bytes and b"\n" not in source_bytes.replace(b"\r\n", b""), "cmd.exe requires CRLF batch line endings"
    source = source_bytes.decode("utf-8")
    assert not re.search(r"taskkill\.exe|tasklist\.exe|wscript|cscript|mshta|mv2-browser\.exe", source, re.I)
    if sys.platform != "win32":
        print("Native installer runtime tests skipped: Windows required")
        return
    test_process_control()
    with tempfile.TemporaryDirectory(prefix="mv2 batch ! & ' ") as directory:
        work = Path(directory).resolve()
        assert work.parent == Path(tempfile.gettempdir()).resolve()
        tools = work / "tools"
        tools.mkdir()
        (tools / "tools.py").write_text(TOOLS)
        for name in ("fltmc", "browser", "schtasks", "ping", "reg", "choice", "copy", "move", "fc", "pause"):
            (tools / f"{name}.cmd").write_text(
                f'@echo off\n"{sys.executable}" "%~dp0tools.py" {name} %*\nexit /b %errorlevel%\n'
            )
            if name in ("fltmc", "schtasks", "ping", "reg", "choice"):
                source = source.replace(f"{name}.exe", f'call "%BAT_INSTALL_TEST_TOOLS%\\{name}.cmd"')
        process_command = next(line for line in source.splitlines() if line.startswith('"%MV2_POWERSHELL%"'))
        source = source.replace(process_command, 'call "%BAT_INSTALL_TEST_TOOLS%\\browser.cmd" "%MV2_PROCESS_MODE%" "%MV2_PROCESS_PATH%"')
        source = source.replace(" pause", ' call "%BAT_INSTALL_TEST_TOOLS%\\pause.cmd"')
        batch = work / "install.bat"
        # Preserve line endings so test copies cannot hide cmd.exe label-scanning bugs.
        def write_batch(text=source):
            batch.write_bytes(text.encode("utf-8"))

        write_batch()
        payload = work / "secur32.dll"
        roots = work / "roots"
        scratch = work / "temp"
        scratch.mkdir()
        log = work / "calls.jsonl"
        env = dict(os.environ, TEMP=str(scratch), TMP=str(scratch),
                   BAT_INSTALL_TEST_TOOLS=str(tools), BAT_INSTALL_TEST_LOG=str(log),
                   BAT_INSTALL_TEST_ADMIN="1")
        for name in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
            env[name] = str(roots)

        def run(*args, cwd=work, input_text="", **extra_env):
            log.unlink(missing_ok=True)
            target = next((Path(arg) for arg in args if isinstance(arg, Path)), edge)
            folder = target if target.is_dir() else target.parent
            if not any((folder / image).exists() for image in ("chrome.exe", "msedge.exe")):
                folder = folder.parent
            image = "msedge.exe" if (folder / "msedge.exe").exists() else "chrome.exe"
            extra_env.setdefault("BAT_INSTALL_TEST_PRIMARY_EXE", str(folder / image))
            command = subprocess.list2cmdline([str(batch), *map(str, args)])
            # set /p can consume several piped lines at once; a file preserves unread replies.
            with tempfile.TemporaryFile(mode="w+") as replies:
                replies.write(input_text)
                replies.seek(0)
                result = subprocess.run(f'cmd /d /s /c "{command}"', cwd=cwd,
                                        env=dict(env, **extra_env), stdin=replies, capture_output=True, text=True)
            calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            assert not list(scratch.iterdir()), (result, list(scratch.iterdir()))
            assert not any(tool == "reg" and values[0] == "add" for tool, values in calls), calls
            assert str(roots) not in result.stdout, result.stdout
            assert "\x1b[96mSelect browser" not in result.stdout
            for tool, values in calls:
                if tool == "browser":
                    assert len(values) == 2 and values[0] in ("running", "windows", "close", "force"), values
                    assert Path(values[1]).is_absolute() and Path(values[1]).name in ("chrome.exe", "msedge.exe"), values
                if tool == "choice":
                    assert values[values.index("/c") + 1].isdigit(), values
                    assert not any("\x1b" in value for value in values), values
            return result, calls

        def expect(code, *args, **extra_env):
            result, calls = run(*args, **extra_env)
            assert result.returncode == code, (args, result)
            pauses = sum(tool == "pause" for tool, _ in calls)
            if code:
                assert pauses == 1, (args, calls)
            elif "-Quiet" in args:
                assert pauses == 0, (args, calls)
            assert "\x1b[" in result.stdout and "\x1b[0m" in result.stdout, result.stdout
            return re.sub(r"\x1b\[[0-9;]*m", "", result.stdout), calls

        applications = []
        for vendor, stem, channels in (
            ("Google", "chrome", ("Chrome", "Chrome Beta", "Chrome Dev", "Chrome SxS")),
            ("", "chrome", ("Chromium",)),
            ("Microsoft", "msedge", ("Edge", "Edge Beta", "Edge Dev", "Edge SxS")),
        ):
            for channel in channels:
                app = roots / vendor / channel / "Application"
                app.mkdir(parents=True)
                fixture(app / f"{stem}.exe")
                version = app / "1.0.0.1"
                version.mkdir()
                fixture(version / f"{stem}.dll")
                applications.append(app)
        chrome, chromium, edge = applications[0], applications[4], applications[5]
        output, calls = expect(1, "check", "-Quiet")
        rows = re.findall(r"^\[\d+\] (.+)$", output, re.M)
        assert rows == ["Chrome Stable", "Chrome Beta", "Chrome Dev", "Chrome Canary", "Chromium",
                        "Edge Stable", "Edge Beta", "Edge Dev", "Edge Canary"], output
        assert "not installed" not in output and "patch installed" not in output
        assert "[WARNING]" not in output
        assert calls == [["fltmc", []], ["pause", []]]
        for args in ((), ("check", "-Quiet"), ("install", edge, "-Quiet"), ("uninstall", edge, "-Quiet"),
                     ("cleanup",), ("cleanup", edge, "-Quiet")):
            output, calls = expect(1, *args, BAT_INSTALL_TEST_ADMIN="0")
            assert "Not running as administrator." in output
            assert 'Right-click this batch file and select "Run as administrator".' in output
            assert all(text not in output for text in ("Chrome / Chromium / Edge MV2 installer", "[1] Chrome Stable",
                                                       "Select browser", "Selected:", "[1] Install"))
            assert calls == [["fltmc", []], ["pause", []]]
        write_batch(source.replace("goto :resolve_target", "goto :missing_target"))
        result, calls = run("check", edge, "-Quiet")
        assert result.returncode != 0 and "batch label specified - missing_target" in result.stderr, result
        assert sum(tool == "pause" for tool, _ in calls) == 1, calls
        write_batch()
        expect(0, "/?")
        expect(0, "install", "/?")
        output, _ = expect(0, input_text="6\n", BAT_INSTALL_TEST_CHOICES="3")
        assert "[1] Install" in output and "Check" not in output and "Cleanup" not in output
        output, _ = expect(0, input_text='1"& echo injected\n01\n-1\n10\n999999999999999999\n6\n', BAT_INSTALL_TEST_CHOICES="3")
        assert output.count("Enter one of the listed numbers.") == 5, output
        assert "Selected: Edge Stable" in output and "injected" not in output
        expect(0, input_text="6\n", BAT_INSTALL_TEST_CHOICES="0")
        expect(0, input_text=f"0\n{edge / 'msedge.exe'}\n", BAT_INSTALL_TEST_CHOICES="3")
        expect(1, "install", edge, "-Quiet", "-Unknown")
        expect(1, "install", edge, "-Quiet", "-Ublock")
        assert not payload.exists()
        output, _ = expect(1, "install", edge, "-Quiet")
        assert "Missing secur32.dll beside install.bat." in output
        assert not (edge / "secur32.dll").exists()
        legacy = edge / "version.dll"
        fixture(legacy, branded=True)
        data_dir = roots / "chrome-mv2-patch"
        data_dir.mkdir()
        app_signatures = edge / "signatures.json"
        local_signatures = data_dir / "signatures.json"
        cache = data_dir / "autoscan"
        cache.mkdir()
        cache_file = cache / "keep.bin"
        cache_file.write_bytes(b"keep the current scanner cache")
        app_signatures.write_text('{"old": true}')
        local_signatures.write_text('{"old": true}')
        expect(1, "cleanup", edge, "-Quiet", LOCALAPPDATA="")
        assert legacy.exists() and app_signatures.exists() and local_signatures.exists()
        expect(1, "cleanup", edge, "-Quiet", BAT_INSTALL_TEST_BUSY="1", BAT_INSTALL_TEST_KILL_FAIL="1",
               BAT_INSTALL_TEST_PRIMARY_EXE=str(chrome / "chrome.exe"))
        assert legacy.exists()
        assert app_signatures.exists() and local_signatures.exists()
        expect(0, "cleanup", edge, "-Quiet", cwd=roots)
        assert not legacy.exists() and not payload.exists()
        assert not app_signatures.exists() and not local_signatures.exists()
        assert cache_file.read_bytes() == b"keep the current scanner cache"
        app_signatures.write_text('{"old": true}')
        write_batch(source.replace('del /f /q "%%~fF"',
                                   'call "%BAT_INSTALL_TEST_TOOLS%\\copy.cmd" "%%~fF"'))
        output, _ = expect(1, "cleanup", edge, "-Quiet", BAT_INSTALL_TEST_BUSY="1")
        assert "signature removal failed" in output and app_signatures.exists(), output
        assert "Browser reopened." in output
        write_batch()
        output, calls = expect(0, "cleanup", edge, "-Quiet", BAT_INSTALL_TEST_BUSY="1")
        assert "Browser reopened." in output
        assert [args[0] for tool, args in calls if tool == "schtasks"] == ["/query", "/create", "/run", "/delete"]

        fixture(payload, branded=True)
        app_signatures.write_text('{"old": true}')
        local_signatures.write_text('{"old": true}')
        _, calls = expect(0, "install", edge, "-Quiet")
        assert not app_signatures.exists() and not local_signatures.exists()
        assert all(values[0] == "query" for tool, values in calls if tool == "reg")
        installed = edge / "secur32.dll"
        timestamp = installed.stat().st_mtime_ns
        output, calls = expect(0, "install", edge, "-Quiet", BAT_INSTALL_TEST_BUSY="1")
        assert "already installed" in output and installed.stat().st_mtime_ns == timestamp
        assert not any(tool in ("browser", "schtasks") for tool, _ in calls)
        expect(0, "uninstall", edge, "-Quiet")

        # Repeated uninstall leaves a running browser alone and does not touch Chrome policies.
        output, calls = expect(0, "uninstall", edge, "-Quiet", BAT_INSTALL_TEST_BUSY="1", BAT_INSTALL_TEST_POLICIES="1")
        assert "Nothing to uninstall." in output
        assert not any(tool in ("browser", "schtasks") for tool, _ in calls)
        assert not any(tool == "reg" and (values[0] != "query" or "Policies" in values[1]) for tool, values in calls)

        # Old extension registration still requires cleanup when the proxy is already absent.
        output, calls = expect(0, "uninstall", edge, "-Quiet", BAT_INSTALL_TEST_BUSY="1", BAT_INSTALL_TEST_EXTENSIONS="edge")
        assert "Uninstall complete." in output and "Browser reopened." in output
        assert [args for tool, args in calls if tool == "browser" and args[0] in ("close", "force")] == [["close", str(edge / "msedge.exe")]]
        assert len([args for tool, args in calls if tool == "reg" and args[0] == "delete"]) == 2

        preserved = applications[-1] / "secur32.dll"
        fixture(preserved, branded=True)
        preserved_bytes = preserved.read_bytes()
        for app in applications:
            fixture(app / "version.dll", branded=True)
            (app / "signatures.json").write_text('{"old": true}')
        local_signatures.write_text('{"old": true}')
        write_batch(source.replace("move /y", 'call "%BAT_INSTALL_TEST_TOOLS%\\move.cmd"'))
        output, calls = expect(0, "install", edge, "-Quiet", BAT_INSTALL_TEST_BUSY="1",
                               BAT_INSTALL_TEST_POLICIES="1", BAT_INSTALL_TEST_EXTENSIONS="chrome,edge",
                               BAT_INSTALL_TEST_MOVE_OK="1")
        write_batch()
        assert installed.read_bytes() == payload.read_bytes()
        assert preserved.read_bytes() == preserved_bytes
        assert all(not (app / "version.dll").exists() and not (app / "signatures.json").exists() for app in applications)
        assert not local_signatures.exists() and cache_file.read_bytes() == b"keep the current scanner cache"
        assert [args for tool, args in calls if tool == "browser" and args[0] in ("close", "force")] == [["close", str(edge / "msedge.exe")]]
        configs = [args for tool, args in calls if tool == "restart-config"]
        assert [args[0] for args in configs] == [str(edge / "msedge.exe")]
        assert len([args for tool, args in calls if tool == "schtasks" and args[0] == "/delete"]) == 1
        commit = next(index for index, (tool, _) in enumerate(calls) if tool == "move")
        deletes = [index for index, (tool, args) in enumerate(calls) if tool == "reg" and args[0] == "delete"]
        assert len(deletes) == 6 and all(index < commit for index in deletes)
        expect(0, "uninstall", edge, "-Quiet")

        # Same-named browsers with old patcher files remain open during a selected install.
        beta = applications[1]
        other_apps = [chrome, chromium, applications[6]]
        for app in [beta, *other_apps]:
            fixture(app / "version.dll", branded=True)
            (app / "signatures.json").write_text('{"old": true}')
        other_executables = [app / ("msedge.exe" if (app / "msedge.exe").exists() else "chrome.exe") for app in other_apps]
        running = json.dumps([str(beta / "chrome.exe"), *map(str, other_executables)])
        output, calls = expect(0, "install", beta, "-Quiet", BAT_INSTALL_TEST_RUNNING_PATHS=running)
        assert "Skipping legacy cleanup for running" in output and "Browser reopened." in output
        assert (beta / "secur32.dll").read_bytes() == payload.read_bytes()
        assert not (beta / "version.dll").exists() and not (beta / "signatures.json").exists()
        assert all((app / "version.dll").exists() and (app / "signatures.json").exists() for app in other_apps)
        assert [args for tool, args in calls if tool == "browser" and args[0] in ("close", "force")] == [["close", str(beta / "chrome.exe")]]
        assert [args[0] for tool, args in calls if tool == "restart-config"] == [str(beta / "chrome.exe")]
        _, calls = expect(0, "uninstall", beta, "-Quiet", BAT_INSTALL_TEST_RUNNING_PATHS=json.dumps(list(map(str, other_executables))))
        assert not any(tool == "browser" and args[0] in ("close", "force") for tool, args in calls)
        assert all((app / "version.dll").exists() for app in other_apps)

        # Explicit cleanup restarts the exact running installations, including Chromium.
        output, calls = expect(0, "cleanup", "-Quiet", BAT_INSTALL_TEST_RUNNING_PATHS=json.dumps(list(map(str, other_executables))))
        assert [args for tool, args in calls if tool == "browser" and args[0] in ("close", "force")] == [["close", str(executable)] for executable in other_executables]
        assert [args[0] for tool, args in calls if tool == "restart-config"] == list(map(str, other_executables))
        assert output.count("Browser reopened.") == len(other_apps)
        assert all(not (app / "version.dll").exists() and not (app / "signatures.json").exists() for app in other_apps)
        assert preserved.read_bytes() == preserved_bytes

        for arch in MACHINES:
            fixture(payload, arch, branded=True, pe_offset=0x8F)
            fixture(edge / "msedge.exe", arch, pe_offset=0x109)
            version_dll = edge / "1.0.0.1/msedge.dll"
            before = version_dll.read_bytes()
            app_signatures.write_text('{"old": true}')
            local_signatures.write_text('{"old": true}')
            fixture(legacy, arch, branded=True)
            output, calls = expect(0, "install", version_dll, "-Quiet", BAT_INSTALL_TEST_EXTENSIONS="edge")
            installed = edge / "secur32.dll"
            assert "removing the old version.dll proxy." in output and not legacy.exists()
            assert installed.read_bytes() == payload.read_bytes()
            assert version_dll.read_bytes() == before
            assert not app_signatures.exists() and not local_signatures.exists()
            assert cache_file.exists()
            deletes = [args for tool, args in calls if tool == "reg" and args[0] == "delete"]
            assert {args[-1] for args in deletes} == {"/reg:64", "/reg:32"}
            assert all(r"Microsoft\Edge\Extensions" in args[1] for args in deletes)
            assert not any("Google" in str(args) for args in deletes)
            output, calls = expect(0, "check", edge / "msedge.exe", "-Quiet")
            assert "[WARNING]" not in output
            assert all(args[0] == "query" for tool, args in calls if tool == "reg")
            assert sum(tool == "fltmc" for tool, _ in calls) == 1
            assert not any(tool in ("browser", "schtasks") for tool, _ in calls)
            expect(0, "uninstall", edge, "-Quiet")
            assert not installed.exists()

        fixture(payload, "x64", branded=True)
        installed = edge / "secur32.dll"
        fixture(installed, "arm64", branded=True)
        before = installed.read_bytes()
        app_signatures.write_text('{"old": true}')
        local_signatures.write_text('{"old": true}')
        expect(1, "install", edge, "-Quiet")
        assert installed.read_bytes() == before
        assert app_signatures.exists() and local_signatures.exists()
        fixture(edge / "msedge.exe", "x64")
        expect(1, "install", edge, "-Quiet", BAT_INSTALL_TEST_BUSY="1", BAT_INSTALL_TEST_KILL_FAIL="1")
        assert installed.read_bytes() == before
        for failure in ("BAT_INSTALL_TEST_PREPARE_FAIL", "BAT_INSTALL_TEST_TASKLIST_FAIL", "BAT_INSTALL_TEST_WINDOWS_QUERY_FAIL"):
            _, calls = expect(1, "install", edge, "-Quiet", BAT_INSTALL_TEST_BUSY="1", **{failure: "1"})
            assert not any(tool == "browser" and args[0] in ("close", "force") for tool, args in calls)
            assert installed.read_bytes() == before
        for name, command in (("copy", "copy /b /y"), ("fc", "fc.exe /b"), ("move", "move /y")):
            write_batch(source.replace(command, f'call "%BAT_INSTALL_TEST_TOOLS%\\{name}.cmd"'))
            output, calls = expect(1, "install", edge, "-Quiet", BAT_INSTALL_TEST_BUSY="1")
            assert "Browser reopened." in output
            assert any(tool == "schtasks" and args[0] == "/delete" for tool, args in calls)
            assert installed.read_bytes() == before
            assert not list(edge.glob("secur32.dll.mv2-*.tmp"))
        write_batch()
        output, calls = expect(0, "install", edge, "-Quiet", BAT_INSTALL_TEST_RUNNING="chrome.exe,msedge.exe")
        kills = [args for tool, args in calls if tool == "browser" and args[0] in ("close", "force")]
        assert kills == [["close", str(edge / "msedge.exe")]]
        config = next(args for tool, args in calls if tool == "restart-config")
        assert config == [str(edge / "msedge.exe"), "--restore-last-session", str(edge),
                          f"{env['USERDOMAIN']}\\{env['USERNAME']}", "InteractiveToken", "LeastPrivilege", "PT0S", "false", "false"]
        assert "Browser reopened." in output
        output, calls = expect(0, "uninstall", edge, "-Quiet", BAT_INSTALL_TEST_BUSY="1", BAT_INSTALL_TEST_GRACE_FAIL="1")
        assert "Force-closing" in output and "Browser reopened." in output
        kills = [args for tool, args in calls if tool == "browser" and args[0] in ("close", "force")]
        assert len(kills) == 17 and all(args[0] == "close" for args in kills[:-1])
        assert kills[-1] == ["force", str(edge / "msedge.exe")]
        assert sum(tool == "ping" for tool, _ in calls) == 15
        assert not installed.exists()

        # A normal close can save the session yet leave background workers running.
        output, calls = expect(0, "install", edge, "-Quiet", BAT_INSTALL_TEST_BUSY="1",
                               BAT_INSTALL_TEST_BACKGROUND="1", BAT_INSTALL_TEST_PARTIAL_KILL_ERROR="1")
        assert "background processes" in output and "The browser did not exit" not in output
        assert "Browser reopened." in output and sum(tool == "ping" for tool, _ in calls) == 2
        kills = [args for tool, args in calls if tool == "browser" and args[0] in ("close", "force")]
        assert kills == [[mode, str(edge / "msedge.exe")] for mode in ("close", "force")]
        expect(0, "uninstall", edge, "-Quiet")

        # No browser window is available to receive a normal close request.
        for title in ("N/A", "OleMainThreadWndName"):
            output, calls = expect(0, "install", edge, "-Quiet", BAT_INSTALL_TEST_BUSY="1",
                                   BAT_INSTALL_TEST_WINDOWS="0", BAT_INSTALL_TEST_BACKGROUND_TITLE=title)
            assert "background processes" in output and "The browser did not exit" not in output
            assert not any(tool == "ping" for tool, _ in calls)
            kills = [args for tool, args in calls if tool == "browser" and args[0] in ("close", "force")]
            assert kills == [["force", str(edge / "msedge.exe")]]
            expect(0, "uninstall", edge, "-Quiet")

        # Titles containing commas, quotes, newlines or shell syntax stay data.
        output, calls = expect(0, "install", edge, "-Quiet", BAT_INSTALL_TEST_BUSY="1",
                               BAT_INSTALL_TEST_WINDOWS="2", BAT_INSTALL_TEST_WINDOW_TITLE='N/A, browser "window"\n"& echo injected & rem "')
        kills = [args for tool, args in calls if tool == "browser" and args[0] in ("close", "force")]
        assert kills == [["close", str(edge / "msedge.exe")]] * 2
        assert sum(tool == "ping" for tool, _ in calls) == 1
        assert "injected" not in output and "Force-closing" not in output and "Browser reopened." in output
        expect(0, "uninstall", edge, "-Quiet")

        output, calls = expect(0, "install", edge, "-Quiet", BAT_INSTALL_TEST_BUSY="1",
                               BAT_INSTALL_TEST_WINDOWS="0", BAT_INSTALL_TEST_RESPAWN="1")
        kills = [args for tool, args in calls if tool == "browser" and args[0] in ("close", "force")]
        assert kills == [["force", str(edge / "msedge.exe")]] * 2
        assert sum(tool == "ping" for tool, _ in calls) == 1
        assert "Browser reopened." in output
        expect(0, "uninstall", edge, "-Quiet")

        output, calls = expect(0, "install", edge, "-Quiet", BAT_INSTALL_TEST_BUSY="1", BAT_INSTALL_TEST_REOPEN_FAIL="1")
        assert "[WARNING] Could not reopen the browser." in output
        assert any(tool == "schtasks" and args[0] == "/delete" for tool, args in calls)
        assert installed.exists()
        before = installed.read_bytes()
        for signatures in (app_signatures, local_signatures):
            signatures.unlink(missing_ok=True)
            signatures.mkdir()
            keep = signatures / "keep.txt"
            keep.write_text("not an old signature file")
            fixture(legacy, branded=True)
            expect(1, "install", edge, "-Quiet")
            expect(1, "cleanup", edge, "-Quiet")
            assert keep.read_text() == "not an old signature file"
            assert legacy.exists()
            assert installed.read_bytes() == before
            keep.unlink()
            signatures.rmdir()
        fixture(payload, branded=False)
        expect(1, "install", edge, "-Quiet")
        fixture(payload, branded=True)
        data = bytearray(payload.read_bytes())
        data[0x80:0x84] = b"NOPE"
        payload.write_bytes(data)
        expect(1, "install", edge, "-Quiet")
        assert installed.read_bytes() == before
        fixture(payload, branded=True)
        installed.write_bytes(b"unrelated")
        output, _ = expect(0, input_text="6\n", BAT_INSTALL_TEST_CHOICES="3")
        assert "[6] Edge Stable" in output.splitlines()
        assert "unrelated secur32.dll" not in output
        expect(1, "install", edge, "-Quiet")
        expect(1, "uninstall", edge, "-Quiet")
        assert installed.read_bytes() == b"unrelated"
        installed.unlink()
        legacy = edge / "version.dll"
        legacy.write_bytes(b"unrelated")
        expect(0, "install", edge, "-Quiet", cwd=roots)
        assert legacy.read_bytes() == b"unrelated"
        before_cleanup = installed.read_bytes()
        expect(0, "cleanup", "-Quiet")
        assert legacy.read_bytes() == b"unrelated"
        assert installed.read_bytes() == before_cleanup
        expect(0, "check", input_text="6\n")
        output, _ = expect(0, input_text="6\n", BAT_INSTALL_TEST_CHOICES="3")
        assert "[1] Install" in output and all(word not in output for word in ("Reinstall", "Check", "Cleanup"))
        timestamp = installed.stat().st_mtime_ns
        write_batch(source.replace("move /y", 'call "%BAT_INSTALL_TEST_TOOLS%\\move.cmd"'))
        output, calls = expect(0, input_text="6\n", BAT_INSTALL_TEST_CHOICES="1", BAT_INSTALL_TEST_MOVE_OK="1")
        write_batch()
        assert "[1] Install" in output and "Reinstall" not in output
        assert not any(tool == "move" for tool, _ in calls)
        assert "already installed" in output and installed.stat().st_mtime_ns == timestamp
        assert legacy.read_bytes() == b"unrelated"
        assert installed.read_bytes() == before_cleanup
        expect(0, "uninstall", edge, "-Quiet")
        fixture(legacy, branded=True)
        expect(0, "install", edge, "-Quiet")
        assert not legacy.exists()
        expect(0, "uninstall", edge, "-Quiet")
        _, calls = expect(0, "install", edge)
        assert not any(tool == "choice" for tool, _ in calls)
        expect(0, "uninstall", edge, "-Quiet")
        fixture(legacy, branded=True)
        fixture(installed, branded=True)
        installed.write_bytes(installed.read_bytes() + b"old patch")
        before_registry_failure = installed.read_bytes()
        output, _ = expect(1, "install", edge, "-Quiet", BAT_INSTALL_TEST_REG_FAIL="1", BAT_INSTALL_TEST_BUSY="1", BAT_INSTALL_TEST_EXTENSIONS="edge")
        assert "Browser reopened." in output
        assert "uBlock Origin removal failed." in output
        assert installed.read_bytes() == before_registry_failure
        expect(0, "uninstall", edge, "-Quiet")

        backup = chrome / "1.0.0.1/chrome.dll.bak"
        backup.write_bytes(b"keep this backup")
        expect(1, "install", chrome, "-Quiet")
        fixture(chrome / "version.dll", branded=True)
        expect(1, "cleanup", chrome, "-Quiet")
        assert backup.read_bytes() == b"keep this backup"
        assert (chrome / "version.dll").exists()
        assert not (chrome / "secur32.dll").exists()
        backup.unlink()
        fixture(chrome / "secur32.dll", branded=True)
        before_cleanup = (chrome / "secur32.dll").read_bytes()
        chrome_signatures = chrome / "signatures.json"
        chrome_signatures.write_text('{"old": true}')
        local_signatures.write_text('{"old": true}')
        _, calls = expect(0, "cleanup", chrome, "-Quiet", BAT_INSTALL_TEST_POLICIES="1", BAT_INSTALL_TEST_EXTENSIONS="chrome")
        assert not (chrome / "version.dll").exists()
        assert (chrome / "secur32.dll").read_bytes() == before_cleanup
        assert not chrome_signatures.exists() and not local_signatures.exists()
        assert cache_file.read_bytes() == b"keep the current scanner cache"
        assert all(r"Google\Chrome" in args[1] for tool, args in calls if tool == "reg" and args[0] == "delete")
        assert len([args for tool, args in calls if tool == "reg" and args[0] == "delete"]) == 4
        fixture(chrome / "version.dll", branded=True)
        chrome_signatures.write_text('{"old": true}')
        local_signatures.write_text('{"old": true}')
        output, calls = expect(0, "install", chrome, "-Quiet", BAT_INSTALL_TEST_POLICIES="1", BAT_INSTALL_TEST_BUSY="1", BAT_INSTALL_TEST_EXTENSIONS="chrome")
        assert "Browser reopened." in output
        assert "removing the old version.dll proxy." in output
        assert not chrome_signatures.exists() and not local_signatures.exists()
        assert [args for tool, args in calls if tool == "browser" and args[0] in ("close", "force")] == [["close", str(chrome / "chrome.exe")]]
        assert all(r"Google\Chrome" in args[1] for tool, args in calls if tool == "reg" and args[0] == "delete")
        assert len([args for tool, args in calls if tool == "reg" and args[0] == "delete"]) == 4
        fixture(chrome / "version.dll", branded=True)
        _, calls = expect(0, "uninstall", chrome, "-Quiet", BAT_INSTALL_TEST_POLICIES="1")
        assert not (chrome / "version.dll").exists()
        assert not any("Policies" in args[1] for tool, args in calls if tool == "reg")
        fixture(chromium / "version.dll", branded=True)
        (chromium / "signatures.json").write_text('{"old": true}')
        _, calls = expect(0, "install", chromium, "-Quiet", BAT_INSTALL_TEST_EXTENSIONS="chromium")
        assert (chromium / "secur32.dll").read_bytes() == payload.read_bytes()
        assert not (chromium / "version.dll").exists() and not (chromium / "signatures.json").exists()
        deletes = [args for tool, args in calls if tool == "reg" and args[0] == "delete"]
        assert len(deletes) == 2 and all(r"Software\Chromium\Extensions" in args[1] for args in deletes)
        output, calls = expect(0, "check", input_text="5\n")
        assert "[5] Chromium - patch installed" in output.splitlines()
        assert all(r"Software\Chromium\Extensions" in args[1] for tool, args in calls if tool == "reg")
        _, calls = expect(0, "uninstall", chromium, "-Quiet", BAT_INSTALL_TEST_EXTENSIONS="chromium", BAT_INSTALL_TEST_POLICIES="1")
        assert not (chromium / "secur32.dll").exists()
        assert all(r"Software\Chromium\Extensions" in args[1] for tool, args in calls if tool == "reg")
        other_roots = work / "other roots"
        for app in applications:
            shutil.copytree(app, other_roots / app.relative_to(roots))
        other_edge = other_roots / applications[-1].relative_to(roots)
        fixture(other_edge / "secur32.dll", branded=True)
        output, _ = expect(0, "check", input_text="18\n",
                           **{"ProgramFiles(x86)": str(other_roots)})
        assert "[18] Edge Canary - patch installed" in output and "Selected: Edge Canary" in output
        rows = re.findall(r"^\[\d+\] (.+)$", output, re.M)
        assert [row.split()[0] for row in rows] == ["Chrome"] * 8 + ["Chromium"] * 2 + ["Edge"] * 8
        assert str(other_roots) not in output
        payload.unlink()
        expect(0, "uninstall", edge, "-Quiet")
    print("Native batch installer tests passed: manual elevation, grouped Chrome/Chromium/Edge, patch status, automatic cleanup and safety")


if __name__ == "__main__":
    main()

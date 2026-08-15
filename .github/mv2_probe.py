#!/usr/bin/env python3
"""Functional MV2 probe for CI: does *this* Chrome enable a Manifest V2 extension?

At Chrome 151/152 the MV2 disable is a compiled-in feature default
(ExtensionManifestV2Unsupported / ExtensionManifestV2Disabled); the command-line
--enable-features / --disable-features levers no longer toggle it. So a *stock*
build disables an MV2 extension out of the box and the patch is the only thing
that re-enables it. This script observes that difference behaviourally instead of
scraping chrome://extensions (unreliable headless):

  - Build a tiny MV2 extension whose *persistent background page* fetches a
    local URL the instant the extension is enabled.
  - A disabled extension never loads its background page, so it never pings.
  - Launch Chrome headless with --load-extension, wait, and report "enabled"
    (ping arrived) or "disabled" (no ping) for this binary.

Run it once against the stock app and once against the patched app; the caller
asserts the difference. Exit code is always 0 on a clean run — the observed
state goes to stdout and (optionally) --state-out. A non-zero exit means the
probe harness itself failed (Chrome would not launch, etc.).
"""
import argparse
import http.server
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

PROBE_HIT = threading.Event()


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 (stdlib naming)
        PROBE_HIT.set()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_a):  # silence per-request logging
        pass


def _start_listener():
    """Bind an ephemeral loopback port and serve in a daemon thread."""
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, port


def _write_extension(dirpath, port):
    manifest = (
        '{\n'
        '  "manifest_version": 2,\n'
        '  "name": "mv2probe",\n'
        '  "version": "1.0",\n'
        '  "permissions": ["<all_urls>"],\n'
        '  "background": { "scripts": ["bg.js"], "persistent": true }\n'
        '}\n'
    )
    # Persistent background page runs top-level code the moment the extension is
    # enabled. Retry once in case the net stack is not up on the first tick.
    bg = (
        'function ping(t){ fetch("http://127.0.0.1:%d/alive?"+t)'
        '.catch(function(){}); }\n'
        'ping("a");\n'
        'setTimeout(function(){ ping("b"); }, 1500);\n'
    ) % port
    with open(os.path.join(dirpath, "manifest.json"), "w") as f:
        f.write(manifest)
    with open(os.path.join(dirpath, "bg.js"), "w") as f:
        f.write(bg)


def probe(chrome_bin, timeout, debug=False):
    PROBE_HIT.clear()
    srv, port = _start_listener()
    tmp = tempfile.mkdtemp(prefix="mv2probe-")
    ext = os.path.join(tmp, "ext")
    prof = os.path.join(tmp, "prof")
    os.makedirs(ext)
    os.makedirs(prof)
    _write_extension(ext, port)

    argv = [
        chrome_bin,
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--no-first-run",
        "--user-data-dir=" + prof,
        "--load-extension=" + ext,
        "--disable-extensions-except=" + ext,
        "data:text/html,mv2probe",
    ]
    errlog = os.path.join(tmp, "chrome-stderr.log")
    errfh = open(errlog, "wb")
    # Send Chrome's stderr to a FILE, never a PIPE. New headless on a
    # display-less CI runner spews CVDisplayLinkCreateWithCGDisplay errors; an
    # undrained PIPE fills its ~64 KiB buffer and blocks Chrome mid-startup, so
    # the extension never runs its background page and every build looks
    # "disabled". A regular file never blocks the writer.
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=errfh)
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            if PROBE_HIT.is_set():
                break
            if proc.poll() is not None:
                # Chrome exited before pinging; give the listener a moment.
                time.sleep(1.0)
                break
            time.sleep(0.25)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        srv.shutdown()
        errfh.close()

    if debug or not PROBE_HIT.is_set():
        try:
            with open(errlog, "r", errors="replace") as fh:
                tail = fh.read()[-3000:]
        except OSError:
            tail = "(no stderr captured)"
        sys.stderr.write("chrome rc=%s; PROBE_HIT=%s; stderr tail:\n%s\n"
                         % (proc.returncode, PROBE_HIT.is_set(), tail))
    return "enabled" if PROBE_HIT.is_set() else "disabled"


def main():
    ap = argparse.ArgumentParser(description="MV2 functional probe")
    ap.add_argument("--chrome", required=True, help="path to the chrome binary")
    ap.add_argument("--timeout", type=float, default=30.0,
                    help="seconds to wait for the extension ping")
    ap.add_argument("--state-out", help="write observed state to this file")
    ap.add_argument("--debug", action="store_true",
                    help="always dump a tail of Chrome's stderr for diagnosis")
    args = ap.parse_args()

    if not os.path.exists(args.chrome):
        sys.stderr.write("chrome binary not found: %s\n" % args.chrome)
        return 2

    state = probe(args.chrome, args.timeout, debug=args.debug)
    print(state)
    if args.state_out:
        with open(args.state_out, "w") as f:
            f.write(state)
    return 0


if __name__ == "__main__":
    sys.exit(main())

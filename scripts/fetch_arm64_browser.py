"""Fetch complete stock Windows Chrome/Edge copies for browser tests.

Resolve the latest Stable, Beta or Canary from the vendor's update service,
verify the installer SHA-256 and size, and extract without installing it.
Write matrix.json for the existing browser harness. All files stay in _scratch.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit
import urllib.request
import xml.etree.ElementTree as ET

from fetch_chrome_binary import (REPO, PLATFORMS, _pe_machine, binary_version,
                                 download, extract, find_seven_zip, locate_binary)

APPIDS = {
    'stable': '{8a69d345-d564-463c-aff1-a69d9e530f96}',
    'beta': '{8237e44a-0054-442c-b6b6-ea0509993955}',
    'canary': '{4ea16ac7-fd5a-47c3-875b-dbf4a2008c20}',
}


def chrome_source(channel, arch='arm64'):
    body = (f'<request protocol="3.0"><os platform="win" version="10.0.22000" arch="{arch}"/>'
            f'<app appid="{APPIDS[channel]}" version="" ap="{arch}"><updatecheck/></app></request>').encode()
    request = urllib.request.Request('https://update.googleapis.com/service/update2', data=body,
                                     headers={'Content-Type': 'text/xml'})
    with urllib.request.urlopen(request, timeout=30) as response:
        update = ET.fromstring(response.read()).find('app/updatecheck')
    if update is None or update.get('status') != 'ok':
        raise ValueError(f'Chrome update service did not offer an {arch} installer')
    manifest = update.find('manifest')
    package, = manifest.findall('packages/package')
    base = next((item.get('codebase') for item in update.findall('urls/url')
                 if item.get('codebase', '').startswith('https://dl.google.com/')), None)
    if base is None:
        raise ValueError('Chrome update service did not supply an HTTPS download')
    return dict(version=manifest.get('version'), url=base + package.get('name'),
                sha256=package.get('hash_sha256'), size=int(package.get('size')))


def edge_source(channel, arch='arm64'):
    base = ('https://msedge.api.cdp.microsoft.com/api/v1.1/contents/Browser/namespaces/Default/'
            f'names/msedge-{channel}-win-{arch}/versions/')
    request = urllib.request.Request(base + 'latest?action=select',
        data=b'{"targetingAttributes":{}}', headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        version = json.load(response)['ContentId']['Version']
    if not re.fullmatch(r'\d+\.\d+\.\d+\.\d+', version):
        raise ValueError('Edge update service supplied an invalid version')
    request = urllib.request.Request(base + version + '/files?action=GenerateDownloadInfo',
                                     data=b'{}', headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        files = json.load(response)
    # Delta installers require an older installation; only the complete package is usable.
    package = next((item for item in files if item['FileId'] == f'MicrosoftEdge_{arch.upper()}_{version}.exe'), None)
    if package is None:
        raise ValueError(f'Edge update service did not offer a complete {arch} installer')
    # The HTTPS update response authenticates the hash for Microsoft's HTTP delivery URL.
    return dict(version=version, url=package['Url'],
                sha256=base64.b64decode(package['Hashes']['Sha256'], validate=True).hex(),
                size=int(package['SizeInBytes']))


def verify_download(path, source):
    with path.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if path.stat().st_size != source['size'] or actual != source['sha256']:
        raise ValueError('installer size or SHA-256 differs from the vendor update metadata')


def browser_entry(root, browser, version, arch='arm64'):
    binary_name, executable_name = ('chrome.dll', 'chrome.exe') if browser == 'chrome' else ('msedge.dll', 'msedge.exe')
    platform = {'x64': 'win64', 'x86': 'win', 'arm64': 'win-arm64'}[arch]
    spec = dict(PLATFORMS[platform], binary=binary_name)
    spec.setdefault('machine', 0x14C)
    found = locate_binary(str(root), spec)
    if not found:
        raise ValueError(f'no {arch} {binary_name} in the installer')
    binary = Path(found).resolve()
    application = binary.parent.parent if browser == 'edge' else None
    root_executable = application / executable_name if application else None
    if root_executable and root_executable.is_file() and _pe_machine(root_executable) == spec['machine']:
        executable = root_executable
    else:
        executable = next((parent / executable_name for parent in binary.parents
                           if parent.is_relative_to(root) and (parent / executable_name).is_file()), None)
    if executable is None or _pe_machine(executable) != spec['machine']:
        raise ValueError(f'no matching {arch} {executable_name} beside or above {binary_name}')
    if binary_version(binary) != version or binary_version(executable) != version:
        raise ValueError('extracted browser version differs from the vendor update metadata')
    entry = dict(version=f'{browser} {version} {arch.upper()}', executable=str(executable), binary=str(binary))
    if application and executable == root_executable:
        entry['application'] = str(application)
    return entry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--browser', choices=('chrome', 'edge'), required=True)
    parser.add_argument('--channel', choices=tuple(APPIDS), required=True)
    parser.add_argument('--arch', choices=('x64', 'x86', 'arm64'), default='arm64')
    parser.add_argument('--source', type=Path, help='replay a recorded vendor source.json instead of querying the current channel')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        out = args.out.resolve()
        if not out.is_relative_to((REPO / '_scratch').resolve()):
            raise ValueError('browser downloads must stay beneath _scratch')
        seven_zip = find_seven_zip()
        if not seven_zip:
            raise ValueError('7-Zip is required to extract the browser')
        out.mkdir(parents=True, exist_ok=False)
        if args.source:
            source = json.loads(args.source.read_text(encoding='utf-8-sig'))
            if (source.get('browser'), source.get('channel'), source.get('architecture')) != (args.browser, args.channel, args.arch):
                raise ValueError('recorded source does not match the requested browser, channel and architecture')
        else:
            source = (chrome_source if args.browser == 'chrome' else edge_source)(args.channel, args.arch)
        url = urlsplit(source['url'])
        edge_delivery = (args.browser == 'edge' and url.scheme == 'http'
                         and (url.hostname or '').endswith('.dl.delivery.mp.microsoft.com'))
        if (not (url.scheme == 'https' or edge_delivery) or source['size'] <= 0
                or not re.fullmatch(r'[0-9a-f]{64}', source['sha256'])
                or not re.fullmatch(r'\d+\.\d+\.\d+\.\d+', source['version'])):
            raise ValueError('vendor update metadata lacks a valid download URL, size, SHA-256 or version')
        source.update(browser=args.browser, channel=args.channel, architecture=args.arch)
        (out / 'source.json').write_text(json.dumps(source, indent=2), encoding='utf-8')
        archive = out / 'installer.exe'
        if not download(source['url'], str(archive)):
            raise ValueError('browser download failed')
        verify_download(archive, source)
        root = Path(extract(str(archive), str(out), seven_zip)).resolve()
        entry = browser_entry(root, args.browser, source['version'], args.arch)
        (out / 'matrix.json').write_text(json.dumps([entry], indent=2), encoding='utf-8')
        print(json.dumps(dict(channel=args.channel, **entry)), flush=True)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, ET.ParseError,
            subprocess.SubprocessError) as error:
        parser.exit(2, f'Windows browser fetch failed: {error}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

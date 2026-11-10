"""Read-only evaluation of the native scanner against a JSON list of Windows builds.

Each entry needs a `binary` path and a `version` label. Discovery runs first;
the maintained table is used only afterward to measure known core coverage.
An unlisted build may supply a reviewed_baseline with sha256, provenance, core
and optional RVA lists. That evaluation input is never passed to the scanner.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

from audit_signatures import milestones, would_select
from derive_milestone import masked_match_count, open_images

REPO = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('matrix', type=Path)
    parser.add_argument('--scanner', type=Path, default=REPO / 'mv2-mem-patch-win/out/x64/mv2-scan.exe')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    entries = json.loads(args.matrix.read_text(encoding='utf-8'))
    table = json.loads((REPO / 'signatures.json').read_text(encoding='utf-8'))
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    for index, entry in enumerate(entries):
        path = Path(entry['binary']).resolve()
        started = time.monotonic()
        run = subprocess.run([str(args.scanner), str(path)], capture_output=True, text=True, timeout=60)
        elapsed = time.monotonic() - started
        if run.returncode not in (0, 1):
            raise RuntimeError(f"{entry['version']}: scanner failed ({run.returncode}): {run.stderr}")
        report = json.loads(run.stdout)
        (args.output / f'{index:02d}-scan.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
        img = open_images(str(path))[0]
        digest = hashlib.sha256(img.data).hexdigest()
        best, _, _ = would_select(table, img)
        selected = best[0][3] if best and len(best) == 1 and best[0][0] else None
        expected, optional = set(), set()
        for milestone in milestones(table):
            if milestone.get('container', 'pe') != img.container:
                continue
            for site in milestone['sites']:
                if site['kind'] == 'featurebyte' or (milestone['name'] != selected and not site.get('optional')):
                    continue
                found = masked_match_count(img.text, bytes.fromhex(site['sig']), site['jgOff'], site['kind'],
                                           cap=site['expectedMatches'] + 1)
                if len(found) == site['expectedMatches']:
                    target = optional if site.get('optional') else expected
                    target.update(img.rva(pos) + site['jgOff'] for pos in found)
        basis = 'signatures.json: ' + selected if selected else None
        if 'reviewed_baseline' in entry:
            baseline = entry['reviewed_baseline']
            if baseline['sha256'] != digest or not baseline['provenance']:
                raise ValueError('Reviewed baseline lacks matching identity/provenance')
            reviewed_core = {int(value, 0) for value in baseline['core']}
            optional |= {int(value, 0) for value in baseline.get('optional', [])}
            if not reviewed_core or reviewed_core & optional:
                raise ValueError('Reviewed baseline must have distinct, nonempty core addresses')
            if selected and expected != reviewed_core:
                raise ValueError('Reviewed core baseline differs from the selected table')
            if not selected:
                expected = reviewed_core
                basis = 'reviewed baseline: ' + baseline['provenance']
            else:
                basis += '; reviewed optional: ' + baseline['provenance']
        actual = {g['rva'] for g in report['gates']}
        missing, extra = expected - actual, actual - expected - optional
        ok = bool(basis and report['ready'] and not missing and not extra and report['sha256'] == digest
                  and entry.get('sha256', digest) == digest)
        result = dict(version=entry['version'], binary=str(path), sha256=digest, seconds=round(elapsed, 3),
                      ready=report['ready'], selected=selected, evaluation_basis=basis, gates=len(actual), known_core=len(expected),
                      missing=[hex(x) for x in sorted(missing)], extra=[hex(x) for x in sorted(extra)],
                      optional_found=len(actual & optional), optional_known=len(optional),
                      install_verifier=report.get('install_verifier'),
                      crx_download=report.get('crx_download'),
                      unresolved=report['unresolved'], error=report['error'], passed=ok)
        results.append(result)
        (args.output / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
        print(json.dumps(result), flush=True)
    return 0 if all(result['passed'] for result in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())

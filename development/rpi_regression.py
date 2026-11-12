"""Run the bundled RPi plugins against an existing eight-dump research workspace.

The research workspace supplies rpi-runs.json, matching symbols, dump files and
previously validated JSON outputs. No external plugin directory is loaded.
Raw output stays in --output; the portable summary can be published separately.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

PLUGINS = ('Rpi', 'Model', 'Boot', 'Interfaces', 'Console', 'Firmware', 'DtChanges')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--research', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--workers', type=int, default=2)
    args = parser.parse_args()
    if args.workers < 1:
        parser.error('--workers must be positive')
    repo = Path(__file__).resolve().parents[1]
    research, output = args.research.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    cases = json.loads((research / 'rpi-runs.json').read_text())
    if len(cases) != 8 or len({c['dataset'] for c in cases}) != 8:
        raise ValueError('Expected eight distinct dump cases')
    env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}
    # Ensure tests exercise this checkout, not a caller-supplied plugin override.
    env.pop('PYTHONPATH', None)

    def run(task):
        case, plugin = task
        name = case['dataset']
        target = output / plugin / name
        target.mkdir(parents=True, exist_ok=True)
        previous = case['command']
        cmd = [sys.executable, str(repo / 'vol.py'), '--offline', '-q', '-r', 'json']
        for option in ('--cache-path', '-s', '-f'):
            cmd += [option, previous[previous.index(option) + 1]]
        cmd += ['-o', str(target), 'linux.rpi.' + plugin.lower() + '.' + plugin]
        if plugin in ('Interfaces', 'Console', 'Firmware', 'DtChanges'):
            cmd += ['--details']
        baseline = research / (plugin.lower() + '-validation') / 'results' / name / 'output.json'
        if plugin == 'Rpi':
            baseline = research / 'eeprom-validation/results' / name / 'output.json'
        elif plugin in ('Model', 'Boot'):
            baseline = research / (plugin.lower() + '-validation') / 'results' / plugin / name / 'output.json'
        expected = json.loads(baseline.read_text())
        if plugin == 'Model':
            for row in expected:
                if 'Manufacturer' in row:
                    row['BoardManufacturer'] = row.pop('Manufacturer')
        start = time.monotonic()
        error, code, rows = '', None, []
        with (target / 'output.json').open('w') as stdout, (target / 'stderr.log').open('w') as stderr:
            try:
                code = subprocess.run(cmd, cwd=repo, env=env, stdout=stdout, stderr=stderr, timeout=300).returncode
                if code == 0:
                    rows = json.loads((target / 'output.json').read_text())
            except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
                error = str(exc)
        equal = code == 0 and bool(rows) and rows == expected
        result = {'dataset': name, 'plugin': 'linux.rpi.' + plugin.lower() + '.' + plugin, 'exit_code': code,
                  'rows': len(rows), 'baseline_rows': len(expected), 'matches_baseline': equal,
                  'seconds': round(time.monotonic() - start, 2), 'error': error,
                  'output_sha256': hashlib.sha256((target / 'output.json').read_bytes()).hexdigest()}
        (target / 'run.json').write_text(json.dumps({**result, 'command': cmd}, indent=2) + '\n')
        print(name, plugin, 'PASS' if equal else 'FAIL', flush=True)
        return result

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(run, [(case, plugin) for plugin in PLUGINS for case in cases]))
    summary = {'plugin_sha256': {str(p.relative_to(repo)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((repo / 'volatility3/framework/plugins/linux/rpi').glob('*.py'))},
               'comparison': 'Exact JSON row equality with previously validated research outputs; Model column renamed to BoardManufacturer.',
               'external_plugin_path': False, 'runs': results,
               'passed': sum(result['matches_baseline'] for result in results), 'total': len(results)}
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    if summary['passed'] != summary['total']:
        raise SystemExit('Regression failed; inspect output directories')


if __name__ == '__main__':
    main()

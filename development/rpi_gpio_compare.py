"""Compare Gpio JSON with gpio-sim capture-time line-info snapshots."""
import argparse
import json
from pathlib import Path


def compare(reference, rows):
    if any(str(r.get('Status', '')).startswith('Incomplete:') for r in rows):
        raise ValueError('Incomplete GPIO scan cannot pass capture validation')
    selected = [r for r in rows if r.get('Controller') == reference['controller'] and r.get('Chip') == reference['chip']]
    indexed = {}
    for row in selected:
        offset = row['Offset']
        if offset in indexed:
            raise ValueError('Duplicate GPIO line in plugin output')
        indexed[offset] = row
    if set(indexed) != {r['offset'] for r in reference['lines']} or len(indexed) != 4:
        raise ValueError('Expected exactly four matching simulator lines; run Gpio with --all')
    checked = 0
    for expected in reference['lines']:
        row = indexed[expected['offset']]
        if row.get('Status') not in ('ok', 'generic Linux; Pi identity not established'):
            raise ValueError('Diagnostic on simulator line: ' + str(row.get('Status')))
        fields = {'LineName': expected['name'], 'Consumer': expected['consumer'] or '(none)',
                  'Requested': 'Yes' if expected['used'] else 'No', 'HeaderPin': '-'}
        if expected['used']:
            fields.update(KernelDirection=expected['direction'].title(), ActiveLow='Yes' if expected['active_low'] else 'No')
        else:
            fields.update(KernelDirection='Not requested', ActiveLow='Not requested')
        for key, value in fields.items():
            if row.get(key) != value:
                raise ValueError(f"Offset {expected['offset']} {key}: {row.get(key)!r} != {value!r}")
            checked += 1
    return {'phase': reference['phase'], 'lines': len(indexed), 'fields_matched': checked, 'passed': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', type=Path, required=True)
    parser.add_argument('--after', type=Path, required=True)
    parser.add_argument('--volatility', type=Path, required=True)
    args = parser.parse_args()
    before, after = json.loads(args.before.read_text()), json.loads(args.after.read_text())
    for key in ('phase', 'chip', 'controller', 'lines'):
        if before[key] != after[key]:
            parser.error('Reference changed across capture: ' + key)
    try:
        result = compare(before, json.loads(args.volatility.read_text()))
    except (ValueError, KeyError) as error:
        parser.exit(1, str(error) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

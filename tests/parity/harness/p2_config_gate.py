# SPDX-License-Identifier: AGPL-3.0-or-later
"""Reviewed CFG-01 regression gate over unchanged P1 receipts; never G2."""
import argparse
import hashlib
import json
from pathlib import Path
from gate import evaluate_gate

HERE = Path(__file__).resolve().parent


def evaluate(report, specification, baseline, original_gate):
    checks = evaluate_gate(report, original_gate)['checks']
    closures = {case['id']: case for case in specification['reviewed_closures']}
    # Retain every original isolation/control/ticket check. Replace only the four
    # explicitly reviewed config outcome checks with stronger observed-value checks.
    replaced = {f'{i}:{case}:exact-reviewed-outcome' for i in range(2) for case in closures}
    checks = [check for check in checks if check['id'] not in replaced]
    def check(name, passed):
        checks.append({'id': name, 'passed': bool(passed)})
    check('unchanged-reference-bundle', report.get('bundle') == baseline)
    for index, repetition in enumerate(report['repetitions']):
        observed = {case['id']: case for case in repetition['cases']}
        for case_id, expected in closures.items():
            case = observed.get(case_id, {})
            comparison = case.get('comparison', {})
            check(f'{index}:{case_id}:reviewed-config-agreement',
                  case.get('reference', {}).get('status') == 'ok'
                  and case.get('candidate', {}).get('status') == 'ok'
                  and case.get('reference', {}).get('observations') == expected['observations']
                  and case.get('candidate', {}).get('observations') == expected['observations']
                  and case.get('issues') == expected['original_issues']
                  and case.get('split') == 'development'
                  and comparison.get('decision') == 'unexpected-pass'
                  and comparison.get('reference_mismatches') == []
                  and comparison.get('candidate_mismatches') == [])
    return {'schema_version': 1, 'scope': specification['scope'],
            'passed': all(item['passed'] for item in checks), 'checks': checks,
            'G2_complete': False, 'functional_parity_certified': False,
            'remaining_known_issue': 'SYS-029'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('receipt', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    specification = json.loads((HERE / 'fixtures/p2-config-gate-v1.json').read_text())
    baseline_bytes = (HERE / 'fixtures/baseline-v1.json').read_bytes()
    gate_bytes = (HERE / 'fixtures/gate-v1.json').read_bytes()
    if hashlib.sha256(baseline_bytes).hexdigest() != specification['original_baseline_sha256'] or hashlib.sha256(gate_bytes).hexdigest() != specification['original_gate_sha256']:
        raise SystemExit('Original baseline/gate bytes changed; explicit review required')
    receipt_bytes = args.receipt.read_bytes()
    result = evaluate(json.loads(receipt_bytes), specification, json.loads(baseline_bytes), json.loads(gate_bytes))
    result['receipt_sha256'] = hashlib.sha256(receipt_bytes).hexdigest()
    result['specification_sha256'] = hashlib.sha256((HERE / 'fixtures/p2-config-gate-v1.json').read_bytes()).hexdigest()
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()

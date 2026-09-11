# SPDX-License-Identifier: AGPL-3.0-or-later
"""G1 infrastructure gate; never a functional parity pass."""

def evaluate_gate(report, expected):
    checks = []
    def check(name, passed):
        checks.append({'id': name, 'passed': bool(passed)})
    check('reviewed-bundle-bytes', report['bundle_sha256'] == expected['baseline_bundle_sha256'])
    inventory = report.get('specification_inventory', {})
    check('validated-unexecuted-specification-inventory', inventory.get('status') == 'validated'
          and inventory.get('execution') == 'not-run' and inventory.get('certified') is False)
    required = [x['id'] for x in expected['cases']]
    check('two-independent-repetitions', len(report['repetitions']) == 2)
    check('repeatable-canonical-results', report['reproducible'])
    for repetition, result in enumerate(report['repetitions']):
        check(f'{repetition}:complete-ordered-case-set', [x['id'] for x in result['cases']] == required)
        check(f'{repetition}:comparator-controls', result['self_tests']['passed'])
        check(f'{repetition}:driver-controls', result['driver_controls']['passed'])
        check(f'{repetition}:supplementary-no-hidden-errors', all(
            case['comparison']['decision'] == 'unsupported'
            and case['reference']['status'] in ('ok', 'unsupported')
            and case['candidate']['status'] in ('ok', 'unsupported')
            for case in result.get('supplementary_cases', [])))
        check(f'{repetition}:measured-isolation', result['isolation']['verified'])
        check(f'{repetition}:real-log-fixture-bytes', result.get('real_logs_bundle_sha256') == expected.get('real_logs_bundle_sha256'))
        check(f'{repetition}:real-log-provenance-bytes', result.get('real_logs_provenance_sha256') == expected.get('real_logs_provenance_sha256'))
        check(f'{repetition}:real-log-case-set', [x['id'] for x in result.get('real_log_cases', [])] == expected.get('real_log_case_ids'))
        check(f'{repetition}:real-log-decisions', all(x['comparison']['decision'] == 'pass' for x in result.get('real_log_cases', [])))
        observed = {x['id']: x for x in result['cases']}
        for wanted in expected['cases']:
            case = observed.get(wanted['id'])
            if case is None:
                continue
            comparison = case['comparison']
            desired_decision = 'known-gap' if wanted['candidate_mismatches'] else 'pass'
            check(f'{repetition}:{wanted["id"]}:exact-reviewed-outcome',
                  case['reference']['status'] == case['candidate']['status'] == 'ok'
                  and case['split'] == wanted['split'] and case['issues'] == wanted['issues']
                  and comparison['decision'] == desired_decision
                  and comparison['reference_mismatches'] == []
                  and comparison['candidate_mismatches'] == wanted['candidate_mismatches'])
    return {'passed': all(x['passed'] for x in checks), 'checks': checks,
            'scope': 'G1 infrastructure acceptance; known gaps remain functional failures'}

#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Produce source-only parity case contracts; never execute upstream test bodies."""
import argparse
import ast
from collections import Counter
import csv
import hashlib
import itertools
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import logging

PIN = 'f60978618a101427b06924fc932b44350fec2b63'
BASE = {
 'actionstestcase.py': ['ACT-04', 'ACT-08'],
 'actiontestcase.py': ['ACT-03', 'ACT-05'],
 'banmanagertestcase.py': ['POL-02'],
 'clientbeautifiertestcase.py': ['ADM-03'],
 'clientreadertestcase.py': ['CFG-01', 'CFG-02', 'CFG-04'],
 'databasetestcase.py': ['MIG-03', 'POL-04'],
 'datedetectortestcase.py': ['TIME-01', 'TIME-02'],
 'fail2banclienttestcase.py': ['ADM-03', 'ADM-04'],
 'fail2banregextestcase.py': ['FLT-06'],
 'failmanagertestcase.py': ['POL-01', 'POL-06'],
 'filtertestcase.py': ['FLT-03'],
 'misctestcase.py': ['ADM-04'],
 'observertestcase.py': ['POL-03', 'POL-04'],
 'samplestestcase.py': ['FLT-01', 'FLT-03'],
 'servertestcase.py': ['ADM-01', 'ADM-02'],
 'sockettestcase.py': ['ADM-03', 'ADM-04'],
 'tickettestcase.py': ['POL-01', 'POL-06'],
 'test_smtp.py': ['ACT-06', 'ACT-07'],
 'action.py': ['ACT-06'],
}
CLASS = {
 'IgnoreIP': ['IGN-01', 'IGN-03'], 'IgnoreIPDNS': ['IGN-02', 'IGN-03'],
 'DNSUtilsTests': ['IGN-02', 'POL-06'], 'DNSUtilsNetworkTests': ['IGN-01', 'IGN-02'],
 'StatusExtendedCymruInfo': ['ADM-03', 'IGN-02'],
 'LogFile': ['SRC-01', 'SRC-04'], 'LogFileFilterPoll': ['SRC-02'],
 'LogFileMonitor': ['SRC-01', 'SRC-02'], 'MonitorFailures': ['SRC-01', 'SRC-02', 'SRC-04'],
 'MonitorJournalFailures': ['SRC-03', 'SRC-04'], 'GetFailures': ['SRC-01', 'FLT-03', 'TIME-01'],
 'BasicFilter': ['TIME-01', 'TIME-02', 'IGN-02'],
 'SetupTest': ['QUAL-03'], 'TestsUtilsTest': ['QUAL-02'],
 'MyTimeTest': ['CFG-05'], 'HelpersTest': ['CFG-01', 'ADM-04'],
 'RegexTests': ['FLT-03'], 'LoggingTests': ['ADM-04'], 'TransmitterLogging': ['ADM-04'],
 'ServerConfigReaderTests': ['ACT-01', 'ACT-02', 'ACT-03', 'ACT-07'],
 'FilterReaderTest': ['CFG-02', 'FLT-02'], 'ConfigReaderTest': ['CFG-01', 'CFG-03'],
}
# These refinements associate an individually inspected API/name family with a
# behavior contract. Exact assertion calls/hashes stay beside the association.
REFINE = {
 'multiline': ['FLT-05'], 'maxlines': ['FLT-05'], 'ignore': ['IGN-01'],
 'ignoreregex': ['FLT-04'], 'ignorecommand': ['IGN-03'], 'ignorecache': ['IGN-03'],
 'dns': ['IGN-02'], 'date': ['TIME-02'], 'timezone': ['TIME-02'],
 'timejump': ['TIME-01'], 'wrongtime': ['TIME-01'], 'journal': ['SRC-03'],
 'encoding': ['SRC-04'], 'wrongchar': ['SRC-04'], 'rotation': ['SRC-02'],
 'rewrite': ['SRC-02'], 'move': ['SRC-02'], 'seek': ['SRC-02'],
 'bantimeincr': ['POL-03'], 'multipliers': ['POL-03'], 'formula': ['POL-03'],
 'permanent': ['POL-02'], 'maxretry': ['POL-01'], 'findtime': ['POL-01'],
 'maxmatches': ['POL-06'], 'repair': ['ACT-08'], 'consistency': ['ACT-08'],
 'reban': ['ACT-08'], 'timeout': ['ACT-05'], 'python': ['ACT-06'],
 'reload': ['ADM-01'], 'socketactivation': ['ADM-04-SOCKET-ACTIVATION'],
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(path.read_text())


def name_of(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return name_of(node.value) + '.' + node.attr
    return type(node).__name__


def safe_condition(text, scope):
    """Interpret only the four exact metadata comparisons at the pinned commit."""
    node = ast.parse(text, mode='eval').body
    if not isinstance(node, ast.Compare) or len(node.ops) != 1 or len(node.comparators) != 1:
        raise ValueError('condition outside audited comparison grammar')
    right = node.comparators[0]
    if not isinstance(right, ast.Constant) or not isinstance(right.value, str):
        raise ValueError('condition requires a string literal')
    left = node.left
    if isinstance(left, ast.Name) and left.id == 'name':
        value = scope['name']
    elif (isinstance(left, ast.Call) and name_of(left.func) == 'opts.get'
          and len(left.args) == 1 and not left.keywords
          and isinstance(left.args[0], ast.Constant) and left.args[0].value == 'mode'):
        value = scope['opts'].get('mode')
    else:
        raise ValueError('condition outside audited variable grammar')
    if isinstance(node.ops[0], ast.Eq):
        return value == right.value
    if isinstance(node.ops[0], ast.NotEq):
        return value != right.value
    raise ValueError('condition outside audited operator grammar')


def guard(value, record_constraint=None):
    if isinstance(value, bool):
        return value
    if 'expression' in value:
        if record_constraint == (value.get('anchor'), value['expression']):
            return True  # Construction precedes per-record constraint filtering.
        return safe_condition(value['expression'], value['scope'])
    if 'all' in value:
        return all(guard(item, record_constraint) for item in value['all'])
    if 'not_any' in value:
        return not any(guard(item, record_constraint) for item in value['not_any'])
    raise ValueError('unknown guard')


def self_checks():
    checks = []
    for text, scope, expected in [
        ("name == 'sshd'", {'name': 'sshd', 'opts': {}}, True),
        ("name=='sshd'", {'name': 'postfix', 'opts': {}}, False),
        ("opts.get('mode') != 'aggressive'", {'name': 'sshd', 'opts': {}}, True),
        ("opts.get('mode') == 'aggressive'", {'name': 'sshd', 'opts': {'mode': 'aggressive'}}, True),
    ]:
        assert safe_condition(text, scope) == expected
        checks.append({'case': text, 'expected': expected, 'passed': True})
    # Benign syntax outside the supported language must fail closed.
    for text in ['1 + 2', "name.startswith('s')", "opts.get('other') == 'x'", "name < 'z'"]:
        try:
            safe_condition(text, {'name': 'sshd', 'opts': {}})
        except ValueError:
            checks.append({'case': text, 'expected': 'reject grammar', 'passed': True})
        else:
            raise AssertionError('unsupported grammar accepted')
    assert guard({'all': [True, {'not_any': [False]}]}) is True
    checks.append({'case': 'compound guard', 'expected': True, 'passed': True})
    synthetic = {'all': [True, {'expression': "opts.get('mode') == 'aggressive'", 'anchor': 'original:1', 'scope': {'name': 'original', 'opts': {'mode': 'normal'}}}]}
    assert guard(synthetic) is False
    assert guard(synthetic, ('original:1', "opts.get('mode') == 'aggressive'")) is True
    assert guard({'all': [False, synthetic]}, ('original:1', "opts.get('mode') == 'aggressive'")) is False
    checks.append({'case': 'lazy construction precedes record constraint but follows block gate', 'expected': 'construct without execution when constraint alone excludes record; never construct in ignored block', 'passed': True})
    return checks


def map_tests(reference, audit):
    result = []
    source_hashes = {}
    trees = {}
    for item in audit['syntactic_test_definition_inventory']:
        path, line = item['anchor'].rsplit(':', 1)
        if path not in trees:
            data = (reference / path).read_bytes()
            source_hashes[path] = sha(data)
            trees[path] = ast.parse(data)
        ancestors = {}
        for parent in ast.walk(trees[path]):
            for child in ast.iter_child_nodes(parent):
                ancestors[child] = parent
        nodes = [node for node in ast.walk(trees[path]) if isinstance(node, ast.FunctionDef)
                 and node.lineno == int(line) and node.name == item['test_name']]
        if len(nodes) != 1:
            raise ValueError('syntactic inventory does not match AST: ' + item['anchor'])
        node = nodes[0]
        owners = []
        parent = ancestors.get(node)
        while parent:
            if isinstance(parent, (ast.FunctionDef, ast.ClassDef)):
                owners.insert(0, parent.name)
            parent = ancestors.get(parent)
        classes = [o for o in owners if o in CLASS]
        reqs = list(CLASS[classes[-1]] if classes else BASE[Path(path).name])
        calls = sorted(set(name_of(n.func) for n in ast.walk(node) if isinstance(n, ast.Call)))
        for key, additional in REFINE.items():
            if key in node.name.lower():
                reqs.extend(additional)
        kind = 'test definition'
        if node.name == 'testSampleRegexsFactory':
            kind = 'generated test factory, not a directly runnable test'
        elif node.name == 'testFilter' and 'testSampleRegexsFactory' in owners:
            kind = 'generated test body'
        elif path.endswith('files/action.d/action.py'):
            kind = 'fixture action method, not a unittest test'
        elif 'TestsUtilsTest' in owners:
            kind = 'reference harness self-test; requires analogous harness checks, not production API'
        start = min([node.lineno] + [d.lineno for d in node.decorator_list])
        lines = (reference / path).read_bytes().split(b'\n')
        result.append({
            'id': 'upstream-definition:' + item['anchor'], 'anchor': item['anchor'],
            'qualified_name': '.'.join(owners + [node.name]), 'kind': kind,
            'end_line': node.end_lineno,
            'body_sha256': sha(b'\n'.join(lines[start - 1:node.end_lineno])),
            'requirement_ids': sorted(set(reqs)),
            'mapping_basis': 'source class responsibility plus named behavior refinements; assertion and call inventory below',
            'assertion_calls': [x for x in calls if 'assert' in x.lower()],
            'exercised_call_names': calls,
            'decorator_syntax': [ast.dump(d, include_attributes=False) for d in node.decorator_list],
            'acceptance': 'Port the observable assertions to original benign fixtures under the mapped contracts; record all assertion outcomes and profile skips. Do not import or replay this upstream body automatically.',
            'loop_families': [{'anchor': path + ':' + str(n.lineno), 'iterator_ast_sha256': sha(ast.dump(n.iter, include_attributes=False).encode()), 'literal_arity': len(n.iter.elts) if isinstance(n.iter, (ast.List, ast.Tuple, ast.Set)) else None, 'contract': 'retain every iterator member/profile when porting this definition; unknown iteration domains need explicit case generators'} for n in ast.walk(node) if isinstance(n, (ast.For, ast.AsyncFor))],
            'execution': 'not executed',
        })
    generated = []
    by_owner = {}
    for row in result:
        by_owner.setdefault(row['qualified_name'].rsplit('.', 1)[0], []).append(row['id'])
    for owner, profiles, anchor in [
        ('get_monitor_failures_testcase.MonitorFailures', ['polling', 'pyinotify'], 'fail2ban/tests/utils.py:494'),
        ('get_monitor_failures_journal_testcase.MonitorJournalFailures', ['systemd'], 'fail2ban/tests/utils.py:515'),
        ('_SMTPActionTestCase', ['smtp legacy asyncore/smtpd available', 'smtp aiosmtpd available'], 'fail2ban/tests/action_d/test_smtp.py:136'),
        ('Fail2banClientServerBase', ['Fail2banClientTest', 'Fail2banServerTest'], 'fail2ban/tests/fail2banclienttestcase.py:528'),
    ]:
        ids = by_owner.get(owner, [])
        if not ids:
            raise ValueError('unmapped generated family ' + owner)
        generated.append({'family': owner, 'anchor': anchor, 'definition_ids': ids,
                          'profiles': profiles, 'instances': [
                              {'profile': p, 'definition_id': ident, 'execution': 'pending P1/P7 profile availability'}
                              for p in profiles for ident in ids]})
    source_hashes['fail2ban/tests/utils.py'] = sha((reference / 'fail2ban/tests/utils.py').read_bytes())
    return result, generated, source_hashes


def resolve_fixtures(fixture):
    roots = []
    for root in fixture['roots']:
        cache = {}
        variants = {}
        for v in root['variants']:
            active = guard(v['guard'])
            # A lazy fallback is constructed only after an unignored record
            # reaches the loader. Its symbolic absent-instance guard alone
            # does not imply construction while ignoreBlock still suppresses input.
            if v.get('conditional_default'):
                active = active and any(guard(e['guard'], (case['source'], case['expected_metadata'].get('constraint')))
                                        for case in root['cases'] for e in case['executions']
                                        if e['variant_id'] == v['id'])
            if active:
                cache.setdefault(v['instance_key'], v)
            actual = cache.get(v['instance_key']) if active else None
            variants[v['id']] = {
                'id': v['id'], 'eligible': active, 'anchor': v['anchor'],
                'requested_options': v['requested_filter_options'],
                'effective_cached_options': actual['requested_filter_options'] if actual else None,
                'constructed_from_variant': actual['id'] if actual else None,
            }
        cases = []
        for case in root['cases']:
            executions = []
            for e in case['executions']:
                v = variants[e['variant_id']]
                executions.append({'variant_id': e['variant_id'], 'eligible': guard(e['guard']),
                                   'effective_cached_options': v['effective_cached_options'],
                                   'constructed_from_variant': v['constructed_from_variant']})
            cases.append({'id': case['id'], 'record_anchor': case['record_anchor'],
                          'record_sha256': case['record_sha256'], 'requirement_ids': case['requirement_ids'],
                          'executions': executions})
        roots.append({'name': root['name'], 'test_only': root['test_only'], 'filter_path': root['filter_path'],
                      'variants': list(variants.values()), 'cases': cases,
                      'negative_acceptance': {'id': 'benign-negative:' + root['name'],
                          'requirement_ids': root['cases'][0]['requirement_ids'],
                          'input': '2030-01-02T03:04:05Z parity-fixture status=healthy peer=192.0.2.10',
                          'expected': 'No failure ticket and no action dispatch in a fresh filter instance.',
                          'execution': 'not executed; validate the original neutral record against each effective mode in P1/P3'}})
    return roots


def declaration_contracts(reference, audit):
    outputs = []
    selectors = []
    for catalog in audit['catalog']:
        path = catalog['path']
        lines = (reference / path).read_text().split('\n')
        options = catalog['active_option_anchors']
        targets = set(o['name'] for o in options)
        targets.update(o['section'] + '/' + o['name'] for o in options)
        active_text = '\n'.join(line for line in lines if line.strip() and not line.lstrip().startswith(('#', ';')))
        for opt in options:
            line = lines[int(opt['anchor'].rsplit(':', 1)[1]) - 1]
            literal = line.split('=', 1)[1].strip() if '=' in line else ''
            # A declaration is a configuration surface even when it is an
            # internal interpolated fragment; it is not automatically a public parameter.
            outputs.append({'id': 'declaration:' + opt['anchor'], 'source': path,
                'anchor': opt['anchor'], 'section': opt['section'], 'name': opt['name'],
                'declaration_line_sha256': sha(line.encode()),
                'requirement_ids': catalog['requirement_ids'],
                'classification': 'initialization parameter' if opt['section'].startswith('Init') else 'configuration declaration or interpolation fragment',
                'acceptance_cases': [
                    {'kind': 'stock', 'input': 'load pinned declaration with its include closure',
                     'expected': 'same effective value/type or same diagnosed error as pinned reader'},
                    {'kind': 'override', 'input': {opt['name']: 'parity-benign-value'},
                     'expected': 'reference-equivalent override precedence, conversion or diagnosed rejection'},
                    {'kind': 'empty', 'input': {opt['name']: ''},
                     'expected': 'reference-equivalent empty/unset distinction'},
                ], 'execution': 'specified, not executed'})
        for match in re.finditer(r'<([A-Za-z0-9_./-]*<([a-z][\w.-]+)>[A-Za-z0-9_./-]*)>', active_text):
            template, parameter = match.group(1, 2)
            prefix, suffix = template.split('<' + parameter + '>')
            if not prefix and not suffix:
                continue
            values = sorted(set(t[len(prefix):len(t) - len(suffix) if suffix else None]
                                for t in targets if t.startswith(prefix) and t.endswith(suffix)
                                and len(t) > len(prefix) + len(suffix)))
            if not values:
                raise ValueError('unresolved source selector ' + path + ': ' + template)
            ident = path + ':' + template
            if any(s['id'] == ident for s in selectors):
                continue
            selectors.append({'id': ident, 'source': path, 'parameter': parameter,
                'template': template, 'declared_values': values,
                'requirement_ids': catalog['requirement_ids'],
                'cases': [{'input': {parameter: v}, 'expected_selected_key': prefix + v + suffix,
                           'execution': 'source-derived target selection; reader oracle pending P1'} for v in values],
                'boundaries': [{'input': {parameter: v}, 'expected': 'compare pinned reader error or unresolved-tag behavior; never silently claim support'}
                               for v in ['', 'parity_unknown', 'NORMAL']],
                'domain': 'finite declared branches; custom local additions remain an open string domain'})
    # Enumerate source-declared selector intersections across include closures.
    catalog_by_path = {c['path']: c for c in audit['catalog']}
    def closure(path, chain=()):
        if path in chain:
            raise ValueError('catalog include cycle: ' + path)
        result = [path]
        for inc in catalog_by_path[path]['includes']:
            for filename in inc['files']:
                included = (Path(path).parent / filename).as_posix()
                if included in catalog_by_path:
                    result.extend(closure(included, chain + (path,)))
                elif (reference / included).exists():
                    raise ValueError('included source missing catalog entry: ' + included)
        return sorted(set(result))
    combinations = []
    for path in sorted(catalog_by_path):
        includes = closure(path)
        domains = {}
        for sel in [s for s in selectors if s['source'] in includes]:
            values = set(sel['declared_values'])
            domains[sel['parameter']] = values if sel['parameter'] not in domains else domains[sel['parameter']] & values
        if not domains:
            continue
        keys = sorted(domains)
        for values in itertools.product(*(sorted(domains[k]) for k in keys)):
            combinations.append({'source': path, 'include_closure': includes, 'options': dict(zip(keys, values)),
                                 'expected': 'all corresponding selected source keys exist; compare effective reader output and original benign fixtures in P1/P3/P4',
                                 'execution': 'configuration-only oracle below; matcher/action execution pending'})
    return outputs, selectors, combinations



def reader_oracles(reference, audit, roots, combinations, selectors):
    """Read configuration with the pinned parser; do not compile patterns or run actions."""
    sys.path.insert(0, str(reference))
    sys.dont_write_bytecode = True
    # Existing source-adjacent bytecode cannot become the oracle.
    sys.pycache_prefix = tempfile.mkdtemp(prefix='p0-mode-reader-cache-')
    attempts = []
    def block_external(event, args):
        if event.startswith(('subprocess.', 'socket.')) or event in ('os.system', 'os.exec', 'os.posix_spawn'):
            attempts.append(event)
            raise RuntimeError('external execution prohibited by configuration-only oracle')
    sys.addaudithook(block_external)
    from fail2ban.client.filterreader import FilterReader
    from fail2ban.client.actionreader import ActionReader
    logging.getLogger('fail2ban').setLevel(logging.CRITICAL)
    jobs = {}
    def add(path, options, kind):
        key = (path, json.dumps(options, sort_keys=True))
        jobs.setdefault(key, {'source': path, 'options': options, 'reasons': []})['reasons'].append(kind)
    for c in audit['catalog']:
        if c['path'].endswith('.conf'):
            add(c['path'], {}, 'stock default')
    for root in roots:
        path = root['filter_path']
        for v in root['variants']:
            if v['eligible']:
                add(path, v['effective_cached_options'], 'effective sample option set')
    for c in combinations:
        add(c['source'], c['options'], 'source selector combination')
    for sel in selectors:
        for c in sel['boundaries']:
            add(sel['source'], c['input'], 'selector boundary')
    result = []
    for key, job in sorted(jobs.items()):
        path = Path(job['source'])
        basedir = reference / path.parent.parent
        klass = FilterReader if path.parent.name == 'filter.d' else ActionReader
        outcomes = []
        for repeat in range(2):
            try:
                reader = klass(path.stem, 'parity-fixture', dict(job['options']), basedir=str(basedir))
                read_ok = reader.read()
                reader.getOptions({})
                stream = reader.convert()
                serial = json.dumps(stream, sort_keys=True, ensure_ascii=True).encode()
                outcomes.append({'read': bool(read_ok), 'stream_sha256': sha(serial),
                    'command_count': len(stream), 'result': 'configuration stream produced',
                    'unresolved_lowercase_tags': sorted(set(re.findall(r'<([a-z][a-z0-9_.-]*)>', serial.decode())))})
            except Exception as exc:
                outcomes.append({'result': 'diagnosed configuration error', 'exception_class': type(exc).__name__,
                                 'message_sha256': sha(str(exc).encode())})
        if outcomes[0] != outcomes[1]:
            raise ValueError('non-deterministic configuration oracle ' + job['source'])
        result.append({**job, 'oracle': outcomes[0], 'repeat_equal': True,
                       'candidate_result': 'pending P1 harness/P2-P4 implementation'})
    imported = {}
    for module in list(sys.modules.values()):
        filename = getattr(module, '__file__', None)
        if filename:
            path = Path(filename).resolve()
            if path.is_relative_to(reference) and path.suffix == '.py':
                imported[path.relative_to(reference).as_posix()] = sha(path.read_bytes())
    return result, imported, attempts

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--audit', type=Path, default=Path('.project/parity/source-audit.json'))
    parser.add_argument('--fixtures', type=Path, default=Path('.project/parity/evidence/p0-fixture-inventory.json'))
    parser.add_argument('--requirements', type=Path, default=Path('.project/parity/requirements.csv'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    reference = args.reference.resolve()
    output = args.output.resolve()
    if output.is_relative_to(reference) or output in {args.audit.resolve(), args.fixtures.resolve(), args.requirements.resolve(), Path(__file__).resolve()}:
        raise ValueError('output must not overwrite reference or inputs')
    def git(*argv):
        return subprocess.run(['git', *argv], cwd=reference, check=True, capture_output=True,
                              text=True, timeout=15).stdout.strip()
    if git('rev-parse', 'HEAD') != PIN or git('status', '--porcelain'):
        raise ValueError('reference must be clean and pinned')
    audit, fixture = read_json(args.audit), read_json(args.fixtures)
    if audit['reference_commit'] != PIN or fixture['reference_commit'] != PIN:
        raise ValueError('input reference pins differ')
    tests, generated, source_hashes = map_tests(reference, audit)
    roots = resolve_fixtures(fixture)
    declarations, selectors, combinations = declaration_contracts(reference, audit)
    reqids = {r['id'] for r in csv.DictReader(args.requirements.open())}
    def validate(value):
        if isinstance(value, dict):
            if 'requirement_ids' in value and not set(value['requirement_ids']) <= reqids:
                raise ValueError('invalid requirement mapping')
            for v in value.values(): validate(v)
        elif isinstance(value, list):
            for v in value: validate(v)
    for item in [tests, roots, declarations, selectors]: validate(item)
    for path, expected in fixture['source_hashes'].items():
        if sha((reference / path).read_bytes()) != expected:
            raise ValueError('fixture provenance changed: ' + path)
        source_hashes[path] = expected
    for c in audit['catalog']:
        if sha((reference / c['path']).read_bytes()) != c['sha256']:
            raise ValueError('catalog provenance changed')
        source_hashes[c['path']] = c['sha256']
    checks = self_checks()
    oracle, imported, attempts = reader_oracles(reference, audit, roots, combinations, selectors)
    source_hashes.update(imported)
    executions = [e for r in roots for c in r['cases'] for e in c['executions']]
    report = {
        'schema_version': 1, 'reference_commit': PIN, 'tool_sha256': sha(Path(__file__).read_bytes()),
        'input_sha256': {str(p): sha(p.read_bytes()) for p in [args.audit, args.fixtures, args.requirements]},
        'source_hashes': source_hashes,
        'controls': {'upstream_test_bodies_executed': 0, 'sample_records_executed': 0,
                     'shell_actions_executed': 0, 'arbitrary_expression_evaluation': False},
        'counts': {'syntactic_definitions_mapped': len(tests), 'generated_non_sample_families': len(generated),
                   'generated_non_sample_instances': sum(len(g['instances']) for g in generated), 'loop_family_definitions': sum(len(t['loop_families']) for t in tests),
                   'sample_generated_roots': len(roots), 'fixture_execution_choices': len(executions),
                   'eligible_execution_choices': sum(e['eligible'] for e in executions),
                   'ineligible_execution_choices': sum(not e['eligible'] for e in executions),
                   'unresolved_metadata_conditions': 0, 'catalog_declarations': len(declarations),
                   'selector_templates': len(selectors), 'source_declared_combinations': len(combinations),
                   'original_neutral_negative_specs': len(roots), 'resolver_self_checks_passed': len(checks), 'configuration_oracle_cases': len(oracle), 'configuration_oracle_repeat_agreements': sum(o['repeat_equal'] for o in oracle), 'configuration_oracle_errors': sum(o['oracle']['result'] == 'diagnosed configuration error' for o in oracle), 'external_attempts': len(attempts)},
        'definition_kind_counts': dict(Counter(t['kind'] for t in tests)),
        'test_definitions': tests, 'generated_families': generated, 'resolved_sample_roots': roots,
        'declaration_contracts': declarations, 'selector_contracts': selectors,
        'source_declared_combinations': combinations, 'resolver_self_checks': checks, 'configuration_oracles': oracle,
        'conditional_action_contracts': [{'source': c['path'], 'anchor': sec['anchor'], 'section': sec['name'], 'requirement_ids': c['requirement_ids'], 'cases': [{'runtime_family': family, 'expected': 'compare conditional tag selection in ACT-03 runtime action expansion; configuration stream alone is not the oracle', 'execution': 'pending P1/P4 action context fixture'} for family in ['inet4', 'inet6', 'parity_unknown']]} for c in audit['catalog'] for sec in c['sections'] if '?' in sec['name']],
        'limits': [
            'Requirement associations are source-derived acceptance ownership, not a claim that candidate behavior passes.',
            'Declared selector branches and current metadata choices are resolved; pinned configuration-reader streams are hashed twice. Candidate equivalence and behavior of the resulting matcher/action remain P1-P4 work.',
            'Arbitrary local definitions, strings, regular expressions and shell commands have open value domains; contract boundary/property tests replace impossible exhaustive enumeration.',
            'Original neutral negative specs must be checked against effective filter modes before use as accepted oracle outcomes.',
            'Generated family profiles describe optional dependency applicability; no profile or fixture is certified by this inventory.',
            'Definition call inventories retain only names/hashes and never publish or execute upstream payloads.',
        ],
        'G0_assessment': 'source inventories, concrete mode contracts and configuration-only reference oracles are available; no candidate parity or matcher/action execution certification',
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(report['counts'], sort_keys=True))


if __name__ == '__main__':
    main()

# SPDX-License-Identifier: AGPL-3.0-or-later
"""Validate the packaged assessed specification inventory without executing it."""
import hashlib
import json
from pathlib import Path
import re
try:
    from .contract import load_json, REFERENCE_COMMIT, REFERENCE_PROFILE
except ImportError:
    from contract import load_json, REFERENCE_COMMIT, REFERENCE_PROFILE

EXPECTED_COUNTS = {'declarations': 1215, 'definitions': 444, 'selectors': 37,
                   'combinations': 504, 'negative': 98, 'generated': 4,
                   'commands': 112, 'typed_options': 60, 'stock_assignments': 412,
                   'client_aliases': 28, 'diagnostics': 24, 'reload_properties': 56,
                   'parameter_domains': 15, 'aggregates': 52}


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _canonical(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def _require(condition, message):
    if not condition:
        raise ValueError('specifications: ' + message)


def _hash(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def validate_specifications(directory):
    directory = Path(directory)
    manifest_bytes = (directory / 'specifications-manifest-v1.json').read_bytes()
    manifest = load_json(manifest_bytes)
    _require(manifest.get('specifications_file') == 'specifications-v1.json', 'unexpected filename')
    _require(manifest.get('requirements_file') == 'requirements-v1.json', 'unexpected requirement filename')
    raw = (directory / 'specifications-v1.json').read_bytes()
    requirements_raw = (directory / 'requirements-v1.json').read_bytes()
    _require(_sha(raw) == manifest.get('specifications_sha256'), 'bundle hash mismatch')
    _require(_sha(requirements_raw) == manifest.get('requirements_sha256'), 'requirements hash mismatch')
    bundle = load_json(raw)
    requirements = load_json(requirements_raw)
    owner_ids = {row['id'] for row in requirements['requirements']}
    _require(len(owner_ids) == 471, '471 assessed requirements required')
    for document in (manifest, bundle):
        _require(type(document.get('schema_version')) is int and document['schema_version'] == 1, 'unknown schema')
        _require(document.get('reference_commit') == REFERENCE_COMMIT, 'reference pin mismatch')
        _require(document.get('reference_profile') == REFERENCE_PROFILE, 'profile mismatch')
    _require(manifest.get('execution') == 'not-run' and manifest.get('certified') is False, 'import cannot certify execution')
    _require(manifest.get('counts') == EXPECTED_COUNTS, 'manifest category counts mismatch')
    _require(manifest.get('total_specifications') == sum(EXPECTED_COUNTS.values()), 'manifest total mismatch')
    groups = bundle.get('groups')
    _require(type(groups) is dict and set(groups) == set(EXPECTED_COUNTS), 'unexpected categories')
    sources = bundle.get('reference_source_sha256')
    _require(type(sources) is dict and len(sources) == manifest.get('reference_source_files'), 'source inventory mismatch')
    _require(all(type(path) is str and not path.startswith('/') and '..' not in Path(path).parts and _hash(value)
                 for path, value in sources.items()), 'malformed source hash')
    source_inputs = manifest.get('source_inputs')
    _require(type(source_inputs) is dict and len(source_inputs) == 4, 'source provenance incomplete')
    _require(all(type(value) is dict and _hash(value.get('sha256')) for value in source_inputs.values()), 'source provenance hash malformed')
    seen, covered = set(), set()
    for name, count in EXPECTED_COUNTS.items():
        records = groups[name]
        _require(type(records) is list and len(records) == count, name + ' count mismatch')
        for row in records:
            _require(type(row) is dict and set(row) == {'id', 'requirement_ids', 'execution', 'certified', 'source_input',
                     'source_selector', 'source_record_sha256', 'specification'}, 'record fields malformed')
            identity = row['id']
            _require(type(identity) is str and identity.startswith(name + ':') and identity not in seen, 'unstable/duplicate id')
            seen.add(identity)
            owners = row['requirement_ids']
            _require(type(owners) is list and owners and all(type(owner) is str and owner in owner_ids for owner in owners), 'unknown owner')
            _require(len(set(owners)) == len(owners), 'duplicate owner')
            covered.update(owners)
            _require(row['execution'] == 'not-run' and row['certified'] is False, 'import cannot become a passing test')
            _require(row['source_input'] in source_inputs, 'unknown source provenance')
            selector = row['source_selector']
            _require(type(selector) is list and selector and all(type(part) in (str, int) for part in selector), 'source selector malformed')
            spec = row['specification']
            _require(type(spec) is dict, 'metadata must be object')
            _require(_sha(_canonical(spec)) == row['source_record_sha256'], 'source record hash mismatch')
            expected_id = name + ':' + (spec.get('id') or _sha(_canonical(spec))[:24])
            _require(identity == expected_id, 'stable id does not match metadata')
    return {'status': 'validated', 'execution': 'not-run', 'certified': False,
            'specifications': len(seen), 'counts': EXPECTED_COUNTS, 'requirements_referenced': len(covered),
            'reference_source_files': len(sources), 'reference_commit': REFERENCE_COMMIT,
            'specifications_sha256': _sha(raw), 'manifest_sha256': _sha(manifest_bytes),
            'scope': 'Packaged specification structure/provenance validation only; zero scenarios executed or certified.'}


if __name__ == '__main__':
    print(json.dumps(validate_specifications(Path(__file__).parent / 'fixtures'), indent=2))

# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from specs import validate_specifications


class SpecificationTests(unittest.TestCase):
    def test_fresh_directory_without_project(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            for name in ('specifications-v1.json', 'specifications-manifest-v1.json', 'requirements-v1.json'):
                shutil.copyfile(Path(__file__).parent / 'fixtures' / name, target / name)
            result = validate_specifications(target)
            self.assertEqual(result['specifications'], 3061)
            self.assertEqual(result['execution'], 'not-run')
            self.assertFalse(result['certified'])

    def test_mutation_and_forged_pass_are_rejected(self):
        mutations = [lambda x: x['groups']['declarations'][0].update(certified=True),
                     lambda x: x['groups']['declarations'][0].update(requirement_ids=['FAKE-001']),
                     lambda x: x['groups']['declarations'][0]['specification'].update(name='changed'),
                     lambda x: x.update(reference_profile='upstream-1.0.2')]
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as temporary:
                target = Path(temporary)
                for name in ('specifications-v1.json', 'specifications-manifest-v1.json', 'requirements-v1.json'):
                    shutil.copyfile(Path(__file__).parent / 'fixtures' / name, target / name)
                path = target / 'specifications-v1.json'
                data = json.loads(path.read_text())
                mutate(data)
                path.write_text(json.dumps(data))
                # Even updating the outer file hash must not bypass owner/pin/not-run/record validation.
                manifest_path = target / 'specifications-manifest-v1.json'
                manifest = json.loads(manifest_path.read_text())
                manifest['specifications_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                manifest_path.write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    validate_specifications(target)


if __name__ == '__main__':
    unittest.main()

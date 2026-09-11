#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Compare original byte records through candidate and pinned reference decoding APIs."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import codecs
from unittest.mock import patch


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--reference', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    commit = subprocess.check_output(['git', '-C', str(args.reference), 'rev-parse', 'HEAD'], text=True).strip()
    if commit != 'f60978618a101427b06924fc932b44350fec2b63':
        raise SystemExit('wrong reference commit')
    sys.path.insert(0, str(args.reference))
    from fail2ban.server.filter import FileContainer, Filter
    path = Path(__file__).resolve().parents[2] / 'engine/compat/text_codec.py'
    spec = importlib.util.spec_from_file_location('f2z_codec_compare', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    rows = []
    for encoding in ['utf8', 'ascii', 'latin1', 'cp1252', 'utf-16-le', 'utf-16-be', 'utf32', 'shift_jis']:
        for data in ['neutral 123'.encode(encoding), b'neutral\xff', b'\xff\xfe', b'\n', b'\r', b'']:
            try:
                expected, reference_error = FileContainer.decode_line('original-synthetic', encoding, data), None
            except Exception as exc:
                expected, reference_error = None, type(exc).__name__
            try:
                observed, candidate_error = module.TextDecoder(encoding).decode('original-synthetic', data, 100).text, None
            except Exception as exc:
                observed, candidate_error = None, type(exc).__name__
            rows.append(dict(codec=encoding, bytes_hex=data.hex(), expected=expected,
                             observed=observed, reference_error=reference_error,
                             candidate_error=candidate_error,
                             equal=expected == observed and reference_error == candidate_error))
    for preference in ('utf-8','latin1','ANSI_X3.4-1968'):
        for encoding in ('auto','AUTO','AuTo','utf8'):
            with patch('fail2ban.server.filter.PREFER_ENC', preference):
                reference = Filter(None)
                selected = reference.setLogEncoding(encoding)
                expected = codecs.lookup(selected).name
            observed = module.resolve_encoding(encoding,preferred_encoding=preference)
            rows.append(dict(codec=encoding,preference=preference,expected=expected,observed=observed,equal=expected==observed))
    result = dict(scope='codec and configured auto-encoding component only; worker/source framing not covered',
                  reference_commit=commit,
                  candidate_source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                  cases=rows, equal=sum(row['equal'] for row in rows),
                  mismatches=sum(not row['equal'] for row in rows))
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({key:value for key,value in result.items() if key != 'cases'}))
    return bool(result['mismatches'])


if __name__ == '__main__':
    raise SystemExit(main())

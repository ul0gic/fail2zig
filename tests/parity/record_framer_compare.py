#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Original codec-aware line/offset fixtures against the pinned FileContainer.

Reference little-endian and repeated-BOM offset/data-loss behaviors are retained as explicit
intentional differences, never relabeled exact agreements.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--reference',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    commit=subprocess.check_output(['git','-C',str(args.reference),'rev-parse','HEAD'],text=True).strip()
    if commit!='f60978618a101427b06924fc932b44350fec2b63':
        raise SystemExit('wrong reference commit')
    sys.path.insert(0,str(args.reference))
    from fail2ban.server.filter import FileContainer
    path=Path(__file__).resolve().parents[2]/'engine/compat/record_framer.py'
    spec=importlib.util.spec_from_file_location('f2z_framer_compare',path)
    module=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=module
    spec.loader.exec_module(module)
    cases=[]
    for codec in ('utf8','latin1','cp1252','utf16','utf-16-le','utf-16-be','utf32','utf-32-le','utf-32-be','shift_jis','iso2022_jp','unicode_escape','raw_unicode_escape','utf-7'):
        for text in ('first\nsecond\npartial','terminal\r'):
            cases.append((codec+':'+repr(text),codec,text.encode(codec),codec in ('utf16','utf32') and text.startswith('first')))
    cases += [
        ('escaped-nl','unicode_escape',b'neutral\\n',False),
        ('escaped-unicode-nl','raw_unicode_escape',b'neutral\\u000a',False),
        ('utf7-encoded-nl','utf-7',b'neutral+AAo-',False),
        ('escaped-middle-nl','unicode_escape',b'a\\nb\\\nc',False),
        ('le16-correct-boundary','utf-16-le','Ċ\r\nb\npartial'.encode('utf-16-le'),True),
        ('le32-correct-boundary','utf-32-le','Ċ\r\nb\npartial'.encode('utf-32-le'),True),
    ]
    rows=[]
    with tempfile.TemporaryDirectory(prefix='f2z-original-frame-') as directory:
        for index,(name,codec,data,intentional) in enumerate(cases):
            file=Path(directory)/str(index)
            file.write_bytes(data)
            container=FileContainer(str(file),codec)
            expected=[]
            if container.open():
                for _ in range(32):
                    start=container.tell()
                    line=container.readline()
                    if line is None:
                        break
                    expected.append(dict(text=line,start=start,end=container.tell()))
                else:
                    raise RuntimeError('reference fixture record bound')
                container.close()
            observed=[]
            offset=0
            for _ in range(32):
                result=module.frame(data[offset:],codec,eof=True)
                if result.disposition=='incomplete':
                    break
                if result.disposition!='complete' or result.consumed<=0:
                    raise RuntimeError('unexpected candidate framing disposition: '+result.disposition)
                observed.append(dict(text=result.text,start=offset,end=offset+result.consumed))
                offset+=result.consumed
            else:
                raise RuntimeError('candidate fixture record bound')
            corrected=None
            if intentional:
                width=2 if codec in ('utf-16-le','utf16') else 4
                if codec in ('utf16','utf32'):
                    corrected=[dict(text='first',start=0,end=7*width),dict(text='second',start=7*width,end=14*width)]
                else:
                    corrected=[dict(text='Ċ',start=0,end=3*width),dict(text='b',start=3*width,end=5*width)]
            rows.append(dict(id=name,codec=codec,bytes_hex=data.hex(),expected=expected,observed=observed,
                             equal=expected==observed,intentional_reference_loss_fix=intentional,
                             candidate_preserves_aligned_records=observed==corrected if intentional else None))
    unexpected=[row for row in rows if not row['equal'] and not(row['intentional_reference_loss_fix'] and row['candidate_preserves_aligned_records'])]
    result=dict(scope='codec-aware framing component; no source cursor acknowledgment or daemon integration',
                reference_commit=commit,candidate_source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=rows,
                agreements=sum(row['equal'] for row in rows),intentional_differences=sum(row['intentional_reference_loss_fix'] and not row['equal'] for row in rows),
                unexpected_mismatches=len(unexpected))
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({key:value for key,value in result.items() if key!='cases'}))
    return bool(unexpected)


if __name__=='__main__':
    raise SystemExit(main())

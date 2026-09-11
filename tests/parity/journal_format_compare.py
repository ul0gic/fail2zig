#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Original journal fields against actual binding conversion and formatter.

No journal files, services or upstream test bodies are used by this component probe.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import types


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    commit=subprocess.check_output(['git','-C',str(args.reference),'rev-parse','HEAD'],text=True).strip()
    if commit!='f60978618a101427b06924fc932b44350fec2b63': raise SystemExit('wrong reference commit')
    sys.path.insert(0,str(args.reference))
    from fail2ban.server.filtersystemd import FilterSystemd
    from systemd import journal
    component=Path(__file__).resolve().parents[2]/'engine/compat/journal_format.py'
    sys.path.insert(0,str(component.parent))
    spec=importlib.util.spec_from_file_location('f2z_journal_format',component)
    candidate=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(candidate)
    converter=types.SimpleNamespace(converters=journal.DEFAULT_CONVERTERS)
    converter._convert_field=lambda key,value:journal.Reader._convert_field(converter,key,value)
    controls=[
        ('utf8-first',[('_HOSTNAME','hôte'.encode()),('SYSLOG_IDENTIFIER','Ω'.encode()),('MESSAGE','café'.encode())]),
        ('bytes-fallback',[('_HOSTNAME',b'host\xff'),('SYSLOG_IDENTIFIER',b'name\xff'),('MESSAGE',b'value\xff')]),
        ('utf16-fallback',[('MESSAGE','Ω'.encode('utf-16-le'))]),
        ('pid-zero',[('SYSLOG_IDENTIFIER',b'kernel'),('SYSLOG_PID',b'0'),('MESSAGE',b'ordinary')]),
        ('pid-zero-fallback',[('SYSLOG_IDENTIFIER',b'example'),('SYSLOG_PID',b'0'),('_PID',b'42'),('MESSAGE',b'ordinary')]),
        ('pid-hex',[('SYSLOG_IDENTIFIER',b'example'),('SYSLOG_PID',b'0x2a'),('MESSAGE',b'ordinary')]),
        ('pid-decimal',[('SYSLOG_IDENTIFIER',b'example'),('SYSLOG_PID',b'007'),('MESSAGE',b'ordinary')]),
        ('pid-bytes-repr',[('SYSLOG_IDENTIFIER',b'example'),('SYSLOG_PID',b'opaque\xff'),('MESSAGE',b'ordinary')]),
        ('comm-fallback',[('SYSLOG_IDENTIFIER',b''),('_COMM','é'.encode()),('MESSAGE',b'ordinary')]),
        ('message-list',[('MESSAGE','café'.encode()),('MESSAGE',b'part\xff'),('MESSAGE',b'last\nline')]),
        ('missing-message',[('_HOSTNAME',b'host')]),
        ('kernel-source-monotonic',[('SYSLOG_IDENTIFIER',b'kernel'),('_SOURCE_MONOTONIC_TIMESTAMP',b'1234567'),('MESSAGE',b'ordinary')]),
        ('kernel-negative-monotonic',[('SYSLOG_IDENTIFIER',b'kernel'),('_SOURCE_MONOTONIC_TIMESTAMP',b'-1'),('MESSAGE',b'ordinary')]),
        ('kernel-invalid-monotonic',[('SYSLOG_IDENTIFIER',b'kernel'),('_SOURCE_MONOTONIC_TIMESTAMP',b'invalid'),('MESSAGE',b'ordinary')]),
        ('repeated-host',[('_HOSTNAME',b'first'),('_HOSTNAME',b'second'),('MESSAGE',b'ordinary')]),
    ]
    rows=[]
    for encoding in ('utf8','latin1','cp1252','utf-16-le','utf-16-be','ascii','shift_jis','unicode_escape'):
        for name,fields in controls:
            raw={}
            for key,value in fields:
                if key in raw:
                    if not isinstance(raw[key],list): raw[key]=[raw[key]]
                    raw[key].append(value)
                else: raw[key]=value
            raw['__REALTIME_TIMESTAMP']=1730000000123456
            raw['__MONOTONIC_TIMESTAMP']=(1000001,bytes.fromhex('11'*16))
            converted=journal.Reader._convert_entry(converter,raw)
            formatter=types.SimpleNamespace(getLogEncoding=lambda:encoding,jailName='original-fixture')
            formatter.getJrnEntTime=lambda entry:FilterSystemd.getJrnEntTime(formatter,entry)
            try: expected=dict(text=FilterSystemd.formatJournalEntry(formatter,converted)[0][2])
            except (ValueError,TypeError,AttributeError,UnicodeError): expected=dict(error='invalid_field')
            try: observed=dict(text=candidate.format_entry(fields,encoding,'1000001')['text'])
            except (ValueError,TypeError,AttributeError,UnicodeError): observed=dict(error='invalid_field')
            rows.append(dict(id=name,encoding=encoding,fields=[(key,value.hex()) for key,value in fields],expected=expected,observed=observed,agreement=expected==observed))
    result=dict(scope='actual binding field conversion and pinned formatter versus candidate component; no journal opens',reference_commit=commit,
                candidate_source_sha256=hashlib.sha256(component.read_bytes()).hexdigest(),binding_source_sha256=hashlib.sha256(Path(journal.__file__).read_bytes()).hexdigest(),
                cases=rows,case_count=len(rows),agreements=sum(row['agreement'] for row in rows))
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(f"{result['agreements']}/{result['case_count']} journal field-format agreements")
    return result['agreements']!=result['case_count']

if __name__=='__main__': raise SystemExit(main())

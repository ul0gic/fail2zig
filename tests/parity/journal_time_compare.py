#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Original microsecond/time-text controls against installed systemd bindings."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    from systemd import journal
    source=Path(__file__).resolve().parents[2]/'engine/compat/journal_time.py'
    spec=importlib.util.spec_from_file_location('f2z_journal_time',source)
    candidate=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(candidate)
    rows=[]
    values=[0,1,999999,1000000,1730000000000001,1730000000123456,
            9007199254740991,9007199254740993,9007199254740995,
            10000000000000001,253402300799999970,253402300799999999,18446744073709551615]
    for value in values:
        raw=str(value)
        try:
            date=journal._convert_timestamp(raw)
            expected=dict(timestamp_us=raw,timestamp_bits=struct.pack('>d',date.timestamp()).hex(),iso8601=date.isoformat(),time_text=date.isoformat()+' ')
        except (ValueError,OverflowError,OSError):
            expected=dict(error='calendar_range')
        try: observed=candidate.convert(raw)
        except (ValueError,OverflowError,OSError): observed=dict(error='calendar_range')
        rows.append(dict(raw_microseconds=raw,expected=expected,observed=observed,agreement=expected==observed))
    result=dict(scope='actual Python systemd timestamp conversion and ISO tuple text; no journal opens',
                binding_timezone=str(journal._LOCAL_TIMEZONE),candidate_timezone=str(candidate.LOCAL_TIMEZONE),
                binding_source_sha256=hashlib.sha256(Path(journal.__file__).read_bytes()).hexdigest(),
                candidate_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                cases=rows,case_count=len(rows),agreements=sum(row['agreement'] for row in rows))
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(f"{result['agreements']}/{result['case_count']} journal time agreements")
    return result['agreements']!=result['case_count']

if __name__=='__main__':
    raise SystemExit(main())

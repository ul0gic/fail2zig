#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Original private filesystem journal argument cases; never opens a journal."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
from unittest.mock import patch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    commit = subprocess.check_output(['git', '-C', str(args.reference), 'rev-parse', 'HEAD'], text=True).strip()
    if commit != 'f60978618a101427b06924fc932b44350fec2b63':
        raise SystemExit('wrong reference commit')
    sys.path.insert(0, str(args.reference))
    import fail2ban.server.filtersystemd as reference
    from systemd import journal
    with tempfile.TemporaryDirectory(prefix='f2z-original-journal-policy-') as directory:
        root = Path(directory)
        state, runtime = root/'state', root/'runtime'
        names = ['system.journal','system@original.journal','user-0.journal','user-1000.journal',
                 'user-1000@original.journal','user-1001.journal','ordinary.journal','.hidden.journal','note.txt']
        for base in (state, runtime):
            for machine in ('machine-a','machine-b'):
                folder = base/'journal'/machine
                folder.mkdir(parents=True)
                for name in names:
                    (folder/name).write_text('original policy fixture; not a journal\n')
                (folder/'directory.fixture').mkdir()
                (folder/'broken.fixture').symlink_to('absent-original-target')
        selected = str(state/'journal'/'machine-a')
        cases = []
        def add(name, options=None, **extra):
            cases.append(dict(id=name,options=options or {},state_logs=str(state),runtime_logs=str(runtime),**extra))
        add('default')
        for flags in (None,'0','1','2','4','8','12','-1','2147483648','1208925819614629174706180','bad','1__2','_4','4_','  +04  ','٤','\u2003４\u00a0'):
            for rotated in ('0','1'):
                options = dict(rotated=rotated)
                if flags is not None: options['flags'] = flags
                add(f'flags:{flags!r}:rotated:{rotated}', options)
        for flags in (None,'0','1','2','4','8','12','-1','bad'):
            for rotated in ('0','yes'):
                add(f'environment:{flags!r}:rotated:{rotated}', dict(rotated=rotated), default_flags=flags)
        for rotated in ('0','1','true','YES','false',' true ','unknown',''):
            for namespace in (None,'','original-namespace'):
                options = dict(rotated=rotated)
                if namespace is not None: options['namespace'] = namespace
                add(f'namespace:{namespace!r}:rotated:{rotated}', options)
        patterns = [[],[selected+'/absent*'],[selected+'/*.journal'],[selected+'/system.journal']*2,
                    [selected+'/directory.fixture/'],[selected+'/broken.fixture'],[selected+'/.hidden.journal'],[selected.replace('/journal/','//journal/')+'/*.journal']]
        for index, files in enumerate(patterns):
            for rotated in ('0','1'):
                for namespace in (None,'original-namespace'):
                    options = dict(files=files,rotated=rotated)
                    if namespace is not None: options['namespace'] = namespace
                    add(f'files:{index}:rotated:{rotated}:namespace:{namespace}', options)
        for path in ('',selected,str(root/'missing'),str(state/'journal'/'*')):
            for flags in (None,'0','2','4','8','12'):
                for rotated in ('0','1'):
                    options = dict(path=path,rotated=rotated)
                    if flags is not None: options['flags'] = flags
                    add(f'path:{path}:flags:{flags}:rotated:{rotated}',options)
        for uid in (0,1000,1001):
            for flags in (None,'0','2','4','8','12'):
                options = {} if flags is None else dict(flags=flags)
                add(f'uid:{uid}:flags:{flags}:denied', options, effective_uid=uid,
                    unreadable=[str(base/'journal'/machine/'system.journal') for base in (state,runtime) for machine in ('machine-a','machine-b')])
        for words in ('',selected+'/system.journal,\n'+selected+'/user-1000.journal',selected+'/system.journal\u2003'+selected+'/broken.fixture'):
            add('splitwords:'+repr(words),files_words=words)
        add('missing-default-paths', state_logs_override=str(root/'no-state'))
        # Record the explicit environment and preserve canonical flag text: Python
        # preparation supports arbitrary integers even though native admission does not.
        requests = []
        expected = []
        for case in cases:
            request = {key:value for key,value in case.items() if key not in ('id','state_logs_override')}
            request['private_root']=str(root)
            if 'state_logs_override' in case: request['state_logs']=case['state_logs_override']
            requests.append(request)
            options = request['options']
            kwargs = {dict(path='journalpath',files='journalfiles',flags='journalflags').get(key,key):value for key,value in options.items()}
            if 'files_words' in request: kwargs['journalfiles']=request['files_words']
            mapping={'system-state-logs':request['state_logs'],'system-runtime-logs':request['runtime_logs']}
            denied=set(request.get('unreadable',[]))
            with patch.object(reference,'_getSystemdPath',side_effect=lambda name:mapping[name]), \
                 patch.object(reference.os,'geteuid',return_value=request.get('effective_uid',0)), \
                 patch.object(reference.os,'access',side_effect=lambda path,mode:path not in denied), \
                 patch.object(reference.os,'getenv',return_value=request.get('default_flags')):
                try:
                    raw=reference.FilterSystemd._getJournalArgs(kwargs)
                    normalized={}
                    for key in ('flags','path','files','namespace'):
                        normalized[key+'_present']=key in raw
                        value=raw.get(key)
                        normalized[key]=sorted(value) if key=='files' and value is not None else str(value) if key=='flags' and value is not None else value
                    captured=[]
                    capture=types.SimpleNamespace(__init__=lambda *values:captured.append(values))
                    with patch.object(journal,'super',return_value=capture,create=True):
                        journal.Reader.__init__(types.SimpleNamespace(),**raw)
                    effective_flags=captured[0][0]
                    private=raw.get('path') is not None or raw.get('files') is not None
                    reader_error=None
                    if private:
                        path=raw.get('path')
                        if path and not path.startswith(str(root)+'/'): raise RuntimeError('nonprivate path')
                        if any(not path.startswith(str(root)+'/') for path in (raw.get('files') or [])): raise RuntimeError('nonprivate files')
                        try:
                            value=journal.Reader(**raw)
                            value.close()
                        except SystemError:
                            reader_error='BindingInternalError'
                        except OverflowError:
                            reader_error='InvalidFlags'
                        except ValueError:
                            reader_error='InvalidJournalSelection'
                        except OSError as error:
                            reader_error={1:'AccessDenied',2:'FileNotFound',13:'AccessDenied',22:'InvalidJournalSelection'}.get(error.errno,'JournalReadFailed')
                    expected.append(dict(arguments=normalized,preparation_error=None,effective_flags=str(effective_flags),reader_checked=private,reader_error=reader_error))
                except (ValueError,OverflowError):
                    expected.append(dict(arguments=None,preparation_error='InvalidFlags',effective_flags=None,reader_checked=False,reader_error=None))
        input_file=root/'requests.json'
        input_file.write_text(json.dumps(requests))
        process=subprocess.run([str(args.candidate),str(input_file)],check=True,text=True,capture_output=True,timeout=30)
        actual=json.loads(process.stdout)
        if len(actual)!=len(cases): raise RuntimeError('candidate case count mismatch')
        rows=[]
        for case,wanted,observed in zip(cases,expected,actual):
            preparation_equal=all(wanted[key]==observed[key] for key in ('arguments','preparation_error'))
            flags_equal=(wanted['effective_flags'] is None or
                         str(observed['selection_flags'])==wanted['effective_flags'] or
                         observed['selection_error'] is not None)
            def admission_class(error):
                return 'InvalidJournalSelection' if error in ('InvalidFlags','EmptyJournalFiles','BindingInternalError') else error
            reader_equal=(wanted['reader_checked']==observed['reader_checked'] and
                          admission_class(wanted['reader_error'])==admission_class(observed['reader_error']))
            rows.append(dict(id=case['id'],input=case,expected=wanted,observed=observed,
                             preparation_equal=preparation_equal,flags_equal=flags_equal,reader_equal=reader_equal,
                             agreement=preparation_equal and flags_equal and reader_equal))
        result=dict(scope='effective journal arguments, captured Python constructor flags, and private-only reader admission; no default/live journal opens',
                    reference_commit=commit,candidate_sha256=hashlib.sha256(args.candidate.read_bytes()).hexdigest(),
                    reference_source_sha256=hashlib.sha256(Path(reference.__file__).read_bytes()).hexdigest(),
                    candidate_source_sha256=hashlib.sha256((Path(__file__).resolve().parents[2]/'engine/core/journal_policy.zig').read_bytes()).hexdigest(),
                    error_normalization={'InvalidFlags':'InvalidJournalSelection','EmptyJournalFiles':'InvalidJournalSelection','BindingInternalError':'InvalidJournalSelection'},
                    normalization_reason='Preserve failed admission while distinguishing typed policy rejection from binding internal/overflow diagnostics. Raw diagnostics remain in every row.',
                    cases=rows,case_count=len(rows),agreements=sum(row['agreement'] for row in rows))
        args.output.write_text(json.dumps(result,indent=2)+'\n')
        print(f"{result['agreements']}/{result['case_count']} journal policy agreements")
        return result['agreements'] != result['case_count']

if __name__=='__main__':
    raise SystemExit(main())

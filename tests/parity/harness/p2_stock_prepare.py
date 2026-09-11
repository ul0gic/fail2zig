#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Whole pinned stock configuration preparation; no filter/action execution."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import tomllib


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference',type=Path,required=True)
    parser.add_argument('--candidate',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--roundtrip-probe',type=Path,required=True)
    args=parser.parse_args()
    reference=args.reference.resolve();candidate=args.candidate.resolve()
    commit=subprocess.check_output(['git','-C',str(reference),'rev-parse','HEAD'],text=True).strip()
    if commit!='f60978618a101427b06924fc932b44350fec2b63':raise ValueError('wrong reference commit')
    subprocess.run(['git','-C',str(reference),'diff','--exit-code','HEAD','--'],check=True,capture_output=True)
    root=Path(__file__).resolve().parents[3]
    paths=['engine/config/fail2ban.zig','engine/config/migration.zig','engine/config/native.zig','engine/config/source_plan.zig','engine/config/filter_context.zig','tests/parity/harness/p2_stock_prepare.py']
    report={'schema_version':1,'scope':'Whole pinned stock source preparation and native validation only; no upstream sample/test execution, regex matching, actions or daemon activation',
            'reference_commit':commit,'candidate_binary_sha256':digest(candidate),
            'candidate_source_hashes':{path:digest(root/path) for path in paths},
            'reference_config_hashes':{str(path.relative_to(reference)):digest(path) for path in sorted((reference/'config').rglob('*')) if path.is_file()}}
    with tempfile.TemporaryDirectory(prefix='f2z-p2-stock-preparation-') as directory:
        output=Path(directory)/'prepared.toml'
        preparation=subprocess.run([str(candidate),'--import-config',str(reference/'config'),'--import-output',str(output)],capture_output=True,text=True,timeout=60)
        report.update(preparation_returncode=preparation.returncode,preparation_stderr=preparation.stderr,output_created=output.exists())
        success=preparation.returncode in (0,1) and output.exists()
        if success:
            data=output.read_bytes();config=tomllib.loads(data.decode());manifest=json.loads(config['global']['compatibility_manifest'])
            validation=subprocess.run([str(candidate),'--validate-config','--config',str(output)],capture_output=True,text=True,timeout=30)
            changed=Path(directory)/'guard-check.toml'
            changed.write_bytes(data+b'\n[jails.original-admission-check]\nenabled=true\nfilter="sshd"\n')
            changed.chmod(0o600)
            guarded=subprocess.run([str(candidate),'--validate-config','--config',str(changed)],capture_output=True,text=True,timeout=30)
            pending=config['global'].get('compatibility_pending') is True
            disabled=all(not jail.get('enabled',False) for jail in config.get('jails',{}).values())
            report.update(output_bytes=len(data),output_sha256=hashlib.sha256(data).hexdigest(),output_mode=oct(output.stat().st_mode&0o777),
                manifest_schema=manifest['schema_version'],global_pending=pending,all_native_jails_disabled=disabled,
                prepared_options=len(manifest['options']),prepared_assets=len(manifest['assets']),source_occurrences=len(manifest['sources']),
                global_source_occurrences=len(manifest['global']['sources']),source_plans=len(manifest.get('source_plans',[])),
                filter_context_errors=[{'jail':asset['jail'],'error':asset['admission']} for asset in manifest['assets'] if asset.get('consumer_phase')=='filter-context-error'],
                source_plan_diagnostics=[{'jail':plan['jail'],'source':plan['diagnostics'],'processing':plan['processing']['diagnostics'],'ignore':plan['ignore']['diagnostics']} for plan in manifest.get('source_plans',[]) if plan['diagnostics'] or plan['processing']['diagnostics'] or plan['ignore']['diagnostics']],
                validation_returncode=validation.returncode,validation_stderr=validation.stderr,
                activation_guard_returncode=guarded.returncode,activation_guard_stderr=guarded.stderr)
            success=validation.returncode==0 and pending and disabled and guarded.returncode!=0 and 'CompatibilityNotAdmitted' in guarded.stderr
            roundtrip_output=Path(directory)/'roundtrip.toml'
            roundtrip=subprocess.run([str(args.roundtrip_probe.resolve()),str(output),str(roundtrip_output)],capture_output=True,text=True,timeout=30)
            report['roundtrip_probe_sha256']=digest(args.roundtrip_probe)
            report['roundtrip_returncode']=roundtrip.returncode
            report['roundtrip']=json.loads(roundtrip.stdout) if roundtrip.stdout else None
            success=success and roundtrip.returncode==0 and report['roundtrip'] is not None

    report['passed']=success
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({key:report.get(key) for key in ('passed','output_bytes','prepared_options','prepared_assets','validation_returncode','activation_guard_returncode')}))
    return 0 if success else 1

if __name__=='__main__':raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Original prepare/invalid-replacement/reprepare trajectory; no daemon reload."""
import argparse,hashlib,json,subprocess,tempfile,tomllib
from pathlib import Path

def digest(data):return hashlib.sha256(data).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('candidate','roundtrip-probe','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();candidate=a.candidate.resolve();checks=[]
 with tempfile.TemporaryDirectory(prefix='f2z-p2-prepared-reload-') as tmp:
  root=Path(tmp);src=root/'source';src.mkdir();(src/'filter.d').mkdir()
  files={'jail.conf':'[DEFAULT]\nenabled=true\n[probe]\nfilter=original[mode=custom]\nbackend=polling\nlogpath=/original/log tail\nmaxretry=7\ncustom=kept\n','fail2ban.conf':'[Definition]\nlogtarget=STDERR\nallowipv6=no\n','filter.d/original.conf':'[Definition]\ndatepattern=EPOCH\njournalmatch=K=<mode>\n[Init]\nmode=base\n'}
  for name,data in files.items():(src/name).write_text(data)
  output=root/'prepared.toml'
  def prepare():return subprocess.run([str(candidate),'--import-config',str(src),'--import-output',str(output)],text=True,capture_output=True,timeout=20)
  def manifest():return json.loads(tomllib.loads(output.read_text())['global']['compatibility_manifest'])
  initial=prepare();assert initial.returncode in (0,1) and output.exists(),initial.stderr
  original=output.read_bytes();before=manifest();checks.append({'id':'initial-private-preparation','passed':output.stat().st_mode&0o777==0o600,'generation':before['config_generation']})
  for name,path,bad in [('duplicate-jail','jail.conf','[probe]\nmaxretry=1\nmaxretry=2\n'),('duplicate-global','fail2ban.conf','[Definition]\nlogtarget=A\nlogtarget=B\n'),('invalid-selected-asset','filter.d/original.conf','[Definition\ndatepattern=EPOCH\n')]:
   (src/path).write_text(bad);failed=prepare()
   checks.append({'id':name,'passed':failed.returncode not in (0,1) and output.read_bytes()==original and not list(root.glob('prepared.toml.tmp-*')),'returncode':failed.returncode,'diagnostic':failed.stderr,'previous_output_sha256':digest(output.read_bytes())})
   (src/path).write_text(files[path])
  (src/'jail.local').write_text('[probe]\nmaxretry=9\ncustom=\n')
  changed=prepare();after=manifest();changed_data=output.read_bytes()
  observed={r['name']:r for r in after['options'] if r['section']=='probe'}
  checks.append({'id':'valid-reprepare-new-generation','passed':changed.returncode in (0,1) and before['config_generation']!=after['config_generation'] and observed['maxretry']['effective']=='9' and observed['custom']['effective']=='' and observed['custom']['raw']=='','generation':after['config_generation']})
  repeated=prepare();checks.append({'id':'unchanged-source-reprepare-stable','passed':repeated.returncode in (0,1) and output.read_bytes()==changed_data})
  roundtrip=subprocess.run([str(a.roundtrip_probe.resolve()),str(output),str(root/'roundtrip.toml')],text=True,capture_output=True,timeout=20)
  checks.append({'id':'parse-render-reload-structural','passed':roundtrip.returncode==0,'result':json.loads(roundtrip.stdout) if roundtrip.stdout else None})
  validate=subprocess.run([str(candidate),'--validate-config','--config',str(root/'roundtrip.toml')],text=True,capture_output=True,timeout=20)
  checks.append({'id':'reloaded-file-valid','passed':validate.returncode==0})
 repo=Path(__file__).resolve().parents[3]
 paths=['engine/config/migration.zig','engine/config/native.zig','engine/config/fail2ban.zig','engine/config/source_plan.zig','engine/config/filter_context.zig','tests/parity/harness/p2_prepare_reload.py']
 report={'schema_version':1,'scope':'Prepared-file replacement, deterministic regeneration and structural reload; no live daemon/P6 transaction assertion','candidate_sha256':digest(candidate.read_bytes()),'roundtrip_probe_sha256':digest(a.roundtrip_probe.read_bytes()),'source_hashes':{x:digest((repo/x).read_bytes()) for x in paths},'checks':checks,'passed':all(x['passed'] for x in checks)}
 a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':report['passed'],'checks':len(checks)}));return int(not report['passed'])
if __name__=='__main__':raise SystemExit(main())

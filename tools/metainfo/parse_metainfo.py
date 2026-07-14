#!/usr/bin/env python3
"""Parse Audi MMI 2G METAINFO descriptors into normalized JSON/CSV.

Read-only research tool. It does not build update media or communicate with a vehicle.
"""
from __future__ import annotations
import argparse, csv, json, re
from pathlib import Path

SECTION_RE = re.compile(r'^\[(.+)\]$')
VALUE_RE = re.compile(r'^([^=]+?)\s*=\s*"(.*)"\s*$')
BARE_RE = re.compile(r'^([^=]+?)\s*=\s*(.*?)\s*$')

def parse(path: Path) -> dict:
    sections=[]; current=None
    for line_no, raw in enumerate(path.read_text('latin1').splitlines(),1):
        line=raw.strip()
        if not line or line.startswith('#'): continue
        m=SECTION_RE.match(line)
        if m:
            current={'name':m.group(1),'line':line_no,'fields':{}}
            sections.append(current); continue
        if current is None: continue
        m=VALUE_RE.match(line) or BARE_RE.match(line)
        if m: current['fields'][m.group(1).strip()]=m.group(2).strip().strip('"')
    common={}; devices={}; payloads=[]; links=[]; options=[]
    for section in sections:
        parts=section['name'].split('\\')
        if section['name'].lower()=='common': common=section['fields']; continue
        if len(parts)==1:
            devices[parts[0]]=section['fields']; continue
        if len(parts)>=5:
            record={'section':section['name'],'line':section['line'],'component':parts[0],
                    'application_id':parts[1],'hardware_index':parts[2],
                    'variant':parts[3],'role':parts[4].lower(),**section['fields']}
            if 'Link' in section['fields']: links.append(record)
            elif record['role']=='options': options.append(record)
            else: payloads.append(record)
    return {'source':path.name,'common':common,'devices':devices,'payloads':payloads,
            'links':links,'options':options,'section_count':len(sections)}

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument('files',nargs='+',type=Path); ap.add_argument('-o','--output',type=Path,required=True)
    args=ap.parse_args(); args.output.mkdir(parents=True,exist_ok=True)
    documents=[parse(p) for p in args.files]
    (args.output/'metainfo-normalized.json').write_text(json.dumps(documents,indent=2))
    rows=[]
    for disc,doc in enumerate(documents,1):
        for r in doc['payloads']+doc['links']+doc['options']:
            row={'disc':disc,'release':doc['common'].get('release',''),**r}; rows.append(row)
    keys=sorted(set().union(*(r.keys() for r in rows))) if rows else []
    with (args.output/'metainfo-records.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=keys); w.writeheader(); w.writerows(rows)
    return 0
if __name__=='__main__': raise SystemExit(main())

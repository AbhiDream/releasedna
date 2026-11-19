"""Offline archive inspection; package code is never executed."""
import argparse
import json
from pathlib import Path
from app.services.local_compare import read_bounded
from app.services.process_boundary import bounded_inspection


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact',type=Path,required=True)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    for side in ('artifact','source'):
        parser.add_argument('--'+side+'-layout',choices=['auto','strip','keep'],default='auto')
        parser.add_argument('--'+side+'-prefix',default='')
    args=vars(parser.parse_args())
    output=args.pop('output')
    for side in ('artifact','source'): args[side]=read_bounded(args[side])
    result=bounded_inspection('local',args)
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(f"{result['status']} | score {result['risk_score']} | {len(result['findings'])} findings | {output}")


if __name__=='__main__': main()

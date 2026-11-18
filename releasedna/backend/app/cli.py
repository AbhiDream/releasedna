import argparse
import json
from pathlib import Path
from app.services.scan import scan


def main():
    parser = argparse.ArgumentParser(description='ReleaseDNA - package/source forensics; never executes downloaded code')
    parser.add_argument('ecosystem', choices=['npm', 'pypi'])
    parser.add_argument('name')
    parser.add_argument('version')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    report = scan(args.ecosystem, args.name, args.version)
    data = json.dumps(report, indent=2, ensure_ascii=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(data, encoding='utf-8')
        print(f"{report['status']} | score={report['risk_score']} | findings={len(report['findings'])} | {args.output}")
    else:
        print(data)


if __name__ == '__main__':
    main()

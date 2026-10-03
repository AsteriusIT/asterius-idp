#!/usr/bin/env python3
"""Render JSON templates without shell interpolation or stdout credentials."""
import argparse
import json
import os
from pathlib import Path
import re

PATTERN = re.compile(r'\$\{([A-Z][A-Z0-9_]*)\}')


def render(template, values):
    def replace(value):
        if isinstance(value, str):
            def resolve(match):
                selected = values.get(match[1])
                if not isinstance(selected, str) or not selected:
                    raise ValueError('missing nonempty template value: '+match[1])
                return selected
            return PATTERN.sub(resolve, value)
        if isinstance(value, list):
            return [replace(item) for item in value]
        if isinstance(value, dict):
            return {key:replace(item) for key,item in value.items()}
        return value
    return replace(json.loads(Path(template).read_text()))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--template',required=True)
    parser.add_argument('--values',required=True,help='private JSON values file (mode0600)')
    parser.add_argument('--output',required=True,help='new private output file; never overwrite')
    args=parser.parse_args()
    source=Path(args.values)
    if source.stat().st_mode & 0o077:
        raise SystemExit('values file must not be readable by group or others')
    result=render(args.template,json.loads(source.read_text()))
    descriptor=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(descriptor,'w') as output:
        json.dump(result,output,indent=2);output.write('\n')


if __name__ == '__main__':
    main()

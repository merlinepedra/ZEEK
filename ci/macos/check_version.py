import argparse
import json
import subprocess
import sys

from packaging.version import parse as parse_version
from parse import parse as parse_string

def parse_openssl(ver_str):

    ver = parse_string("{:d}.{:d}.{:d}{:3l}", ver_str)
    if ver:
        return ver

    ver = parse_string("{:d}.{:d}.{:d}", ver_str)
    return ver

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--get_brew_version', metavar='package', type=str)
group.add_argument('--compare_openssl', nargs=2, metavar=('current','expected'), type=str)
group.add_argument('--compare', nargs=2, metavar=('current','expected'), type=str)

args = parser.parse_args()

if args.get_brew_version:

    binary = args.get_brew_version
    proc = subprocess.run(['brew','info','--json=v1',binary], capture_output=True)
    j = json.loads(proc.stdout)
    if len(j) == 0:
        print('')
        sys.exit(0)

    installed = j[0].get('installed',[])
    if len(installed) == 0:
        print('')
        sys.exit(0)

    print(installed[0].get('version', ''))

elif args.compare:

    current = parse_version(args.compare[0])
    expected = parse_version(args.compare[1])

    if current < expected:
        sys.exit(1)

elif args.compare_openssl:

    current = parse_openssl(args.compare_openssl[0])
    expected = parse_openssl(args.compare_openssl[1])
    current_num_only = '{:d}.{:d}.{:d}'.format(current[0], current[1], current[2])
    expected_num_only = '{:d}.{:d}.{:d}'.format(expected[0], expected[1], expected[2])

    current_letters = ''
    if len(current.fixed) == 4:
        current_letters = current[3]

    expected_letters = ''
    if len(expected.fixed) == 4:
        expected_letters = expected[3]

    current = parse_version(current_num_only)
    expected = parse_version(expected_num_only)

    if current < expected:
        sys.exit(1)

    if current == expected and current_letters < expected_letters:
        sys.exit(1)

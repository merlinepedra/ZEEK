from packaging.version import parse as parse_version
from parse import parse as parse_string
import sys

def parse_openssl(ver_str):

    ver = parse_string("{:d}.{:d}.{:d}{:3l}", ver_str)
    if ver:
        return ver

    ver = parse_string("{:d}.{:d}.{:d}", ver_str)
    return ver

if len(sys.argv) == 3:

    print(type(sys.argv[1]))
    print(type(sys.argv[2]))

    current = parse_version(str(sys.argv[1]))
    expected = parse_version(str(sys.argv[2]))
    print(current)
    print(expected)
    print(current < expected)

    if current < expected:
        print("version fail")
        sys.exit(1)

    sys.exit(0)

elif len(sys.argv) == 4:

    current = parse_openssl(sys.argv[1])
    expected = parse_openssl(sys.argv[2])
    current_num_only = '{:d}.{:d}.{:d}'.format(current[0], current[1], current[2])
    expected_num_only = '{:d}.{:d}.{:d}'.format(expected[0], expected[1], expected[2])

    current_letters = ''
    if len(current.fixed) == 4:
        current_letters = current[3]

    expected_letters = ''
    if len(expected.fixed) == 4:
        expected_letters = expected[3]

    current = parse_version(sys.argv[1])
    expected = parse_version(sys.argv[2])

    if current < expected:
        print("version fail")
        sys.exit(1)

    if current == expected and current_letters < expected_letters:
        print("letter fail")
        print(current_letters < expected_letters)
        sys.exit(1)

    sys.exit(0)

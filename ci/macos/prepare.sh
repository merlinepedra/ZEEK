#!/bin/sh

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

echo "Preparing macOS environment"
sysctl hw.model hw.machine hw.ncpu hw.physicalcpu hw.logicalcpu
set -e
set -x

# This is used to compare version numbers between what's installed and what's
# expected from the packages we install via brew. We check the version numbers
# to avoid a lenghty update process that might not need to run.
pip3 install packaging
pip3 install parse

DO_UPDATE=0

# First try to grab the version number of each installed package from brew,
# but if that fails try to query it from the binary itself.
OPENSSL_VERSION=$(python3 ${SCRIPT_DIR}/check_version.py --get_brew_version openssl)
if [ -z "${OPENSSL_VERSION}" ]; then
    if which openssl; then
	OPENSSL_VERSION=$(openssl version | awk '{print $2}')
    else
	DO_UPDATE=1
    fi
fi

CMAKE_VERSION=$(python3 ${SCRIPT_DIR}/check_version.py --get_brew_version cmake)
if [ -z "${CMAKE_VERSION}" ]; then
    if which cmake; then
	CMAKE_VERSION=$(cmake --version | head -1 | awk '{print $3}')
    else
	DO_UPDATE=1
    fi
fi

SWIG_VERSION=$(python3 ${SCRIPT_DIR}/check_version.py --get_brew_version swig)
if [ -z "${SWIG_VERSION}" ]; then
    if which swig; then
	SWIG_VERSION=$(swig -version | head -2 | awk 'NF {print $3}')
    else
	DO_UPDATE=1
    fi
fi

BISON_VERSION=$(python3 ${SCRIPT_DIR}/check_version.py --get_brew_version bison)
if [ -z "${BISON_VERSION}" ]; then
    if which bison; then
	BISON_VERSION=$(bison --version | head -1 | awk '{print $4}')
    else
	DO_UPDATE=1
    fi
fi

echo "Current openssl: ${OPENSSL_VERSION:=not installed}"
echo "Current cmake: ${CMAKE_VERSION:=not installed}"
echo "Current swig: ${SWIG_VERSION:=not installed}"
echo "Current bison: ${BISON_VERSION:=not installed}"

if [ ${DO_UPDATE} -eq 0 ]; then

    if ! python3 ${SCRIPT_DIR}/check_version.py --compare_openssl "${OPENSSL_VERSION}" "1.1.1l"; then
	DO_UPDATE=1
    elif ! python3 ${SCRIPT_DIR}/check_version.py --compare "${CMAKE_VERSION}" "3.20.0"; then
	DO_UPDATE=1
    elif ! python3 ${SCRIPT_DIR}/check_version.py --compare "${SWIG_VERSION}" "4.0.0"; then
	DO_UPDATE=1
    elif ! python3 ${SCRIPT_DIR}/check_version.py --compare "${BISON_VERSION}" "3.8.0"; then
	DO_UPDATE=1
    fi

fi

if [ ${DO_UPDATE} -eq 1 ]; then

    brew update
    brew upgrade cmake openssl@1.1
    brew install swig bison

fi

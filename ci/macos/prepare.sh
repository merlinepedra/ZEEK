#!/bin/sh

echo "Preparing macOS environment"
sysctl hw.model hw.machine hw.ncpu hw.physicalcpu hw.logicalcpu
set -e
set -x

# This is used to compare version numbers between what's installed and what's
# expected from the packages we install via brew. We check the version numbers
# to avoid a lenghty update process that might not need to run.
pip3 install packaging
pip3 install parse

# First try to grab the version number of each installed package from brew,
# but if that fails try to query it from the binary itself.
OPENSSL_VERSION=$(brew info --json=v1 openssl | jq -r '.[0].installed[0].version')
if [ "${OPENSSL_VERSION}" = "null" ]; then
    OPENSSL_VERSION=$(openssl version | awk '{print $2}')
fi

CMAKE_VERSION=$(brew info --json=v1 cmake | jq -r '.[0].installed[0].version')
if [ "${CMAKE_VERSION}" = "null" ]; then
    CMAKE_VERSION=$(cmake --version | head -1 | awk '{print $3}')
fi

SWIG_VERSION=$(brew info --json=v1 swig | jq -r '.[0].installed[0].version')
if [ "${SWIG_VERSION}" = "null" ]; then
    SWIG_VERSION=$(swig -version | head -2 | awk 'NF {print $3}')
fi

BISON_VERSION=$(brew info --json=v1 bison | jq -r '.[0].installed[0].version')
if [ "${BISON_VERSION}" = "null" ]; then
    BISON_VERSION=$(bison --version | head -1 | awk '{print $4}')
fi

DO_UPDATE=0
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

echo "Current openssl: ${OPENSSL_VERSION}"
echo "Current cmake: ${CMAKE_VERSION}"
echo "Current swig: ${SWIG_VERSION}"
echo "Current bison: ${BISON_VERSION}"

if ! python3 ${SCRIPT_DIR}/check_version.py "${OPENSSL_VERSION}" "1.1.1l" 1; then
    DO_UPDATE=1
elif ! python3 ${SCRIPT_DIR}/check_version.py "${CMAKE_VERSION}" "3.20.0"; then
    DO_UPDATE=1
elif ! python3 ${SCRIPT_DIR}/check_version.py "${SWIG_VERSION}" "4.0.0"; then
    DO_UPDATE=1
elif ! python3 ${SCRIPT_DIR}/check_version.py "${BISON_VERSION}" "3.8.0"; then
    DO_UPDATE=1
fi

if [ ${DO_UPDATE} -eq 1 ]; then

    brew update
    brew upgrade cmake openssl@1.1
    brew install swig bison

fi

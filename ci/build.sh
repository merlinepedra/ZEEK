#! /usr/bin/env bash

set -e
set -x

EXTRA_CONFIGURE_ENV=""

if [ "${ZEEK_CI_USE_CLANG}" == "1" ]; then
    export CC=clang-11
    export CXX=clang++-11
fi

if [ "${ZEEK_CI_CREATE_ARTIFACT}" != "1" ]; then
    ./configure ${ZEEK_CI_CONFIGURE_FLAGS}
    cd build
    make -j ${ZEEK_CI_CPUS}
else
    ./configure ${ZEEK_CI_CONFIGURE_FLAGS} --prefix=${CIRRUS_WORKING_DIR}/install
    cd build
    make -j ${ZEEK_CI_CPUS} install
    cd ..
    tar -czf ${CIRRUS_WORKING_DIR}/build.tgz ${CIRRUS_WORKING_DIR}/install
fi

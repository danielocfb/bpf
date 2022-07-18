#!/bin/bash

set -euo pipefail

ARCH="$1"
TOOLCHAIN="$2"
TOOLCHAIN_NAME="$(echo $TOOLCHAIN | cut -d '-' -f 1)"
TOOLCHAIN_VERSION="$(echo $TOOLCHAIN | cut -d '-' -f 2)"

if [ "$TOOLCHAIN_NAME" == "llvm" ]; then
export LLVM="-$TOOLCHAIN_VERSION"
fi

THISDIR="$(cd $(dirname $0) && pwd)"

source "${THISDIR}"/helpers.sh

foldable start build_kernel "Building kernel with $TOOLCHAIN"

cp ${GITHUB_WORKSPACE}/tools/testing/selftests/bpf/configs/config-latest.${ARCH} .config

make olddefconfig > /dev/null
make -j $((4*$(nproc))) all > /dev/null

foldable end build_kernel

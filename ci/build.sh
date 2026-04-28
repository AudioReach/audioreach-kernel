#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
set -ex
PREBUILD_SCRIPT_PATH="${PREBUILD_SCRIPT:-$(dirname "${BASH_SOURCE[0]}")/pre_build.sh}"
source "$PREBUILD_SCRIPT_PATH"

# load build args from file if environment variable is not set
if [ -z "${BUILD_ARGS:-}" ]; then
    BUILD_OPTIONS_FILE="${GITHUB_WORKSPACE}/ci/build_options.txt"
    BUILD_ARGS="$(sed -E 's/#.*$//' "$BUILD_OPTIONS_FILE" | sed '/^[[:space:]]*$/d' | tr '\n' ' ')"
fi

echo "Running build script..."
# Build/Compile audioreach-kernel
source ${GITHUB_WORKSPACE}/install/environment-setup-armv8-2a-qcom-linux

# Prepare Kernel module
cd $PKG_CONFIG_SYSROOT_DIR/lib/modules/*/build
make ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE modules_prepare
cd -
make KERNEL_SRC=$PKG_CONFIG_SYSROOT_DIR/lib/modules/*/build/ modules
cp -r audioreach-driver/*.ko /tmp/rootfs/lib/modules/*/updates

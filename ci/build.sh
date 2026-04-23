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

# make sure we are in the right directory
cd ${GITHUB_WORKSPACE}

# 1) Clone and build first kernel baseline (linux-qcom-next)
git clone https://github.com/qualcomm-linux/kernel.git
cd kernel
git checkout $(curl -s https://raw.githubusercontent.com/qualcomm-linux/meta-qcom/master/recipes-kernel/linux/linux-qcom-next_git.bb | grep '^SRCREV ?=' | awk -F'"' '{print $2}')
export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-gnu-
make -j$(nproc) defconfig
make -j$(nproc) Image.gz dtbs modules
cd ..

# 2) Clone AudioReach and build against the first kernel
git clone https://github.com/AudioReach/audioreach-kernel.git
cd audioreach-kernel
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- KERNEL_SRC=../kernel modules
cd ../kernel


# 3) Switch to second kernel baseline (linux-qcom_6.18) and rebuild
git checkout $(curl -s https://raw.githubusercontent.com/qualcomm-linux/meta-qcom/master/recipes-kernel/linux/linux-qcom_6.18.bb | grep '^SRCREV ?=' | awk -F'"' '{print $2}')
export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-gnu-
make -j$(nproc) defconfig
make -j$(nproc) Image.gz dtbs modules


# 4) Rebuild AudioReach modules against the second kernel
cd ../audioreach-kernel
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- KERNEL_SRC=../kernel modules

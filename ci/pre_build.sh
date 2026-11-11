#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
set -euo pipefail
echo "Running pre-build script..."

# Define target_image.json url
url="https://raw.githubusercontent.com/AudioReach/audioreach-workflows/master/.github/actions/loading/target_image.json"

# Download <sdk>.sh from aws s3 bucket and install the sdk
if [ ! -d "${GITHUB_WORKSPACE}/install" ]; then
    echo "SDK_NAME environment variable is not set. Fetching from JSON."
    if curl -fsSL -o target_image.json "${url}"; then
        SDK=$(jq -r 'to_entries[0].value.SDK_name' target_image.json)
        if [ -n "$SDK" ] && [ "$SDK" != "null" ]; then
            export SDK_NAME="$SDK"
            echo "SDK_NAME set to ${SDK_NAME}"
        else
            echo "Error: SDK_name not found in JSON." >&2
            exit 3
        fi
    else
        echo "Failed to fetch target_image.json from $url" >&2
        exit 1
    fi
    if aws s3 cp s3://qli-prd-audior-gh-artifacts/AudioReach/meta-audioreach/post_merge_build/${SDK_NAME} "${GITHUB_WORKSPACE}"; then
        echo "SDK downloaded successfully."
        chmod 777 "${GITHUB_WORKSPACE}/${SDK_NAME}"
    else
        echo "Failed to download SDK from S3. Exiting."
        exit 1
    fi
    # Setup directory for sdk installation
    mkdir -p "${GITHUB_WORKSPACE}/install"
    orig_dir=$(pwd)
    cd "${GITHUB_WORKSPACE}"
    # Install the sdk
    echo "Running SDK script..."
    if echo "./install" | ./"${SDK_NAME}" ; then
        echo "SDK Script ran successfully."
    else
        echo "Error running SDK script. Exiting."
        exit 1
    fi
    cd "$orig_dir"
else
    echo "SDK already installed. Skipping download and installation."
fi

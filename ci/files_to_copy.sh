#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
cd ..


# copy the build artifacts to a temporary directory
cp  -R build/* /tmp/rootfs/lib/modules/*/updates

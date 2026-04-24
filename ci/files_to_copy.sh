#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
cd ..



# copy the build artifacts to a temporary directory
cp  -R build/* /tmp/rootfs/lib/modules/*/updates

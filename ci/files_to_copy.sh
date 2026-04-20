#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
cd ..

# copy the build artifacts to a temporary directory
cp -R build/usr/* /tmp/rootfs/usr/
cp -R build/etc/* /tmp/rootfs/etc/

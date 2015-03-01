#!/bin/bash
kernelver=$1
kernel_source_dir=$2
PACKAGE_NAME=$3
PACKAGE_VERSION=$4

config_flag=`/var/lib/dkms/${PACKAGE_NAME}/${PACKAGE_VERSION}/source/ofed_scripts/dkms_ofed $kernelver get-config`

make distclean

./configure --kernel-version=$kernelver --kernel-sources=$kernel_source_dir ${config_flag}

make -j`grep ^processor /proc/cpuinfo | wc -l`
./ofed_scripts/install_helper

#!/bin/bash
#
# Copyright (c) 2006 Mellanox Technologies. All rights reserved.
#
# This Software is licensed under one of the following licenses:
#
# 1) under the terms of the "Common Public License 1.0" a copy of which is
#    available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/cpl.php.
#
# 2) under the terms of the "The BSD License" a copy of which is
#    available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/bsd-license.php.
#
# 3) under the terms of the "GNU General Public License (GPL) Version 2" a
#    copy of which is available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/gpl-license.php.
#
# Licensee has the right to choose one of the above licenses.
#
# Redistributions of source code must retain the above copyright
# notice and one of the license notices.
#
# Redistributions in binary form must reproduce both the above copyright
# notice, one of the license notices in the documentation
# and/or other materials provided with the distribution.


# Execute command w/ echo and exit if it fail
ex()
{
        echo "$@"
        if ! "$@"; then
                printf "\nFailed executing $@\n\n"
                exit 1
        fi
}

KER_UNAME_R=`uname -r`
KER_PATH=/lib/modules/${KER_UNAME_R}/build

usage()
{
cat << EOF

Usage: `basename $0` [--help]: Prints this message
		[--with-memtrack]: Compile with memtrack kernel module to debug memory leaks
		[-k|--kernel <kernel version>]: Build package for this kernel version. Default: $KER_UNAME_R
		[-s|--kernel-sources  <path to the kernel sources>]: Use these kernel sources for the build. Default: $KER_PATH
EOF
}
			 
parseparams() {

	while [ ! -z "$1" ]
	do
		case $1 in
			--with-memtrack)
				CONFIG_MEMTRACK="m"
			;;
			-k | --kernel | --kernel-version)
				shift
				KVERSION=$1
			;;
			-s|--kernel-sources)
				shift
				KSRC=$1
			;;
			*)
				echo "Bad input parameter: $1"
				usage
				exit 1
			;;
		esac

		shift
	done
}

function check_autofconf {
	VAR=$1
	VALUE=$(tac ${KSRC}/include/*/autoconf.h | grep -m1 ${VAR} | sed -ne 's/.*\([01]\)$/\1/gp')

	eval "export $VAR=$VALUE"
}

main() {

#Set default values
WITH_QUILT=${WITH_QUILT:-"yes"}
WITH_PATCH=${WITH_PATCH:-"yes"}
EXTRA_FLAGS=""
CONFIG_MEMTRACK=""
CONFIG_MLX4_EN_DCB=""

parseparams $@

KVERSION=${KVERSION:-$KER_UNAME_R}
KSRC=${KSRC:-"/lib/modules/${KVERSION}/build"}

QUILT=${QUILT:-$(/usr/bin/which quilt  2> /dev/null)}
CWD=$(pwd)
CONFIG="config.mk"
PATCH_DIR=${PATCH_DIR:-""}

DEFINE_MLX4_EN_DCB='#undef CONFIG_MLX4_EN_DCB'
check_autofconf CONFIG_DCB
if [ X${CONFIG_DCB} == "X1" ]; then
	CONFIG_MLX4_EN_DCB=y
	DEFINE_MLX4_EN_DCB="#undef CONFIG_MLX4_EN_DCB\n#define CONFIG_MLX4_EN_DCB 1"
fi


        # Create config.mk
        /bin/rm -f ${CWD}/${CONFIG}
        cat >> ${CWD}/${CONFIG} << EOFCONFIG
KVERSION=${KVERSION}
ARCH=`uname -m`
MODULES_DIR:=/lib/modules/${KVERSION}/updates
KSRC:=${KSRC}
KLIB_BUILD=${KSRC}
CWD=${CWD}
MLNX_EN_EXTRA_CFLAGS:=${EXTRA_FLAGS}
CONFIG_MEMTRACK:=${CONFIG_MEMTRACK}
CONFIG_MLX4_EN_DCB:=${CONFIG_MLX4_EN_DCB}
EOFCONFIG

echo "Created ${CONFIG}:"
cat ${CWD}/${CONFIG}

# Create autoconf.h
#/bin/rm -f ${CWD}/include/linux/autoconf.h
if (/bin/ls -1 $KSRC/include/*/autoconf.h 2>/dev/null | head -1 | grep -q generated); then
    AUTOCONF_H="${CWD}/include/generated/autoconf.h"
    mkdir -p ${CWD}/include/generated
else
    AUTOCONF_H="${CWD}/include/linux/autoconf.h"
    mkdir -p ${CWD}/include/linux
fi

cat >> ${AUTOCONF_H}<< EOFAUTO
#define CONFIG_MLX4_CORE 1
#define CONFIG_MLX4_EN 1
$(echo -e "${DEFINE_MLX4_EN_DCB}")
EOFAUTO


}

main $@

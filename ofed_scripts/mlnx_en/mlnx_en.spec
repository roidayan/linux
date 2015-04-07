#
# Copyright (c) 2012 Mellanox Technologies. All rights reserved.
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
#
#

# KMP is disabled by default
%{!?KMP: %global KMP 0}

%{!?MEMTRACK: %global MEMTRACK 0}
%{!?MLX4: %global MLX4 1}
%{!?MLX5: %global MLX5 1}

%{!?KVERSION: %global KVERSION %(uname -r)}
%global kernel_version %{KVERSION}
%global krelver %(echo -n %{KVERSION} | sed -e 's/-/_/g')
# take path to kernel sources if provided, otherwise look in default location (for non KMP rpms).
%{!?K_SRC: %global K_SRC /lib/modules/%{KVERSION}/build}

%if "%{_vendor}" == "suse"
%if %{!?KVER:1}%{?KVER:0}
%ifarch x86_64
%define flav debug default kdump smp xen
%else
%define flav bigsmp debug default kdump kdumppae smp vmi vmipae xen xenpae pae ppc64
%endif
%endif

%if %{!?KVER:0}%{?KVER:1}
%define flav %(echo %{KVER} | awk -F"-" '{print $3}')
%endif
%endif

%if "%{_vendor}" == "redhat"
%if %{!?KVER:1}%{?KVER:0}
%define flav ""
%endif
%if %{!?KVER:0}%{?KVER:1}
%if "%{flav}" == ""
%define flav default
%endif
%endif
%endif

%{!?_name: %global _name mlnx-en}
%{!?_version: %global _version @VERSION@}
%{!?_release: %global _release @RELEASE@}

Name: %{_name}
Group: System Environment
Version: %{_version}
Release: %{_release}%{?_dist}
License: GPLv2 or BSD
Url: http://www.mellanox.com
Group: System Environment/Kernel
Vendor: Mellanox Technologies
Source0: %{_name}-%{_version}.tgz
Source1: mlx4.files
Provides: %{_name}
%if "%{KMP}" == "1"
Conflicts: mlnx_en
%endif
BuildRoot: %{?build_root:%{build_root}}%{!?build_root:/var/tmp/MLNX_EN}
Summary: mlnx-en kernel module(s)
%description
ConnectX Ehternet device driver
The driver sources are located at: http://www.mellanox.com/downloads/Drivers/mlnx-en-@VERSION@-@MAJOR_RELEASE@.tgz

%package doc
Summary: Documentation for the Mellanox Ethernet Driver for Linux
Group: System/Kernel

%description doc
Documentation for the Mellanox Ethernet Driver for Linux
The driver sources are located at: http://www.mellanox.com/downloads/Drivers/mlnx-en-@VERSION@-@MAJOR_RELEASE@.tgz

%package sources
Summary: Sources for the Mellanox Ethernet Driver for Linux
Group: System Environment/Libraries

%description sources
Sources for the Mellanox Ethernet Driver for Linux
The driver sources are located at: http://www.mellanox.com/downloads/Drivers/mlnx-en-@VERSION@-@MAJOR_RELEASE@.tgz

%package utils
Summary: Utilities for the Mellanox Ethernet Driver for Linux
Group: System Environment/Libraries
conflicts: ofed-scripts

%description utils
Utilities for the Mellanox Ethernet Driver for Linux
The driver sources are located at: http://www.mellanox.com/downloads/Drivers/mlnx-en-@VERSION@-@MAJOR_RELEASE@.tgz

%package KMP
Summary: mlnx-en kernel module(s)
Group: System/Kernel
%description KMP
mlnx-en kernel module(s)
The driver sources are located at: http://www.mellanox.com/downloads/Drivers/mlnx-en-@VERSION@-@MAJOR_RELEASE@.tgz

# build KMP rpms?
%if "%{KMP}" == "1"
%global kernel_release() $(make -C %{1} kernelrelease | grep -v make | tail -1)
BuildRequires: %kernel_module_package_buildreqs
%(echo "Requires: mlnx-en-utils" > ${RPM_BUILD_ROOT}/preamble)
%kernel_module_package -f %{SOURCE1} %flav -p ${RPM_BUILD_ROOT}/preamble
%else # not KMP
%global kernel_source() %{K_SRC}
%global kernel_release() %{KVERSION}
%global flavors_to_build default
%package -n mlnx_en
Version: %{_version}
Release: %{_release}.%{krelver}
Requires: coreutils
Requires: kernel
Requires: pciutils
Requires: grep
Requires: perl
Requires: procps
Requires: module-init-tools
Requires: mlnx-en-utils
Group: System Environment/Base
Summary: Ethernet NIC Driver
%description -n mlnx_en
ConnectX Ehternet device driver
The driver sources are located at: http://www.mellanox.com/downloads/Drivers/mlnx-en-@VERSION@-@MAJOR_RELEASE@.tgz
%endif #end if "%{KMP}" == "1"

#
# setup module sign scripts if paths to the keys are given
#
%global WITH_MOD_SIGN %(if ( test -f "$MODULE_SIGN_PRIV_KEY" && test -f "$MODULE_SIGN_PUB_KEY" ); \
	then \
		echo -n '1'; \
	else \
		echo -n '0'; fi)

%if "%{WITH_MOD_SIGN}" == "1"
# call module sign script
%global __modsign_install_post \
    $RPM_BUILD_DIR/%{name}-%{version}/source/ofed_scripts/tools/sign-modules $RPM_BUILD_ROOT/lib/modules/ || exit 1 \
%{nil}

%global __debug_package 1
%global buildsubdir %{name}-%{version}
# Disgusting hack alert! We need to ensure we sign modules *after* all
# invocations of strip occur, which is in __debug_install_post if
# find-debuginfo.sh runs, and __os_install_post if not.
#
%global __spec_install_post \
  %{?__debug_package:%{__debug_install_post}} \
  %{__arch_install_post} \
  %{__os_install_post} \
  %{__modsign_install_post} \
%{nil}

%endif # end of setup module sign scripts
#

%if "%{_vendor}" == "suse"
%global install_mod_dir updates
%debug_package
%endif

%if "%{_vendor}" == "redhat"
%if 0%{?fedora}
%global install_mod_dir updates
%else
%global install_mod_dir extra/%{name}
%endif
%global __find_requires %{nil}
%endif

%prep
%setup
set -- *
mkdir source
mv "$@" source/
mkdir obj

%build
rm -rf $RPM_BUILD_ROOT
export EXTRA_CFLAGS='-DVERSION=\"%version\"'
for flavor in %{flavors_to_build}; do
	rm -rf obj/$flavor
	cp -r source obj/$flavor
	cd $PWD/obj/$flavor
	export KSRC=%{kernel_source $flavor}
	export KVERSION=%{kernel_release $KSRC}
	export MLNX_EN_PATCH_PARAMS="--kernel $KVERSION --kernel-sources $KSRC"
	%if "%{MEMTRACK}" == "1"
		export MLNX_EN_PATCH_PARAMS="$MLNX_EN_PATCH_PARAMS --with-memtrack"
	%endif
	%if "%{MLX4}" == "0"
		export MLNX_EN_PATCH_PARAMS="$MLNX_EN_PATCH_PARAMS --without-mlx4"
	%endif
	%if "%{MLX5}" == "0"
		export MLNX_EN_PATCH_PARAMS="$MLNX_EN_PATCH_PARAMS --without-mlx5"
	%endif
	find compat -type f -exec touch -t 200012201010 '{}' \; || true
	./scripts/mlnx_en_patch.sh $MLNX_EN_PATCH_PARAMS %{?_smp_mflags}
	make KSRC=$KSRC V=0 %{?_smp_mflags}
	cd -
done
gzip -c source/scripts/mlx4_en.7 > mlx4_en.7.gz

cd source/ofed_scripts/utils
python setup.py build
cd -

%install
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT
export INSTALL_MOD_DIR=%install_mod_dir
for flavor in %{flavors_to_build}; do
	cd $PWD/obj/$flavor
	export KSRC=%{kernel_source $flavor}
	export KVERSION=%{kernel_release $KSRC}
	make install KSRC=$KSRC MODULES_DIR=$INSTALL_MOD_DIR DESTDIR=$RPM_BUILD_ROOT KERNELRELEASE=$KVERSION
	# Cleanup unnecessary kernel-generated module dependency files.
	find $INSTALL_MOD_PATH/lib/modules -iname 'modules.*' -exec rm {} \;
	cd -
done

# Set the module(s) to be executable, so that they will be stripped when packaged.
find %{buildroot} -type f -name \*.ko -exec %{__chmod} u+x \{\} \;

%if "%{_vendor}" == "redhat"
%if "%{KMP}" == "1"
%{__install} -d $RPM_BUILD_ROOT%{_sysconfdir}/depmod.d/
for module in `find $RPM_BUILD_ROOT/ -name '*.ko'`
do
ko_name=${module##*/}
mod_name=${ko_name/.ko/}
mod_path=${module/*%{name}}
mod_path=${mod_path/\/${ko_name}}
echo "override ${mod_name} * weak-updates/%{name}${mod_path}" >> $RPM_BUILD_ROOT%{_sysconfdir}/depmod.d/%{name}.conf
done
%endif
%endif

install -D -m 644 mlx4_en.7.gz $RPM_BUILD_ROOT/%{_mandir}/man7/mlx4_en.7.gz

install -D -m 755 source/ofed_scripts/common_irq_affinity.sh $RPM_BUILD_ROOT/%{_sbindir}/common_irq_affinity.sh
install -D -m 755 source/ofed_scripts/set_irq_affinity.sh $RPM_BUILD_ROOT/%{_sbindir}/set_irq_affinity.sh
install -D -m 755 source/ofed_scripts/show_irq_affinity.sh $RPM_BUILD_ROOT/%{_sbindir}/show_irq_affinity.sh
install -D -m 755 source/ofed_scripts/set_irq_affinity_bynode.sh $RPM_BUILD_ROOT/%{_sbindir}/set_irq_affinity_bynode.sh
install -D -m 755 source/ofed_scripts/set_irq_affinity_cpulist.sh $RPM_BUILD_ROOT/%{_sbindir}/set_irq_affinity_cpulist.sh
install -D -m 755 source/ofed_scripts/sysctl_perf_tuning $RPM_BUILD_ROOT/sbin/sysctl_perf_tuning
install -D -m 755 source/ofed_scripts/mlnx_tune $RPM_BUILD_ROOT/usr/sbin/mlnx_tune
install -D -m 644 source/scripts/mlnx-en.conf $RPM_BUILD_ROOT/etc/mlnx-en.conf
install -D -m 755 source/scripts/mlnx-en.d $RPM_BUILD_ROOT/etc/init.d/mlnx-en.d

mkdir -p $RPM_BUILD_ROOT/%{_prefix}/src
cp -r source $RPM_BUILD_ROOT/%{_prefix}/src/%{name}-%{version}

touch ofed-files
cd source/ofed_scripts/utils
python setup.py install -O1 --root=$RPM_BUILD_ROOT --record ../../../ofed-files
cd -

if [[ "$(ls %{buildroot}/%{_bindir}/tc_wrap.py* 2>/dev/null)" != "" ]]; then
	echo '%{_bindir}/tc_wrap.py*' >> ofed-files
fi

%if 0%{?suse_version} == 1315
install -D -m 644 source/scripts/mlnx-en.d.service $RPM_BUILD_ROOT/%{_prefix}/lib/systemd/system/mlnx-en.d.service
%endif

%postun doc
if [ -f %{_mandir}/man7/mlx4_en.7.gz ]; then
	exit 0
fi

%if "%{KMP}" != "1"
%post -n mlnx_en
/sbin/depmod -r -ae %{KVERSION}

%postun -n mlnx_en
if [ $1 = 0 ]; then  # 1 : Erase, not upgrade
	/sbin/depmod -r -ae %{KVERSION}
fi
%endif

%post -n mlnx-en-utils
if [ $1 -eq 1 ]; then # 1 : This package is being installed

if [[ -f /etc/redhat-release || -f /etc/rocks-release ]]; then        
perl -i -ne 'if (m@^#!/bin/bash@) {
        print q@#!/bin/bash
#
# Bring up/down mlnx-en.d
#
# chkconfig: 2345 05 95
# description: Activates/Deactivates mlnx-en Driver to \
#              start at boot time.
#
### BEGIN INIT INFO
# Provides:       mlnx-en.d
### END INIT INFO
@;
                 } else {
                     print;
                 }' /etc/init.d/mlnx-en.d

        if ! ( /sbin/chkconfig --del mlnx-en.d > /dev/null 2>&1 ); then
                true
        fi
        if ! ( /sbin/chkconfig --add mlnx-en.d > /dev/null 2>&1 ); then
                true
        fi
fi

if [ -f /etc/SuSE-release ]; then
    local_fs='$local_fs'
        perl -i -ne "if (m@^#!/bin/bash@) {
        print q@#!/bin/bash
### BEGIN INIT INFO
# Provides:       mlnx-en.d
# Required-Start: $local_fs
# Required-Stop: 
# Default-Start:  2 3 5
# Default-Stop: 0 1 2 6
# Description:    Activates/Deactivates mlnx-en.d Driver to \
#                 start at boot time.
### END INIT INFO
@;
                 } else {
                     print;
                 }" /etc/init.d/mlnx-en.d

        if ! ( /sbin/insserv mlnx-en.d > /dev/null 2>&1 ); then
                true
        fi
        if ! ( /sbin/chkconfig mlnx-en.d on > /dev/null 2>&1 ); then
                true
        fi
fi

%if 0%{?suse_version} == 1315
/usr/bin/systemctl daemon-reload >/dev/null 2>&1 || :
%endif

fi # 1 : closed
# END of post utils

%preun -n mlnx-en-utils
if [ $1 = 0 ]; then  # 1 : Erase, not upgrade
          if [[ -f /etc/redhat-release || -f /etc/rocks-release ]]; then        
                if ! ( /sbin/chkconfig --del mlnx-en.d  > /dev/null 2>&1 ); then
                        true
                fi
          fi
          if [ -f /etc/SuSE-release ]; then
                if ! ( /sbin/insserv -r mlnx-en.d > /dev/null 2>&1 ); then
                        true
                fi
                if ! ( /sbin/chkconfig mlnx-en.d off > /dev/null 2>&1 ); then
                        true
                fi
          fi
fi
# END of pre uninstall utils

%postun -n mlnx-en-utils
%if 0%{?suse_version} == 1315
/usr/bin/systemctl daemon-reload >/dev/null 2>&1 || :
%endif
#end of post uninstall

%clean
rm -rf %{buildroot}

%if "%{KMP}" != "1"
%files -n mlnx_en
/lib/modules/%{KVERSION}/
%endif

%files doc
%defattr(-,root,root,-)
%{_mandir}/man7/mlx4_en.7.gz

%files sources
%defattr(-,root,root,-)
%{_prefix}/src/%{name}-%{version}

%files utils -f ofed-files
%defattr(-,root,root,-)
%{_sbindir}/*
/sbin/*
%config(noreplace) /etc/mlnx-en.conf
/etc/init.d/mlnx-en.d
%if 0%{?suse_version} == 1315
%{_prefix}/lib/systemd/system/mlnx-en.d.service
%endif

%changelog
* Mon Mar 24 2014 Alaa Hleihel <alaa@mellanox.com>
- Use one source rpm for KMP and none-KMP rpms.
* Tue May 1 2012 Vladimir Sokolovsky <vlad@mellanox.com>
- Created spec file for mlnx_en

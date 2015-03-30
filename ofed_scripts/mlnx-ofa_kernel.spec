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

%{!?configure_options: %global configure_options %{nil}}

%global MEMTRACK %(if ( echo %{configure_options} | grep "with-memtrack" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%global MADEYE %(if ( echo %{configure_options} | grep "with-madeye-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)

%{!?KVERSION: %global KVERSION %(uname -r)}
%global kernel_version %{KVERSION}
%global krelver %(echo -n %{KVERSION} | sed -e 's/-/_/g')
# take path to kernel sources if provided, otherwise look in default location (for non KMP rpms).
%{!?K_SRC: %global K_SRC /lib/modules/%{KVERSION}/build}

# Select packages to build

# Kernel module packages to be included into kernel-ib
%ifarch x86_64
%global build_qib %(if ( echo %{configure_options} | grep "with-qib-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%else
%global build_qib 0
%endif
%global build_ipoib %(if ( echo %{configure_options} | grep "with-ipoib-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%global build_eipoib %(if ( echo %{configure_options} | grep "with-e_ipoib-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%global build_sdp %(if ( echo %{configure_options} | grep "with-sdp-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%global build_oiscsi %(if ( echo %{configure_options} | grep "with-iscsi-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%global build_mlx4 %(if ( echo %{configure_options} | grep "with-mlx4-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%global build_mlx5 %(if ( echo %{configure_options} | grep "with-mlx5-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%global build_mlx4_en %(if ( echo %{configure_options} | grep "with-mlx4_en-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%global build_mlx4_vnic %(if ( echo %{configure_options} | grep "with-mlx4_vnic-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)

%{!?LIB_MOD_DIR: %global LIB_MOD_DIR /lib/modules/%{KVERSION}/updates}

%{!?IB_CONF_DIR: %global IB_CONF_DIR /etc/infiniband}

%{!?KERNEL_SOURCES: %global KERNEL_SOURCES /lib/modules/%{KVERSION}/source}

%{!?_name: %global _name mlnx-ofa_kernel}
%{!?_version: %global _version @VERSION@}
%{!?_release: %global _release @RELEASE@}

%if "%{KMP}" == "1"
%global devel_pname %{_name}-devel
%global p_name mlnx-ofa_kernel
%else
%global devel_pname kernel-ib-devel
%global p_name kernel-ib
%endif

Summary: Infiniband HCA Driver
Name: %{_name}
Version: %{_version}
Release: %{_release}%{?_dist}
License: GPLv2 or BSD
Url: http://www.mellanox.com/
Group: System Environment/Base
Source: %{_name}-%{_version}.tgz
BuildRoot: %{?build_root:%{build_root}}%{!?build_root:/var/tmp/OFED}
Vendor: Mellanox Technologies
Obsoletes: kernel-ib
Obsoletes: compat-rdma
Requires: coreutils
Requires: pciutils
Requires: grep
Requires: perl
Requires: procps
Requires: module-init-tools
Requires: lsof
%description 
InfiniBand "verbs", Access Layer  and ULPs

BuildRequires: sysfsutils-devel

# build KMP rpms?
%if "%{KMP}" == "1"
%global kernel_release() $(make -C %{1} kernelrelease | grep -v make | tail -1)
BuildRequires: %kernel_module_package_buildreqs
%{kernel_module_package}
%else # not KMP
%global kernel_source() %{K_SRC}
%global kernel_release() %{KVERSION}
%global flavors_to_build default
%package -n kernel-ib
Requires: coreutils
Requires: pciutils
Requires: grep
Requires: perl
Requires: procps
Requires: module-init-tools
Requires: lsof
Version: %{_version}
Release: %{krelver}_%{_release}
Summary: Infiniband Driver and ULPs kernel modules
Group: System Environment/Libraries
%description -n kernel-ib
Core, HW and ULPs kernel modules
%endif #end if "%{KMP}" == "1"

%package -n %{devel_pname}
Version: %{_version}
# build KMP rpms?
%if "%{KMP}" == "1"
Release: %{_release}%{?_dist}
Obsoletes: kernel-ib-devel
Obsoletes: compat-rdma-devel
%else
Release: %{krelver}_%{_release}
Requires: coreutils
Requires: pciutils
Requires: kernel-ib
%endif
Summary: Infiniband Driver and ULPs kernel modules sources
Group: System Environment/Libraries
%description -n %{devel_pname}
Core, HW and ULPs kernel modules sources

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
    $RPM_BUILD_DIR/$NAME-$VERSION/source/ofed_scripts/tools/sign-modules $RPM_BUILD_ROOT/lib/modules/ || exit 1 \
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
%setup -n %{_name}-%{_version}
set -- *
mkdir source
mv "$@" source/
mkdir obj

%build
export EXTRA_CFLAGS='-DVERSION=\"%version\"'
export INSTALL_MOD_DIR=%install_mod_dir
export CONF_OPTIONS="%{configure_options}"
for flavor in %flavors_to_build; do
	export KSRC=%{kernel_source $flavor}
	export KVERSION=%{kernel_release $KSRC}
	export LIB_MOD_DIR=/lib/modules/$KVERSION/$INSTALL_MOD_DIR
	rm -rf obj/$flavor
	cp -a source obj/$flavor
	cd $PWD/obj/$flavor
	find compat -type f -exec touch -t 200012201010 '{}' \; || true
	./configure --prefix=%{_prefix} --kernel-version $KVERSION --kernel-sources $KSRC --modules-dir $LIB_MOD_DIR $CONF_OPTIONS %{?_smp_mflags}
	make %{?_smp_mflags} kernel
	make build_py_scripts
	cd -
done

%install
touch ofed-files
export RECORD_PY_FILES=1
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT
export INSTALL_MOD_DIR=%install_mod_dir
export NAME=$RPM_PACKAGE_NAME
export VERSION=$RPM_PACKAGE_VERSION
export PREFIX=%{_prefix}
for flavor in %flavors_to_build; do 
	export KSRC=%{kernel_source $flavor}
	export KVERSION=%{kernel_release $KSRC}
	cd $PWD/obj/$flavor
	make install_modules KERNELRELEASE=$KVERSION
	# install script and configuration files
	make install_scripts
	mkdir -p $RPM_BUILD_ROOT/$PREFIX/src/$NAME/$flavor
	mkdir -p $RPM_BUILD_DIR/src/$NAME/$flavor
	cp -ar include/ $RPM_BUILD_DIR/src/$NAME/$flavor
	cp -ar config* $RPM_BUILD_DIR/src/$NAME/$flavor
	cp -ar compat*  $RPM_BUILD_DIR/src/$NAME/$flavor
	cp -ar ofed_scripts $RPM_BUILD_DIR/src/$NAME/$flavor

	modsyms=`find . -name Module.symvers -o -name Modules.symvers`
	if [ -n "$modsyms" ]; then
		for modsym in $modsyms
		do
			cat $modsym >> $RPM_BUILD_DIR/src/$NAME/$flavor/Module.symvers
		done
	else
		./ofed_scripts/create_Module.symvers.sh
		cp ./Module.symvers $RPM_BUILD_DIR/src/$NAME/$flavor/Module.symvers
	fi
	# Cleanup unnecessary kernel-generated module dependency files.
	find $INSTALL_MOD_PATH/lib/modules -iname 'modules.*' -exec rm {} \;
	cd -
done

if [[ "$(ls %{buildroot}/%{_bindir}/tc_wrap.py* 2>/dev/null)" != "" ]]; then
	echo '%{_bindir}/tc_wrap.py*' >> ofed-files
fi

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

# copy sources
mkdir -p $RPM_BUILD_ROOT/%{_prefix}/src
cp -ar $RPM_BUILD_DIR/$NAME-$VERSION/source $RPM_BUILD_ROOT/%{_prefix}/src/ofa_kernel-$VERSION
cd $RPM_BUILD_ROOT/%{_prefix}/src/
ln -snf ofa_kernel-$VERSION mlnx-ofa_kernel-$VERSION
cd -
cp -ar $RPM_BUILD_DIR/src/$NAME $RPM_BUILD_ROOT/%{_prefix}/src/ofa_kernel
rm -rf $RPM_BUILD_DIR/src
%ifarch ppc64
if [ ! -d "$RPM_BUILD_ROOT/%{_prefix}/src/ofa_kernel/default" ]; then
    ln -snf /%{_prefix}/src/ofa_kernel/ppc64 $RPM_BUILD_ROOT/%{_prefix}/src/ofa_kernel/default
fi
%endif

INFO=${RPM_BUILD_ROOT}/etc/infiniband/info
/bin/rm -f ${INFO}
mkdir -p ${RPM_BUILD_ROOT}/etc/infiniband
touch ${INFO}

cat >> ${INFO} << EOFINFO
#!/bin/bash

echo prefix=%{_prefix}
echo Kernel=%{KVERSION}
echo
echo "Configure options: %{configure_options}"
echo
EOFINFO

chmod +x ${INFO} > /dev/null 2>&1

%if 0%{?suse_version} == 1315
install -d $RPM_BUILD_ROOT/%{_prefix}/lib/systemd/system
install -m 0644 $RPM_BUILD_DIR/$NAME-$VERSION/source/ofed_scripts/openibd.service $RPM_BUILD_ROOT/%{_prefix}/lib/systemd/system
%endif
install -d $RPM_BUILD_ROOT/bin
install -m 0755 $RPM_BUILD_DIR/$NAME-$VERSION/source/ofed_scripts/mlnx_interface_mgr.sh $RPM_BUILD_ROOT/bin/

%clean
rm -rf %{buildroot}

%post -n %{p_name}
if [ $1 -eq 1 ]; then # 1 : This package is being installed

/sbin/depmod %{KVERSION}

#############################################################################################################


if [[ -f /etc/redhat-release || -f /etc/rocks-release ]]; then        
perl -i -ne 'if (m@^#!/bin/bash@) {
        print q@#!/bin/bash
#
# Bring up/down openib
#
# chkconfig: 2345 05 95
# description: Activates/Deactivates InfiniBand Driver to \
#              start at boot time.
#
### BEGIN INIT INFO
# Provides:       openibd
### END INIT INFO
@;
                 } else {
                     print;
                 }' /etc/init.d/openibd

        if ! ( /sbin/chkconfig --del openibd > /dev/null 2>&1 ); then
                true
        fi
        if ! ( /sbin/chkconfig --add openibd > /dev/null 2>&1 ); then
                true
        fi
fi

if [ -f /etc/SuSE-release ]; then
    local_fs='$local_fs'
    openiscsi=''
    %if %{build_oiscsi}
        openiscsi='open-iscsi'
    %endif
        perl -i -ne "if (m@^#!/bin/bash@) {
        print q@#!/bin/bash
### BEGIN INIT INFO
# Provides:       openibd
# Required-Start: $local_fs
# Required-Stop: opensmd $openiscsi
# Default-Start:  2 3 5
# Default-Stop: 0 1 2 6
# Description:    Activates/Deactivates InfiniBand Driver to \
#                 start at boot time.
### END INIT INFO
@;
                 } else {
                     print;
                 }" /etc/init.d/openibd

        if ! ( /sbin/insserv openibd > /dev/null 2>&1 ); then
                true
        fi
        if ! ( /sbin/chkconfig openibd on > /dev/null 2>&1 ); then
                true
        fi
fi

if [ -f /etc/debian_version ]; then
    local_fs='$local_fs'
    openiscsi=''
    %if %{build_oiscsi}
        openiscsi='open-iscsi'
    %endif
        perl -i -ne "if (m@^#!/bin/bash@) {
        print q@#!/bin/bash
### BEGIN INIT INFO
# Provides:       openibd
# Required-Start: $local_fs
# Required-Stop: opensmd $openiscsi
# Default-Start:  2 3 5
# Default-Stop: 0 1 2 6
# Description:    Activates/Deactivates InfiniBand Driver to \
#                 start at boot time.
### END INIT INFO
@;
                 } else {
                     print;
                 }" /etc/init.d/openibd

        if ! ( /usr/sbin/update-rc.d openibd defaults > /dev/null 2>&1 ); then
                true
        fi
fi

%if 0%{?suse_version} == 1315
/usr/bin/systemctl daemon-reload >/dev/null 2>&1 || :
%endif

fi # 1 : closed
# END of post

%preun -n %{p_name}
if [ $1 = 0 ]; then  # 1 : Erase, not upgrade
          if [[ -f /etc/redhat-release || -f /etc/rocks-release ]]; then        
                if ! ( /sbin/chkconfig --del openibd  > /dev/null 2>&1 ); then
                        true
                fi
          fi
          if [ -f /etc/SuSE-release ]; then
                if ! ( /sbin/insserv -r openibd > /dev/null 2>&1 ); then
                        true
                fi
		        if ! ( /sbin/chkconfig openibd off > /dev/null 2>&1 ); then
                        true
                fi
          fi
          if [ -f /etc/debian_version ]; then
                if ! ( /usr/sbin/update-rc.d openibd remove > /dev/null 2>&1 ); then
                        true
                fi
          fi
fi

%postun -n %{p_name}
%if 0%{?suse_version} == 1315
/usr/bin/systemctl daemon-reload >/dev/null 2>&1 || :
%endif
#end of post uninstall

%files -n %{p_name} -f ofed-files
%defattr(-,root,root,-)
%if "%{KMP}" == "1"
%if "%{_vendor}" == "redhat"
%{_sysconfdir}/depmod.d
%endif # end rh
%else # not KMP
/lib/modules/%{KVERSION}/
%endif
%dir /etc/infiniband
%config(noreplace) /etc/infiniband/openib.conf
/etc/infiniband/info
/etc/init.d/openibd
%if 0%{?suse_version} == 1315
%{_prefix}/lib/systemd/system/openibd.service
%endif
/sbin/sysctl_perf_tuning
/usr/sbin/mlnx_tune
%config(noreplace) /etc/modprobe.d/mlnx.conf
%{_sbindir}/*
/etc/udev/rules.d/90-ib.rules
/bin/mlnx_interface_mgr.sh
%if %{build_qib}
%config(noreplace) /etc/infiniband/truescale.cmds
%endif
%if %{build_ipoib}
/etc/modprobe.d/ib_ipoib.conf
%if %{build_eipoib}
/sbin/ipoibd
/sbin/eipoib_daemon
%endif
%endif
%if %{build_sdp}
/etc/modprobe.d/ib_sdp.conf
%endif
%if %{build_mlx4} || %{build_mlx5}
%{_bindir}/ibdev2netdev
%endif
%if %{build_mlx4_en}
/sbin/connectx_port_config
%config(noreplace) /etc/infiniband/connectx.conf
%endif
%if %{build_mlx4_vnic}
/etc/init.d/mlx4_vnic_confd
/sbin/mlx4_vnic_info
/sbin/mlx4_vnicd
%endif

%files -n %{devel_pname}
%defattr(-,root,root,-)
%{_prefix}/src

%changelog
* Thu Apr 10 2014 Alaa Hleihel <alaa@mellanox.com>
- Add QoS utils.
* Thu Mar 13 2014 Alaa Hleihel <alaa@mellanox.com>
- Use one spec for KMP and non-KMP OS's.
* Tue Apr 24 2012 Vladimir Sokolovsky <vlad@mellanox.com>
- Remove FC support
* Tue Mar 6 2012 Vladimir Sokolovsky <vlad@mellanox.com>
- Add weak updates support
* Wed Jul 6 2011 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Add KMP support
* Mon Oct 4 2010 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Add mlx4_fc and mlx4_vnic support
* Mon May 10 2010 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Support install macro that removes RPM_BUILD_ROOT
* Thu Feb 4 2010 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Added ibdev2netdev script
* Wed Sep 8 2008 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Added nfsrdma support
* Wed Aug 13 2008 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Added mlx4_en support
* Tue Aug 21 2007 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Added %build macro
* Sun Jan 28 2007 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Created spec file for kernel-ib

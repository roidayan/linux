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

%{!?configure_options: %define configure_options %{nil}}

%define MEMTRACK %(if ( echo %{configure_options} | grep "with-memtrack" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define MADEYE %(if ( echo %{configure_options} | grep "with-madeye-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)

%{!?KVERSION: %define KVERSION %(uname -r)}
%define krelver %(echo -n %{KVERSION} | sed -e 's/-/_/g')

%{!?build_kernel_ib: %define build_kernel_ib 0}
%{!?build_kernel_ib_devel: %define build_kernel_ib_devel 0}

# Select packages to build
%{!?modprobe_update: %define modprobe_update %(if ( echo %{configure_options} | grep "without-modprobe" > /dev/null ); then echo -n '0'; else echo -n '1'; fi)}

# Kernel module packages to be included into kernel-ib
%define build_mthca %(if ( echo %{configure_options} | grep "with-mthca-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_qib %(if ( echo %{configure_options} | grep "with-qib-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_ipath %(if ( echo %{configure_options} | grep "with-ipath_inf-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_ehca %(if ( echo %{configure_options} | grep "with-ehca-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_ipoib %(if ( echo %{configure_options} | grep "with-ipoib-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_eipoib %(if ( echo %{configure_options} | grep "with-e_ipoib-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_sdp %(if ( echo %{configure_options} | grep "with-sdp-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_srp %(if ( echo %{configure_options} | grep "with-srp-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_srpt %(if ( echo %{configure_options} | grep "with-srp-target-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_iser %(if ( echo %{configure_options} | grep "with-iser-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_oiscsi %(if ( echo %{configure_options} | grep "with-iscsi-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_rds %(if ( echo %{configure_options} | grep "with-rds-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_cxgb3 %(if ( echo %{configure_options} | grep "with-cxgb3-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_nes %(if ( echo %{configure_options} | grep "with-nes-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_mlx4 %(if ( echo %{configure_options} | grep "with-mlx4-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_mlx5 %(if ( echo %{configure_options} | grep "with-mlx5-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_mlx4_en %(if ( echo %{configure_options} | grep "with-mlx4_en-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_mlx4_vnic %(if ( echo %{configure_options} | grep "with-mlx4_vnic-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_qlgc_vnic %(if ( echo %{configure_options} | grep "with-qlgc_vnic-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%define build_nfsrdma %(if ( echo %{configure_options} | grep "with-nfsrdma-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)

%{!?LIB_MOD_DIR: %define LIB_MOD_DIR /lib/modules/%{KVERSION}/updates}

%define LIB_MOD_DIR_INF %{LIB_MOD_DIR}/kernel/drivers/infiniband
%define LIB_MOD_DIR_NET %{LIB_MOD_DIR}/kernel/drivers/net
%define LIB_MOD_DIR_SCSI %{LIB_MOD_DIR}/kernel/drivers/scsi
%define LIB_MOD_DIR_KERNEL_NET %{LIB_MOD_DIR}/kernel/net
%define LIB_MOD_DIR_KERNEL_FS %{LIB_MOD_DIR}/kernel/fs

%{!?IB_CONF_DIR: %define IB_CONF_DIR /etc/infiniband}
%{!?MLXNET_CONF_DIR: %define MLXNET_CONF_DIR /etc/mlxethernet}

%{!?K_SRC: %define K_SRC /lib/modules/%{KVERSION}/build}

%{!?KERNEL_SOURCES: %define KERNEL_SOURCES /lib/modules/%{KVERSION}/source}

# Do not include srp.h if it exist in the kernel
%define include_srp_h %(if [ -e %{KERNEL_SOURCES}/include/scsi/srp.h ]; then echo -n 0; else echo -n 1; fi )
%define include_rdma %(if [ -d %{KERNEL_SOURCES}/include/rdma ]; then echo -n 1; else echo -n 0; fi )

%define include_udev_rules %(eval `grep udev_rules /etc/udev/udev.conf | grep -v '^#'` ; if test -d $udev_rules; then echo -n 1; else echo -n 0; fi)

# Disable debugging
%define debug_package %{nil}
%define __check_files %{nil}

# Disable brp-lib64-linux
%ifarch x86_64 ia64
%define __arch_install_post %{nil}
%endif

%{!?_name: %define _name mlnx-ofa_kernel}
%{!?_version: %define _version @VERSION@}
%{!?_release: %define _release @RELEASE@}

Summary: Infiniband HCA Driver
Name: %{_name}
Version: %{_version}
Release: %{_release}%{?_dist}
License: GPL/BSD
Url: http://openfabrics.org/
Group: System Environment/Base
Source: %{_name}-%{_version}.tgz
BuildRoot: %{?build_root:%{build_root}}%{!?build_root:/var/tmp/OFED}
Vendor: OpenFabrics
%description 
InfiniBand "verbs", Access Layer  and ULPs

%package devel
Version: %{_version}
Release: %{_release}%{?_dist}
Summary: Infiniband Driver and ULPs kernel modules sources
Group: System Environment/Libraries
%description devel
Core, HW and ULPs kernel modules sources

# KMP
%define debug_package %{nil}

BuildRequires: %kernel_module_package_buildreqs
%kernel_module_package
%description
Core, HW and ULPs kernel modules

%if "%{_vendor}" == "suse"
%define install_mod_dir updates
%endif

%if "%{_vendor}" == "redhat"
%define install_mod_dir extra/%{name}
%define __find_requires %{nil}
%endif

%prep
%setup
set -- *
mkdir source
mv "$@" source/
mkdir obj

%build
export EXTRA_CFLAGS='-DVERSION=\"%version\"'
export INSTALL_MOD_DIR=%install_mod_dir
export CONF_OPTIONS="%{configure_options}"
export BUILD_SRPT=%{build_srpt}
for flavor in %flavors_to_build; do
	export KSRC=%{kernel_source $flavor}
	export KVERSION=`make -C $KSRC kernelrelease | grep -v make`
	export LIB_MOD_DIR=/lib/modules/$KVERSION/$INSTALL_MOD_DIR
	rm -rf obj/$flavor
	cp -r source obj/$flavor
	cd $PWD/obj/$flavor
        ./configure --prefix=%{_prefix} --kernel-version $KVERSION --kernel-sources $KSRC --modules-dir $LIB_MOD_DIR $CONF_OPTIONS
	if [ $BUILD_SRPT -eq 1 ]; then
		if [ -f /usr/local/include/scst/Module.symvers ]; then
		        cat /usr/local/include/scst/Module.symvers >> ./Module.symvers
		fi
	fi
	make kernel
	cd -
done

%install
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT
export INSTALL_MOD_DIR=%install_mod_dir
export NAME=$RPM_PACKAGE_NAME
export VERSION=$RPM_PACKAGE_VERSION
export PREFIX=%{_prefix}
for flavor in %flavors_to_build; do 
	export KSRC=%{kernel_source $flavor}
	export KVERSION=`make -C $KSRC kernelrelease | grep -v make`
	cd $PWD/obj/$flavor
	make install_modules
	mkdir -p $RPM_BUILD_ROOT/$PREFIX/src/$NAME/$flavor
	mkdir -p $RPM_BUILD_DIR/src/$NAME/$flavor
	cp -ar include/ $RPM_BUILD_DIR/src/$NAME/$flavor
	cp -ar config* $RPM_BUILD_DIR/src/$NAME/$flavor
	cp -ar compat*  $RPM_BUILD_DIR/src/$NAME/$flavor

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
	cd -
done

%if "%{_vendor}" == "redhat"
# Set the module(s) to be executable, so that they will be stripped when packaged.
find %{buildroot} -type f -name \*.ko -exec %{__chmod} u+x \{\} \;

%{__install} -d $RPM_BUILD_ROOT%{_sysconfdir}/depmod.d/
for module in `find $RPM_BUILD_ROOT/ -name '*.ko'`
do
ko_name=${module##*/}
mod_name=${ko_name/.ko/}
mod_path=${module/*%{name}}
mod_path=${mod_path/\/${ko_name}}
echo "override ${mod_name} * weak-updates/%{name}${mod_path}" > $RPM_BUILD_ROOT%{_sysconfdir}/depmod.d/${mod_name}.conf
done
%else
find %{buildroot} -type f -name \*.ko -exec %{__strip} -p --strip-debug --discard-locals -R .comment -R .note \{\} \;
%endif

mkdir -p $RPM_BUILD_ROOT/%{_prefix}/src
cp -ar $RPM_BUILD_DIR/$NAME-$VERSION/source $RPM_BUILD_ROOT/%{_prefix}/src/ofa_kernel-$VERSION
cp -ar $RPM_BUILD_DIR/src/$NAME $RPM_BUILD_ROOT/%{_prefix}/src/ofa_kernel
rm -rf $RPM_BUILD_DIR/src

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

# Copy infiniband configuration
install -d $RPM_BUILD_ROOT//etc/infiniband
install -m 0644 $RPM_BUILD_DIR/$NAME-$VERSION/source/ofed_scripts/openib.conf $RPM_BUILD_ROOT//etc/infiniband

# Install openib service script
install -d $RPM_BUILD_ROOT/etc/init.d
install -m 0755 $RPM_BUILD_DIR/$NAME-$VERSION/source/ofed_scripts/openibd $RPM_BUILD_ROOT/etc/init.d
install -d $RPM_BUILD_ROOT/sbin
install -m 0755 $RPM_BUILD_DIR/$NAME-$VERSION/source/ofed_scripts/sysctl_perf_tuning $RPM_BUILD_ROOT/sbin
install -d $RPM_BUILD_ROOT/%{_sbindir}
install -m 0755 $RPM_BUILD_DIR/$NAME-$VERSION/source/ofed_scripts/*affinity* $RPM_BUILD_ROOT/%{_sbindir}

install -d $RPM_BUILD_ROOT/etc/modprobe.d
install -m 0644 $RPM_BUILD_DIR/$NAME-$VERSION/source/ofed_scripts/mlnx.conf $RPM_BUILD_ROOT/etc/modprobe.d

%if %{build_mlx4} || %{build_mlx5}
install -d $RPM_BUILD_ROOT/%{_bindir}
install -m 0755 $RPM_BUILD_DIR/$NAME-$VERSION/source/ofed_scripts/ibdev2netdev $RPM_BUILD_ROOT/%{_bindir}
install -m 0755 $RPM_BUILD_DIR/$NAME-$VERSION/source/ofed_scripts/cx_virt_config.py $RPM_BUILD_ROOT/sbin
%endif

%if %{build_mlx4_en}
install -d $RPM_BUILD_ROOT/sbin
install -m 0755 $RPM_BUILD_DIR/$NAME-$VERSION/source/ofed_scripts/connectx_port_config $RPM_BUILD_ROOT/sbin
touch $RPM_BUILD_ROOT//etc/infiniband/connectx.conf
%endif

%if %{build_qib}
install -m 0644 $RPM_BUILD_DIR/$NAME-$VERSION/source/ofed_scripts/truescale.cmds $RPM_BUILD_ROOT//etc/infiniband
%endif

%if %{build_ipoib}
install -d $RPM_BUILD_ROOT/etc/modprobe.d
install -m 0644 $RPM_BUILD_DIR/$NAME-$VERSION/source/ofed_scripts/ib_ipoib.conf $RPM_BUILD_ROOT/etc/modprobe.d
%endif

%if %{build_eipoib}
install -m 0755 $RPM_BUILD_DIR/$NAME-$VERSION/source/ofed_scripts/ipoibd $RPM_BUILD_ROOT/sbin 
%endif

%if %{build_sdp}
install -d $RPM_BUILD_ROOT/etc/modprobe.d
install -m 0644 $RPM_BUILD_DIR/$NAME-$VERSION/source/ofed_scripts/ib_sdp.conf $RPM_BUILD_ROOT/etc/modprobe.d
%endif

%if %{build_mlx4_vnic}
install -d $RPM_BUILD_ROOT/sbin
install -m 0755 $RPM_BUILD_DIR/$NAME-$VERSION/source/ofed_scripts/mlx4_vnic_info $RPM_BUILD_ROOT/sbin
install -m 0755 $RPM_BUILD_DIR/$NAME-$VERSION/source/ofed_scripts/mlx4_vnicd $RPM_BUILD_ROOT/sbin
install -m 0755 $RPM_BUILD_DIR/$NAME-$VERSION/source/ofed_scripts/mlx4_vnic_confd $RPM_BUILD_ROOT/etc/init.d
%endif

%if %{include_udev_rules}
install -d $RPM_BUILD_ROOT/etc/udev/rules.d
install -m 0644 $RPM_BUILD_DIR/$NAME-$VERSION/source/ofed_scripts/90-ib.rules $RPM_BUILD_ROOT/etc/udev/rules.d
case "$(udevinfo -V 2> /dev/null | awk '{print $NF}' 2> /dev/null)" in
0[1-4]*)
sed -i -e 's/KERNEL==/KERNEL=/g'  $RPM_BUILD_ROOT/etc/udev/rules.d/90-ib.rules
;;
esac
%endif

%clean
rm -rf %{buildroot}

%post
if [ $1 -ge 1 ]; then # 1 : This package is being installed or reinstalled

%if %{build_ipoib}
for (( i=0 ; i < 6 ; i++ ))
do
cat >> /etc/modprobe.d/ib_ipoib.conf << EOF
alias netdev-ib${i} ib_ipoib
EOF
done
%endif
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

#%if %{build_kernel_ib}
    echo >> /etc/infiniband/openib.conf
    echo "# Load UCM module" >> /etc/infiniband/openib.conf
    echo "UCM_LOAD=yes" >> /etc/infiniband/openib.conf
    echo >> /etc/infiniband/openib.conf
    echo "# Load RDMA_CM module" >> /etc/infiniband/openib.conf
    echo "RDMA_CM_LOAD=yes" >> /etc/infiniband/openib.conf
    echo >> /etc/infiniband/openib.conf
    echo "# Load RDMA_UCM module" >> /etc/infiniband/openib.conf
    echo "RDMA_UCM_LOAD=yes" >> /etc/infiniband/openib.conf
    echo >> /etc/infiniband/openib.conf
    echo "# Increase ib_mad thread priority" >> /etc/infiniband/openib.conf
    echo "RENICE_IB_MAD=no" >> /etc/infiniband/openib.conf
    echo >> /etc/infiniband/openib.conf
    echo "# Run sysctl performance tuning script" >> /etc/infiniband/openib.conf
    echo "RUN_SYSCTL=yes" >> /etc/infiniband/openib.conf
#%endif

%if %{build_mthca}
       echo >> /etc/infiniband/openib.conf                                                
       echo "# Load MTHCA" >> /etc/infiniband/openib.conf
       echo "MTHCA_LOAD=yes" >> /etc/infiniband/openib.conf
%endif

%if %{build_qib}
       echo >> /etc/infiniband/openib.conf
       echo "# Load QIB" >> /etc/infiniband/openib.conf
       echo "QIB_LOAD=yes" >> /etc/infiniband/openib.conf
%endif

%if %{build_ipath}
       echo >> /etc/infiniband/openib.conf                                                
       echo "# Load IPATH" >> /etc/infiniband/openib.conf
       echo "IPATH_LOAD=yes" >> /etc/infiniband/openib.conf
%endif

%if %{build_ehca}
       echo >> /etc/infiniband/openib.conf                                                
       echo "# Load eHCA" >> /etc/infiniband/openib.conf
       echo "EHCA_LOAD=yes" >> /etc/infiniband/openib.conf
%endif

%if %{build_mlx4}
       echo >> /etc/infiniband/openib.conf
       echo "# Load MLX4 modules" >> /etc/infiniband/openib.conf
       echo "MLX4_LOAD=yes" >> /etc/infiniband/openib.conf
%endif

%if %{build_mlx5}
       echo >> /etc/infiniband/openib.conf
       echo "# Load MLX5 modules" >> /etc/infiniband/openib.conf
       echo "MLX5_LOAD=yes" >> /etc/infiniband/openib.conf
%endif

%if %{build_mlx4_en}
       echo >> /etc/infiniband/openib.conf
       echo "# Load MLX4_EN module" >> /etc/infiniband/openib.conf
       echo "MLX4_EN_LOAD=yes" >> /etc/infiniband/openib.conf
%endif

%if %{build_mlx4_vnic}
       echo >> /etc/infiniband/openib.conf
       echo "# Load MLX4_VNIC module" >> /etc/infiniband/openib.conf
       echo "MLX4_VNIC_LOAD=no" >> /etc/infiniband/openib.conf

#       if [[ -f /etc/redhat-release || -f /etc/rocks-release ]]; then        
#               if ! ( /sbin/chkconfig --del mlx4_vnic_confd > /dev/null 2>&1 ); then
#                       true
#               fi
#               if ! ( /sbin/chkconfig --add mlx4_vnic_confd > /dev/null 2>&1 ); then
#                       true
#               fi
#       fi
#       
#       if [ -f /etc/SuSE-release ]; then
#               if ! ( /sbin/insserv mlx4_vnic_confd > /dev/null 2>&1 ); then
#                       true
#               fi
#       fi
#       
#       if [ -f /etc/debian_version ]; then
#               if ! ( /usr/sbin/update-rc.d mlx4_vnic_confd defaults > /dev/null 2>&1 ); then
#                       true
#               fi
#       fi
%endif

%if %{build_cxgb3}
       echo >> /etc/infiniband/openib.conf                                                
       echo "# Load CXGB3 modules" >> /etc/infiniband/openib.conf
       echo "CXGB3_LOAD=yes" >> /etc/infiniband/openib.conf
%endif

%if %{build_nes}
       echo >> /etc/infiniband/openib.conf                                                
       echo "# Load NES modules" >> /etc/infiniband/openib.conf
       echo "NES_LOAD=yes" >> /etc/infiniband/openib.conf
%endif

%if %{build_ipoib}
       echo >> /etc/infiniband/openib.conf                                                
       echo "# Load IPoIB" >> /etc/infiniband/openib.conf
       echo "IPOIB_LOAD=yes" >> /etc/infiniband/openib.conf
       echo >> /etc/infiniband/openib.conf                                                
       echo "# Enable IPoIB Connected Mode" >> /etc/infiniband/openib.conf
       echo "SET_IPOIB_CM=auto" >> /etc/infiniband/openib.conf
%endif

%if %{build_eipoib}
       echo >> /etc/infiniband/openib.conf
       echo "# Load E_IPoIB" >> /etc/infiniband/openib.conf
       echo "E_IPOIB_LOAD=no" >> /etc/infiniband/openib.conf
       echo >> /etc/infiniband/openib.conf
%endif

%if %{build_sdp}
       echo >> /etc/infiniband/openib.conf                                                
       echo "# Load SDP module" >> /etc/infiniband/openib.conf
       echo "SDP_LOAD=no" >> /etc/infiniband/openib.conf
%endif

%if %{build_srp}
       echo >> /etc/infiniband/openib.conf                                                
       echo "# Load SRP module" >> /etc/infiniband/openib.conf
       echo "SRP_LOAD=no" >> /etc/infiniband/openib.conf
%endif

%if %{build_srpt}
       echo >> /etc/infiniband/openib.conf                                                
       echo "# Load SRP Target module" >> /etc/infiniband/openib.conf
       echo "SRPT_LOAD=no" >> /etc/infiniband/openib.conf
%endif

%if %{build_iser}
       echo >> /etc/infiniband/openib.conf                                                
       echo "# Load ISER module" >> /etc/infiniband/openib.conf
       echo "ISER_LOAD=no" >> /etc/infiniband/openib.conf
%endif

%if %{build_rds}
       echo >> /etc/infiniband/openib.conf                                                
       echo "# Load RDS module" >> /etc/infiniband/openib.conf
       echo "RDS_LOAD=no" >> /etc/infiniband/openib.conf
%endif

%if %{build_qlgc_vnic}
       echo >> /etc/infiniband/openib.conf
       echo "# Load QLogic VNIC module" >> /etc/infiniband/openib.conf
       echo "QLGC_VNIC_LOAD=yes" >> /etc/infiniband/openib.conf
%endif

fi # 1 : closed
# END of post

%preun -n mlnx-ofa_kernel
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
          fi
          if [ -f /etc/debian_version ]; then
                if ! ( /usr/sbin/update-rc.d openibd remove > /dev/null 2>&1 ); then
                        true
                fi
          fi
fi

%files
%dir /etc/infiniband
%config(noreplace) /etc/infiniband/openib.conf
/etc/infiniband/info
/etc/init.d/openibd
/sbin/sysctl_perf_tuning
/etc/modprobe.d/mlnx.conf
%{_sbindir}/*
%if "%{_vendor}" == "redhat"
%{_sysconfdir}/depmod.d
%endif
%if %{include_udev_rules}
/etc/udev/rules.d/90-ib.rules
%endif
%if %{build_qib}
%config(noreplace) /etc/infiniband/truescale.cmds
%endif
%if %{build_ipoib}
/etc/modprobe.d/ib_ipoib.conf
%if %{build_eipoib}
/sbin/ipoibd
%endif
%endif
%if %{build_sdp}
/etc/modprobe.d/ib_sdp.conf
%endif
%if %{build_mlx4} || %{build_mlx5}
%{_bindir}/ibdev2netdev
/sbin/cx_virt_config.py
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

%files devel
%defattr(-,root,root,-)
%{_prefix}/src

%changelog
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

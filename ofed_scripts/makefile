PHONY += all kernel install_kernel install clean clean_kernel
	
all:
.PHONY: $(PHONY)

.DELETE_ON_ERROR:

include ./configure.mk.kernel
include ./ofed_scripts/compat.mk

export CREL=$(shell cat $(CWD)/compat_version)
export CREL_PRE:=.compat_autoconf_
export CREL_CHECK:=$(CREL_PRE)$(CREL)
CFLAGS += \
	-DCOMPAT_BASE="\"$(shell cat compat_base)\"" \
	-DCOMPAT_BASE_TREE="\"$(shell cat compat_base_tree)\"" \
	-DCOMPAT_BASE_TREE_VERSION="\"$(shell cat compat_base_tree_version)\"" \
	-DCOMPAT_PROJECT="\"Compat-mlnx-ofed\"" \
	-DCOMPAT_VERSION="\"$(shell cat compat_version)\"" \

DEPMOD  = /sbin/depmod
INSTALL_MOD_DIR ?= $(shell test -f /etc/SuSE-release && echo updates || echo extra/mlnx-ofa_kernel)

ifeq ($(CONFIG_MEMTRACK),m)
        export KERNEL_MEMTRACK_CFLAGS = -include $(CWD)/drivers/infiniband/debug/mtrack.h
else
        export KERNEL_MEMTRACK_CFLAGS =
endif

ifeq ($(CONFIG_NFS_FS),m)
	export KERNEL_NFS_FS_CFLAGS = -I$(CWD)/include-nfs
else
	export KERNEL_NFS_FS_CFLAGS = 
endif

export OPEN_ISCSI_MODULES = iscsi_tcp.ko libiscsi.ko scsi_transport_iscsi.ko

configure.mk.kernel:
	@echo Please run ./configure
	@exit 1

all: kernel

install: install_kernel
install_kernel: install_modules

autoconf_h=$(shell /bin/ls -1 $(KSRC)/include/*/autoconf.h 2> /dev/null | head -1)
kconfig_h=$(shell /bin/ls -1 $(KSRC)/include/*/kconfig.h 2> /dev/null | head -1)

ifneq ($(kconfig_h),)
KCONFIG_H = -include $(kconfig_h)
endif

V ?= 0

#########################
#	make kernel	#
#########################
#NB: The LINUXINCLUDE value comes from main kernel Makefile
#    with local directories prepended. This eventually affects
#    CPPFLAGS in the kernel Makefile
kernel:
	@echo "Building kernel modules"
	@echo "Kernel version: $(KVERSION)"
	@echo "Modules directory: $(INSTALL_MOD_PATH)/lib/modules/$(KVERSION)/$(INSTALL_MOD_DIR)"
	@echo "Kernel sources: $(KSRC)"
	env CWD=$(CWD) BACKPORT_INCLUDES=$(BACKPORT_INCLUDES) \
		$(MAKE) -C $(KSRC) SUBDIRS="$(CWD)" \
		V=$(V) $(WITH_MAKE_PARAMS) \
		CONFIG_MEMTRACK=$(CONFIG_MEMTRACK) \
		CONFIG_DEBUG_INFO=$(CONFIG_DEBUG_INFO) \
		CONFIG_INFINIBAND=$(CONFIG_INFINIBAND) \
		CONFIG_INFINIBAND_IPOIB=$(CONFIG_INFINIBAND_IPOIB) \
		CONFIG_INFINIBAND_IPOIB_CM=$(CONFIG_INFINIBAND_IPOIB_CM) \
                CONFIG_INFINIBAND_MLNX_BX=$(CONFIG_INFINIBAND_MLNX_BX) \
		CONFIG_INFINIBAND_SDP=$(CONFIG_INFINIBAND_SDP) \
		CONFIG_INFINIBAND_SRP=$(CONFIG_INFINIBAND_SRP) \
		CONFIG_INFINIBAND_SRPT=$(CONFIG_INFINIBAND_SRPT) \
		CONFIG_INFINIBAND_USER_MAD=$(CONFIG_INFINIBAND_USER_MAD) \
		CONFIG_INFINIBAND_USER_ACCESS=$(CONFIG_INFINIBAND_USER_ACCESS) \
		CONFIG_INFINIBAND_USER_MEM=$(CONFIG_INFINIBAND_USER_MEM) \
		CONFIG_INFINIBAND_ADDR_TRANS=$(CONFIG_INFINIBAND_ADDR_TRANS) \
		CONFIG_INFINIBAND_MTHCA=$(CONFIG_INFINIBAND_MTHCA) \
		CONFIG_INFINIBAND_IPOIB_DEBUG=$(CONFIG_INFINIBAND_IPOIB_DEBUG) \
		CONFIG_INFINIBAND_ISER=$(CONFIG_INFINIBAND_ISER) \
		CONFIG_SCSI_ISCSI_ATTRS=$(CONFIG_SCSI_ISCSI_ATTRS) \
		CONFIG_ISCSI_TCP=$(CONFIG_ISCSI_TCP) \
		CONFIG_INFINIBAND_EHCA=$(CONFIG_INFINIBAND_EHCA) \
		CONFIG_INFINIBAND_EHCA_SCALING=$(CONFIG_INFINIBAND_EHCA_SCALING) \
		CONFIG_E_IPOIB=$(CONFIG_E_IPOIB) \
		CONFIG_RDS=$(CONFIG_RDS) \
		CONFIG_RDS_RDMA=$(CONFIG_RDS_RDMA) \
		CONFIG_RDS_TCP=$(CONFIG_RDS_TCP) \
		CONFIG_RDS_DEBUG=$(CONFIG_RDS_DEBUG) \
		CONFIG_INFINIBAND_IPOIB_DEBUG_DATA=$(CONFIG_INFINIBAND_IPOIB_DEBUG_DATA) \
		CONFIG_INFINIBAND_SDP_SEND_ZCOPY=$(CONFIG_INFINIBAND_SDP_SEND_ZCOPY) \
		CONFIG_INFINIBAND_SDP_RECV_ZCOPY=$(CONFIG_INFINIBAND_SDP_RECV_ZCOPY) \
		CONFIG_INFINIBAND_SDP_DEBUG=$(CONFIG_INFINIBAND_SDP_DEBUG) \
		CONFIG_INFINIBAND_SDP_DEBUG_DATA=$(CONFIG_INFINIBAND_SDP_DEBUG_DATA) \
		CONFIG_INFINIBAND_IPATH=$(CONFIG_INFINIBAND_IPATH) \
		CONFIG_INFINIBAND_QIB=$(CONFIG_INFINIBAND_QIB) \
		CONFIG_INFINIBAND_MTHCA_DEBUG=$(CONFIG_INFINIBAND_MTHCA_DEBUG) \
		CONFIG_INFINIBAND_MADEYE=$(CONFIG_INFINIBAND_MADEYE) \
		CONFIG_INFINIBAND_QLGC_VNIC=$(CONFIG_INFINIBAND_QLGC_VNIC) \
		CONFIG_INFINIBAND_QLGC_VNIC_DEBUG=$(CONFIG_INFINIBAND_QLGC_VNIC_DEBUG) \
		CONFIG_INFINIBAND_QLGC_VNIC_STATS=$(CONFIG_INFINIBAND_QLGC_VNIC_STATS) \
		CONFIG_CHELSIO_T3=$(CONFIG_CHELSIO_T3) \
		CONFIG_INFINIBAND_CXGB3=$(CONFIG_INFINIBAND_CXGB3) \
		CONFIG_INFINIBAND_CXGB3_DEBUG=$(CONFIG_INFINIBAND_CXGB3_DEBUG) \
		CONFIG_CHELSIO_T4=$(CONFIG_CHELSIO_T4) \
		CONFIG_INFINIBAND_CXGB4=$(CONFIG_INFINIBAND_CXGB4) \
		CONFIG_INFINIBAND_NES=$(CONFIG_INFINIBAND_NES) \
		CONFIG_INFINIBAND_NES_DEBUG=$(CONFIG_INFINIBAND_NES_DEBUG) \
		CONFIG_MLX4_CORE=$(CONFIG_MLX4_CORE) \
		CONFIG_MLX5_CORE=$(CONFIG_MLX5_CORE) \
		CONFIG_MLX4_EN=$(CONFIG_MLX4_EN) \
		CONFIG_MLX4_EN_DCB=$(CONFIG_MLX4_EN_DCB) \
		CONFIG_MLX4_VNIC=$(CONFIG_MLX4_VNIC) \
		CONFIG_MLX4_VNIC_DEBUG=$(CONFIG_MLX4_VNIC_DEBUG) \
		CONFIG_MLX4_INFINIBAND=$(CONFIG_MLX4_INFINIBAND) \
		CONFIG_MLX5_INFINIBAND=$(CONFIG_MLX5_INFINIBAND) \
		CONFIG_MLX4_ETHERNET=$(CONFIG_MLX4_ETHERNET) \
		CONFIG_MLX4_DEBUG=$(CONFIG_MLX4_DEBUG) \
		CONFIG_MLX5_DEBUG=$(CONFIG_MLX5_DEBUG) \
		CONFIG_MLX4_FC=$(CONFIG_MLX4_FC) \
                CONFIG_LIBFC=$(CONFIG_LIBFC) \
                CONFIG_LIBFCOE=$(CONFIG_LIBFCOE) \
		CONFIG_INFINIBAND_AMSO1100=$(CONFIG_INFINIBAND_AMSO1100) \
		CONFIG_SUNRPC_XPRT_RDMA=$(CONFIG_SUNRPC_XPRT_RDMA) \
		CONFIG_SUNRPC=$(CONFIG_SUNRPC) \
		CONFIG_SUNRPC_GSS=$(CONFIG_SUNRPC_GSS) \
		CONFIG_RPCSEC_GSS_KRB5=$(CONFIG_RPCSEC_GSS_KRB5) \
		CONFIG_RPCSEC_GSS_SPKM3=$(CONFIG_RPCSEC_GSS_SPKM3) \
		CONFIG_NFS_FS=$(CONFIG_NFS_FS) \
		CONFIG_NFS_V3=$(CONFIG_NFS_V3) \
		CONFIG_NFS_V3_ACL=$(CONFIG_NFS_V3_ACL) \
		CONFIG_NFS_V4=$(CONFIG_NFS_V4) \
		CONFIG_NFS_ACL_SUPPORT=$(CONFIG_NFS_ACL_SUPPORT) \
		CONFIG_NFS_DIRECTIO=$(CONFIG_NFS_DIRECTIO) \
		CONFIG_EXPORTFS=$(CONFIG_EXPORTFS)\
		CONFIG_LOCKD=$(CONFIG_LOCKD) \
		CONFIG_LOCKD_V4=$(CONFIG_LOCKD_V4) \
		CONFIG_NFSD=$(CONFIG_NFSD) \
		CONFIG_NFSD_V2_ACL=$(CONFIG_NFSD_V2_ACL) \
		CONFIG_NFSD_V3=$(CONFIG_NFSD_V3) \
		CONFIG_NFSD_V3_ACL=$(CONFIG_NFSD_V3_ACL) \
		CONFIG_NFSD_V4=$(CONFIG_NFSD_V4) \
		CONFIG_NFSD_RDMA=$(CONFIG_NFSD_RDMA) \
		LINUXINCLUDE=' \
		-D__OFED_BUILD__ \
		$(CFLAGS) \
		-include $(autoconf_h) \
		-include $(CWD)/include/linux/autoconf.h \
		$(KCONFIG_H) \
		-include $(CWD)/include/linux/compat-2.6.h \
		$(BACKPORT_INCLUDES) \
		$(KERNEL_MEMTRACK_CFLAGS) \
		$(KERNEL_NFS_FS_CFLAGS) \
		$(OPENIB_KERNEL_EXTRA_CFLAGS) \
		-I$(CWD)/include \
		-I$(CWD)/drivers/infiniband/debug \
		-I/usr/local/include/scst \
		-I$(CWD)/drivers/infiniband/ulp/srpt \
		$$(if $$(CONFIG_XEN),-D__XEN_INTERFACE_VERSION__=$$(CONFIG_XEN_INTERFACE_VERSION)) \
		$$(if $$(CONFIG_XEN),-I$$(srctree)/arch/x86/include/mach-xen) \
		-I$$(srctree)/arch/$$(SRCARCH)/include \
		-Iarch/$$(SRCARCH)/include/generated \
		-Iinclude \
		-I$$(srctree)/arch/$(SRCARCH)/include/uapi \
		-Iarch/$$(SRCARCH)/include/generated/uapi \
		-I$$(srctree)/include/uapi \
		-Iinclude/generated/uapi \
		$$(if $$(KBUILD_SRC),-Iinclude2 -I$$(srctree)/include) \
		-I$$(srctree)/arch/$$(SRCARCH)/include \
		-Iarch/$$(SRCARCH)/include/generated \
		' \
		modules


#########################
#	Install kernel	#
#########################
install_modules:
	@echo "Installing kernel modules"

	$(MAKE) -C $(KSRC) SUBDIRS="$(CWD)" \
		INSTALL_MOD_PATH=$(INSTALL_MOD_PATH) \
		INSTALL_MOD_DIR=$(INSTALL_MOD_DIR) \
		$(WITH_MAKE_PARAMS) modules_install;

	if [ ! -n "$(INSTALL_MOD_PATH)" ]; then $(DEPMOD) $(KVERSION);fi;

clean: clean_kernel

clean_kernel:
	$(MAKE) -C $(KSRC) SUBDIRS="$(CWD)" $(WITH_MAKE_PARAMS) clean

help:
	@echo
	@echo kernel: 		        build kernel modules
	@echo all: 		        build kernel modules
	@echo
	@echo install_kernel:	        install kernel modules under $(INSTALL_MOD_PATH)/lib/modules/$(KVERSION)/$(INSTALL_MOD_DIR)
	@echo install:	        	run install_kernel
	@echo
	@echo clean:	        	delete kernel modules binaries
	@echo clean_kernel:	        delete kernel modules binaries
	@echo

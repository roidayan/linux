export

## NOTE
## Make sure to have each variable declaration start
## in the first column, no whitespace allowed.
# include $(KLIB_BUILD)/.config

ifneq ($(wildcard $(KLIB_BUILD)/Makefile),)

COMPAT_LATEST_VERSION = 7

KERNEL_VERSION := $(shell $(MAKE) -C $(KLIB_BUILD) kernelversion | sed -n 's/^\([0-9]\)\..*/\1/p')

ifneq ($(KERNEL_VERSION),2)
KERNEL_SUBLEVEL := $(shell $(MAKE) -C $(KLIB_BUILD) kernelversion | sed -n 's/^3\.\([0-9]\+\).*/\1/p')
else
COMPAT_26LATEST_VERSION = 39
KERNEL_26SUBLEVEL := $(shell $(MAKE) -C $(KLIB_BUILD) kernelversion | sed -n 's/^2\.6\.\([0-9]\+\).*/\1/p')
COMPAT_26VERSIONS := $(shell I=$(COMPAT_26LATEST_VERSION); while [ "$$I" -gt $(KERNEL_26SUBLEVEL) ]; do echo $$I; I=$$(($$I - 1)); done)
$(foreach ver,$(COMPAT_26VERSIONS),$(eval CONFIG_COMPAT_KERNEL_2_6_$(ver)=y))
KERNEL_SUBLEVEL := -1
endif

COMPAT_VERSIONS := $(shell I=$(COMPAT_LATEST_VERSION); while [ "$$I" -gt $(KERNEL_SUBLEVEL) ]; do echo $$I; I=$$(($$I - 1)); done)
$(foreach ver,$(COMPAT_VERSIONS),$(eval CONFIG_COMPAT_KERNEL_3_$(ver)=y))

RHEL_MAJOR := $(shell grep ^RHEL_MAJOR $(KLIB_BUILD)/Makefile | sed -n 's/.*= *\(.*\)/\1/p')

ifneq ($(RHEL_MAJOR),)
RHEL_MINOR := $(shell grep ^RHEL_MINOR $(KLIB_BUILD)/Makefile | sed -n 's/.*= *\(.*\)/\1/p')
COMPAT_RHEL_VERSIONS := $(shell I=$(RHEL_MINOR); while [ "$$I" -ge 0 ]; do echo $$I; I=$$(($$I - 1)); done)
$(foreach ver,$(COMPAT_RHEL_VERSIONS),$(eval CONFIG_COMPAT_RHEL_$(RHEL_MAJOR)_$(ver)=y))
endif

SLES_11_2_KERNEL := $(shell echo $(KVERSION) | sed -n 's/^\(3\.0\.[0-9]\+\)\-\(.*\)\-\(.*\)/\1-\2-\3/p')
ifneq ($(SLES_11_2_KERNEL),)
SLES_MAJOR := "11"
SLES_MINOR := "2"
CONFIG_COMPAT_SLES_11_2 := y
endif

SLES_11_1_KERNEL := $(shell echo $(KVERSION) | sed -n 's/^\(2\.6\.32\.[0-9]\+\)\-\(.*\)\-\(.*\)/\1-\2-\3/p')
ifneq ($(SLES_11_1_KERNEL),)
SLES_MAJOR := "11"
SLES_MINOR := "1"
CONFIG_COMPAT_SLES_11_1 := y
endif

FC14_KERNEL := $(shell echo $(KVERSION) | grep fc14)
ifneq ($(FC14_KERNEL),)
 CONFIG_COMPAT_DISABLE_DCB=y
endif

endif # kernel Makefile check

ifdef CONFIG_COMPAT_KERNEL_2_6_36
ifndef CONFIG_COMPAT_RHEL_6_1
 CONFIG_COMPAT_KFIFO=y
endif #CONFIG_COMPAT_RHEL_6_1
endif #CONFIG_COMPAT_KERNEL_2_6_36

ifdef CONFIG_COMPAT_KERNEL_3_2
ifndef CONFIG_COMPAT_RHEL_6_3
 CONFIG_COMPAT_SKB_FRAG_NEEDED=y
endif #CONFIG_COMPAT_RHEL_6_3
endif #CONFIG_COMPAT_KERNEL_3_2

ifdef CONFIG_COMPAT_KERNEL_2_6_38
ifndef CONFIG_COMPAT_RHEL_6_3
 CONFIG_COMPAT_NO_PRINTK_NEEDED=y
endif #CONFIG_COMPAT_RHEL_6_3
endif #CONFIG_COMPAT_KERNEL_2_6_38

ifdef CONFIG_COMPAT_SLES_11_1
 CONFIG_COMPAT_DISABLE_DCB=y
endif

ifdef CONFIG_COMPAT_SLES_11_2
 NEED_MIN_DUMP_ALLOC_ARG=y
 CONFIG_COMPAT_IS_NUM_TX_QUEUES=y
 CONFIG_COMPAT_NEW_TX_RING_SCHEME=y
 CONFIG_COMPAT_IS___SKB_TX_HASH=y
 CONFIG_COMPAT_ISER_ATTR_IS_VISIBLE=y
 CONFIG_COMPAT_ISCSI_ISER_GET_EP_PARAM=y
endif

ifdef CONFIG_COMPAT_RHEL_6_3
 CONFIG_COMPAT_XPRTRDMA_NEEDED=y
endif

ifeq ($(RHEL_MAJOR),6)
 CONFIG_COMPAT_IS_PRIO_TC_MAP=y
 CONFIG_COMPAT_IS_NUM_TX_QUEUES=y
 CONFIG_COMPAT_NEW_TX_RING_SCHEME=y
 CONFIG_COMPAT_IS___SKB_TX_HASH=y
 CONFIG_COMPAT_ISER_ATTR_IS_VISIBLE=y
 CONFIG_COMPAT_ISCSI_ISER_GET_EP_PARAM=y
endif

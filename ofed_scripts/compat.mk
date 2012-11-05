export

## NOTE
## Make sure to have each variable declaration start
## in the first column, no whitespace allowed.
# include $(KLIB_BUILD)/.config

ifneq ($(wildcard $(KLIB_BUILD)/Makefile),)

COMPAT_LATEST_VERSION = 3

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

KLIB_SOURCE := $(subst build,source,$(KLIB_BUILD))
NAME := $(shell grep ^NAME $(KLIB_SOURCE)/Makefile | sed -n 's/.*= *\(.*\)/\1/p')
ifneq ($(NAME),)
ifeq ("$(strip $(NAME))","Sneaky Weasel")
SLES_MAJOR := "11"
SLES_MINOR := "2"
CONFIG_COMPAT_SLES_11_2 := y
endif
endif

endif # kernel Makefile check

ifdef CONFIG_COMPAT_KERNEL_2_6_36
ifndef CONFIG_COMPAT_RHEL_6_1
 CONFIG_COMPAT_KFIFO=y
endif #CONFIG_COMPAT_RHEL_6_1
endif #CONFIG_COMPAT_KERNEL_2_6_36

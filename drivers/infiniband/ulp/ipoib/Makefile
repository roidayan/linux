ccflags-y += $(MLNX_CFLAGS)

obj-$(CONFIG_INFINIBAND_IPOIB)			+= ib_ipoib.o

ib_ipoib-y					:= ipoib_main.o \
						   ipoib_ib.o \
						   ipoib_multicast.o \
						   ipoib_verbs.o \
						   ipoib_vlan.o \
						   ipoib_netlink.o \
						   ipoib_ethtool.o
ib_ipoib-$(CONFIG_INFINIBAND_IPOIB_CM)		+= ipoib_cm.o
ib_ipoib-$(CONFIG_INFINIBAND_IPOIB_DEBUG)	+= ipoib_fs.o
ib_ipoib-$(CONFIG_IPOIB_ALL_MULTI)		+= ipoib_genetlink.o \
						   ipoib_allmulti.o


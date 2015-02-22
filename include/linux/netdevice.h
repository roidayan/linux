#ifndef _COMPAT_LINUX_NETDEVICE_H
#define _COMPAT_LINUX_NETDEVICE_H 1

#include_next <linux/netdevice.h>

#ifndef SET_ETHTOOL_OPS
#define SET_ETHTOOL_OPS(netdev,ops) \
    ( (netdev)->ethtool_ops = (ops) )
#endif

#ifndef NETDEV_BONDING_INFO
#define NETDEV_BONDING_INFO     0x0019
#endif

#endif	/* _COMPAT_LINUX_NETDEVICE_H */

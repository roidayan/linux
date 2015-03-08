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


#ifndef HAVE_NETDEV_MASTER_UPPER_DEV_GET_RCU
#define netdev_master_upper_dev_get_rcu(x) (x)->master
#endif

#ifndef NAPI_POLL_WEIGHT
/* Default NAPI poll() weight
 * Device drivers are strongly advised to not use bigger value
 */
#define NAPI_POLL_WEIGHT 64
#endif

#ifndef NETDEV_JOIN
#define NETDEV_JOIN           0x0014
#endif

#endif	/* _COMPAT_LINUX_NETDEVICE_H */

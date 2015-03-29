#ifndef LINUX_3_17_COMPAT_H
#define LINUX_3_17_COMPAT_H

#include <linux/version.h>
#include <linux/dcbnl.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0))

#ifndef HAVE_KTIME_GET_REAL_NS
#include <linux/ktime.h>
static inline u64 ktime_get_real_ns(void) {
	return ktime_to_ns(ktime_get_real());
}
#endif /* HAVE_KTIME_GET_REAL_NS */

#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)) */
#include <linux/netdevice.h>
#define alloc_netdev_mqs(a, b, c, d, e) alloc_netdev_mqs(a, b, NET_NAME_UNKNOWN, c, d, e)

#ifdef alloc_netdev_mq
#undef alloc_netdev_mq
#define alloc_netdev_mq(sizeof_priv, name, setup, count) \
    alloc_netdev_mqs(sizeof_priv, name, setup, count, count)
#endif

#ifdef alloc_netdev
#undef alloc_netdev
#define alloc_netdev(sizeof_priv, name, name_assign_type, setup) \
	alloc_netdev_mqs(sizeof_priv, name, setup, 1, 1)
#endif

#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)) */

#endif /* LINUX_3_17_COMPAT_H */

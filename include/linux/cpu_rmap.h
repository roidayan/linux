#ifndef _COMPAT_LINUX_CPU_RMAP_H
#define _COMPAT_LINUX_CPU_RMAP_H 1

#include <linux/version.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0))
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39))
#include_next <linux/cpu_rmap.h>
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)) */
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)) */

#endif	/* _COMPAT_LINUX_CPU_RMAP_H */

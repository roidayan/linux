#ifndef _COMPAT_LINUX_MODULE_H
#define _COMPAT_LINUX_MODULE_H

#include_next <linux/module.h>

/* This is a workaround to support UEK3 kernels */
#ifdef CONFIG_DTRACE
#undef CONFIG_DTRACE
#endif

#endif /* _COMPAT_LINUX_MODULE_H */

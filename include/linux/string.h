#ifndef _COMPAT_LINUX_STRING_H
#define _COMPAT_LINUX_STRING_H

#include_next <linux/string.h>

#ifndef HAVE_STRNICMP
#ifndef __HAVE_ARCH_STRNICMP
#define strnicmp strncasecmp
#endif
#endif /* HAVE_STRNICMP */

#endif /* _COMPAT_LINUX_STRING_H */

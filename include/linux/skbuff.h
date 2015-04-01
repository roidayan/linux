#ifndef _COMPAT_LINUX_SKBUFF_H
#define _COMPAT_LINUX_SKBUFF_H

#include_next <linux/skbuff.h>

#ifndef HAVE_SKB_PULL_INLINE
static inline unsigned char *skb_pull_inline(struct sk_buff *skb, unsigned int len)
{
	return unlikely(len > skb->len) ? NULL : __skb_pull(skb, len);
}
#endif /* HAVE_SKB_PULL_INLINE */

#endif /* _COMPAT_LINUX_SKBUFF_H */

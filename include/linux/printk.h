#ifndef _COMPAT_LINUX_PRINTK_H
#define _COMPAT_LINUX_PRINTK_H 1

#include <linux/version.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37))
#include_next <linux/printk.h>
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37)) */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38))
#include <linux/kernel.h>

#define pr_emerg_once(fmt, ...)					\
	printk_once(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_alert_once(fmt, ...)					\
	printk_once(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_crit_once(fmt, ...)					\
	printk_once(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err_once(fmt, ...)					\
	printk_once(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn_once(fmt, ...)					\
	printk_once(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn pr_warning
#define pr_notice_once(fmt, ...)				\
	printk_once(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#define pr_info_once(fmt, ...)					\
	printk_once(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#define pr_cont_once(fmt, ...)					\
	printk_once(KERN_CONT pr_fmt(fmt), ##__VA_ARGS__)
#if defined(DEBUG)
#define pr_debug_once(fmt, ...)					\
	printk_once(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#else
#define pr_debug_once(fmt, ...)					\
	no_printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#endif

/*
 * ratelimited messages with local ratelimit_state,
 * no local ratelimit_state used in the !PRINTK case
 */
#ifndef printk_ratelimited
#ifdef CONFIG_PRINTK
#define printk_ratelimited(fmt, ...)                                    \
({                                                                      \
        static DEFINE_RATELIMIT_STATE(_rs,                              \
                                      DEFAULT_RATELIMIT_INTERVAL,       \
                                      DEFAULT_RATELIMIT_BURST);         \
                                                                        \
        if (__ratelimit(&_rs))                                          \
                printk(fmt, ##__VA_ARGS__);                             \
})
#else
#define printk_ratelimited(fmt, ...)                                    \
        no_printk(fmt, ##__VA_ARGS__)
#endif
#endif /* ifndef printk_ratelimited */

#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38)) */

#endif	/* _COMPAT_LINUX_PRINTK_H */

#ifndef _TRACE_H
#define _TRACE_H

#define TRACE_ENABLED        1
#define TRACE_DEBUG          (TRACE_ENABLED && 1)

#if !TRACE_ENABLED
#undef TRACE
#define TRACE 0
#endif

#define TRACE_LEVEL_ERRORS   1
#define TRACE_LEVEL_MESSAGES 2
#define TRACE_LEVEL_NOTICES  3
#define TRACE_LEVEL_ALL      4

#ifndef TRACE_LEVEL
#define TRACE_LEVEL          TRACE_LEVEL_ALL
#endif

#define SUPPRESS_UNUSED      __attribute__ ((unused))
#ifndef TRACE
#define TRACE 1
#endif

#define __SHORT_FORM_OF_FILE__ \
 (strrchr(__FILE__,'/')        \
 ? strrchr(__FILE__,'/')+1     \
 : __FILE__)

#define __trace(fmt, args...) \
            printk("[ct-poc, %d] <%s/%s> "fmt"\n", task_cpu(current), __SHORT_FORM_OF_FILE__, __func__, ##args)


#if TRACE

#if TRACE_LEVEL >= TRACE_LEVEL_ERRORS
#define etrace(fmt, args...) \
        __trace("ERROR(%d): "fmt,  __LINE__, ##args)

#define atrace(condition, ...) { \
            if (!(condition)) { \
                __trace("ASSERT ON LINE: %d (%s)", __LINE__, #condition); \
                __VA_ARGS__; \
            } \
        }

#define strace() dump_stack()
#else
#define etrace(fmt, args...)
#define atrace(condition, ...)
#define strace()
#endif

#if TRACE_LEVEL >= TRACE_LEVEL_MESSAGES
#define mtrace(fmt, args...) \
        __trace("MESSAGE: "fmt, ##args)
#else
#define mtrace(fmt, args...)
#endif

#if TRACE_LEVEL >= TRACE_LEVEL_NOTICES
#define ntrace(fmt, args...) \
        __trace("NOTICE: "fmt, ##args)
#else
#define ntrace(fmt, args...)
#endif

#if TRACE_LEVEL >= TRACE_LEVEL_ALL
#define trace(fmt, args...) \
        __trace(fmt, ##args)
#else
#define trace(fmt, args...)
#endif

#else /* TRACE */

#define trace(fmt, args...)
#define mtrace(fmt, args...)
#define ntrace(fmt, args...)
#define etrace(fmt, args...)

#define atrace(condition, ...)
#define strace()
#endif

#endif /* _TRACE_H */


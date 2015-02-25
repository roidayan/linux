#include <linux/kernel.h>
#include <linux/crash_dump.h>

#ifndef ELFCORE_ADDR_MAX
#define ELFCORE_ADDR_MAX        (-1ULL)
#endif

unsigned long long elfcorehdr_addr = ELFCORE_ADDR_MAX;
EXPORT_SYMBOL_GPL(elfcorehdr_addr);

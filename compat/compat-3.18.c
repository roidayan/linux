#include <linux/kernel.h>
#include <linux/crash_dump.h>

unsigned long long elfcorehdr_addr = ELFCORE_ADDR_MAX;
EXPORT_SYMBOL_GPL(elfcorehdr_addr);

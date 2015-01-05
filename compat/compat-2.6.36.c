/*
 * Copyright 2010    Hauke Mehrtens <hauke@hauke-m.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Compatibility file for Linux wireless for kernels 2.6.36.
 */

#include <linux/compat.h>

struct workqueue_struct *system_wq __read_mostly;
struct workqueue_struct *system_long_wq __read_mostly;
struct workqueue_struct *system_nrt_wq __read_mostly;
EXPORT_SYMBOL_GPL(system_wq);
EXPORT_SYMBOL_GPL(system_long_wq);
EXPORT_SYMBOL_GPL(system_nrt_wq);

int schedule_work(struct work_struct *work)
{
	return queue_work(system_wq, work);
}
EXPORT_SYMBOL_GPL(schedule_work);

int schedule_work_on(int cpu, struct work_struct *work)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
	return queue_work_on(cpu, system_wq, work);
#else
	return queue_work(system_wq, work);
#endif
}
EXPORT_SYMBOL_GPL(schedule_work_on);

int schedule_delayed_work(struct delayed_work *dwork,
                                 unsigned long delay)
{
	return queue_delayed_work(system_wq, dwork, delay);
}
EXPORT_SYMBOL_GPL(schedule_delayed_work);

int schedule_delayed_work_on(int cpu,
                                    struct delayed_work *dwork,
                                    unsigned long delay)
{
	return queue_delayed_work_on(cpu, system_wq, dwork, delay);
}
EXPORT_SYMBOL_GPL(schedule_delayed_work_on);

void flush_scheduled_work(void)
{
	/*
	 * It is debatable which one we should prioritize first, lets
	 * go with the old kernel's one first for now (keventd_wq) and
	 * if think its reasonable later we can flip this around.
	 */
	flush_workqueue(system_wq);
	flush_scheduled_work();
}
EXPORT_SYMBOL_GPL(flush_scheduled_work);

/**
 * work_busy - test whether a work is currently pending or running
 * @work: the work to be tested
 *
 * Test whether @work is currently pending or running.  There is no
 * synchronization around this function and the test result is
 * unreliable and only useful as advisory hints or for debugging.
 * Especially for reentrant wqs, the pending state might hide the
 * running state.
 *
 * RETURNS:
 * OR'd bitmask of WORK_BUSY_* bits.
 */
unsigned int work_busy(struct work_struct *work)
{
	unsigned int ret = 0;

	if (work_pending(work))
		ret |= WORK_BUSY_PENDING;

	return ret;
}
EXPORT_SYMBOL_GPL(work_busy);

int backport_system_workqueue_create()
{
	system_wq = alloc_workqueue("events", 0, 0);
	if (!system_wq)
		return -ENOMEM;

	system_long_wq = alloc_workqueue("events_long", 0, 0);
	if (!system_long_wq)
		goto err1;

	system_nrt_wq = create_singlethread_workqueue("events_nrt");
	if (!system_nrt_wq)
		goto err2;

	return 0;

err2:
	destroy_workqueue(system_long_wq);
err1:
	destroy_workqueue(system_wq);
	return -ENOMEM;
}

void backport_system_workqueue_destroy()
{
	destroy_workqueue(system_nrt_wq);
	destroy_workqueue(system_wq);
	destroy_workqueue(system_long_wq);
}

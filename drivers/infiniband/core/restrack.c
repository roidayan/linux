/* SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause) */
/*
 * Copyright (c) 2017-2018 Mellanox Technologies. All rights reserved.
 */

#include <rdma/ib_verbs.h>
#include <rdma/restrack.h>
#include <linux/srcu.h>
#include <linux/mutex.h>
#include <linux/sched/task.h>
#include <linux/uaccess.h>
#include <linux/pid_namespace.h>

int rdma_restrack_init(struct rdma_restrack_root *res)
{
	mutex_init(&res->mutex);
	return init_srcu_struct(&res->srcu);
}

void rdma_restrack_clean(struct rdma_restrack_root *res)
{
	cleanup_srcu_struct(&res->srcu);
	WARN_ON_ONCE(!hash_empty(res->hash));
}

int rdma_restrack_count(struct rdma_restrack_root *res,
			enum rdma_restrack_type type,
			struct pid_namespace *ns)
{
	struct rdma_restrack_entry *e;
	u32 cnt = 0;
	int key;

	key = srcu_read_lock(&res->srcu);
	hash_for_each_possible_rcu(res->hash, e, node, type) {
		if (ns == &init_pid_ns ||
		    (!rdma_is_kernel_res(e) &&
		     ns == task_active_pid_ns(e->task)))
			cnt++;
	}
	srcu_read_unlock(&res->srcu, key);
	return cnt;
}
EXPORT_SYMBOL(rdma_restrack_count);

void rdma_restrack_add(struct rdma_restrack_entry *res)
{
	enum rdma_restrack_type type = res->type;
	struct ib_device *dev;
	const char *caller;
	struct ib_pd *pd;
	struct ib_cq *cq;
	struct ib_qp *qp;

	switch (type) {
	case RDMA_RESTRACK_PD:
		pd = container_of(res, struct ib_pd, res);
		dev = pd->device;
		caller = pd->caller;
		break;
	case RDMA_RESTRACK_CQ:
		cq = container_of(res, struct ib_cq, res);
		dev = cq->device;
		caller = cq->caller;
		break;
	case RDMA_RESTRACK_QP:
		qp = container_of(res, struct ib_qp, res);
		dev = qp->device;
		caller = qp->pd->caller;
		break;
	default:
		WARN_ONCE(true, "Wrong resource tracking type %u\n", type);
		return;
	}

	res->kern_name = NULL;
	res->task = NULL;

	if (!uaccess_kernel()) {
		get_task_struct(current);
		res->task = current;
	} else {
		res->kern_name = caller;
	}

	res->valid = true;

	mutex_lock(&dev->res.mutex);
	hash_add_rcu(dev->res.hash, &res->node, res->type);
	mutex_unlock(&dev->res.mutex);
}
EXPORT_SYMBOL(rdma_restrack_add);

void rdma_restrack_del(struct rdma_restrack_entry *res)
{
	enum rdma_restrack_type type;
	struct ib_device *dev;
	struct ib_pd *pd;
	struct ib_cq *cq;
	struct ib_qp *qp;

	if (!res->valid)
		return;

	type = res->type;

	switch (type) {
	case RDMA_RESTRACK_PD:
		pd = container_of(res, struct ib_pd, res);
		dev = pd->device;
		break;
	case RDMA_RESTRACK_CQ:
		cq = container_of(res, struct ib_cq, res);
		dev = cq->device;
		break;
	case RDMA_RESTRACK_QP:
		qp = container_of(res, struct ib_qp, res);
		dev = qp->device;
		break;
	default:
		WARN_ONCE(true, "Wrong resource tracking type %u\n", type);
		return;
	}

	mutex_lock(&dev->res.mutex);
	hash_del_rcu(&res->node);
	mutex_unlock(&dev->res.mutex);

	res->valid = false;

	if (res->task)
		put_task_struct(res->task);
	synchronize_srcu(&dev->res.srcu);
}
EXPORT_SYMBOL(rdma_restrack_del);

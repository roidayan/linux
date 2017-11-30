/*
 * Copyright (c) 2017 Mellanox Technologies. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <rdma/ib_verbs.h>
#include <rdma/restrack.h>
#include <linux/rculist.h>

int rdma_restrack_init(struct rdma_restrack_root *res)
{
	int i = 0;
	int ret;

	for (; i < _RDMA_RESTRACK_MAX; i++) {
		ret = init_srcu_struct(&res->srcu[i]);
		if (ret)
			goto err;

		refcount_set(&res->cnt[i], 0);
		INIT_LIST_HEAD_RCU(&res->list[i]);
		mutex_init(&res->lock[i]);
	}

	return 0;

err:
	while (i)
		cleanup_srcu_struct(&res->srcu[--i]);

	return ret;
}

void rdma_restrack_clean(struct rdma_restrack_root *res)
{
	int i = 0;

	for (; i < _RDMA_RESTRACK_MAX; i++) {
		WARN_ON_ONCE(refcount_read(&res->cnt[i]));
		WARN_ON_ONCE(list_empty(&res->list[i]));
		cleanup_srcu_struct(&res->srcu[i]);
	}
}

static bool is_restrack_valid(enum rdma_restrack_obj type)
{
	return !(type >= _RDMA_RESTRACK_MAX);
}

int rdma_restrack_count(struct rdma_restrack_root *res,
			enum rdma_restrack_obj type)
{
	if (!is_restrack_valid(type))
		return 0;

	return refcount_read(&res->cnt[type]);
}

void rdma_restrack_add(struct rdma_restrack_entry *res,
		       enum rdma_restrack_obj type, const char *comm)
{
	struct ib_device *dev;
	struct ib_pd *pd;
	struct ib_cq *cq;
	struct ib_qp *qp;

	if (!is_restrack_valid(type))
		return;

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
		/* unreachable */
		return;
	}

	refcount_inc(&dev->res.cnt[type]);

	if (!comm || !strlen(comm)) {
		get_task_comm(res->task_comm, current);
		/*
		 * Return global PID
		 */
		res->pid = task_pid_nr(current);
	} else {
		/*
		 * no need to set PID, it comes from
		 * core kernel, so pid will be zero
		 */
		strncpy(res->task_comm, comm, TASK_COMM_LEN);
	}
	mutex_lock(&dev->res.lock[type]);
	list_add_rcu(&res->list, &dev->res.list[type]);
	mutex_unlock(&dev->res.lock[type]);
}

void rdma_restrack_del(struct rdma_restrack_entry *res,
		       enum rdma_restrack_obj type)
{
	struct ib_device *dev;
	struct ib_pd *pd;
	struct ib_cq *cq;
	struct ib_qp *qp;

	if (!is_restrack_valid(type))
		return;

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
		/* unreachable */
		return;
	}

	refcount_dec(&dev->res.cnt[type]);
	mutex_lock(&dev->res.lock[type]);
	list_del_rcu(&res->list);
	mutex_unlock(&dev->res.lock[type]);
	synchronize_srcu(&dev->res.srcu[type]);
}

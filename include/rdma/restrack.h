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

#ifndef _RDMA_RESTRACK_H_
#define _RDMA_RESTRACK_H_

#include <linux/typecheck.h>
#include <linux/srcu.h>
#include <linux/refcount.h>
#include <linux/sched.h>

/**
 * enum rdma_restrack_obj - HW objects to track
 */
enum rdma_restrack_obj {
	/**
	 * @RDMA_RESTRACK_PD: Protection domain (PD)
	 */
	RDMA_RESTRACK_PD,
	/**
	 * @RDMA_RESTRACK_CQ: Completion queue (CQ)
	 */
	RDMA_RESTRACK_CQ,
	/**
	 * @RDMA_RESTRACK_QP: Queue pair (QP)
	 */
	RDMA_RESTRACK_QP,
	/* private: counts number of elements, always last */
	_RDMA_RESTRACK_MAX
};

/**
 * struct rdma_restrack_root - main resource tracking management
 * entity, per-device
 */
struct rdma_restrack_root {
	/**
	 * @cnt: global counter to avoid the need to count number
	 * of elements in the object's list.
	 *
	 * It can be different from the list_count, because we are
	 * not taking lock during counter increment and don't
	 * synchronize the RCU.
	 */
	refcount_t		cnt[_RDMA_RESTRACK_MAX];
	/**
	 * @list: linked list of all entries per-object
	 */
	struct list_head	list[_RDMA_RESTRACK_MAX];
	/* private: Internal read/write lock.
	 * It is needed to protect the add/delete list operations.
	 */
	struct rw_semaphore	rwsem[_RDMA_RESTRACK_MAX];
};

/**
 * struct rdma_restrack_entry - metadata per-entry
 */
struct rdma_restrack_entry {
	/**
	 * @list: linked list between entries
	 */
	struct list_head	list;
	/**
	 * @valid: validity indicator
	 *
	 * The entries are filled during rdma_restrack_add,
	 * can be attempted to be free during rdma_restrack_del.
	 *
	 * As an example for that, see mlx5 QPs with type MLX5_IB_QPT_HW_GSI
	 */
	bool			valid;
	/**
	 * @srcu: sleepable RCU to protect object data.
	 */
	struct srcu_struct	srcu;
	/**
	 * @task: owner of resource tracking entity
	 *
	 * There are two types of entities: created by user and created
	 * by kernel.
	 *
	 * This is relevant for the entities created by users.
	 * For the entieies created by kernel, this pointer will be NULL.
	 */
	struct task_struct	*task;
	/**
	 * @kern_name: name of owner for the kernel created entities.
	 */
	const char		*kern_name;
};

/**
 * rdma_restrack_init() - initialize resource tracking
 * @res:  resource tracking root
 */
int rdma_restrack_init(struct rdma_restrack_root *res);

/**
 * rdma_restrack_clean() - clean resource tracking
 * @res:  resource tracking root
 */
void rdma_restrack_clean(struct rdma_restrack_root *res);

/**
 * for_each_res_safe() - resource iterator
 * @r:    resource entity
 * @n:    next resrouce entity
 * @type: actual type of object to operate
 * @dev:  IB device to operate on
 * Use rdma_restrack_lock/rdma_restrack_unlock to protect it
 */
#define for_each_res_safe(r, n, type, dev) \
	list_for_each_entry_safe(r, n, &(dev)->res.list[type], list)

/**
 * rdma_restrack_lock() - lock to protect reads of restrack_obj structs
 * @res:  resource entry
 * @type: actual type of object to operate
 */
static inline void rdma_restrack_lock(struct rdma_restrack_root *res,
				      enum rdma_restrack_obj type)
{
	down_read(&res->rwsem[type]);
}

/**
 * rdma_restrack_unlock() - unlock to protect reads of restrack_obj structs
 * @res:  resource entry
 * @type: actual type of object to operate
 */
static inline void rdma_restrack_unlock(struct rdma_restrack_root *res,
					enum rdma_restrack_obj type)
{
	up_read(&res->rwsem[type]);
}

/**
 * rdma_restrack_count() - the current usage of specific object
 * @res:  resource entry
 * @type: actual type of object to operate
 *
 * Users can get device utilization by comparing with max_objname
 * (e.g. max_qp, max_pd e.t.c),
 */
int rdma_restrack_count(struct rdma_restrack_root *res,
			enum rdma_restrack_obj type);

/**
 * rdma_restrack_add() - add object to the reource tracking database
 * @res:  resource entry
 * @type: actual type of object to operate
 * @comm: the owner of this resource. For kernel created resources,
 *        there is a need to pass a name here, which will be visible to users.
 *        For user created resources, there is a need to pass NULL here and the
 *        owner will be taken from current struct task_struct.
 */
void rdma_restrack_add(struct rdma_restrack_entry *res,
		       enum rdma_restrack_obj type, const char *comm);

/**
 * rdma_restrack_add() - delete object from the reource tracking database
 * @res:  resource entry
 * @type: actual type of object to operate
 */
void rdma_restrack_del(struct rdma_restrack_entry *res,
		       enum rdma_restrack_obj type);
#endif /* _RDMA_RESTRACK_H_ */

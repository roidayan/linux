/*
 * Copyright (c) 2016,  Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if !defined(IB_PEER_MEM_H)
#define IB_PEER_MEM_H

#include <rdma/peer_mem.h>

struct ib_ucontext;
struct ib_umem;
struct invalidation_ctx;

struct ib_peer_memory_client {
	const struct peer_memory_client *peer_mem;
	struct list_head	core_peer_list;
	int invalidation_required;
	struct kref ref;
	struct completion unload_comp;
	/* lock is used via the invalidation flow */
	struct mutex lock;
	struct list_head   core_ticket_list;
	u64	last_ticket;
};

struct core_ticket {
	unsigned long key;
	void *context;
	struct list_head   ticket_list;
};

struct ib_peer_memory_client *ib_get_peer_client(struct ib_ucontext *context,
						 unsigned long addr,
						 size_t size,
						 unsigned long flags,
						 void **peer_client_context);

void ib_put_peer_client(struct ib_peer_memory_client *ib_peer_client,
			void *peer_client_context);

int ib_peer_create_invalidation_ctx(struct ib_peer_memory_client *ib_peer_mem,
				    struct ib_umem *umem,
				    struct invalidation_ctx **invalidation_ctx);

void ib_peer_destroy_invalidation_ctx(struct ib_peer_memory_client *ib_peer_mem,
				      struct invalidation_ctx *ctx);

#endif

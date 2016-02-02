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

#include <rdma/ib_peer_mem.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_umem.h>

static DEFINE_MUTEX(peer_memory_mutex);
static LIST_HEAD(peer_memory_list);

static int ib_invalidate_peer_memory(void *reg_handle, u64 core_context)
{
	return -ENOSYS;
}

void *ib_register_peer_memory_client(struct peer_memory_client *peer_client,
				     int (**invalidate_callback)
				     (void *reg_handle, u64 core_context))
{
	struct ib_peer_memory_client *ib_peer_client;

	ib_peer_client = kzalloc(sizeof(*ib_peer_client), GFP_KERNEL);
	if (!ib_peer_client)
		return NULL;

	ib_peer_client->peer_mem = peer_client;
	/* Once peer supplied a non NULL callback it's an indication that
	 * invalidation support is required for any memory owning.
	 */
	if (invalidate_callback) {
		*invalidate_callback = ib_invalidate_peer_memory;
		ib_peer_client->invalidation_required = 1;
	}

	mutex_lock(&peer_memory_mutex);
	list_add_tail(&ib_peer_client->core_peer_list, &peer_memory_list);
	mutex_unlock(&peer_memory_mutex);

	return ib_peer_client;
}
EXPORT_SYMBOL(ib_register_peer_memory_client);

void ib_unregister_peer_memory_client(void *reg_handle)
{
	struct ib_peer_memory_client *ib_peer_client = reg_handle;

	mutex_lock(&peer_memory_mutex);
	list_del(&ib_peer_client->core_peer_list);
	mutex_unlock(&peer_memory_mutex);

	kfree(ib_peer_client);
}
EXPORT_SYMBOL(ib_unregister_peer_memory_client);

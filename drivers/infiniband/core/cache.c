/*
 * Copyright (c) 2004 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Intel Corporation. All rights reserved.
 * Copyright (c) 2005 Sun Microsystems, Inc. All rights reserved.
 * Copyright (c) 2005 Voltaire, Inc. All rights reserved.
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

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/netdevice.h>
#include <net/addrconf.h>

#include <rdma/ib_cache.h>

#include "core_priv.h"

struct ib_pkey_cache {
	int             table_len;
	u16             table[0];
};

struct ib_update_work {
	struct work_struct work;
	struct ib_device  *device;
	u8                 port_num;
};

union ib_gid zgid;
EXPORT_SYMBOL_GPL(zgid);

static const struct ib_gid_attr zattr;

enum gid_attr_find_mask {
	GID_ATTR_FIND_MASK_GID          = 1UL << 0,
	GID_ATTR_FIND_MASK_NETDEV	= 1UL << 1,
	GID_ATTR_FIND_MASK_DEFAULT	= 1UL << 2,
};

struct ib_gid_table_entry {
	rwlock_t	    lock;
	bool		    invalid;
	union ib_gid        gid;
	struct ib_gid_attr  attr;
	void		   *context;
	bool		    default_gid;
};

struct ib_gid_table {
	int		     active;
	int                  sz;
	/* locking against multiple writes in data_vec */
	struct mutex         lock;
	struct ib_gid_table_entry *data_vec;
};

static int write_gid(struct ib_device *ib_dev, u8 port,
		     struct ib_gid_table *table, int ix,
		     const union ib_gid *gid,
		     const struct ib_gid_attr *attr,
		     bool  default_gid)
{
	int ret = 0;
	struct net_device *old_net_dev;

	write_lock(&table->data_vec[ix].lock);

	if (rdma_cap_roce_gid_table(ib_dev, port)) {
		table->data_vec[ix].invalid = true;
		write_unlock(&table->data_vec[ix].lock);
		ret = ib_dev->modify_gid(ib_dev, port, ix, gid, attr,
					 &table->data_vec[ix].context);
		write_lock(&table->data_vec[ix].lock);
	}

	old_net_dev = table->data_vec[ix].attr.ndev;
	if (old_net_dev && old_net_dev != attr->ndev)
		dev_put(old_net_dev);
	/* if modify_gid failed, just delete the old gid */
	if (ret || !memcmp(gid, &zgid, sizeof(*gid))) {
		gid = &zgid;
		attr = &zattr;
		table->data_vec[ix].context = NULL;
	}
	table->data_vec[ix].default_gid = default_gid;
	memcpy(&table->data_vec[ix].gid, gid, sizeof(*gid));
	memcpy(&table->data_vec[ix].attr, attr, sizeof(*attr));
	if (table->data_vec[ix].attr.ndev &&
	    table->data_vec[ix].attr.ndev != old_net_dev)
		dev_hold(table->data_vec[ix].attr.ndev);

	table->data_vec[ix].invalid = false;

	write_unlock(&table->data_vec[ix].lock);

	if (!ret && rdma_cap_roce_gid_table(ib_dev, port)) {
		struct ib_event event;

		event.device		= ib_dev;
		event.element.port_num	= port;
		event.event		= IB_EVENT_GID_CHANGE;

		ib_dispatch_event(&event);
	}
	return ret;
}

static int find_gid(struct ib_gid_table *table, const union ib_gid *gid,
		    const struct ib_gid_attr *val, bool default_gid,
		    unsigned long mask)
{
	int i;

	for (i = 0; i < table->sz; i++) {
		struct ib_gid_attr *attr = &table->data_vec[i].attr;

		read_lock(&table->data_vec[i].lock);

		if (table->data_vec[i].invalid)
			goto next;

		if (mask & GID_ATTR_FIND_MASK_GID &&
		    memcmp(gid, &table->data_vec[i].gid, sizeof(*gid)))
			goto next;

		if (mask & GID_ATTR_FIND_MASK_NETDEV &&
		    attr->ndev != val->ndev)
			goto next;

		if (mask & GID_ATTR_FIND_MASK_DEFAULT &&
		    table->data_vec[i].default_gid != default_gid)
			goto next;

		read_unlock(&table->data_vec[i].lock);
		return i;
next:
		read_unlock(&table->data_vec[i].lock);
	}

	return -1;
}

static void make_default_gid(struct  net_device *dev, union ib_gid *gid)
{
	gid->global.subnet_prefix = cpu_to_be64(0xfe80000000000000LL);
	addrconf_ifid_eui48(&gid->raw[8], dev);
}

int ib_cache_gid_add(struct ib_device *ib_dev, u8 port,
		     union ib_gid *gid, struct ib_gid_attr *attr)
{
	struct ib_gid_table **ports_table =
		READ_ONCE(ib_dev->cache.gid_cache);
	struct ib_gid_table *table;
	int ix;
	int ret = 0;
	struct net_device *idev;

	/* all table reads depend on ports_table, no need for smp_rmb() */
	if (!ports_table)
		return -EOPNOTSUPP;

	table = ports_table[port - rdma_start_port(ib_dev)];

	if (!table)
		return -EPROTONOSUPPORT;

	if (!memcmp(gid, &zgid, sizeof(*gid)))
		return -EINVAL;

	if (ib_dev->get_netdev) {
		idev = ib_dev->get_netdev(ib_dev, port);
		if (idev && attr->ndev != idev) {
			union ib_gid default_gid;

			/* Adding default GIDs in not permitted */
			make_default_gid(idev, &default_gid);
			if (!memcmp(gid, &default_gid, sizeof(*gid))) {
				dev_put(idev);
				return -EPERM;
			}
		}
		if (idev)
			dev_put(idev);
	}

	mutex_lock(&table->lock);

	ix = find_gid(table, gid, attr, false, GID_ATTR_FIND_MASK_GID |
		      GID_ATTR_FIND_MASK_NETDEV);
	if (ix >= 0)
		goto out_unlock;

	ix = find_gid(table, &zgid, NULL, false, GID_ATTR_FIND_MASK_GID |
		      GID_ATTR_FIND_MASK_DEFAULT);
	if (ix < 0) {
		ret = -ENOSPC;
		goto out_unlock;
	}

	write_gid(ib_dev, port, table, ix, gid, attr, false);

out_unlock:
	mutex_unlock(&table->lock);
	return ret;
}

int ib_cache_gid_del(struct ib_device *ib_dev, u8 port,
		     union ib_gid *gid, struct ib_gid_attr *attr)
{
	struct ib_gid_table **ports_table =
		READ_ONCE(ib_dev->cache.gid_cache);
	struct ib_gid_table *table;
	union ib_gid default_gid;
	int ix;

	/* all table reads depend on ports_table, no need for smp_rmb() */
	if (!ports_table)
		return 0;

	table  = ports_table[port - rdma_start_port(ib_dev)];

	if (!table)
		return -EPROTONOSUPPORT;

	if (attr->ndev) {
		/* Deleting default GIDs in not permitted */
		make_default_gid(attr->ndev, &default_gid);
		if (!memcmp(gid, &default_gid, sizeof(*gid)))
			return -EPERM;
	}

	mutex_lock(&table->lock);

	ix = find_gid(table, gid, attr, false,
		      GID_ATTR_FIND_MASK_GID	  |
		      GID_ATTR_FIND_MASK_NETDEV	  |
		      GID_ATTR_FIND_MASK_DEFAULT);
	if (ix < 0)
		goto out_unlock;

	write_gid(ib_dev, port, table, ix, &zgid, &zattr, false);

out_unlock:
	mutex_unlock(&table->lock);
	return 0;
}

int ib_cache_gid_del_all_netdev_gids(struct ib_device *ib_dev, u8 port,
				     struct net_device *ndev)
{
	struct ib_gid_table **ports_table =
		READ_ONCE(ib_dev->cache.gid_cache);
	struct ib_gid_table *table;
	int ix;

	/* all table reads depend on ports_table, no need for smp_rmb() */
	if (!ports_table)
		return 0;

	table  = ports_table[port - rdma_start_port(ib_dev)];

	if (!table)
		return -EPROTONOSUPPORT;

	mutex_lock(&table->lock);

	for (ix = 0; ix < table->sz; ix++)
		if (table->data_vec[ix].attr.ndev == ndev)
			write_gid(ib_dev, port, table, ix, &zgid, &zattr, false);

	mutex_unlock(&table->lock);
	return 0;
}

int ib_cache_gid_get(struct ib_device *ib_dev, u8 port, int index,
		     union ib_gid *gid, struct ib_gid_attr *attr)
{
	struct ib_gid_table **ports_table =
		READ_ONCE(ib_dev->cache.gid_cache);
	struct ib_gid_table *table;

	/* all table reads depend on ports_table, no need for smp_rmb() */
	if (!ports_table)
		return -EOPNOTSUPP;

	table = ports_table[port - rdma_start_port(ib_dev)];

	if (!table)
		return -EPROTONOSUPPORT;

	if (index < 0 || index >= table->sz)
		return -EINVAL;

	read_lock(&table->data_vec[index].lock);
	if (table->data_vec[index].invalid) {
		read_unlock(&table->data_vec[index].lock);
		return -EAGAIN;
	}

	memcpy(gid, &table->data_vec[index].gid, sizeof(*gid));
	if (attr) {
		memcpy(attr, &table->data_vec[index].attr, sizeof(*attr));
		if (attr->ndev)
			dev_hold(attr->ndev);
	}

	read_unlock(&table->data_vec[index].lock);
	return 0;
}

static int _ib_cache_gid_table_find(struct ib_device *ib_dev,
				    const union ib_gid *gid,
				    const struct ib_gid_attr *val,
				    unsigned long mask,
				    u8 *port, u16 *index)
{
	struct ib_gid_table **ports_table =
		READ_ONCE(ib_dev->cache.gid_cache);
	struct ib_gid_table *table;
	u8 p;
	int local_index;

	/* all table reads depend on ports_table, no need for smp_rmb() */
	if (!ports_table)
		return -ENOENT;

	for (p = 0; p < ib_dev->phys_port_cnt; p++) {
		table = ports_table[p];
		if (!table)
			continue;
		local_index = find_gid(table, gid, val, false, mask);
		if (local_index >= 0) {
			if (index)
				*index = local_index;
			if (port)
				*port = p + rdma_start_port(ib_dev);
			return 0;
		}
	}

	return -ENOENT;
}

static int ib_cache_gid_find(struct ib_device *ib_dev,
			     const union ib_gid *gid,
			     struct net_device *ndev, u8 *port,
			     u16 *index)
{
	unsigned long mask = GID_ATTR_FIND_MASK_GID;
	struct ib_gid_attr gid_attr_val = {.ndev = ndev};

	if (ndev)
		mask |= GID_ATTR_FIND_MASK_NETDEV;

	return _ib_cache_gid_table_find(ib_dev, gid, &gid_attr_val,
					mask, port, index);
}

int ib_cache_gid_find_by_port(struct ib_device *ib_dev,
			      const union ib_gid *gid,
			      u8 port, struct net_device *ndev,
			      u16 *index)
{
	int local_index;
	struct ib_gid_table **ports_table =
		READ_ONCE(ib_dev->cache.gid_cache);
	struct ib_gid_table *table;
	unsigned long mask = GID_ATTR_FIND_MASK_GID;
	struct ib_gid_attr val = {.ndev = ndev};

	/* all table reads depend on ports_table, no need for smp_rmb() */
	if (!ports_table || port < rdma_start_port(ib_dev) ||
	    port > rdma_end_port(ib_dev))
		return -ENOENT;

	table = ports_table[port - rdma_start_port(ib_dev)];
	if (!table)
		return -ENOENT;

	if (ndev)
		mask |= GID_ATTR_FIND_MASK_NETDEV;

	local_index = find_gid(table, gid, &val, false, mask);
	if (local_index >= 0) {
		if (index)
			*index = local_index;
		return 0;
	}

	return -ENOENT;
}

static struct ib_gid_table *alloc_gid_table(int sz)
{
	unsigned int i;
	struct ib_gid_table *table =
		kzalloc(sizeof(struct ib_gid_table), GFP_KERNEL);
	if (!table)
		return NULL;

	table->data_vec = kcalloc(sz, sizeof(*table->data_vec), GFP_KERNEL);
	if (!table->data_vec)
		goto err_free_table;

	mutex_init(&table->lock);

	table->sz = sz;

	for (i = 0; i < sz; i++)
		rwlock_init(&table->data_vec[i].lock);

	return table;

err_free_table:
	kfree(table);
	return NULL;
}

static void free_gid_table(struct ib_device *ib_dev, u8 port,
			   struct ib_gid_table *table)
{
	int i;

	if (!table)
		return;

	for (i = 0; i < table->sz; ++i) {
		if (memcmp(&table->data_vec[i].gid, &zgid,
			   sizeof(table->data_vec[i].gid)))
			write_gid(ib_dev, port, table, i, &zgid, &zattr,
				  table->data_vec[i].default_gid);
	}
	kfree(table->data_vec);
	kfree(table);
}

void ib_cache_gid_set_default_gid(struct ib_device *ib_dev, u8 port,
				  struct net_device *ndev,
				  enum ib_cache_gid_default_mode mode)
{
	struct ib_gid_table **ports_table =
		READ_ONCE(ib_dev->cache.gid_cache);
	union ib_gid gid;
	struct ib_gid_attr gid_attr;
	struct ib_gid_table *table;
	int ix;
	union ib_gid current_gid;
	struct ib_gid_attr current_gid_attr = {};

	if (!ports_table)
		return;

	/* all table reads depend on ports_table, no need for smp_rmb() */
	table  = ports_table[port - rdma_start_port(ib_dev)];

	if (!table)
		return;

	make_default_gid(ndev, &gid);
	memset(&gid_attr, 0, sizeof(gid_attr));
	gid_attr.ndev = ndev;

	ix = find_gid(table, &gid, &gid_attr, true,
		      GID_ATTR_FIND_MASK_DEFAULT);

	if (ix < 0) {
		pr_warn("ib_cache_gid: couldn't find index for default gid\n");
		return;
	}

	mutex_lock(&table->lock);
	if (!ib_cache_gid_get(ib_dev, port, ix,
			      &current_gid, &current_gid_attr) &&
	    mode == IB_CACHE_GID_DEFAULT_MODE_SET &&
	    !memcmp(&gid, &current_gid, sizeof(gid)) &&
	    !memcmp(&gid_attr, &current_gid_attr, sizeof(gid_attr)))
		goto unlock;

	if ((memcmp(&current_gid, &zgid, sizeof(current_gid)) ||
	     memcmp(&current_gid_attr, &zattr,
		    sizeof(current_gid_attr))) &&
	    write_gid(ib_dev, port, table, ix, &zgid, &zattr, true)) {
		pr_warn("ib_cache_gid: can't delete index %d for default gid %pI6\n",
			ix, gid.raw);
		goto unlock;
	}

	if (mode == IB_CACHE_GID_DEFAULT_MODE_SET)
		if (write_gid(ib_dev, port, table, ix, &gid, &gid_attr,
			      true))
			pr_warn("ib_cache_gid: unable to add default gid %pI6\n",
				gid.raw);

unlock:
	if (current_gid_attr.ndev)
		dev_put(current_gid_attr.ndev);
	mutex_unlock(&table->lock);
}

static int gid_table_reserve_default(struct ib_device *ib_dev, u8 port,
				     struct ib_gid_table *table)
{
	if (roce_gid_type_support(ib_dev, port) &&
	    rdma_protocol_roce(ib_dev, port)) {
		struct ib_gid_table_entry *entry =
			&table->data_vec[0];

		entry->default_gid = true;
	}

	return 0;
}

static int gid_table_setup_one(struct ib_device *ib_dev)
{
	u8 port;
	struct ib_gid_table **table;
	int err = 0;

	table = kcalloc(ib_dev->phys_port_cnt, sizeof(*table), GFP_KERNEL);

	if (!table) {
		pr_warn("failed to allocate ib gid cache for %s\n",
			ib_dev->name);
		return -ENOMEM;
	}

	for (port = 0; port < ib_dev->phys_port_cnt; port++) {
		uint8_t rdma_port = port + rdma_start_port(ib_dev);

		table[port] =
			alloc_gid_table(
				ib_dev->port_immutable[rdma_port].gid_tbl_len);
		if (!table[port]) {
			err = -ENOMEM;
			goto rollback_table_setup;
		}

		err = gid_table_reserve_default(ib_dev,
						port + rdma_start_port(ib_dev),
						table[port]);
		if (err)
			goto rollback_table_setup;
	}

	ib_dev->cache.gid_cache = table;
	return 0;

rollback_table_setup:
	for (port = 1; port <= ib_dev->phys_port_cnt; port++)
		free_gid_table(ib_dev, port, table[port]);

	kfree(table);
	return err;
}

static void gid_table_cleanup_one(struct ib_device *ib_dev,
				  struct ib_gid_table **table)
{
	u8 port;

	if (!table)
		return;

	for (port = 0; port < ib_dev->phys_port_cnt; port++)
		free_gid_table(ib_dev, port + rdma_start_port(ib_dev),
			       table[port]);

	kfree(table);
}

static void gid_table_client_cleanup_one(struct ib_device *ib_dev)
{
	struct ib_gid_table **table = ib_dev->cache.gid_cache;

	if (!table)
		return;

	ib_dev->cache.gid_cache = NULL;
	/* smp_wmb is mandatory in order to make sure all executing works
	 * realize we're freeing this ib_cache_gid. Every function which
	 * could be executed in a work, fetches ib_dev->cache.gid_cache
	 * once (READ_ONCE + smp_rmb) into a local variable.
	 * If it fetched a value != NULL, we wait for this work to finish by
	 * calling flush_workqueue. If it fetches NULL, it'll return immediately.
	 */
	smp_wmb();
	/* Make sure no gid update task is still referencing this device */
	flush_workqueue(roce_gid_mgmt_wq);
	flush_workqueue(ib_wq);

	gid_table_cleanup_one(ib_dev, table);
}

static void gid_table_client_setup_one(struct ib_device *ib_dev)
{
	if (!gid_table_setup_one(ib_dev))
		if (roce_rescan_device(ib_dev))
			gid_table_client_cleanup_one(ib_dev);
}

int ib_get_cached_gid(struct ib_device *device,
		      u8                port_num,
		      int               index,
		      union ib_gid     *gid)
{
	if (port_num < rdma_start_port(device) || port_num > rdma_end_port(device))
		return -EINVAL;

	return ib_cache_gid_get(device, port_num, index, gid, NULL);
}
EXPORT_SYMBOL(ib_get_cached_gid);

int ib_find_cached_gid(struct ib_device *device,
		       const union ib_gid *gid,
		       u8               *port_num,
		       u16              *index)
{
	return ib_cache_gid_find(device, gid, NULL, port_num, index);
}
EXPORT_SYMBOL(ib_find_cached_gid);

int ib_get_cached_pkey(struct ib_device *device,
		       u8                port_num,
		       int               index,
		       u16              *pkey)
{
	struct ib_pkey_cache *cache;
	unsigned long flags;
	int ret = -ENOENT;

	if (port_num < rdma_start_port(device) || port_num > rdma_end_port(device))
		return -EINVAL;

	if (!device->cache.pkey_cache)
		return -ENOENT;

	read_lock_irqsave(&device->cache.lock, flags);

	cache = device->cache.pkey_cache[port_num - rdma_start_port(device)];
	if (cache && index >= 0 && index < cache->table_len) {
		*pkey = cache->table[index];
		ret = 0;
	}

	read_unlock_irqrestore(&device->cache.lock, flags);
	return ret;
}
EXPORT_SYMBOL(ib_get_cached_pkey);

int ib_find_cached_pkey(struct ib_device *device,
			u8                port_num,
			u16               pkey,
			u16              *index)
{
	struct ib_pkey_cache *cache;
	unsigned long flags;
	int i;
	int ret = -ENOENT;
	int partial_ix = -1;

	if (port_num < rdma_start_port(device) || port_num > rdma_end_port(device))
		return -EINVAL;

	if (!device->cache.pkey_cache)
		return -ENOENT;

	read_lock_irqsave(&device->cache.lock, flags);

	cache = device->cache.pkey_cache[port_num - rdma_start_port(device)];
	if (!cache)
		goto out;

	*index = -1;

	for (i = 0; i < cache->table_len; ++i)
		if ((cache->table[i] & 0x7fff) == (pkey & 0x7fff)) {
			if (cache->table[i] & 0x8000) {
				*index = i;
				ret = 0;
				break;
			} else
				partial_ix = i;
		}

	if (ret && partial_ix >= 0) {
		*index = partial_ix;
		ret = 0;
	}

out:
	read_unlock_irqrestore(&device->cache.lock, flags);
	return ret;
}
EXPORT_SYMBOL(ib_find_cached_pkey);

int ib_find_exact_cached_pkey(struct ib_device *device,
			      u8                port_num,
			      u16               pkey,
			      u16              *index)
{
	struct ib_pkey_cache *cache;
	unsigned long flags;
	int i;
	int ret = -ENOENT;

	if (port_num < rdma_start_port(device) || port_num > rdma_end_port(device))
		return -EINVAL;

	if (!device->cache.pkey_cache)
		return -ENOENT;

	read_lock_irqsave(&device->cache.lock, flags);

	cache = device->cache.pkey_cache[port_num - rdma_start_port(device)];
	if (!cache)
		goto out;

	*index = -1;

	for (i = 0; i < cache->table_len; ++i)
		if (cache->table[i] == pkey) {
			*index = i;
			ret = 0;
			break;
		}
out:
	read_unlock_irqrestore(&device->cache.lock, flags);
	return ret;
}
EXPORT_SYMBOL(ib_find_exact_cached_pkey);

int ib_get_cached_lmc(struct ib_device *device,
		      u8                port_num,
		      u8                *lmc)
{
	unsigned long flags;
	int ret = -ENOENT;

	if (port_num < rdma_start_port(device) || port_num > rdma_end_port(device))
		return -EINVAL;

	read_lock_irqsave(&device->cache.lock, flags);
	if (device->cache.lmc_cache) {
		*lmc = device->cache.lmc_cache[port_num - rdma_start_port(device)];
		ret = 0;
	}
	read_unlock_irqrestore(&device->cache.lock, flags);

	return ret;
}
EXPORT_SYMBOL(ib_get_cached_lmc);

static void ib_cache_update(struct ib_device *device,
			    u8                port)
{
	struct ib_port_attr       *tprops = NULL;
	struct ib_pkey_cache      *pkey_cache = NULL, *old_pkey_cache;
	struct ib_gid_cache {
		int             table_len;
		union ib_gid    table[0];
	}			  *gid_cache = NULL;
	int                        i;
	int                        ret;
	struct ib_gid_table	  *table;
	struct ib_gid_table	 **ports_table =
		READ_ONCE(device->cache.gid_cache);
	bool			   use_roce_gid_table =
					rdma_cap_roce_gid_table(device, port);

	/* all table reads depend on ports_table, no need for smp_rmb() */
	if (!ports_table)
		return;

	if (port < rdma_start_port(device) || port > rdma_end_port(device))
		return;

	table = ports_table[port - rdma_start_port(device)];

	if (!table)
		return;

	if (!(device->cache.pkey_cache &&
	      device->cache.lmc_cache))
		return;

	tprops = kmalloc(sizeof *tprops, GFP_KERNEL);
	if (!tprops)
		return;

	ret = ib_query_port(device, port, tprops);
	if (ret) {
		printk(KERN_WARNING "ib_query_port failed (%d) for %s\n",
		       ret, device->name);
		goto err;
	}

	pkey_cache = kmalloc(sizeof *pkey_cache + tprops->pkey_tbl_len *
			     sizeof *pkey_cache->table, GFP_KERNEL);
	if (!pkey_cache)
		goto err;

	pkey_cache->table_len = tprops->pkey_tbl_len;

	if (!use_roce_gid_table) {
		gid_cache = kmalloc(sizeof(*gid_cache) + tprops->gid_tbl_len *
			    sizeof(*gid_cache->table), GFP_KERNEL);
		if (!gid_cache)
			goto err;

		gid_cache->table_len = tprops->gid_tbl_len;
	}

	for (i = 0; i < pkey_cache->table_len; ++i) {
		ret = ib_query_pkey(device, port, i, pkey_cache->table + i);
		if (ret) {
			printk(KERN_WARNING "ib_query_pkey failed (%d) for %s (index %d)\n",
			       ret, device->name, i);
			goto err;
		}
	}

	if (!use_roce_gid_table) {
		for (i = 0;  i < gid_cache->table_len; ++i) {
			ret = ib_query_gid(device, port, i,
					   gid_cache->table + i);
			if (ret) {
				printk(KERN_WARNING "ib_query_gid failed (%d) for %s (index %d)\n",
				       ret, device->name, i);
				goto err;
			}
		}
	}

	write_lock_irq(&device->cache.lock);

	old_pkey_cache = device->cache.pkey_cache[port - rdma_start_port(device)];

	device->cache.pkey_cache[port - rdma_start_port(device)] = pkey_cache;
	if (!use_roce_gid_table) {
		for (i = 0; i < gid_cache->table_len; i++) {
			write_gid(device, port, table, i, gid_cache->table + i,
				  &zattr, false);
		}
	}

	device->cache.lmc_cache[port - rdma_start_port(device)] = tprops->lmc;

	write_unlock_irq(&device->cache.lock);

	kfree(gid_cache);
	kfree(old_pkey_cache);
	kfree(tprops);
	return;

err:
	kfree(pkey_cache);
	kfree(gid_cache);
	kfree(tprops);
}

static void ib_cache_task(struct work_struct *_work)
{
	struct ib_update_work *work =
		container_of(_work, struct ib_update_work, work);

	ib_cache_update(work->device, work->port_num);
	kfree(work);
}

static void ib_cache_event(struct ib_event_handler *handler,
			   struct ib_event *event)
{
	struct ib_update_work *work;

	if (event->event == IB_EVENT_PORT_ERR    ||
	    event->event == IB_EVENT_PORT_ACTIVE ||
	    event->event == IB_EVENT_LID_CHANGE  ||
	    event->event == IB_EVENT_PKEY_CHANGE ||
	    event->event == IB_EVENT_SM_CHANGE   ||
	    event->event == IB_EVENT_CLIENT_REREGISTER ||
	    event->event == IB_EVENT_GID_CHANGE) {
		work = kmalloc(sizeof *work, GFP_ATOMIC);
		if (work) {
			INIT_WORK(&work->work, ib_cache_task);
			work->device   = event->device;
			work->port_num = event->element.port_num;
			queue_work(ib_wq, &work->work);
		}
	}
}

static void ib_cache_setup_one(struct ib_device *device)
{
	int p;

	rwlock_init(&device->cache.lock);

	device->cache.pkey_cache =
		kmalloc(sizeof *device->cache.pkey_cache *
			(rdma_end_port(device) - rdma_start_port(device) + 1), GFP_KERNEL);
	gid_table_client_setup_one(device);
	device->cache.lmc_cache = kmalloc(sizeof *device->cache.lmc_cache *
					  (rdma_end_port(device) -
					   rdma_start_port(device) + 1),
					  GFP_KERNEL);

	if (!device->cache.pkey_cache || !device->cache.gid_cache ||
	    !device->cache.lmc_cache) {
		printk(KERN_WARNING "Couldn't allocate cache "
		       "for %s\n", device->name);
		goto err;
	}

	for (p = 0; p <= rdma_end_port(device) - rdma_start_port(device); ++p) {
		device->cache.pkey_cache[p] = NULL;
		ib_cache_update(device, p + rdma_start_port(device));
	}

	INIT_IB_EVENT_HANDLER(&device->cache.event_handler,
			      device, ib_cache_event);
	if (ib_register_event_handler(&device->cache.event_handler))
		goto err_cache;

	return;

err_cache:
	for (p = 0; p <= rdma_end_port(device) - rdma_start_port(device); ++p)
		kfree(device->cache.pkey_cache[p]);

err:
	kfree(device->cache.pkey_cache);
	gid_table_client_cleanup_one(device);
	kfree(device->cache.lmc_cache);
	device->cache.pkey_cache = NULL;
	device->cache.lmc_cache = NULL;
}

static void ib_cache_cleanup_one(struct ib_device *device)
{
	int p;

	if (!(device->cache.pkey_cache &&
	      device->cache.lmc_cache))
		return;

	ib_unregister_event_handler(&device->cache.event_handler);
	flush_workqueue(ib_wq);

	for (p = 0; p <= rdma_end_port(device) - rdma_start_port(device); ++p)
		kfree(device->cache.pkey_cache[p]);

	kfree(device->cache.pkey_cache);
	gid_table_client_cleanup_one(device);
	kfree(device->cache.lmc_cache);
}

static struct ib_client cache_client = {
	.name   = "cache",
	.add    = ib_cache_setup_one,
	.remove = ib_cache_cleanup_one
};

int __init ib_cache_setup(void)
{
	roce_gid_mgmt_init();
	return ib_register_client(&cache_client);
}

void __exit ib_cache_cleanup(void)
{
	ib_unregister_client(&cache_client);
	roce_gid_mgmt_cleanup();
}

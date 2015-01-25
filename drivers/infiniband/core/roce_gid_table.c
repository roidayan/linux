/*
 * Copyright (c) 2015, Mellanox Technologies inc.  All rights reserved.
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

#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <rdma/ib_cache.h>
#include <net/addrconf.h>

#include "core_priv.h"

union ib_gid zgid;
EXPORT_SYMBOL_GPL(zgid);

static const struct ib_gid_attr zattr;

enum gid_attr_find_mask {
	GID_ATTR_FIND_MASK_GID          = 1UL << 0,
	GID_ATTR_FIND_MASK_GID_TYPE	= 1UL << 1,
	GID_ATTR_FIND_MASK_NETDEV	= 1UL << 2,
	GID_ATTR_FIND_MASK_DEFAULT	= 1UL << 3,
};

static const char * const gid_type_str[] = {
	[IB_GID_TYPE_IB]	= "IB/RoCE v1\n",
};

static inline int start_port(struct ib_device *ib_dev)
{
	return (ib_dev->node_type == RDMA_NODE_IB_SWITCH) ? 0 : 1;
}

struct dev_put_rcu {
	struct rcu_head		rcu;
	struct net_device	*ndev;
};

const char *roce_gid_table_type_str(enum ib_gid_type gid_type)
{
	if (gid_type < ARRAY_SIZE(gid_type_str) && gid_type_str[gid_type])
		return gid_type_str[gid_type];

	return "Invalid GID type";
}

static void put_ndev(struct rcu_head *rcu)
{
	struct dev_put_rcu *put_rcu =
		container_of(rcu, struct dev_put_rcu, rcu);

	dev_put(put_rcu->ndev);
	kfree(put_rcu);
}

static int write_gid(struct ib_device *ib_dev, u8 port,
		     struct ib_roce_gid_table *table, int ix,
		     const union ib_gid *gid,
		     const struct ib_gid_attr *attr,
		     bool  default_gid)
{
	int ret;
	struct dev_put_rcu	*put_rcu;
	struct net_device *old_net_dev;

	write_seqcount_begin(&table->data_vec[ix].seq);

	table->data_vec[ix].default_gid = default_gid;
	ret = ib_dev->modify_gid(ib_dev, port, ix, gid, attr,
				 &table->data_vec[ix].context);

	old_net_dev = table->data_vec[ix].attr.ndev;
	if (old_net_dev && old_net_dev != attr->ndev) {
		put_rcu = kmalloc(sizeof(*put_rcu), GFP_KERNEL);
		if (put_rcu) {
			put_rcu->ndev = old_net_dev;
			call_rcu(&put_rcu->rcu, put_ndev);
		} else {
			pr_warn("roce_gid_table: can't allocate rcu context, using synchronize\n");
			synchronize_rcu();
			dev_put(old_net_dev);
		}
	}
	/* if modify_gid failed, just delete the old gid */
	if (ret || !memcmp(gid, &zgid, sizeof(*gid))) {
		gid = &zgid;
		attr = &zattr;
		table->data_vec[ix].context = NULL;
	}
	memcpy(&table->data_vec[ix].gid, gid, sizeof(*gid));
	memcpy(&table->data_vec[ix].attr, attr, sizeof(*attr));
	if (table->data_vec[ix].attr.ndev &&
	    table->data_vec[ix].attr.ndev != old_net_dev)
		dev_hold(table->data_vec[ix].attr.ndev);

	write_seqcount_end(&table->data_vec[ix].seq);

	if (!ret) {
		struct ib_event event;

		event.device		= ib_dev;
		event.element.port_num	= port;
		event.event		= IB_EVENT_GID_CHANGE;

		ib_dispatch_event(&event);
	}
	return ret;
}

static int find_gid(struct ib_roce_gid_table *table, union ib_gid *gid,
		    const struct ib_gid_attr *val, bool default_gid,
		    unsigned long mask)
{
	int i;

	for (i = 0; i < table->sz; i++) {
		struct ib_gid_attr *attr = &table->data_vec[i].attr;
		unsigned int orig_seq = read_seqcount_begin(&table->data_vec[i].seq);

		if (mask & GID_ATTR_FIND_MASK_GID_TYPE &&
		    attr->gid_type != val->gid_type)
			continue;

		if (mask & GID_ATTR_FIND_MASK_GID &&
		    memcmp(gid, &table->data_vec[i].gid, sizeof(*gid)))
			continue;

		if (mask & GID_ATTR_FIND_MASK_NETDEV &&
		    attr->ndev != val->ndev)
			continue;

		if (mask & GID_ATTR_FIND_MASK_DEFAULT &&
		    table->data_vec[i].default_gid != default_gid)
			continue;

		if (!read_seqcount_retry(&table->data_vec[i].seq, orig_seq))
			return i;
		/* The sequence number changed under our feet,
		 * the GID entry is invalid. Continue to the
		 * next entry.
		 */
	}

	return -1;
}

static void make_default_gid(struct  net_device *dev, union ib_gid *gid)
{
	gid->global.subnet_prefix = cpu_to_be64(0xfe80000000000000LL);
	addrconf_ifid_eui48(&gid->raw[8], dev);
}

int roce_add_gid(struct ib_device *ib_dev, u8 port,
		 union ib_gid *gid, struct ib_gid_attr *attr)
{
	struct ib_roce_gid_table *table;
	int ix;
	int ret = 0;
	struct net_device *idev;

	if (!ib_dev->cache.roce_gid_table)
		return -ENOSYS;

	table = ib_dev->cache.roce_gid_table[port - start_port(ib_dev)];

	if (!table || !table->active)
		return -ENOSYS;

	if (!memcmp(gid, &zgid, sizeof(*gid)))
		return -EINVAL;

	if (ib_dev->get_netdev) {
		rcu_read_lock();
		idev = ib_dev->get_netdev(ib_dev, port);
		if (idev && attr->ndev != idev) {
			union ib_gid default_gid;

			/* Adding default GIDs in not permitted */
			make_default_gid(idev, &default_gid);
			if (!memcmp(gid, &default_gid, sizeof(*gid))) {
				rcu_read_unlock();
				return -EPERM;
			}
		}
		rcu_read_unlock();
	}

	mutex_lock(&table->lock);

	ix = find_gid(table, gid, attr, false, GID_ATTR_FIND_MASK_GID |
		      GID_ATTR_FIND_MASK_GID_TYPE |
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

int roce_del_gid(struct ib_device *ib_dev, u8 port,
		 union ib_gid *gid, struct ib_gid_attr *attr)
{
	struct ib_roce_gid_table *table;
	union ib_gid default_gid;
	int ix;

	if (!ib_dev->cache.roce_gid_table)
		return 0;

	table  = ib_dev->cache.roce_gid_table[port - start_port(ib_dev)];

	if (!table || !table->active)
		return -ENOSYS;

	if (attr->ndev) {
		/* Deleting default GIDs in not permitted */
		make_default_gid(attr->ndev, &default_gid);
		if (!memcmp(gid, &default_gid, sizeof(*gid)))
			return -EPERM;
	}

	mutex_lock(&table->lock);

	ix = find_gid(table, gid, attr, false,
		      GID_ATTR_FIND_MASK_GID	  |
		      GID_ATTR_FIND_MASK_GID_TYPE |
		      GID_ATTR_FIND_MASK_NETDEV	  |
		      GID_ATTR_FIND_MASK_DEFAULT);
	if (ix < 0)
		goto out_unlock;

	write_gid(ib_dev, port, table, ix, &zgid, &zattr, false);

out_unlock:
	mutex_unlock(&table->lock);
	return 0;
}

int roce_del_all_netdev_gids(struct ib_device *ib_dev, u8 port,
			     struct net_device *ndev)
{
	struct ib_roce_gid_table *table;
	int ix;

	if (!ib_dev->cache.roce_gid_table)
		return 0;

	table  = ib_dev->cache.roce_gid_table[port - start_port(ib_dev)];

	if (!table || !table->active)
		return -ENOSYS;

	mutex_lock(&table->lock);

	for (ix = 0; ix < table->sz; ix++)
		if (table->data_vec[ix].attr.ndev == ndev)
			write_gid(ib_dev, port, table, ix, &zgid, &zattr, false);

	mutex_unlock(&table->lock);
	return 0;
}

int roce_gid_table_get_gid(struct ib_device *ib_dev, u8 port, int index,
			   union ib_gid *gid, struct ib_gid_attr *attr)
{
	struct ib_roce_gid_table *table;
	union ib_gid local_gid;
	struct ib_gid_attr local_attr;
	unsigned int orig_seq;

	if (!ib_dev->cache.roce_gid_table)
		return -EINVAL;

	table = ib_dev->cache.roce_gid_table[port - start_port(ib_dev)];

	if (!table || !table->active)
		return -ENOSYS;

	if (index < 0 || index >= table->sz)
		return -EINVAL;

	orig_seq = read_seqcount_begin(&table->data_vec[index].seq);

	memcpy(&local_gid, &table->data_vec[index].gid, sizeof(local_gid));
	memcpy(&local_attr, &table->data_vec[index].attr, sizeof(local_attr));

	if (read_seqcount_retry(&table->data_vec[index].seq, orig_seq))
		return -EAGAIN;

	memcpy(gid, &local_gid, sizeof(*gid));
	if (attr)
		memcpy(attr, &local_attr, sizeof(*attr));
	return 0;
}

static int _roce_gid_table_find_gid(struct ib_device *ib_dev, union ib_gid *gid,
				    const struct ib_gid_attr *val,
				    unsigned long mask,
				    u8 *port, u16 *index)
{
	struct ib_roce_gid_table *table;
	u8 p;
	int local_index;

	if (!ib_dev->cache.roce_gid_table)
		return -ENOENT;

	for (p = 0; p < ib_dev->phys_port_cnt; p++) {
		if (rdma_port_get_link_layer(ib_dev, p + start_port(ib_dev)) !=
		    IB_LINK_LAYER_ETHERNET)
			continue;
		table = ib_dev->cache.roce_gid_table[p];
		if (!table || !table->active)
			continue;
		local_index = find_gid(table, gid, val, false, mask);
		if (local_index >= 0) {
			if (index)
				*index = local_index;
			if (port)
				*port = p + start_port(ib_dev);
			return 0;
		}
	}

	return -ENOENT;
}

static int get_netdev_from_ifindex(struct net *net, int if_index,
				   struct ib_gid_attr *gid_attr_val)
{
	if (if_index && net) {
		rcu_read_lock();
		gid_attr_val->ndev = dev_get_by_index_rcu(net, if_index);
		rcu_read_unlock();
		if (gid_attr_val->ndev)
			return GID_ATTR_FIND_MASK_NETDEV;
	}
	return 0;
}

int roce_gid_table_find_gid(struct ib_device *ib_dev, union ib_gid *gid,
			    enum ib_gid_type gid_type, struct net *net,
			    int if_index, u8 *port, u16 *index)
{
	unsigned long mask = GID_ATTR_FIND_MASK_GID |
			     GID_ATTR_FIND_MASK_GID_TYPE;
	struct ib_gid_attr gid_attr_val = {.gid_type = gid_type};

	mask |= get_netdev_from_ifindex(net, if_index, &gid_attr_val);

	return _roce_gid_table_find_gid(ib_dev, gid, &gid_attr_val,
					mask, port, index);
}

int roce_gid_table_find_gid_by_port(struct ib_device *ib_dev, union ib_gid *gid,
				    enum ib_gid_type gid_type, u8 port,
				    struct net *net, int if_index, u16 *index)
{
	int local_index;
	struct ib_roce_gid_table *table;
	unsigned long mask = GID_ATTR_FIND_MASK_GID |
			     GID_ATTR_FIND_MASK_GID_TYPE;
	struct ib_gid_attr val = {.gid_type = gid_type};

	if (!ib_dev->cache.roce_gid_table || port < start_port(ib_dev) ||
	    port >= (start_port(ib_dev) + ib_dev->phys_port_cnt))
		return -ENOENT;

	table = ib_dev->cache.roce_gid_table[port - start_port(ib_dev)];
	if (!table || !table->active)
		return -ENOENT;

	mask |= get_netdev_from_ifindex(net, if_index, &val);

	local_index = find_gid(table, gid, &val, false, mask);
	if (local_index >= 0) {
		if (index)
			*index = local_index;
		return 0;
	}

	return -ENOENT;
}

static struct ib_roce_gid_table *alloc_roce_gid_table(int sz)
{
	unsigned int i;
	struct ib_roce_gid_table *table =
		kzalloc(sizeof(struct ib_roce_gid_table), GFP_KERNEL);
	if (!table)
		return NULL;

	table->data_vec = kcalloc(sz, sizeof(*table->data_vec), GFP_KERNEL);
	if (!table->data_vec)
		goto err_free_table;

	mutex_init(&table->lock);

	table->sz = sz;

	for (i = 0; i < sz; i++)
		seqcount_init(&table->data_vec[i].seq);

	return table;

err_free_table:
	kfree(table);
	return NULL;
}

static void free_roce_gid_table(struct ib_device *ib_dev, u8 port)
{
	int i;
	struct ib_roce_gid_table *table =
		ib_dev->cache.roce_gid_table[port - 1];

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

static void set_roce_gid_table_active(struct ib_roce_gid_table *table,
				      int active)
{
	if (!table)
		return;

	table->active = active;
}

void roce_gid_table_set_default_gid(struct ib_device *ib_dev, u8 port,
				    struct net_device *ndev,
				    unsigned long gid_type_mask,
				    enum roce_gid_table_default_mode mode)
{
	union ib_gid gid;
	struct ib_gid_attr gid_attr;
	struct ib_gid_attr zattr_type = zattr;
	struct ib_roce_gid_table *table;
	unsigned int gid_type;

	table  = ib_dev->cache.roce_gid_table[port - 1];

	if (!table)
		return;

	make_default_gid(ndev, &gid);
	memset(&gid_attr, 0, sizeof(gid_attr));
	gid_attr.ndev = ndev;
	for (gid_type = 0; gid_type < IB_GID_TYPE_SIZE; ++gid_type) {
		int ix;
		union ib_gid current_gid;
		struct ib_gid_attr current_gid_attr;

		if (1UL << gid_type & ~gid_type_mask)
			continue;

		gid_attr.gid_type = gid_type;

		ix = find_gid(table, &gid, &gid_attr, true,
			      GID_ATTR_FIND_MASK_GID_TYPE |
			      GID_ATTR_FIND_MASK_DEFAULT);

		if (ix < 0) {
			pr_warn("roce_gid_table: couldn't find index for default gid type %u\n",
				gid_type);
			continue;
		}

		zattr_type.gid_type = gid_type;

		mutex_lock(&table->lock);
		if (!roce_gid_table_get_gid(ib_dev, port, ix,
					    &current_gid, &current_gid_attr) &&
		    mode == ROCE_GID_TABLE_DEFAULT_MODE_SET &&
		    !memcmp(&gid, &current_gid, sizeof(gid)) &&
		    !memcmp(&gid_attr, &current_gid_attr, sizeof(gid_attr))) {
			mutex_unlock(&table->lock);
			continue;
		}

		if ((memcmp(&current_gid, &zgid, sizeof(current_gid)) ||
		     memcmp(&current_gid_attr, &zattr_type,
			    sizeof(current_gid_attr))) &&
		    write_gid(ib_dev, port, table, ix, &zgid, &zattr, true)) {
			pr_warn("roce_gid_table: can't delete index %d for default gid %pI6\n",
				ix, gid.raw);
			mutex_unlock(&table->lock);
			continue;
		}

		if (mode == ROCE_GID_TABLE_DEFAULT_MODE_SET)
			if (write_gid(ib_dev, port, table, ix, &gid, &gid_attr,
				      true))
				pr_warn("roce_gid_table: unable to add default gid %pI6\n",
					gid.raw);

		mutex_unlock(&table->lock);
	}
}

static int roce_gid_table_reserve_default(struct ib_device *ib_dev, u8 port)
{
	unsigned int i;
	unsigned long roce_gid_type_mask;
	unsigned int num_default_gids;
	struct ib_roce_gid_table *table;

	table  = ib_dev->cache.roce_gid_table[port - 1];

	roce_gid_type_mask = roce_gid_type_mask_support(ib_dev, port);
	num_default_gids = hweight_long(roce_gid_type_mask);
	for (i = 0; i < num_default_gids && i < table->sz; i++) {
		struct ib_roce_gid_table_entry *entry =
			&table->data_vec[i];

		entry->default_gid = true;
		entry->attr.gid_type = find_next_bit(&roce_gid_type_mask,
						     BITS_PER_LONG,
						     i);
	}

	return 0;
}

static int roce_gid_table_setup_one(struct ib_device *ib_dev)
{
	u8 port;
	int err = 0;

	if (!ib_dev->modify_gid)
		return -ENOSYS;

	ib_dev->cache.roce_gid_table =
		kcalloc(ib_dev->phys_port_cnt,
			sizeof(*ib_dev->cache.roce_gid_table), GFP_KERNEL);

	if (!ib_dev->cache.roce_gid_table) {
		pr_warn("failed to allocate roce addr table for %s\n",
			ib_dev->name);
		return -ENOMEM;
	}

	for (port = 0; port < ib_dev->phys_port_cnt; port++) {
		if (rdma_port_get_link_layer(ib_dev, port + start_port(ib_dev))
		    != IB_LINK_LAYER_ETHERNET)
			continue;
		ib_dev->cache.roce_gid_table[port] =
			alloc_roce_gid_table(ib_dev->gid_tbl_len[port]);
		if (!ib_dev->cache.roce_gid_table[port]) {
			err = -ENOMEM;
			goto rollback_table_setup;
		}

		err = roce_gid_table_reserve_default(ib_dev, port + 1);
		if (err)
			goto rollback_table_setup;
	}
	return 0;

rollback_table_setup:
	for (port = 1; port <= ib_dev->phys_port_cnt; port++)
		free_roce_gid_table(ib_dev, port);

	kfree(ib_dev->cache.roce_gid_table);
	ib_dev->cache.roce_gid_table = NULL;
	return err;
}

static void roce_gid_table_cleanup_one(struct ib_device *ib_dev)
{
	u8 port;

	if (!ib_dev->cache.roce_gid_table)
		return;

	for (port = 1; port <= ib_dev->phys_port_cnt; port++)
		free_roce_gid_table(ib_dev, port);

	kfree(ib_dev->cache.roce_gid_table);
	ib_dev->cache.roce_gid_table = NULL;
}

static void roce_gid_table_set_active_state(struct ib_device *ib_dev,
					    int active)
{
	u8 port;

	if (!ib_dev->cache.roce_gid_table)
		return;

	for (port = 0; port < ib_dev->phys_port_cnt; port++)
		set_roce_gid_table_active(ib_dev->cache.roce_gid_table[port],
					  active);
}

int roce_gid_table_is_active(struct ib_device *ib_dev, u8 port)
{
	return ib_dev->cache.roce_gid_table &&
		ib_dev->cache.roce_gid_table[port - start_port(ib_dev)]->active;
}

static void roce_gid_table_client_setup_one(struct ib_device *ib_dev)
{
	if (!roce_gid_table_setup_one(ib_dev)) {
		roce_gid_table_set_active_state(ib_dev, 1);
		if (roce_rescan_device(ib_dev)) {
			roce_gid_table_set_active_state(ib_dev, 0);
			roce_gid_table_cleanup_one(ib_dev);
		}
	}
}

static void roce_gid_table_client_cleanup_one(struct ib_device *ib_dev)
{
	roce_gid_table_set_active_state(ib_dev, 0);
	/* Make sure no gid update task is still referencing this device */
	flush_workqueue(roce_gid_mgmt_wq);

	roce_gid_table_cleanup_one(ib_dev);
}

static struct ib_client table_client = {
	.name   = "roce_gid_table",
	.add    = roce_gid_table_client_setup_one,
	.remove = roce_gid_table_client_cleanup_one
};

int __init roce_gid_table_setup(void)
{
	roce_gid_mgmt_init();

	return ib_register_client(&table_client);
}

void __exit roce_gid_table_cleanup(void)
{
	ib_unregister_client(&table_client);

	roce_gid_mgmt_cleanup();

	flush_workqueue(system_wq);

	rcu_barrier();
}

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

#include "core_priv.h"

union ib_gid zgid;
EXPORT_SYMBOL_GPL(zgid);

static const struct ib_gid_attr zattr;

enum gid_attr_find_mask {
	GID_ATTR_FIND_MASK_GID          = 1UL << 0,
	GID_ATTR_FIND_MASK_GID_TYPE	= 1UL << 1,
	GID_ATTR_FIND_MASK_NETDEV	= 1UL << 2,
};

static inline int start_port(struct ib_device *ib_dev)
{
	return (ib_dev->node_type == RDMA_NODE_IB_SWITCH) ? 0 : 1;
}

struct dev_put_rcu {
	struct rcu_head		rcu;
	struct net_device	*ndev;
};

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
		     const struct ib_gid_attr *attr)
{
	int ret;
	struct dev_put_rcu	*put_rcu;
	struct net_device *old_net_dev;

	write_seqcount_begin(&table->data_vec[ix].seq);

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
		    const struct ib_gid_attr *val, unsigned long mask)
{
	int i;

	for (i = 0; i < table->sz; i++) {
		struct ib_gid_attr *attr = &table->data_vec[i].attr;
		unsigned int orig_seq = read_seqcount_begin(&table->data_vec[i].seq);

		if (mask & GID_ATTR_FIND_MASK_GID_TYPE &&
		    attr->gid_type != val->gid_type)
			continue;

		if (memcmp(gid, &table->data_vec[i].gid, sizeof(*gid)))
			continue;

		if (mask & GID_ATTR_FIND_MASK_NETDEV &&
		    attr->ndev != val->ndev)
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

int roce_add_gid(struct ib_device *ib_dev, u8 port,
		 union ib_gid *gid, struct ib_gid_attr *attr)
{
	struct ib_roce_gid_table **ports_table =
		READ_ONCE(ib_dev->cache.roce_gid_table);
	struct ib_roce_gid_table *table;
	int ix;
	int ret = 0;

	/* make sure we read the ports_table */
	smp_rmb();

	if (!ports_table)
		return -EOPNOTSUPP;

	table = ports_table[port - start_port(ib_dev)];

	if (!table)
		return -EPROTONOSUPPORT;

	if (!memcmp(gid, &zgid, sizeof(*gid)))
		return -EINVAL;

	mutex_lock(&table->lock);

	ix = find_gid(table, gid, attr, GID_ATTR_FIND_MASK_GID_TYPE |
		      GID_ATTR_FIND_MASK_NETDEV);
	if (ix >= 0)
		goto out_unlock;

	ix = find_gid(table, &zgid, NULL, 0);
	if (ix < 0) {
		ret = -ENOSPC;
		goto out_unlock;
	}

	write_gid(ib_dev, port, table, ix, gid, attr);

out_unlock:
	mutex_unlock(&table->lock);
	return ret;
}

int roce_del_gid(struct ib_device *ib_dev, u8 port,
		 union ib_gid *gid, struct ib_gid_attr *attr)
{
	struct ib_roce_gid_table **ports_table =
		READ_ONCE(ib_dev->cache.roce_gid_table);
	struct ib_roce_gid_table *table;
	int ix;

	/* make sure we read the ports_table */
	smp_rmb();

	if (!ports_table)
		return 0;

	table  = ports_table[port - start_port(ib_dev)];

	if (!table)
		return -EPROTONOSUPPORT;

	mutex_lock(&table->lock);

	ix = find_gid(table, gid, attr,
		      GID_ATTR_FIND_MASK_GID_TYPE |
		      GID_ATTR_FIND_MASK_NETDEV);
	if (ix < 0)
		goto out_unlock;

	write_gid(ib_dev, port, table, ix, &zgid, &zattr);

out_unlock:
	mutex_unlock(&table->lock);
	return 0;
}

int roce_del_all_netdev_gids(struct ib_device *ib_dev, u8 port,
			     struct net_device *ndev)
{
	struct ib_roce_gid_table **ports_table =
		READ_ONCE(ib_dev->cache.roce_gid_table);
	struct ib_roce_gid_table *table;
	int ix;

	/* make sure we read the ports_table */
	smp_rmb();

	if (!ports_table)
		return 0;

	table  = ports_table[port - start_port(ib_dev)];

	if (!table)
		return -EPROTONOSUPPORT;

	mutex_lock(&table->lock);

	for (ix = 0; ix < table->sz; ix++)
		if (table->data_vec[ix].attr.ndev == ndev)
			write_gid(ib_dev, port, table, ix, &zgid, &zattr);

	mutex_unlock(&table->lock);
	return 0;
}

int roce_gid_table_get_gid(struct ib_device *ib_dev, u8 port, int index,
			   union ib_gid *gid, struct ib_gid_attr *attr)
{
	struct ib_roce_gid_table **ports_table =
		READ_ONCE(ib_dev->cache.roce_gid_table);
	struct ib_roce_gid_table *table;
	union ib_gid local_gid;
	struct ib_gid_attr local_attr;
	unsigned int orig_seq;

	/* make sure we read the ports_table */
	smp_rmb();

	if (!ports_table)
		return -EOPNOTSUPP;

	table = ports_table[port - start_port(ib_dev)];

	if (!table)
		return -EPROTONOSUPPORT;

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
	struct ib_roce_gid_table **ports_table =
		READ_ONCE(ib_dev->cache.roce_gid_table);
	struct ib_roce_gid_table *table;
	u8 p;
	int local_index;

	/* make sure we read the ports_table */
	smp_rmb();

	if (!ports_table)
		return -ENOENT;

	for (p = 0; p < ib_dev->phys_port_cnt; p++) {
		if (rdma_port_get_link_layer(ib_dev, p + start_port(ib_dev)) !=
		    IB_LINK_LAYER_ETHERNET)
			continue;
		table = ports_table[p];
		if (!table)
			continue;
		local_index = find_gid(table, gid, val, mask);
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
	struct ib_roce_gid_table **ports_table =
		READ_ONCE(ib_dev->cache.roce_gid_table);
	struct ib_roce_gid_table *table;
	unsigned long mask = GID_ATTR_FIND_MASK_GID_TYPE;
	struct ib_gid_attr val = {.gid_type = gid_type};

	/* make sure we read the ports_table */
	smp_rmb();

	if (!ports_table || port < start_port(ib_dev) ||
	    port >= (start_port(ib_dev) + ib_dev->phys_port_cnt))
		return -ENOENT;

	table = ports_table[port - start_port(ib_dev)];
	if (!table)
		return -ENOENT;

	mask |= get_netdev_from_ifindex(net, if_index, &val);

	local_index = find_gid(table, gid, &val, mask);
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

static void free_roce_gid_table(struct ib_device *ib_dev, u8 port,
				struct ib_roce_gid_table *table)
{
	int i;

	if (!table)
		return;

	for (i = 0; i < table->sz; ++i) {
		if (memcmp(&table->data_vec[i].gid, &zgid,
			   sizeof(table->data_vec[i].gid)))
			write_gid(ib_dev, port, table, i, &zgid, &zattr);
	}
	kfree(table->data_vec);
	kfree(table);
}

static int roce_gid_table_setup_one(struct ib_device *ib_dev)
{
	u8 port;
	struct ib_roce_gid_table **table;
	int err = 0;

	if (!ib_dev->modify_gid)
		return -EOPNOTSUPP;

	table = kcalloc(ib_dev->phys_port_cnt, sizeof(*table), GFP_KERNEL);

	if (!table) {
		pr_warn("failed to allocate roce addr table for %s\n",
			ib_dev->name);
		return -ENOMEM;
	}

	for (port = 0; port < ib_dev->phys_port_cnt; port++) {
		if (rdma_port_get_link_layer(ib_dev, port + start_port(ib_dev))
		    != IB_LINK_LAYER_ETHERNET)
			continue;
		table[port] =
			alloc_roce_gid_table(ib_dev->gid_tbl_len[port]);
		if (!table[port]) {
			err = -ENOMEM;
			goto rollback_table_setup;
		}
	}

	ib_dev->cache.roce_gid_table = table;
	return 0;

rollback_table_setup:
	for (port = 1; port <= ib_dev->phys_port_cnt; port++)
		free_roce_gid_table(ib_dev, port, table[port]);

	kfree(table);
	return err;
}

static void roce_gid_table_cleanup_one(struct ib_device *ib_dev,
				       struct ib_roce_gid_table **table)
{
	u8 port;

	if (!table)
		return;

	for (port = 0; port < ib_dev->phys_port_cnt; port++)
		free_roce_gid_table(ib_dev, port + start_port(ib_dev),
				    table[port]);

	kfree(table);
}


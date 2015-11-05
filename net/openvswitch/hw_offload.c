/*
 * Copyright (c) 2014 Jiri Pirko <jiri@resnulli.us>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <net/sw_flow.h>
#include <net/switchdev.h>

#include "datapath.h"
#include "vport-netdev.h"

static int sw_flow_action_create(struct datapath *dp,
				 struct sw_flow_actions **p_actions,
				 struct ovs_flow_actions *acts)
{
	const struct nlattr *attr = acts->actions;
	int len = acts->actions_len;
	const struct nlattr *a;
	int rem;
	struct sw_flow_actions *actions;
	struct sw_flow_action *cur;
	size_t count = 0;
	int err, drop_only = 0;

	for (a = attr, rem = len; rem > 0; a = nla_next(a, &rem))
		count++;

	/* Open-Flow's drop action is pipeline termination --> no OVS action
	 * for HW offloading we need to set explicit HW drop action.
	 */
	if (count == 0) {
		drop_only = 1;
		count = 1;
	}

	actions = kzalloc(sizeof(struct sw_flow_actions) +
			  sizeof(struct sw_flow_action) * count,
			  GFP_KERNEL);
	if (!actions)
		return -ENOMEM;
	actions->count = count;

	cur = actions->actions;

	if (drop_only) {
		cur->type = SW_FLOW_ACTION_TYPE_DROP;
		goto out;
	}

	for (a = attr, rem = len; rem > 0; a = nla_next(a, &rem)) {
		switch (nla_type(a)) {
		case OVS_ACTION_ATTR_OUTPUT:
			{
				struct vport *vport;

				vport = ovs_vport_ovsl_rcu(dp, nla_get_u32(a));
				cur->type = SW_FLOW_ACTION_TYPE_OUTPUT;
				cur->out_port_ifindex =
					vport->ops->get_netdev(vport)->ifindex;
			}
			break;

		case OVS_ACTION_ATTR_PUSH_VLAN:
			{
				const struct ovs_action_push_vlan *vlan;

				vlan = nla_data(a);
				cur->type = SW_FLOW_ACTION_TYPE_VLAN_PUSH;
				cur->vlan.vlan_proto = vlan->vlan_tpid;
				cur->vlan.vlan_tci = vlan->vlan_tci;
			}
			break;

		case OVS_ACTION_ATTR_POP_VLAN:
			cur->type = SW_FLOW_ACTION_TYPE_VLAN_POP;
			break;

		default:
			err = -EOPNOTSUPP;
			goto errout;
		}
		cur++;
	}

out:
	*p_actions = actions;
	return 0;

errout:
	kfree(actions);
	return err;
}

struct net_device *ovs_hw_flow_adjust(struct datapath *dp, struct ovs_flow *flow)
{
	struct vport *vport = NULL;
	struct net_device *dev = NULL;

	flow->flow.key.misc.in_port_ifindex = 0;
	flow->flow.mask->key.misc.in_port_ifindex = 0;
	vport = ovs_vport_ovsl(dp, flow->flow.key.phy.in_port);

	pr_debug("%s in_port %d vport %p type %d\n", __func__,
		flow->flow.key.phy.in_port, vport, vport? vport->ops->type: -1);

	if (vport && vport->ops->type == OVS_VPORT_TYPE_NETDEV) {
		dev = vport->ops->get_netdev(vport);
		if (dev) {
			flow->flow.key.misc.in_port_ifindex = dev->ifindex;
			flow->flow.mask->key.misc.in_port_ifindex = 0xFFFFFFFF;
		} else
			printk("%s couldn't get netdev for vport\n", __func__);
	}

	return dev;
}

int ovs_hw_flow_insert(struct datapath *dp, struct ovs_flow *flow)
{
	struct sw_flow_actions *actions;
#ifdef OVS_USE_HW_REPS
	struct vport *vport;
#endif
	struct net_device *dev;
	int err, did_rtnl_lock;

	ASSERT_OVSL();
	BUG_ON(flow->flow.actions);

	dev = ovs_hw_flow_adjust(dp, flow);

	err = sw_flow_action_create(dp, &actions, flow->sf_acts);
	if (err)
		return err;
	flow->flow.actions = actions;

#ifdef OVS_USE_HW_REPS
	list_for_each_entry(vport, &dp->swdev_rep_list, swdev_rep_list) {
		dev = vport->ops->get_netdev(vport);
		BUG_ON(!dev);

		did_rtnl_lock = 0;
		if (rtnl_trylock())
			did_rtnl_lock = 1;
		err = switchdev_port_flow_add(dev, &flow->flow);
		if (did_rtnl_lock)
			rtnl_unlock();

		if (err == -ENODEV) /* out device is not in this switch */
			continue;
		if (err)
			break;
	}
#else
	if (!dev || !dev->switchdev_ops) {
		pr_debug("%s can't offload flow add: in_dev %s\n", __func__, dev? dev->name: "no dev");
		err = -ENODEV;
	} else {
		if (rtnl_trylock())
			did_rtnl_lock = 1;
		err = switchdev_port_flow_add(dev, &flow->flow);
		if (did_rtnl_lock)
			rtnl_unlock();
	}
#endif

	if (err) {
		kfree(actions);
		flow->flow.actions = NULL;
		flow->hw_offloaded = 0;
	} else {
		printk(KERN_ERR "%s ovs flow %p sw_flow %p offloaded -- added \n", __func__, flow, &flow->flow);
		if (ovs_identifier_is_ufid(&flow->id))
			printk(KERN_ERR "%s ovs flow %p sw_flow %p ID %.8x %.8x %.8x %.8x\n", __func__,
				flow, &flow->flow, flow->id.ufid[0], flow->id.ufid[1], flow->id.ufid[2], flow->id.ufid[3]);
		flow->hw_offloaded = 1;
	}

	return err;
}

int ovs_hw_flow_remove(struct datapath *dp, struct ovs_flow *flow)
{
	struct sw_flow_actions *actions;
#ifdef OVS_USE_HW_REPS
	struct vport *vport;
#endif
	struct net_device *dev;
	int err = 0;

	ASSERT_OVSL();

	if (!flow->hw_offloaded)
		return 0;
	else {
		printk(KERN_ERR "%s ovs flow %p sw_flow %p offloaded -- deleted\n", __func__, flow, &flow->flow);
		if (ovs_identifier_is_ufid(&flow->id))
			printk(KERN_ERR "%s ovs flow %p sw_flow %p ID %.8x %.8x %.8x %.8x\n", __func__,
				flow, &flow->flow, flow->id.ufid[0], flow->id.ufid[1], flow->id.ufid[2], flow->id.ufid[3]);
	}

	dev = ovs_hw_flow_adjust(dp, flow);

	if (!flow->flow.actions) {
		err = sw_flow_action_create(dp, &actions, flow->sf_acts);
		if (err)
			return err;
		flow->flow.actions = actions;
	}

#ifdef OVS_USE_HW_REPS
	list_for_each_entry(vport, &dp->swdev_rep_list, swdev_rep_list) {
		dev = vport->ops->get_netdev(vport);
		BUG_ON(!dev);
		err = switchdev_port_flow_del(dev, &flow->flow);
		if (err == -ENODEV) /* out device is not in this switch */
			continue;
		if (err)
			break;
	}
#else
	if (!dev || !dev->switchdev_ops) {
		printk(KERN_ERR "%s can't offload flow del: in_dev %s\n", __func__, dev? dev->name: "no dev");
		err = -ENODEV;
	} else
		err = switchdev_port_flow_del(dev, &flow->flow);
#endif
	kfree(flow->flow.actions);
	flow->flow.actions = NULL;
	return err;
}

int ovs_hw_flow_flush(struct datapath *dp)
{
	struct table_instance *ti;
	int i;
	int ver;
	int err;

	ti = ovsl_dereference(dp->table.ti);
	ver = ti->node_ver;

	for (i = 0; i < ti->n_buckets; i++) {
		struct ovs_flow *flow;
		struct hlist_head *head = flex_array_get(ti->buckets, i);

		/* FIXME need rcu_ ? */
		hlist_for_each_entry(flow, head, flow_table.node[ver]) {
			err = ovs_hw_flow_remove(dp, flow);
			if (err)
				return err;
		}
	}
	return 0;
}

static bool __is_vport_in_swdev_rep_list(struct datapath *dp,
					 struct vport *vport)
{
	struct vport *cur_vport;

	list_for_each_entry(cur_vport, &dp->swdev_rep_list, swdev_rep_list) {
		if (cur_vport == vport)
			return true;
	}
	return false;
}

static struct vport *__find_vport_by_swdev_id(struct datapath *dp,
					      struct vport *vport)
{
	struct net_device *dev;
	struct vport *cur_vport;
	int i;
	int err;
	struct switchdev_attr attr,curr_attr;

	attr.id = curr_attr.id =  SWITCHDEV_ATTR_PORT_PARENT_ID;
	attr.flags = curr_attr.flags = SWITCHDEV_F_NO_RECURSE;

	err = switchdev_port_attr_get(vport->ops->get_netdev(vport), &attr);
	if (err)
		return ERR_PTR(err);

	for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++) {
		hlist_for_each_entry(cur_vport, &dp->ports[i], dp_hash_node) {
			if (cur_vport->ops->type != OVS_VPORT_TYPE_NETDEV)
				continue;
			if (cur_vport == vport)
				continue;
			dev = cur_vport->ops->get_netdev(cur_vport);
			if (!dev)
				continue;
			err = switchdev_port_attr_get(dev, &curr_attr);
			if (err)
				continue;
			if (netdev_phys_item_ids_match(&attr.u.ppid, &curr_attr.u.ppid))
				return cur_vport;
		}
	}
	return ERR_PTR(-ENOENT);
}

void ovs_hw_port_add(struct datapath *dp, struct vport *vport)
{
	struct vport *found_vport;

	ASSERT_OVSL();
	/* The representative list contains always one port per switch dev id */
	found_vport = __find_vport_by_swdev_id(dp, vport);
	if (IS_ERR(found_vport) && PTR_ERR(found_vport) == -ENOENT) {
		list_add(&vport->swdev_rep_list, &dp->swdev_rep_list);
		pr_debug("%s added to rep_list\n", vport->ops->get_name(vport));
	}
}

void ovs_hw_port_del(struct datapath *dp, struct vport *vport)
{
	struct vport *found_vport;

	ASSERT_OVSL();
	if (!__is_vport_in_swdev_rep_list(dp, vport))
		return;

	list_del(&vport->swdev_rep_list);
	pr_debug("%s deleted from rep_list\n", vport->ops->get_name(vport));
	found_vport = __find_vport_by_swdev_id(dp, vport);
	if (!IS_ERR(found_vport)) {
		list_add(&found_vport->swdev_rep_list, &dp->swdev_rep_list);
		pr_debug("%s added to rep_list instead\n",
			 found_vport->ops->get_name(found_vport));
	}
}

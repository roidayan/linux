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
#include <net/ip_fib.h>

#include "datapath.h"
#include "vport-netdev.h"

static int get_vxlan_udp_dst_port(struct vport *vport)
{
	const struct nlattr *a;
	struct sk_buff *skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	int ret = -1;

	if (!skb)
		return ret;

	if (!vport->ops->get_options(vport, skb)) {
		a = (struct nlattr *)skb->data;
		a = nla_find(a, skb->len, OVS_TUNNEL_ATTR_DST_PORT);
		if (a)
			ret = nla_get_u16(a);
	}
	nlmsg_free(skb);

	return ret;
}

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
	int drop_only = 0;

	for (a = attr, rem = len; rem > 0; a = nla_next(a, &rem)) {
		if (nla_type(a) != OVS_ACTION_ATTR_SET)
			count++;
	}

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

				if (vport->ops->type != OVS_VPORT_TYPE_NETDEV) {
					pr_warn("unexpected output port type %d\n",
						vport->ops->type);
					goto errout;
				}

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
		case OVS_ACTION_ATTR_SET:
			{
				struct ovs_tunnel_info *egress_tun_info;
				struct vport *vport;
				const struct nlattr *b = nla_data(a);
				int err;

				if (nla_type(b) != OVS_KEY_ATTR_TUNNEL_INFO) {
					pr_warn("unexpected second nla_type %d\n",
						nla_type(b));
					goto errout;
				}

				egress_tun_info = nla_data(b);

				a = nla_next(a, &rem);
				if (nla_type(a) != OVS_ACTION_ATTR_OUTPUT) {
					pr_warn("unexpected second action type %d\n",
						nla_type(a));
					goto errout;
				}

				vport =	ovs_vport_ovsl_rcu(dp, nla_get_u32(a));
				if (!vport) {
					pr_warn("failed to get vport number %d\n",
						nla_get_u32(a));
					goto errout;
				}

				cur->type = SW_FLOW_ACTION_TYPE_ENCAP;
				cur->tun_key = egress_tun_info->tunnel;

				switch (vport->ops->type) {
				case OVS_VPORT_TYPE_VXLAN:
					err = get_vxlan_udp_dst_port(vport);
					if (err == -1) {
						pr_warn("%s: failed to obtain vxlan udp dst_port\n",
							__func__);
						goto errout;
					}

					cur->tun_key.tp_dst = htons(err);
					cur->tunnel_type = SW_FLOW_TUNNEL_VXLAN;
					break;

				default:
					pr_warn("unexpected output port type %d\n",
						vport->ops->type);
					goto errout;
				}
			}
			break;
		default:
			goto errout;
		}
		cur++;
	}

out:
	*p_actions = actions;
	return 0;

errout:
	kfree(actions);
	return -EOPNOTSUPP;
}

struct net_device *ovs_hw_flow_adjust(struct datapath *dp, struct ovs_flow *flow)
{
	struct vport *vport = NULL;
	struct net_device *dev = NULL;

	vport = ovs_vport_ovsl(dp, flow->flow.key.phy.in_port);

	if (!vport) {
		pr_debug("%s: failed to get vport in_port %d\n", __func__,
			 flow->flow.key.phy.in_port);
		return NULL;
	}

	pr_debug("%s: in_port %d type %d\n", __func__,
		 flow->flow.key.phy.in_port, vport->ops->type);

	if (vport->ops->type == OVS_VPORT_TYPE_NETDEV) {
		dev = vport->ops->get_netdev(vport);
		flow->flow.tunnel_type = SW_FLOW_TUNNEL_NONE;
	} else if (vport->ops->type == OVS_VPORT_TYPE_VXLAN) {
		struct sw_flow_key_ipv4_tunnel *tun = &flow->flow.key.tun_key;
		struct net *ns = ovs_dp_get_net(dp);
		struct flowi4 flp = {
				.daddr = tun->ipv4_dst,
				.saddr = tun->ipv4_src,
				.flowi4_proto = IPPROTO_UDP
		};
		struct fib_result res;
		int err;

		err = get_vxlan_udp_dst_port(vport);
		if (err == -1) {
			pr_debug("%s: failed to obtain vxlan udp dst_port\n",
					__func__);
			return NULL;
		}

		flow->flow.tunnel_port = err;
		flp.fl4_dport = flow->flow.tunnel_port;

		if (flow->flow.mask->key.tun_key.tp_src == htons(0xffff))
			flp.fl4_sport = flow->flow.key.tun_key.tp_src;

		err = fib_lookup(ns, &flp, &res, FIB_LOOKUP_NOREF);
		if (err) {
			pr_debug("%s fib_lookup returned %d\n", __func__, err);
			return NULL;
		}

		flow->flow.tunnel_type = SW_FLOW_TUNNEL_VXLAN;
		dev = FIB_RES_DEV(res);
	}

	return dev;
}

int ovs_hw_flow_insert(struct datapath *dp, struct ovs_flow *flow)
{
	struct sw_flow_actions *actions;
	struct net_device *dev;
	int err;

	ASSERT_OVSL();
	BUG_ON(flow->flow.actions);

	flow->hw_offloaded = 0;
	dev = ovs_hw_flow_adjust(dp, flow);

	err = sw_flow_action_create(dp, &actions, flow->sf_acts);
	if (err)
		return err;
	flow->flow.actions = actions;

	if (!dev || !dev->switchdev_ops) {
		pr_debug("%s can't offload flow add: in_dev %s\n", __func__, dev? dev->name: "no dev");
		err = -ENODEV;
	} else {
		rtnl_lock();
		err = switchdev_port_flow_add(dev, &flow->flow);
		rtnl_unlock();
	}

	if (err) {
		kfree(actions);
		flow->flow.actions = NULL;
	} else {
		pr_debug("%s ovs flow %p sw_flow %p offloaded -- added \n", __func__, flow, &flow->flow);
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
	struct net_device *dev;
	int err = 0;

	ASSERT_OVSL();

	if (!flow->hw_offloaded)
		return 0;
	else {
		pr_debug("%s ovs flow %p sw_flow %p offloaded -- deleted\n", __func__, flow, &flow->flow);
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

	if (!dev || !dev->switchdev_ops) {
		printk(KERN_ERR "%s can't offload flow del: in_dev %s\n", __func__, dev? dev->name: "no dev");
		err = -ENODEV;
	} else {
		rtnl_lock();
		err = switchdev_port_flow_del(dev, &flow->flow);
		rtnl_unlock();
	}
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

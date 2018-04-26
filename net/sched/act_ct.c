/*
 * net/sched/act_conntrack.c  connection tracking action
 *
 * Copyright (c) 2018 Yossi Kuperman <yossiku@mellanox.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
*/

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/act_api.h>
#include <uapi/linux/tc_act/tc_ct.h>
#include <net/tc_act/tc_ct.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_labels.h>

#include <net/pkt_cls.h>

#include <linux/yktrace.h>

static unsigned int conntrack_net_id;
static struct tc_action_ops act_conntrack_ops;

static void ct_notify_underlying_device(struct sk_buff *skb, struct nf_conn *ct,
                                        enum ip_conntrack_info ctinfo, struct net *net)
{
	struct tc_ct_offload cto = { skb, net, NULL, NULL };
	if (ct) {
		cto.zone = (struct nf_conntrack_zone *)nf_ct_zone(ct);
		cto.tuple = nf_ct_tuple(ct, CTINFO2DIR(ctinfo));
	}

	/* TODO: do we want tuple as a cookie? */
	tc_setup_cb_call(NULL, NULL, TC_SETUP_CT, &cto, false);
}

static int tcf_conntrack(struct sk_buff *skb, const struct tc_action *a,
			 struct tcf_result *res)
{
	struct tcf_conntrack_info *ca = to_conntrack(a);
	struct net *net = dev_net(skb->dev);
	enum ip_conntrack_info ctinfo;
	struct nf_conntrack_zone zone;
	struct nf_conn *tmpl;
	struct nf_conn *ct;
	int nh_ofs;
	int err, ret = 0;

	/* The conntrack module expects to be working at L3. */
	nh_ofs = skb_network_offset(skb);
	skb_pull_rcsum(skb, nh_ofs);

	spin_lock(&ca->tcf_lock);
	tcf_lastuse_update(&ca->tcf_tm);
	bstats_update(&ca->tcf_bstats, skb);

	trace("ca->commit: %d, ca->zone: %d, ca->mark: %d", ca->commit, ca->zone, ca->mark);

	nf_ct_zone_init(&zone, ca->zone,
			NF_CT_DEFAULT_ZONE_DIR, 0);
	tmpl = nf_ct_tmpl_alloc(net, &zone, GFP_ATOMIC);
	/* TODO: check for error and many other stuff :) */

	if (skb_nfct(skb))
		nf_conntrack_put(skb_nfct(skb));

	nf_conntrack_get(&tmpl->ct_general);	
	nf_ct_set(skb, tmpl, IP_CT_NEW);

	__set_bit(IPS_CONFIRMED_BIT, &tmpl->status);

	err = nf_conntrack_in(net, PF_INET,
			      NF_INET_PRE_ROUTING, skb);
	if (err != NF_ACCEPT) {
		etrace("tcf_conntrack: nf_conntrack_in failed: %d", err);
		ret = -1;
		goto out;
	}

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct) {
		etrace("tcf_conntrack: nf_ct_get failed");
		ret = -1;
		goto out;
	}

	if (ctinfo == IP_CT_ESTABLISHED ||
	    ctinfo == IP_CT_ESTABLISHED_REPLY) {
		ct_notify_underlying_device(skb, ct, ctinfo, net);
	}

	/* TODO: must check this code very carefully; move to another function */
	if (ca->commit) {
		u32 *labels = ca->labels;
		u32 *labels_m = ca->labels_mask;

#if IS_ENABLED(CONFIG_NF_CONNTRACK_MARK)
		if (ca->mark_mask) {
			u32 ct_mark = ca->mark;
			u32 mask = ca->mark_mask;
			u32 new_mark;

			new_mark = ct_mark | (ct->mark & ~(mask));
			if (ct->mark != new_mark) {
				ct->mark = new_mark;
				if (nf_ct_is_confirmed(ct))
					nf_conntrack_event_cache(IPCT_MARK, ct);
			}
		}
#endif
		if (!nf_ct_is_confirmed(ct)) {
			struct nf_conn_labels *cl, *master_cl;
			bool have_mask = !!(memchr_inv(ca->labels_mask, 0, sizeof(ca->labels_mask)));

			/* Inherit master's labels to the related connection? */
			master_cl = ct->master ? nf_ct_labels_find(ct->master) : NULL;

			if (!master_cl && !have_mask)
				goto skip; /* Nothing to do. */

			cl = nf_ct_labels_find(ct);
			if (!cl) {
				nf_ct_labels_ext_add(ct);
				cl = nf_ct_labels_find(ct);
			}

			if (!cl)
				goto out;

			/* Inherit the master's labels, if any. */
			if (master_cl)
				*cl = *master_cl;

			if (have_mask) {
				u32 *dst = (u32 *)cl->bits;
				int i;

				for (i = 0; i < 4; i++)
					dst[i] = (dst[i] & ~labels_m[i]) | (labels[i] & labels_m[i]);

				//todo: can we just replace?
			}

			/* Labels are included in the IPCTNL_MSG_CT_NEW event only if the
			 * IPCT_LABEL bit is set in the event cache.
			 */
			nf_conntrack_event_cache(IPCT_LABEL, ct);
		} else if (!!memchr_inv(labels_m, 0, sizeof(ca->labels_mask))) {
			struct nf_conn_labels *cl;

			cl = nf_ct_labels_find(ct);
			if (!cl) {
				nf_ct_labels_ext_add(ct);
				cl = nf_ct_labels_find(ct);
			}

			if (!cl)
				goto out;

			nf_connlabels_replace(ct, ca->labels, ca->labels_mask, 4);
		}
skip:
		nf_conntrack_confirm(skb);
	}

out:
	if (ret == -1)
		ct_notify_underlying_device(skb, NULL, IP_CT_UNTRACKED, net);

	skb_push(skb, nh_ofs);
	skb_postpush_rcsum(skb, skb->data, nh_ofs);

	spin_unlock(&ca->tcf_lock);
	return ca->tcf_action;
}

static const struct nla_policy conntrack_policy[TCA_CONNTRACK_MAX + 1] = {
	[TCA_CONNTRACK_PARMS] = { .len = sizeof(struct tc_conntrack) },
};

static int tcf_conntrack_init(struct net *net, struct nlattr *nla,
			     struct nlattr *est, struct tc_action **a,
			     int ovr, int bind, bool rtnl_held)
{
	struct tc_action_net *tn = net_generic(net, conntrack_net_id);
	struct nlattr *tb[TCA_CONNTRACK_MAX + 1];
	struct tcf_conntrack_info *ci;
	struct tc_conntrack *parm;
	int ret = 0;

	if (!nla)
		return -EINVAL;

	ret = nla_parse_nested(tb, TCA_CONNTRACK_MAX, nla, conntrack_policy);
	if (ret < 0)
		return ret;

	if (!tb[TCA_CONNTRACK_PARMS])
		return -EINVAL;

	parm = nla_data(tb[TCA_CONNTRACK_PARMS]);

	ret = tcf_idr_check_alloc(tn, &parm->index, a, bind);
	if (!ret) {
		ret = tcf_idr_create(tn, parm->index, est, a,
				     &act_conntrack_ops, bind, false);
		if (ret) {
			tcf_idr_cleanup(tn, parm->index);
			return ret;
		}
 
		ci = to_conntrack(*a);
		ci->tcf_action = parm->action;
		ci->net = net;
		ci->commit = parm->commit;
		ci->zone = parm->zone;
		ci->mark = parm->mark;
		ci->mark_mask = parm->mark_mask;
		memcpy(ci->labels, parm->labels, sizeof(parm->labels));
		memcpy(ci->labels_mask, parm->labels_mask, sizeof(parm->labels_mask));

		tcf_idr_insert(tn, *a);
		ret = ACT_P_CREATED;
	} else if (ret > 0) {
		mtrace("Replacing CT action");
		ci = to_conntrack(*a);
		if (bind)
			return 0;
		if (!ovr) {
			tcf_idr_release(*a, bind);
			return -EEXIST;
		}
		/* replacing action and zone */
		spin_lock_bh(&ci->tcf_lock);
		ci->tcf_action = parm->action;
		ci->zone = parm->zone;
		spin_unlock_bh(&ci->tcf_lock);
		ret = 0;
	}

	return ret;
}

static inline int tcf_conntrack_dump(struct sk_buff *skb, struct tc_action *a,
				    int bind, int ref)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct tcf_conntrack_info *ci = to_conntrack(a);

	struct tc_conntrack opt = {
		.index   = ci->tcf_index,
		.refcnt  = refcount_read(&ci->tcf_refcnt) - ref,
		.bindcnt = atomic_read(&ci->tcf_bindcnt) - bind,
	};
	struct tcf_t t;

	spin_lock_bh(&ci->tcf_lock);
	opt.action  = ci->tcf_action,
	opt.zone   = ci->zone,
	opt.commit = ci->commit,
	opt.mark = ci->mark,
	opt.mark_mask = ci->mark_mask,

	memcpy(opt.labels, ci->labels, sizeof(opt.labels));
	memcpy(opt.labels_mask, ci->labels_mask, sizeof(opt.labels_mask));

	if (nla_put(skb, TCA_CONNTRACK_PARMS, sizeof(opt), &opt))
		goto nla_put_failure;

	tcf_tm_dump(&t, &ci->tcf_tm);
	if (nla_put_64bit(skb, TCA_CONNTRACK_TM, sizeof(t), &t,
			  TCA_CONNTRACK_PAD))
		goto nla_put_failure;
	spin_unlock_bh(&ci->tcf_lock);

	return skb->len;
nla_put_failure:
	spin_unlock_bh(&ci->tcf_lock);
	nlmsg_trim(skb, b);
	return -1;
}

static int tcf_conntrack_walker(struct net *net, struct sk_buff *skb,
			       struct netlink_callback *cb, int type,
			       const struct tc_action_ops *ops)
{
	struct tc_action_net *tn = net_generic(net, conntrack_net_id);

	return tcf_generic_walker(tn, skb, cb, type, ops);
}

static int tcf_conntrack_search(struct net *net, struct tc_action **a, u32 index)
{
	struct tc_action_net *tn = net_generic(net, conntrack_net_id);

	return tcf_idr_search(tn, a, index);
}

static struct tc_action_ops act_conntrack_ops = {
	.kind		=	"ct",
	.type		=	TCA_ACT_CONNTRACK,
	.owner		=	THIS_MODULE,
	.act		=	tcf_conntrack,
	.dump		=	tcf_conntrack_dump,
	.init		=	tcf_conntrack_init,
	.walk		=	tcf_conntrack_walker,
	.lookup		=	tcf_conntrack_search,
	.size		=	sizeof(struct tcf_conntrack_info),
};

static __net_init int conntrack_init_net(struct net *net)
{
	struct tc_action_net *tn = net_generic(net, conntrack_net_id);

	return tc_action_net_init(tn, &act_conntrack_ops);
}

static void __net_exit conntrack_exit_net(struct list_head *net_list)
{
	tc_action_net_exit(net_list, conntrack_net_id);
}

static struct pernet_operations conntrack_net_ops = {
	.init = conntrack_init_net,
	.exit_batch = conntrack_exit_net,
	.id   = &conntrack_net_id,
	.size = sizeof(struct tc_action_net),
};

static int __init conntrack_init_module(void)
{
	return tcf_register_action(&act_conntrack_ops, &conntrack_net_ops);
}

static void __exit conntrack_cleanup_module(void)
{
	tcf_unregister_action(&act_conntrack_ops, &conntrack_net_ops);
}

module_init(conntrack_init_module);
module_exit(conntrack_cleanup_module);
MODULE_AUTHOR("Yossi Kuperman <yossiku@mellanox.com>");
MODULE_DESCRIPTION("Connection tracking action");
MODULE_LICENSE("GPL");


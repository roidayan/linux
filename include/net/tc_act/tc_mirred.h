#ifndef __NET_TC_MIR_H
#define __NET_TC_MIR_H

#include <net/act_api.h>
#include <linux/tc_act/tc_mirred.h>

struct tcf_mirred {
	struct tc_action	common;
	int			tcfm_eaction;
	bool			tcfm_mac_header_xmit;
	struct net_device __rcu	*tcfm_dev;
	struct list_head	tcfm_list;
};
#define to_mirred(a) ((struct tcf_mirred *)a)

static const struct nla_policy mirred_policy_compat[TCA_MIRRED_MAX + 1] = {
	[TCA_MIRRED_PARMS]		= { .len = sizeof(struct tc_mirred) },
};

static inline bool is_tcf_mirred_compat(const struct tc_action *a)
{
#ifdef CONFIG_NET_CLS_ACT
	if (a->ops && a->ops->type == TCA_ACT_MIRRED)
		return true;
#endif
	return false;
}

static struct tc_mirred to_mirred_compat(const struct tc_action *a)
{
	struct nlattr *tb[TCA_MIRRED_MAX + 1];
	struct tc_mirred m = { .ifindex = 0 };
	struct sk_buff *skb;
	struct nlattr *nla;

	if (!a->ops || !a->ops->dump || !is_tcf_mirred_compat(a))
		return m;

	skb = alloc_skb(256, GFP_KERNEL);
	if (!skb)
		return m;

	if (a->ops->dump(skb, (struct tc_action *) a, 0, 0) < 0)
		goto freeskb;

	nla = (struct nlattr *) skb->data;
	if (nla_parse(tb, TCA_MIRRED_MAX, nla, skb->len, mirred_policy_compat)
		      < 0)
		goto freeskb;

	if (!tb[TCA_MIRRED_PARMS])
		goto freeskb;

	m = *((struct tc_mirred *) nla_data(tb[TCA_MIRRED_PARMS]));

freeskb:
	kfree_skb(skb);

	return m;
}

static inline bool is_tcf_mirred_egress_redirect(const struct tc_action *a)
{
#ifdef CONFIG_NET_CLS_ACT
	if (a->ops && a->ops->type == TCA_ACT_MIRRED)
		return to_mirred(a)->tcfm_eaction == TCA_EGRESS_REDIR;
#endif
	return false;
}

static inline bool is_tcf_mirred_egress_mirror(const struct tc_action *a)
{
#ifdef CONFIG_NET_CLS_ACT
	if (a->ops && a->ops->type == TCA_ACT_MIRRED)
		return to_mirred(a)->tcfm_eaction == TCA_EGRESS_MIRROR;
#endif
	return false;
}

static inline struct net_device *tcf_mirred_dev(const struct tc_action *a)
{
	return rtnl_dereference(to_mirred(a)->tcfm_dev);
}

static inline int tcf_mirred_ifindex(const struct tc_action *a)
{
	return to_mirred_compat(a).ifindex;
}

#endif /* __NET_TC_MIR_H */

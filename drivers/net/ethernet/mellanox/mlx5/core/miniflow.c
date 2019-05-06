// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2019 Mellanox Technologies. */

#include <net/tc_act/tc_pedit.h>

#include "miniflow.h"
#include "eswitch.h"
#include "en_rep.h"
#include "en_tc.h"
#include "en.h"

static int enable_ct_ageing = 1; /* On by default */
module_param(enable_ct_ageing, int, 0644);

static int nr_total_workqueue_elm = 0;
module_param(nr_total_workqueue_elm, int, 0644);

static int nr_concurrent_workqueue_elm = 0;
module_param(nr_concurrent_workqueue_elm, int, 0644);

static int nr_workqueue_elm = 0;
module_param(nr_workqueue_elm, int, 0644);

static int nr_mf_err = 0;
module_param(nr_mf_err, int, 0644);

static int nr_mf_succ = 0;
module_param(nr_mf_succ, int, 0644);

static int max_nr_mf = 1024*1024;
module_param(max_nr_mf, int, 0644);

/* Derived from current insertion rate (flows/s) */
#define MINIFLOW_WORKQUEUE_MAX_SIZE 40 * 1000

struct workqueue_struct *miniflow_wq;
static atomic_t miniflow_wq_size = ATOMIC_INIT(0);

/* TOOD: we should init this variable only once, rather than per PF? */
/* we should have a miniflow init/cleanup functions */
static int miniflow_cache_allocated;
static struct kmem_cache *miniflow_cache; // __ro_after_init; crashes??

/* TODO: current_miniflow is global and probelmatic when we'll support
 * multiple HCAs. move it into mdev? */
DEFINE_PER_CPU(struct mlx5e_miniflow *, current_miniflow) = NULL;

static DEFINE_SPINLOCK(miniflow_lock);

static const struct rhashtable_params mf_ht_params = {
	.head_offset = offsetof(struct mlx5e_miniflow, node),
	.key_offset = offsetof(struct mlx5e_miniflow, path.cookies),
	.key_len = sizeof(((struct mlx5e_miniflow *)0)->path.cookies),
	.automatic_shrinking = true,
};

/* TODO: have a second look */
static struct rhashtable *get_mf_ht(struct mlx5e_priv *priv)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5e_rep_priv *uplink_rpriv;

	uplink_rpriv = mlx5_eswitch_get_uplink_priv(esw, REP_ETH);
	return &uplink_rpriv->mf_ht;
}

static void miniflow_path_append_cookie(struct mlx5e_miniflow *miniflow,
					u64 cookie, u8 flags)
{
	WARN_ON(cookie & MFC_INFOMASK);
	miniflow->path.cookies[miniflow->nr_flows++] = cookie | flags;
}

static u8 miniflow_cookie_flags(u64 cookie)
{
	return (cookie & MFC_INFOMASK);
}

static void miniflow_abort(struct mlx5e_miniflow *miniflow)
{
	miniflow->nr_flows = -1;
}

static void miniflow_cleanup(struct mlx5e_miniflow *miniflow)
{
	struct mlx5e_tc_flow *flow;
	int j;

	for (j = 0; j < MINIFLOW_MAX_CT_TUPLES; j++) {
		flow = miniflow->ct_tuples[j].flow;
		if (flow)
			mlx5e_flow_put(flow->priv, flow);
	}
}

static struct mlx5e_miniflow *miniflow_alloc(void)
{
	return kmem_cache_alloc(miniflow_cache, GFP_ATOMIC);
}

static void miniflow_free(struct mlx5e_miniflow *miniflow)
{
	if (miniflow)
		kmem_cache_free(miniflow_cache, miniflow);
}

static struct mlx5e_miniflow *miniflow_read(void)
{
	return this_cpu_read(current_miniflow);
}

static void miniflow_write(struct mlx5e_miniflow *miniflow)
{
	this_cpu_write(current_miniflow, miniflow);
}

static void miniflow_init(struct mlx5e_miniflow *miniflow,
			  struct mlx5e_priv *priv)
{
	memset(miniflow, 0, sizeof(*miniflow));

	miniflow->priv = priv;
}

static void miniflow_free_current_miniflow(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		miniflow_free(per_cpu(current_miniflow, cpu));
		per_cpu(current_miniflow, cpu) = NULL;
	}
}

static void miniflow_attach(struct mlx5e_miniflow *miniflow)
{
	struct mlx5e_tc_flow *flow;
	int i;

	spin_lock_bh(&miniflow_lock);
	/* Attach to all parent flows */
	for (i=0; i<miniflow->nr_flows; i++) {
		flow = miniflow->path.flows[i];

		miniflow->mnodes[i].miniflow = miniflow;
		list_add(&miniflow->mnodes[i].node, &flow->miniflow_list);
	}
	spin_unlock_bh(&miniflow_lock);
}

static void miniflow_detach(struct mlx5e_miniflow *miniflow)
{
	int i;

	/* Detach from all parent flows */
	for (i = 0; i < miniflow->nr_flows; i++)
		list_del(&miniflow->mnodes[i].node);
}

static void miniflow_merge_match(struct mlx5e_tc_flow *mflow,
				  struct mlx5e_tc_flow *flow)
{
	u32 *dst = (u32 *) &mflow->esw_attr->parse_attr->spec;
	u32 *src = (u32 *) &flow->esw_attr->parse_attr->spec;
	int i;

	BUILD_BUG_ON((sizeof(struct mlx5_flow_spec) % sizeof(u32)) != 0);

	for (i = 0; i < sizeof(struct mlx5_flow_spec) / sizeof(u32); i++)
		*dst++ |= *src++;

	mflow->esw_attr->match_level = max(flow->esw_attr->match_level,
					   mflow->esw_attr->match_level);

	mflow->esw_attr->tunnel_match_level =
		max(flow->esw_attr->tunnel_match_level,
		    mflow->esw_attr->tunnel_match_level);
}

static void miniflow_merge_action(struct mlx5e_tc_flow *mflow,
				   struct mlx5e_tc_flow *flow)
{
	mflow->esw_attr->action |= flow->esw_attr->action;
}

static int miniflow_merge_mirred(struct mlx5e_tc_flow *mflow,
				  struct mlx5e_tc_flow *flow)
{
	struct mlx5_esw_flow_attr *dst_attr = mflow->esw_attr;
	struct mlx5_esw_flow_attr *src_attr = flow->esw_attr;
	int out_count;
	int i, j;

	if (!(src_attr->action & MLX5_FLOW_CONTEXT_ACTION_FWD_DEST))
		return 0;

	out_count = dst_attr->out_count + src_attr->out_count;
	if (out_count > MLX5_MAX_FLOW_FWD_VPORTS)
		return -1;

	for (i = 0, j = dst_attr->out_count; j < out_count; i++, j++) {
		dst_attr->out_rep[j] = src_attr->out_rep[i];
		dst_attr->out_mdev[j] = src_attr->out_mdev[i];
	}

	dst_attr->out_count = out_count;
	dst_attr->mirror_count += src_attr->mirror_count;

	return 0;
}

static int miniflow_merge_hdr(struct mlx5e_priv *priv,
			       struct mlx5e_tc_flow *mflow,
			       struct mlx5e_tc_flow *flow)
{
	struct mlx5e_tc_flow_parse_attr *dst_parse_attr;
	struct mlx5e_tc_flow_parse_attr *src_parse_attr;
	int max_actions, action_size;
	int err;

	if (!(flow->esw_attr->action & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR))
		return 0;

	action_size = MLX5_MH_ACT_SZ;

	dst_parse_attr = mflow->esw_attr->parse_attr;
	if (!dst_parse_attr->mod_hdr_actions) {
		err = alloc_mod_hdr_actions(priv, 0 /* maximum */,
					    MLX5_FLOW_NAMESPACE_FDB,
					    dst_parse_attr, GFP_ATOMIC);
		if (err) {
			mlx5_core_warn(priv->mdev, "alloc hdr actions failed\n");
			return -ENOMEM;
		}

		dst_parse_attr->num_mod_hdr_actions = 0;
	}

	max_actions = MLX5_CAP_ESW_FLOWTABLE_FDB(priv->mdev, max_modify_header_actions);
	src_parse_attr = flow->esw_attr->parse_attr;

	if (dst_parse_attr->num_mod_hdr_actions + src_parse_attr->num_mod_hdr_actions >= max_actions) {
		mlx5_core_warn(priv->mdev, "max hdr actions reached\n");
		kfree(dst_parse_attr->mod_hdr_actions);
		dst_parse_attr->mod_hdr_actions = NULL;
		return -E2BIG;
	}

	memcpy(dst_parse_attr->mod_hdr_actions + dst_parse_attr->num_mod_hdr_actions * action_size,
	       src_parse_attr->mod_hdr_actions,
	       src_parse_attr->num_mod_hdr_actions * action_size);

	dst_parse_attr->num_mod_hdr_actions += src_parse_attr->num_mod_hdr_actions;

	return 0;
}

static void miniflow_merge_vxlan(struct mlx5e_tc_flow *mflow,
				 struct mlx5e_tc_flow *flow)
{
	if (!(flow->esw_attr->action & MLX5_FLOW_CONTEXT_ACTION_PACKET_REFORMAT))
		return;

	mflow->esw_attr->parse_attr->mirred_ifindex = flow->esw_attr->parse_attr->mirred_ifindex;
	mflow->esw_attr->parse_attr->tun_info = flow->esw_attr->parse_attr->tun_info;
}

static u8 mlx5e_etype_to_ipv(u16 ethertype)
{
	if (ethertype == ETH_P_IP)
		return 4;

	if (ethertype == ETH_P_IPV6)
		return 6;

	return 0;
}

static void miniflow_merge_tuple(struct mlx5e_tc_flow *mflow,
				 struct nf_conntrack_tuple *nf_tuple)
{
	struct mlx5_flow_spec *spec = &mflow->esw_attr->parse_attr->spec;
	void *headers_c, *headers_v;
	int match_ipv;
	u8 ipv;

	if (mflow->esw_attr->action & MLX5_FLOW_CONTEXT_ACTION_DECAP) {
		headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
					 inner_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
					 inner_headers);
		match_ipv = MLX5_CAP_FLOWTABLE_NIC_RX(mflow->priv->mdev,
					 ft_field_support.inner_ip_version);
	} else {
		headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
					 outer_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
					 outer_headers);
		match_ipv = MLX5_CAP_FLOWTABLE_NIC_RX(mflow->priv->mdev,
					 ft_field_support.outer_ip_version);
	}

	ipv = mlx5e_etype_to_ipv(ntohs(nf_tuple->src.l3num));
	if (match_ipv && ipv) {
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ip_version);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_version, ipv);
	} else {
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ethertype);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ethertype, nf_tuple->src.l3num);
	}

	if (nf_tuple->src.l3num == htons(ETH_P_IP)) {
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
					src_ipv4_src_ipv6.ipv4_layout.ipv4),
					&nf_tuple->src.u3.ip,
					4);
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
					dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
					&nf_tuple->dst.u3.ip,
					4);

		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c,
					src_ipv4_src_ipv6.ipv4_layout.ipv4);
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c,
					dst_ipv4_dst_ipv6.ipv4_layout.ipv4);
	}

	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ip_protocol);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_protocol, nf_tuple->dst.protonum);

	switch (nf_tuple->dst.protonum) {
	case IPPROTO_UDP:
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, udp_dport);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, udp_dport, ntohs(nf_tuple->dst.u.udp.port));

		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, udp_sport);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, udp_sport, ntohs(nf_tuple->src.u.udp.port));
	break;
	case IPPROTO_TCP:
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, tcp_dport);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, tcp_dport, ntohs(nf_tuple->dst.u.tcp.port));

		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, tcp_sport);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, tcp_sport, ntohs(nf_tuple->src.u.tcp.port));

		// FIN=1 SYN=2 RST=4 PSH=8 ACK=16 URG=32
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, tcp_flags, 0x17);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, tcp_flags, 0x10);
	break;
	}
}


static int miniflow_register_ct_tuple(struct mlx5e_ct_tuple *ct_tuple)
{
	struct nf_conntrack_tuple *tuple;
	struct nf_conntrack_zone *zone;
	struct net *net;

	net = (struct net *) ct_tuple->net;
	zone = &ct_tuple->zone;
	tuple = &ct_tuple->tuple;

	return mlx5_ct_flow_offload_add(net, zone, tuple, ct_tuple->flow);
}

static int miniflow_register_ct_flow(struct mlx5e_miniflow *miniflow)
{
	struct mlx5e_ct_tuple *ct_tuple;
	int err = 0;
	int i;

	if (!enable_ct_ageing)
		return 0;

	for (i = 0; i < miniflow->nr_ct_tuples; i++) {
		ct_tuple = &miniflow->ct_tuples[i];

		err = miniflow_register_ct_tuple(ct_tuple);
		if (err)
			break;
	}

	return err;
}

static int __miniflow_ct_parse_nat(struct mlx5e_priv *priv,
				   struct mlx5e_ct_tuple *ct_tuple,
				   struct mlx5e_tc_flow_parse_attr *parse_attr)
{
	struct tc_pedit_entry keys[2];

	/* TOOD: support IPv6 */
	keys[0].htype = TCA_PEDIT_KEY_EX_HDR_TYPE_IP4;
	keys[0].cmd = TCA_PEDIT_KEY_EX_CMD_SET;
	keys[0].mask = 0;
	keys[0].val = ct_tuple->ipv4;

	keys[0].offset = ct_tuple->nat & IPS_SRC_NAT ?
			 offsetof(struct iphdr, saddr) :
			 offsetof(struct iphdr, daddr);

	keys[1].cmd = TCA_PEDIT_KEY_EX_CMD_SET;
	keys[1].mask = 0xFFFF0000;
	keys[1].val = ct_tuple->port;

	switch (ct_tuple->proto) {
	case IPPROTO_UDP:
		keys[1].htype = TCA_PEDIT_KEY_EX_HDR_TYPE_UDP;
		keys[1].offset = ct_tuple->nat & IPS_SRC_NAT ?
				 offsetof(struct udphdr, source) :
				 offsetof(struct udphdr, dest);
	break;
	case IPPROTO_TCP:
		keys[1].htype = TCA_PEDIT_KEY_EX_HDR_TYPE_TCP;
		keys[1].offset = ct_tuple->nat & IPS_SRC_NAT ?
				 offsetof(struct tcphdr, source) :
				 offsetof(struct tcphdr, dest);
	break;
	}

	return alloc_mod_hdr_from_keys(priv, keys, 2, MLX5_FLOW_NAMESPACE_FDB,
				       parse_attr, GFP_ATOMIC, NULL);
}

static int miniflow_ct_parse_nat(struct mlx5e_priv *priv,
				 struct mlx5e_tc_flow *flow,
				 struct mlx5e_ct_tuple *ct_tuple)
{
	int err;

	if (!ct_tuple->nat)
		return 0;

	err = __miniflow_ct_parse_nat(priv, ct_tuple,
				      flow->esw_attr->parse_attr);
	if (err)
		return err;

	flow->esw_attr->action |= MLX5_FLOW_CONTEXT_ACTION_MOD_HDR;
	return 0;
}

static struct mlx5e_ct_tuple *
miniflow_ct_tuple_alloc(struct mlx5e_miniflow *miniflow)
{
	if (miniflow->nr_ct_tuples >= MINIFLOW_MAX_CT_TUPLES) {
		pr_err("Failed to allocate ct_tuple, maximum (%d)",
		       MINIFLOW_MAX_CT_TUPLES);
		return NULL;
	}

	return &miniflow->ct_tuples[miniflow->nr_ct_tuples++];
}

static struct mlx5e_tc_flow *
miniflow_ct_flow_alloc(struct mlx5e_priv *priv,
		       struct mlx5e_ct_tuple *ct_tuple)
{
	struct mlx5e_tc_flow_parse_attr *parse_attr;
	struct mlx5e_tc_flow *flow;
	int err;

	err = mlx5e_alloc_flow(priv, 0 /* cookie */,
			       MLX5E_TC_FLOW_ESWITCH | MLX5E_TC_FLOW_CT,
			       GFP_ATOMIC, &parse_attr, &flow);
	if (err)
		return NULL;

	flow->esw_attr->parse_attr = parse_attr;
	flow->esw_attr->action = MLX5_FLOW_CONTEXT_ACTION_COUNT;

	err = miniflow_ct_parse_nat(priv, flow, ct_tuple);
	if (err)
		goto err_free;

	ct_tuple->flow = flow;

	return flow;

err_free:
	mlx5e_flow_put(priv, flow);
	return NULL;
}

static int miniflow_resolve_path_flows(struct mlx5e_miniflow *miniflow)
{
	struct mlx5e_priv *priv = miniflow->priv;
	struct mlx5e_tc_flow *flow;
	unsigned long cookie;
	int i, j;

	for (i = 0, j = 0; i < miniflow->nr_flows; i++) {
		cookie = miniflow->path.cookies[i];

		if (miniflow_cookie_flags(cookie) & MFC_CT_FLOW)
			flow = miniflow_ct_flow_alloc(priv, &miniflow->ct_tuples[j++]);
		else
			flow = mlx5e_lookup_tc_ht(priv, &cookie);

		if (!flow)
			return -1;

		miniflow->path.flows[i] = flow;
	}

	return 0;
}

static int miniflow_verify_path_flows(struct mlx5e_miniflow *miniflow)
{
	struct mlx5e_priv *priv = miniflow->priv;
	struct mlx5e_tc_flow *flow;
	unsigned long cookie;
	int i;

	for (i = 0; i < miniflow->nr_flows; i++) {
		cookie = miniflow->path.cookies[i];
		if (miniflow_cookie_flags(cookie) & MFC_CT_FLOW)
			continue;

		flow = mlx5e_lookup_tc_ht(priv, &cookie);
		if (!flow)
			return -1;
	}

	return 0;
}

#define ESW_FLOW_COUNTER(flow) (flow->esw_attr->counter)

static void miniflow_link_dummy_counters(struct mlx5e_tc_flow *flow,
					 struct mlx5_fc **dummies,
					 int nr_dummies)
{
	struct mlx5_fc *counter;

	counter = ESW_FLOW_COUNTER(flow);
	if (!counter)
		return;

	WARN_ON(counter->dummy);
	mlx5_fc_link_dummies(counter, dummies, nr_dummies);
}

static void miniflow_unlink_dummy_counters(struct mlx5e_tc_flow *flow)
{
	struct mlx5_fc *counter;

	counter = ESW_FLOW_COUNTER(flow);
	if (!counter)
		return;

	mlx5_fc_unlink_dummies(counter);
}

static struct mlx5_fc *miniflow_alloc_dummy_counter(struct mlx5_core_dev *dev)
{
	struct mlx5_fc *counter;

	counter = mlx5_fc_alloc(dev, GFP_ATOMIC);
	if (!counter)
		return NULL;

	counter->dummy = true;
	counter->aging = true;

	return counter;
}

static void  miniflow_free_dummy_counter(struct mlx5_core_dev *dev,
					 struct mlx5_fc *counter)
{
	mlx5_fc_dealloc(dev, counter);
}

static int miniflow_attach_dummy_counter(struct mlx5e_tc_flow *flow)
{
	struct mlx5_fc *counter;

	if (flow->dummy_counter)
		return 0;

	if (flow->esw_attr->action & MLX5_FLOW_CONTEXT_ACTION_COUNT) {
		counter = miniflow_alloc_dummy_counter(flow->priv->mdev);
		if (!counter)
			return -ENOMEM;

		rcu_read_lock();
		if (flow->dummy_counter)
			miniflow_free_dummy_counter(flow->priv->mdev, counter);
		else
			flow->dummy_counter = counter;
		rcu_read_unlock();
	}

	return 0;
}

static int __miniflow_merge(struct mlx5e_miniflow *miniflow)
{
	struct mlx5_fc *dummy_counters[MINIFLOW_MAX_FLOWS];
	struct mlx5e_tc_flow_parse_attr *mparse_attr;
	struct mlx5e_priv *priv = miniflow->priv;
	struct rhashtable *mf_ht = get_mf_ht(priv);
	struct mlx5e_rep_priv *rpriv = priv->ppriv;
	struct mlx5e_tc_flow *mflow, *flow;
	int flags = MLX5E_TC_FLOW_SIMPLE | MLX5E_TC_FLOW_ESWITCH;
	int i;
	int err;

	err = mlx5e_alloc_flow(priv, 0 /* cookie */, flags,
			       GFP_KERNEL, &mparse_attr, &mflow);
	if (err)
		return -1;

	mflow->esw_attr->parse_attr = mparse_attr;

	rcu_read_lock();
	err = miniflow_resolve_path_flows(miniflow);
	if (err)
		goto err_rcu;

	miniflow->flow = mflow;
	mflow->miniflow = miniflow;
	mflow->esw_attr->in_rep = rpriv->rep;
	mflow->esw_attr->in_mdev = priv->mdev;

	/* Main merge loop */
	for (i=0; i < miniflow->nr_flows; i++) {
		flow = miniflow->path.flows[i];

		flags |= atomic_read(&flow->flags);

		miniflow_merge_match(mflow, flow);
		miniflow_merge_action(mflow, flow);
		err = miniflow_merge_mirred(mflow, flow);
		if (err)
			goto err_rcu;
		err = miniflow_merge_hdr(priv, mflow, flow);
		if (err)
			goto err_rcu;
		miniflow_merge_vxlan(mflow, flow);
		/* TODO: vlan is not supported yet */

		err = miniflow_attach_dummy_counter(flow);
		if (err)
			goto err_rcu;
		dummy_counters[i] = flow->dummy_counter;
	}
	rcu_read_unlock();

	flags &= ~MLX5E_TC_FLOW_INIT_DONE;
	atomic_set(&mflow->flags, flags);
	miniflow_merge_tuple(mflow, &miniflow->tuple);
	/* TODO: Workaround: crashes otherwise, should fix */
	mflow->esw_attr->action &= ~(MLX5_FLOW_CONTEXT_ACTION_CT |
				     MLX5_FLOW_CONTEXT_ACTION_GOTO);

	err = mlx5e_tc_add_fdb_flow(priv, mparse_attr, mflow, NULL);
	if (err)
		goto err;

	err = mlx5e_tc_update_and_init_done_fdb_flow(priv, mflow);
	if (err)
		goto err_verify;

	rcu_read_lock();
	err = miniflow_verify_path_flows(miniflow);
	if (err) {
		/* TODO: refactor this function and the error handling */
		rcu_read_unlock();
		goto err_verify;
	}

	miniflow_link_dummy_counters(miniflow->flow,
				     dummy_counters,
				     miniflow->nr_flows);
	miniflow_attach(miniflow);

	atomic_inc((atomic_t *)&nr_mf_succ);

	err = miniflow_register_ct_flow(miniflow);
	if (err) {
		rcu_read_unlock();
		miniflow_cleanup(miniflow);
		return -1;
	}

	rcu_read_unlock();
	return 0;

err_rcu:
	rcu_read_unlock();
err:
err_verify:
	mlx5e_flow_put(priv, mflow);
	rhashtable_remove_fast(mf_ht, &miniflow->node, mf_ht_params);
	miniflow_cleanup(miniflow);
	miniflow_free(miniflow);
	atomic_inc((atomic_t *)&nr_mf_err);
	return -1;
}

static bool miniflow_workqueue_busy(void)
{
	return (atomic_read(&miniflow_wq_size) > MINIFLOW_WORKQUEUE_MAX_SIZE);
}

static void miniflow_merge_work(struct work_struct *work)
{
	struct mlx5e_miniflow *miniflow = container_of(work, struct mlx5e_miniflow, work);

	atomic_dec((atomic_t *)&nr_workqueue_elm);
	atomic_inc((atomic_t *)&nr_concurrent_workqueue_elm);
	atomic_dec(&miniflow_wq_size);
	__miniflow_merge(miniflow);
	atomic_dec((atomic_t *)&nr_concurrent_workqueue_elm);
}

static int miniflow_merge(struct mlx5e_miniflow *miniflow)
{
	atomic_inc((atomic_t *)&nr_total_workqueue_elm);
	atomic_inc((atomic_t *)&nr_workqueue_elm);

	atomic_inc(&miniflow_wq_size);
	INIT_WORK(&miniflow->work, miniflow_merge_work);
	if (queue_work(miniflow_wq, &miniflow->work))
		return 0;

	return -1;
}

static void mlx5e_del_miniflow(struct mlx5e_miniflow *miniflow)
{
	struct rhashtable *mf_ht = get_mf_ht(miniflow->priv);

	atomic_dec((atomic_t *)&nr_mf_succ);

	mlx5e_flow_put(miniflow->priv, miniflow->flow);
	rhashtable_remove_fast(mf_ht, &miniflow->node, mf_ht_params);
	miniflow_free(miniflow);
}

static void mlx5e_del_miniflow_work(struct work_struct *work)
{
	struct mlx5e_miniflow *miniflow = container_of(work,
						       struct mlx5e_miniflow,
						       work);
	atomic_dec((atomic_t *)&nr_workqueue_elm);
	atomic_inc((atomic_t *)&nr_concurrent_workqueue_elm);
	miniflow_cleanup(miniflow);
	mlx5e_del_miniflow(miniflow);
	atomic_dec((atomic_t *)&nr_concurrent_workqueue_elm);
}

void mlx5e_del_miniflow_list(struct mlx5e_tc_flow *flow)
{
	struct mlx5e_miniflow_node *mnode, *n;

	spin_lock_bh(&miniflow_lock);
	list_for_each_entry_safe(mnode, n, &flow->miniflow_list, node) {
		struct mlx5e_miniflow *miniflow = mnode->miniflow;

		miniflow_unlink_dummy_counters(miniflow->flow);
		miniflow_detach(miniflow);

		atomic_inc((atomic_t *)&nr_total_workqueue_elm);
		atomic_inc((atomic_t *)&nr_workqueue_elm);

		INIT_WORK(&miniflow->work, mlx5e_del_miniflow_work);
		queue_work(miniflow_wq, &miniflow->work);
	}
	spin_unlock_bh(&miniflow_lock);
}

int miniflow_cache_init(struct mlx5e_priv *priv)
{
	struct rhashtable *mf_ht = get_mf_ht(priv);
	int err;

	if (miniflow_cache_allocated)
		return -EINVAL;

	err = mlx5_ct_flow_offload_table_init();
	if (err)
		return err;

	miniflow_cache = kmem_cache_create("mlx5_miniflow_cache",
					    sizeof(struct mlx5e_miniflow),
					    0, SLAB_HWCACHE_ALIGN,
					    NULL);
	if (!miniflow_cache)
		goto err_mf_cache;

	miniflow_cache_allocated = 1;

	err = rhashtable_init(mf_ht, &mf_ht_params);
	if (err)
		goto err_mf_ht;

	miniflow_wq = alloc_workqueue("miniflow", __WQ_LEGACY | WQ_MEM_RECLAIM |
						  WQ_UNBOUND | WQ_HIGHPRI | WQ_SYSFS, 16);
	if (!miniflow_wq)
		goto err_wq;

	return 0;

err_wq:
	rhashtable_free_and_destroy(mf_ht, NULL, NULL);
err_mf_ht:
	kmem_cache_destroy(miniflow_cache);
	miniflow_cache_allocated = 0;
err_mf_cache:
	mlx5_ct_flow_offload_table_destroy();
	return -ENOMEM;
}

void miniflow_cache_destroy(struct mlx5e_priv *priv)
{
	struct rhashtable *mf_ht = get_mf_ht(priv);

	/* TODO: it does not make sense to process the remaining miniflows? */
	flush_workqueue(miniflow_wq);
	destroy_workqueue(miniflow_wq);
	rhashtable_free_and_destroy(mf_ht, NULL, NULL);
	miniflow_free_current_miniflow();
	kmem_cache_destroy(miniflow_cache);
	miniflow_cache_allocated = 0;
	mlx5_ct_flow_offload_table_destroy();
}

static int miniflow_extract_tuple(struct mlx5e_miniflow *miniflow,
				  struct sk_buff *skb)
{
	struct nf_conntrack_tuple *nf_tuple = &miniflow->tuple;
	struct iphdr *iph, _iph;
	struct udphdr *udph, _udph;
	struct tcphdr *tcph, _tcph;
	int ihl;

	if (skb->protocol != htons(ETH_P_IP) &&
	    skb->protocol != htons(ETH_P_IPV6))
		goto err;

	if (skb->protocol == htons(ETH_P_IPV6)) {
		pr_warn_once("IPv6 is not supported\n");
		goto err;
	}

	iph = skb_header_pointer(skb, skb_network_offset(skb), sizeof(_iph), &_iph);
	if (iph == NULL)
		goto err;

	ihl = ip_hdrlen(skb);
	if (ihl > sizeof(struct iphdr)) {
		pr_warn_once("Offload with IPv4 options is not supported\n");
		goto err;
	}

	if (iph->frag_off & htons(IP_MF | IP_OFFSET)) {
		pr_warn_once("IP fragments are not supported\n");
		goto err;
	}

	nf_tuple->src.l3num = skb->protocol;
	nf_tuple->dst.protonum = iph->protocol;
	nf_tuple->src.u3.ip = iph->saddr;
	nf_tuple->dst.u3.ip = iph->daddr;

	switch (nf_tuple->dst.protonum) {
	case IPPROTO_TCP:
		tcph = skb_header_pointer(skb, skb_network_offset(skb) + ihl,
					  sizeof(_tcph), &_tcph);

		if (!tcph || tcph->fin || tcph->syn || tcph->rst)
			goto err;

		nf_tuple->src.u.all = tcph->source;
		nf_tuple->dst.u.all = tcph->dest;
	break;
	case IPPROTO_UDP:
		udph = skb_header_pointer(skb, skb_network_offset(skb) + ihl,
					  sizeof(_udph), &_udph);

		if (!udph)
			goto err;

		nf_tuple->src.u.all = udph->source;
		nf_tuple->dst.u.all = udph->dest;
	break;
	case IPPROTO_ICMP:
		pr_warn_once("ICMP is not supported\n");
		goto err;
	default:
		pr_warn("Proto %d is not supported\n", nf_tuple->dst.protonum);
		goto err;
	}

	return 0;

err:
	return -1;
}

int miniflow_configure_ct(struct mlx5e_priv *priv,
			  struct tc_ct_offload *cto)
{
	struct mlx5e_miniflow *miniflow;
	struct mlx5e_ct_tuple *ct_tuple;
	unsigned long cookie;

	if (!tc_can_offload(priv->netdev))
		return -EOPNOTSUPP;

	cookie = (unsigned long) cto->tuple;

	miniflow = miniflow_read();
	if (!miniflow)
		return -1;

	if (miniflow->nr_flows == -1)
		goto err;

	if (unlikely(miniflow->nr_flows == MINIFLOW_MAX_FLOWS))
		goto err;

	if (!cookie)
		goto err;

	ct_tuple = miniflow_ct_tuple_alloc(miniflow);
	if (!ct_tuple)
		goto err;

	ct_tuple->net = cto->net;
	ct_tuple->zone = *cto->zone;
	ct_tuple->tuple = *cto->tuple;

	ct_tuple->nat = cto->nat;
	ct_tuple->ipv4 = cto->ipv4;
	ct_tuple->port = cto->port;
	ct_tuple->proto = cto->proto;

	ct_tuple->flow = NULL;

	miniflow_path_append_cookie(miniflow, cookie, MFC_CT_FLOW);
	return 0;

err:
	miniflow_abort(miniflow);
	return -1;
}

int miniflow_configure(struct mlx5e_priv *priv,
		       struct tc_miniflow_offload *mf)
{
	struct rhashtable *mf_ht = get_mf_ht(priv);
	struct sk_buff *skb = mf->skb;
	struct mlx5e_miniflow *miniflow = NULL;
	int err;

	if (!tc_can_offload(priv->netdev))
		return -EOPNOTSUPP;

	miniflow = miniflow_read();
	if (!miniflow) {
		miniflow = miniflow_alloc();
		if (!miniflow)
			return -1;
		miniflow_write(miniflow);
	}

	if (mf->chain_index == 0)
		miniflow_init(miniflow, priv);

	if (miniflow->nr_flows == -1)
		goto err;

	/**
	 * In some conditions merged rule could have another action with drop.
	 * i.e. header rewrite + drop.
	 * Such rule doesn't make sense and also not supported.
	 * For simplicty we will not offload drop rules that are merged rules.
	 */
	if (mf->is_drop)
		goto err;

	/* "Simple" rules should be handled by the normal routines */
	if (miniflow->nr_flows == 0 && mf->last_flow)
		goto err;

	if (unlikely(miniflow->nr_flows == MINIFLOW_MAX_FLOWS))
		goto err;

	if (!mf->cookie)
		goto err;

	if (miniflow->nr_flows == 0) {
		err = miniflow_extract_tuple(miniflow, skb);
		if (err)
			goto err;
	}

	miniflow_path_append_cookie(miniflow, mf->cookie, 0);

	if (!mf->last_flow)
		return 0;

	if (miniflow_workqueue_busy())
		goto err;

	/* If rules in HW + rules in queue exceed the max value, then igore new one.
	 * Note the rules in queue could be the to_be_deleted rules. */
	if ((atomic_read((atomic_t *)&nr_mf_succ) + atomic_read((atomic_t *)&nr_workqueue_elm)) > atomic_read((atomic_t *)&max_nr_mf))
		goto err;

	err = rhashtable_lookup_insert_fast(mf_ht, &miniflow->node, mf_ht_params);
	if (err)
		goto err;

	err = miniflow_merge(miniflow);
	if (err)
		goto err_work;

	miniflow_write(NULL);

	return 0;

err_work:
	rhashtable_remove_fast(mf_ht, &miniflow->node, mf_ht_params);
err:
	miniflow_abort(miniflow);
	return -1;
}

int ct_flow_offload_add(void *arg, struct list_head *head)
{
	struct mlx5e_tc_flow *flow = arg;

	list_add(&flow->nft_node, head);
	return 0;
}

void ct_flow_offload_get_stats(struct list_head *head, u64 *lastuse)
{
	struct mlx5e_tc_flow *flow, *tmp;

	list_for_each_entry_safe(flow, tmp, head, nft_node) {
		struct mlx5_fc *counter = flow->dummy_counter;
		u64 bytes, packets, lastuse1;

		if (counter) {
			mlx5_fc_query_cached(counter, &bytes, &packets, &lastuse1);
			*lastuse = max(*lastuse, lastuse1);
		}
	}
}

static void ct_flow_offload_del(struct mlx5e_tc_flow *flow)
{
	mlx5e_flow_put(flow->priv, flow);
}

int ct_flow_offload_destroy(struct list_head *head)
{
	struct mlx5e_tc_flow *flow, *n;

	list_for_each_entry_safe(flow, n, head, nft_node) {
		list_del_init(&flow->nft_node);
		ct_flow_offload_del(flow);
	}

	return 0;
}

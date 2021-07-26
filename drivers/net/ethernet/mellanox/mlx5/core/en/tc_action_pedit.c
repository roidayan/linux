// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include <linux/if_vlan.h>
#include "tc_action.h"
#include "tc_action_pedit.h"
#include "tc_priv.h"
#include "en_tc.h"

static int pedit_header_offsets[] = {
	[FLOW_ACT_MANGLE_HDR_TYPE_ETH] = offsetof(struct pedit_headers, eth),
	[FLOW_ACT_MANGLE_HDR_TYPE_IP4] = offsetof(struct pedit_headers, ip4),
	[FLOW_ACT_MANGLE_HDR_TYPE_IP6] = offsetof(struct pedit_headers, ip6),
	[FLOW_ACT_MANGLE_HDR_TYPE_TCP] = offsetof(struct pedit_headers, tcp),
	[FLOW_ACT_MANGLE_HDR_TYPE_UDP] = offsetof(struct pedit_headers, udp),
};

#define pedit_header(_ph, _htype) ((void *)(_ph) + pedit_header_offsets[_htype])

static int
set_pedit_val(u8 hdr_type, u32 mask, u32 val, u32 offset,
	      struct pedit_headers_action *hdrs)
{
	u32 *curr_pmask, *curr_pval;

	curr_pmask = (u32 *)(pedit_header(&hdrs->masks, hdr_type) + offset);
	curr_pval  = (u32 *)(pedit_header(&hdrs->vals, hdr_type) + offset);

	if (*curr_pmask & mask)  /* disallow acting twice on the same location */
		goto out_err;

	*curr_pmask |= mask;
	*curr_pval  |= (val & mask);

	return 0;

out_err:
	return -EOPNOTSUPP;
}

static int
parse_pedit_to_modify_hdr(struct mlx5e_priv *priv,
			  const struct flow_action_entry *act, int namespace,
			  struct mlx5e_tc_flow_parse_attr *parse_attr,
			  struct pedit_headers_action *hdrs,
			  struct netlink_ext_ack *extack)
{
	u8 cmd = (act->id == FLOW_ACTION_MANGLE) ? 0 : 1;
	int err = -EOPNOTSUPP;
	u32 mask, val, offset;
	u8 htype;

	htype = act->mangle.htype;
	err = -EOPNOTSUPP; /* can't be all optimistic */

	if (htype == FLOW_ACT_MANGLE_UNSPEC) {
		NL_SET_ERR_MSG_MOD(extack, "legacy pedit isn't offloaded");
		goto out_err;
	}

	if (!mlx5e_flow_namespace_max_modify_action(priv->mdev, namespace)) {
		NL_SET_ERR_MSG_MOD(extack, "The pedit offload action is not supported");
		goto out_err;
	}

	mask = act->mangle.mask;
	val = act->mangle.val;
	offset = act->mangle.offset;

	err = set_pedit_val(htype, ~mask, val, offset, &hdrs[cmd]);
	if (err)
		goto out_err;

	hdrs[cmd].pedits++;

	return 0;
out_err:
	return err;
}

static int
parse_pedit_to_reformat(struct mlx5e_priv *priv,
			const struct flow_action_entry *act,
			struct mlx5e_tc_flow_parse_attr *parse_attr,
			struct netlink_ext_ack *extack)
{
	u32 mask, val, offset;
	u32 *p;

	if (act->id != FLOW_ACTION_MANGLE)
		return -EOPNOTSUPP;

	if (act->mangle.htype != FLOW_ACT_MANGLE_HDR_TYPE_ETH) {
		NL_SET_ERR_MSG_MOD(extack, "Only Ethernet modification is supported");
		return -EOPNOTSUPP;
	}

	mask = ~act->mangle.mask;
	val = act->mangle.val;
	offset = act->mangle.offset;
	p = (u32 *)&parse_attr->eth;
	*(p + (offset >> 2)) |= (val & mask);

	return 0;
}

int
mlx5e_tc_parse_pedit_action(struct mlx5e_priv *priv,
			    const struct flow_action_entry *act, int namespace,
			    struct mlx5e_tc_flow_parse_attr *parse_attr,
			    struct pedit_headers_action *hdrs,
			    struct mlx5e_tc_flow *flow,
			    struct netlink_ext_ack *extack)
{
	if (flow && flow_flag_test(flow, L3_TO_L2_DECAP))
		return parse_pedit_to_reformat(priv, act, parse_attr, extack);

	return parse_pedit_to_modify_hdr(priv, act, namespace, parse_attr, hdrs, extack);
}

static int
tc_action_can_offload_pedit(struct mlx5e_tc_action_parse_state *parse_state,
			    const struct flow_action_entry *act,
			    int act_index)
{
	return 0;
}

static int
tc_action_parse_pedit(struct mlx5e_tc_action_parse_state *parse_state,
		      const struct flow_action_entry *act,
		      struct mlx5e_priv *priv,
		      struct mlx5_flow_attr *attr)
{
	struct mlx5e_tc_flow *flow = parse_state->flow;
	enum mlx5_flow_namespace_type ns_type;
	int err;

	ns_type = mlx5e_tc_get_flow_namespace(flow);

	err = mlx5e_tc_parse_pedit_action(flow->priv, act, ns_type,
					  flow->attr->parse_attr, parse_state->hdrs,
					  flow, parse_state->extack);
	if (err)
		return err;

	if (mlx5e_is_eswitch_flow(flow) && !flow_flag_test(flow, L3_TO_L2_DECAP)) {
		struct mlx5_esw_flow_attr *esw_attr = attr->esw_attr;

		esw_attr->split_count = esw_attr->out_count;
	}

	attr->action |= MLX5_FLOW_CONTEXT_ACTION_MOD_HDR;
	return 0;
}

struct mlx5e_tc_action mlx5e_tc_action_pedit = {
	.can_offload = tc_action_can_offload_pedit,
	.parse_action = tc_action_parse_pedit,
};

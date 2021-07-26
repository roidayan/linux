/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#ifndef __MLX5_TC_ACTION_H__
#define __MLX5_TC_ACTION_H__

#include <net/tc_act/tc_pedit.h>
#include <net/flow_offload.h>
#include <linux/netlink.h>
#include "eswitch.h"
#include "tc_action_pedit.h"

struct mlx5e_tc_action_parse_state {
	unsigned int num_actions;
	bool mpls_push;
	bool encap;
	bool decap;
	int ifindexes[MLX5_MAX_FLOW_FWD_VPORTS];
	int if_count;
	const struct ip_tunnel_info *tun_info;
	struct mlx5e_tc_flow *flow;
	struct netlink_ext_ack *extack;
	struct mlx5_sample_attr sample;
	struct pedit_headers_action hdrs[__PEDIT_CMD_MAX];
};

struct mlx5e_tc_action {
	int (*can_offload)(struct mlx5e_tc_action_parse_state *parse_state,
			   const struct flow_action_entry *act,
			   int act_index);

	int (*parse_action)(struct mlx5e_tc_action_parse_state *parse_state,
			    const struct flow_action_entry *act,
			    struct mlx5e_priv *priv,
			    struct mlx5_flow_attr *attr);
};

extern struct mlx5e_tc_action mlx5e_tc_action_drop;
extern struct mlx5e_tc_action mlx5e_tc_action_trap;
extern struct mlx5e_tc_action mlx5e_tc_action_goto;
extern struct mlx5e_tc_action mlx5e_tc_action_mirred;
extern struct mlx5e_tc_action mlx5e_tc_action_vlan;
extern struct mlx5e_tc_action mlx5e_tc_action_vlan_mangle;
extern struct mlx5e_tc_action mlx5e_tc_action_tun_encap;
extern struct mlx5e_tc_action mlx5e_tc_action_tun_decap;
extern struct mlx5e_tc_action mlx5e_tc_action_csum;
extern struct mlx5e_tc_action mlx5e_tc_action_mpls_push;
extern struct mlx5e_tc_action mlx5e_tc_action_mpls_pop;
extern struct mlx5e_tc_action mlx5e_tc_action_ct;
extern struct mlx5e_tc_action mlx5e_tc_action_sample;
extern struct mlx5e_tc_action mlx5e_tc_action_pedit;
extern struct mlx5e_tc_action mlx5e_tc_action_accept;

void mlx5e_tc_init_tc_actions(void);

struct mlx5e_tc_action *
mlx5e_tc_action_get(enum flow_action_id act_id);

void
mlx5e_tc_action_init_parse_state(struct mlx5e_tc_action_parse_state *parse_state,
				 struct mlx5e_tc_flow *flow,
				 struct flow_action *flow_action,
				 struct netlink_ext_ack *extack);

#endif /* __MLX5_TC_ACTION_H__ */

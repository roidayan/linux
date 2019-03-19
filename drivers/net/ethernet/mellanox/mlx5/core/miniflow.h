/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2019 Mellanox Technologies. */

#ifndef __MLX5_MINIFLOW_H__
#define __MLX5_MINIFLOW_H__

#include <net/netfilter/nf_conntrack.h>
#include "fs_core.h"
#include "en_tc.h"

#define MFC_INFOMASK	7UL
#define MFC_PTRMASK  	~(MFC_INFOMASK)
#define MFC_CT_FLOW     BIT(0)

#define MINIFLOW_MAX_CT_TUPLES 2

struct mlx5e_ct_tuple {
	struct net *net;
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_zone zone;

	struct mlx5e_tc_flow *flow;
};

struct mlx5e_miniflow_node {
	struct list_head node;
	struct mlx5e_miniflow *miniflow;
};

struct mlx5e_miniflow {
	struct rhash_head node;
	struct work_struct work;
	struct mlx5e_priv *priv;
	struct mlx5e_tc_flow *flow;

	struct nf_conntrack_tuple tuple;

	int nr_flows;
	struct {
		unsigned long        cookies[MINIFLOW_MAX_FLOWS];
		struct mlx5e_tc_flow *flows[MINIFLOW_MAX_FLOWS];
	} path;

	int nr_ct_tuples;
	struct mlx5e_ct_tuple ct_tuples[MINIFLOW_MAX_CT_TUPLES];

	struct mlx5e_miniflow_node mnodes[MINIFLOW_MAX_FLOWS];
};


void mlx5e_del_miniflow_list(struct mlx5e_tc_flow *flow);

int miniflow_cache_init(struct mlx5e_priv *priv);
void miniflow_cache_destroy(struct mlx5e_priv *priv);
int miniflow_configure_ct(struct mlx5e_priv *priv,
			  struct tc_ct_offload *cto);
int miniflow_configure(struct mlx5e_priv *priv,
		       struct tc_miniflow_offload *mf);

#endif /* __MLX5_MINIFLOW_H__ */

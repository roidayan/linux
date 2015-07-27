/*
 * Copyright (c) 2015, Mellanox Technologies. All rights reserved.
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

#include <linux/device.h>
#include <linux/netdevice.h>
#include "en.h"
#include "en_ecn.h"

static const char *mlx5e_get_cong_protocol(int protocol)
{
	switch (protocol) {
	case MLX5_CON_PROTOCOL_802_1_RP:
		return "802.1.qau_rp";
	case MLX5_CON_PROTOCOL_R_ROCE_RP:
		return "roce_rp";
	case MLX5_CON_PROTOCOL_R_ROCE_NP:
		return "roce_np";
	}
	return "";
}

static void mlx5e_fill_rp_attributes(struct kobject *kobj,
				     struct mlx5_core_dev *mdev,
				     struct mlx5_ecn_rp_attributes *rp_attr)
{
	int err;

	rp_attr->mdev = mdev;

	sysfs_attr_init(&rp_attr->clamp_tgt_rate.attr);
	rp_attr->clamp_tgt_rate.attr.name = "clamp_tgt_rate";
	rp_attr->clamp_tgt_rate.attr.mode = S_IWUSR | S_IRUGO;
	rp_attr->clamp_tgt_rate.show = mlx5e_show_clamp_tgt_rate;
	rp_attr->clamp_tgt_rate.store = mlx5e_store_clamp_tgt_rate;
	err = sysfs_create_file(kobj, &rp_attr->clamp_tgt_rate.attr);

	sysfs_attr_init(&rp_attr->clamp_tgt_rate_ati.attr);
	rp_attr->clamp_tgt_rate_ati.attr.name = "clamp_tgt_rate_after_time_inc";
	rp_attr->clamp_tgt_rate_ati.attr.mode = S_IWUSR | S_IRUGO;
	rp_attr->clamp_tgt_rate_ati.show = mlx5e_show_clamp_tgt_rate_ati;
	rp_attr->clamp_tgt_rate_ati.store = mlx5e_store_clamp_tgt_rate_ati;
	err = sysfs_create_file(kobj, &rp_attr->clamp_tgt_rate_ati.attr);

	sysfs_attr_init(&rp_attr->rpg_time_reset.attr);
	rp_attr->rpg_time_reset.attr.name = "rpg_time_reset";
	rp_attr->rpg_time_reset.attr.mode = S_IWUSR | S_IRUGO;
	rp_attr->rpg_time_reset.show = mlx5e_show_rpg_time_reset;
	rp_attr->rpg_time_reset.store = mlx5e_store_rpg_time_reset;
	err = sysfs_create_file(kobj, &rp_attr->rpg_time_reset.attr);

	sysfs_attr_init(&rp_attr->rpg_byte_reset.attr);
	rp_attr->rpg_byte_reset.attr.name = "rpg_byte_reset";
	rp_attr->rpg_byte_reset.attr.mode = S_IWUSR | S_IRUGO;
	rp_attr->rpg_byte_reset.show = mlx5e_show_rpg_byte_reset;
	rp_attr->rpg_byte_reset.store = mlx5e_store_rpg_byte_reset;
	err = sysfs_create_file(kobj, &rp_attr->rpg_byte_reset.attr);

	sysfs_attr_init(&rp_attr->rpg_threshold.attr);
	rp_attr->rpg_threshold.attr.name = "rpg_threshold";
	rp_attr->rpg_threshold.attr.mode = S_IWUSR | S_IRUGO;
	rp_attr->rpg_threshold.show = mlx5e_show_rpg_threshold;
	rp_attr->rpg_threshold.store = mlx5e_store_rpg_threshold;
	err = sysfs_create_file(kobj, &rp_attr->rpg_threshold.attr);

	sysfs_attr_init(&rp_attr->rpg_max_rate.attr);
	rp_attr->rpg_max_rate.attr.name = "rpg_max_rate";
	rp_attr->rpg_max_rate.attr.mode = S_IWUSR | S_IRUGO;
	rp_attr->rpg_max_rate.show = mlx5e_show_rpg_max_rate;
	rp_attr->rpg_max_rate.store = mlx5e_store_rpg_max_rate;
	err = sysfs_create_file(kobj, &rp_attr->rpg_max_rate.attr);

	sysfs_attr_init(&rp_attr->rpg_ai_rate.attr);
	rp_attr->rpg_ai_rate.attr.name = "rpg_ai_rate";
	rp_attr->rpg_ai_rate.attr.mode = S_IWUSR | S_IRUGO;
	rp_attr->rpg_ai_rate.show = mlx5e_show_rpg_ai_rate;
	rp_attr->rpg_ai_rate.store = mlx5e_store_rpg_ai_rate;
	err = sysfs_create_file(kobj, &rp_attr->rpg_ai_rate.attr);

	sysfs_attr_init(&rp_attr->rpg_hai_rate.attr);
	rp_attr->rpg_hai_rate.attr.name = "rpg_hai_rate";
	rp_attr->rpg_hai_rate.attr.mode = S_IWUSR | S_IRUGO;
	rp_attr->rpg_hai_rate.show = mlx5e_show_rpg_hai_rate;
	rp_attr->rpg_hai_rate.store = mlx5e_store_rpg_hai_rate;
	err = sysfs_create_file(kobj, &rp_attr->rpg_hai_rate.attr);

	sysfs_attr_init(&rp_attr->rpg_gd.attr);
	rp_attr->rpg_gd.attr.name = "rpg_gd";
	rp_attr->rpg_gd.attr.mode = S_IWUSR | S_IRUGO;
	rp_attr->rpg_gd.show = mlx5e_show_rpg_gd;
	rp_attr->rpg_gd.store = mlx5e_store_rpg_gd;
	err = sysfs_create_file(kobj, &rp_attr->rpg_gd.attr);

	sysfs_attr_init(&rp_attr->rpg_min_dec_fac.attr);
	rp_attr->rpg_min_dec_fac.attr.name = "rpg_min_dec_fac";
	rp_attr->rpg_min_dec_fac.attr.mode = S_IWUSR | S_IRUGO;
	rp_attr->rpg_min_dec_fac.show = mlx5e_show_rpg_min_dec_fac;
	rp_attr->rpg_min_dec_fac.store = mlx5e_store_rpg_min_dec_fac;
	err = sysfs_create_file(kobj, &rp_attr->rpg_min_dec_fac.attr);

	sysfs_attr_init(&rp_attr->rpg_min_rate.attr);
	rp_attr->rpg_min_rate.attr.name = "rpg_min_rate";
	rp_attr->rpg_min_rate.attr.mode = S_IWUSR | S_IRUGO;
	rp_attr->rpg_min_rate.show = mlx5e_show_rpg_min_rate;
	rp_attr->rpg_min_rate.store = mlx5e_store_rpg_min_rate;
	err = sysfs_create_file(kobj, &rp_attr->rpg_min_rate.attr);

	sysfs_attr_init(&rp_attr->rate2set_fcnp.attr);
	rp_attr->rate2set_fcnp.attr.name = "rate_to_set_on_first_cnp";
	rp_attr->rate2set_fcnp.attr.mode = S_IWUSR | S_IRUGO;
	rp_attr->rate2set_fcnp.show = mlx5e_show_rate2set_fcnp;
	rp_attr->rate2set_fcnp.store = mlx5e_store_rate2set_fcnp;
	err = sysfs_create_file(kobj, &rp_attr->rate2set_fcnp.attr);

	sysfs_attr_init(&rp_attr->dce_tcp_g.attr);
	rp_attr->dce_tcp_g.attr.name = "dce_tcp_g";
	rp_attr->dce_tcp_g.attr.mode = S_IWUSR | S_IRUGO;
	rp_attr->dce_tcp_g.show = mlx5e_show_dce_tcp_g;
	rp_attr->dce_tcp_g.store = mlx5e_store_dce_tcp_g;
	err = sysfs_create_file(kobj, &rp_attr->dce_tcp_g.attr);

	sysfs_attr_init(&rp_attr->dce_tcp_rtt.attr);
	rp_attr->dce_tcp_rtt.attr.name = "dce_tcp_rtt";
	rp_attr->dce_tcp_rtt.attr.mode = S_IWUSR | S_IRUGO;
	rp_attr->dce_tcp_rtt.show = mlx5e_show_dce_tcp_rtt;
	rp_attr->dce_tcp_rtt.store = mlx5e_store_dce_tcp_rtt;
	err = sysfs_create_file(kobj, &rp_attr->dce_tcp_rtt.attr);

	sysfs_attr_init(&rp_attr->rreduce_mperiod.attr);
	rp_attr->rreduce_mperiod.attr.name = "rate_reduce_monitor_period";
	rp_attr->rreduce_mperiod.attr.mode = S_IWUSR | S_IRUGO;
	rp_attr->rreduce_mperiod.show = mlx5e_show_rreduce_mperiod;
	rp_attr->rreduce_mperiod.store = mlx5e_store_rreduce_mperiod;
	err = sysfs_create_file(kobj, &rp_attr->rreduce_mperiod.attr);

	sysfs_attr_init(&rp_attr->initial_alpha_value.attr);
	rp_attr->initial_alpha_value.attr.name = "initial_alpha_value";
	rp_attr->initial_alpha_value.attr.mode = S_IWUSR | S_IRUGO;
	rp_attr->initial_alpha_value.show = mlx5e_show_initial_alpha_value;
	rp_attr->initial_alpha_value.store = mlx5e_store_initial_alpha_value;
	err = sysfs_create_file(kobj, &rp_attr->initial_alpha_value.attr);
}

static void mlx5e_remove_rp_attributes(struct kobject *kobj,
				       struct mlx5_ecn_rp_attributes *rp_attr)
{
	sysfs_remove_file(kobj, &rp_attr->clamp_tgt_rate.attr);
	sysfs_remove_file(kobj, &rp_attr->clamp_tgt_rate_ati.attr);
	sysfs_remove_file(kobj, &rp_attr->rpg_time_reset.attr);
	sysfs_remove_file(kobj, &rp_attr->rpg_byte_reset.attr);
	sysfs_remove_file(kobj, &rp_attr->rpg_threshold.attr);
	sysfs_remove_file(kobj, &rp_attr->rpg_max_rate.attr);
	sysfs_remove_file(kobj, &rp_attr->rpg_ai_rate.attr);
	sysfs_remove_file(kobj, &rp_attr->rpg_hai_rate.attr);
	sysfs_remove_file(kobj, &rp_attr->rpg_gd.attr);
	sysfs_remove_file(kobj, &rp_attr->rpg_min_dec_fac.attr);
	sysfs_remove_file(kobj, &rp_attr->rpg_min_rate.attr);
	sysfs_remove_file(kobj, &rp_attr->rate2set_fcnp.attr);
	sysfs_remove_file(kobj, &rp_attr->dce_tcp_g.attr);
	sysfs_remove_file(kobj, &rp_attr->dce_tcp_rtt.attr);
	sysfs_remove_file(kobj, &rp_attr->rreduce_mperiod.attr);
	sysfs_remove_file(kobj, &rp_attr->initial_alpha_value.attr);
}

static void mlx5e_fill_np_attributes(struct kobject *kobj,
				     struct mlx5_core_dev *mdev,
				     struct mlx5_ecn_np_attributes *np_attr)
{
	int err;

	np_attr->mdev = mdev;

	sysfs_attr_init(&np_attr->min_time_between_cnps.attr);
	np_attr->min_time_between_cnps.attr.name = "min_time_between_cnps";
	np_attr->min_time_between_cnps.attr.mode = S_IWUSR | S_IRUGO;
	np_attr->min_time_between_cnps.show  = mlx5e_show_min_time_between_cnps;
	np_attr->min_time_between_cnps.store =
					  mlx5e_store_min_time_between_cnps;
	err = sysfs_create_file(kobj, &np_attr->min_time_between_cnps.attr);

	sysfs_attr_init(&np_attr->cnp_dscp.attr);
	np_attr->cnp_dscp.attr.name = "cnp_dscp";
	np_attr->cnp_dscp.attr.mode = S_IWUSR | S_IRUGO;
	np_attr->cnp_dscp.show  = mlx5e_show_cnp_dscp;
	np_attr->cnp_dscp.store = mlx5e_store_cnp_dscp;
	err = sysfs_create_file(kobj, &np_attr->cnp_dscp.attr);

	sysfs_attr_init(&np_attr->cnp_802p_prio.attr);
	np_attr->cnp_802p_prio.attr.name = "cnp_802p_prio";
	np_attr->cnp_802p_prio.attr.mode = S_IWUSR | S_IRUGO;
	np_attr->cnp_802p_prio.show  = mlx5e_show_cnp_802p_prio;
	np_attr->cnp_802p_prio.store = mlx5e_store_cnp_802p_prio;
	err = sysfs_create_file(kobj, &np_attr->cnp_802p_prio.attr);
}

static void mlx5e_remove_np_attributes(struct kobject *kobj,
				       struct mlx5_ecn_np_attributes *np_attr)
{
	sysfs_remove_file(kobj, &np_attr->min_time_between_cnps.attr);
	sysfs_remove_file(kobj, &np_attr->cnp_dscp.attr);
	sysfs_remove_file(kobj, &np_attr->cnp_802p_prio.attr);
}

static void mlx5e_fill_attributes(struct mlx5e_priv *priv,
				  int proto)
{
	const char *priority_arr[8] = {"0", "1", "2", "3", "4", "5", "6", "7"};
	struct mlx5_ecn_ctx *ecn_ctx = &priv->ecn_ctx[proto];
	struct mlx5_ecn_enable_ctx *ecn_enable_ctx;
	int i, err;

	ecn_ctx->ecn_enable_kobj = kobject_create_and_add("enable",
				   ecn_ctx->ecn_proto_kobj);

	for (i = 0; i < 8; i++) {
		ecn_enable_ctx = &priv->ecn_enable_ctx[proto][i];
		ecn_enable_ctx->priority = i;
		ecn_enable_ctx->cong_protocol = proto;
		ecn_enable_ctx->mdev = priv->mdev;
		sysfs_attr_init(&ecn_enable_ctx->enable.attr);
		ecn_enable_ctx->enable.attr.name = priority_arr[i];
		ecn_enable_ctx->enable.attr.mode = S_IWUSR | S_IRUGO;
		ecn_enable_ctx->enable.show  = mlx5e_show_ecn_enable;
		ecn_enable_ctx->enable.store = mlx5e_store_ecn_enable;
		err = sysfs_create_file(ecn_ctx->ecn_enable_kobj,
					&ecn_enable_ctx->enable.attr);
	}

	switch (proto) {
	case MLX5_CON_PROTOCOL_802_1_RP:
		return;
	case MLX5_CON_PROTOCOL_R_ROCE_RP:
		return mlx5e_fill_rp_attributes(ecn_ctx->ecn_proto_kobj,
						priv->mdev,
						&ecn_ctx->ecn_attr.rp_attr);
	case MLX5_CON_PROTOCOL_R_ROCE_NP:
		return mlx5e_fill_np_attributes(ecn_ctx->ecn_proto_kobj,
						priv->mdev,
						&ecn_ctx->ecn_attr.np_attr);
	}
}

static void mlx5e_remove_attributes(struct mlx5e_priv *priv,
				    int proto)
{
	struct mlx5_ecn_ctx *ecn_ctx = &priv->ecn_ctx[proto];
	struct mlx5_ecn_enable_ctx *ecn_enable_ctx;
	int i;

	for (i = 0; i < 8; i++) {
		ecn_enable_ctx = &priv->ecn_enable_ctx[proto][i];
		sysfs_remove_file(priv->ecn_ctx[proto].ecn_enable_kobj,
				  &ecn_enable_ctx->enable.attr);
	}

	kobject_put(priv->ecn_ctx[proto].ecn_enable_kobj);

	switch (proto) {
	case MLX5_CON_PROTOCOL_802_1_RP:
		return;
	case MLX5_CON_PROTOCOL_R_ROCE_RP:
		mlx5e_remove_rp_attributes(priv->ecn_ctx[proto].ecn_proto_kobj,
					   &ecn_ctx->ecn_attr.rp_attr);
		break;
	case MLX5_CON_PROTOCOL_R_ROCE_NP:
		mlx5e_remove_np_attributes(priv->ecn_ctx[proto].ecn_proto_kobj,
					   &ecn_ctx->ecn_attr.np_attr);
		break;
	}
}

int mlx5e_sysfs_create(struct net_device *dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	int err = 0;
	int i;

	priv->ecn_root_kobj = kobject_create_and_add("ecn", &dev->dev.kobj);

	for (i = 1; i < MLX5_CONG_PROTOCOL_NUM; i++) {
		priv->ecn_ctx[i].ecn_proto_kobj = kobject_create_and_add(
					     mlx5e_get_cong_protocol(i),
					     priv->ecn_root_kobj);
		mlx5e_fill_attributes(priv, i);
	}

	return err;
}

void mlx5e_sysfs_remove(struct net_device *dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	int i;

	for (i = 1; i < MLX5_CONG_PROTOCOL_NUM; i++) {
		mlx5e_remove_attributes(priv, i);
		kobject_put(priv->ecn_ctx[i].ecn_proto_kobj);
	}

	kobject_put(priv->ecn_root_kobj);
}

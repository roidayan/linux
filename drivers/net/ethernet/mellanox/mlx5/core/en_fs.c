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

#include <linux/list.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/hash.h>
#include <linux/mlx5/fs.h>
#include "en.h"

static int mlx5e_add_l2_flow_rule(struct mlx5e_priv *priv,
				  struct mlx5e_l2_rule *ai, int type);
static void mlx5e_del_l2_flow_rule(struct mlx5e_priv *priv,
				   struct mlx5e_l2_rule *ai);

enum {
	MLX5E_VLAN_FT_LEVEL = 0,
	MLX5E_L2_FT_LEVEL,
	MLX5E_TTC_FT_LEVEL,
	MLX5E_ARFS_FT_LEVEL
};

#define MLX5_SET_CFG(p, f, v) MLX5_SET(create_flow_group_in, p, f, v)

#define mlx5e_for_each_hash_arfs_rule(hn, tmp, hash, i) \
	for (i = 0; i < MLX5E_ARFS_HASH_SIZE; i++) \
		hlist_for_each_entry_safe(hn, tmp, &hash[i], hlist)

enum {
	MLX5E_FULLMATCH = 0,
	MLX5E_ALLMULTI  = 1,
	MLX5E_PROMISC   = 2,
};

enum {
	MLX5E_UC        = 0,
	MLX5E_MC_IPV4   = 1,
	MLX5E_MC_IPV6   = 2,
	MLX5E_MC_OTHER  = 3,
};

enum {
	MLX5E_ACTION_NONE = 0,
	MLX5E_ACTION_ADD  = 1,
	MLX5E_ACTION_DEL  = 2,
};

struct mlx5e_l2_hash_node {
	struct hlist_node          hlist;
	u8                         action;
	struct mlx5e_l2_rule ai;
};

static inline int mlx5e_hash_l2(u8 *addr)
{
	return addr[5];
}

static void mlx5e_add_l2_to_hash(struct hlist_head *hash, u8 *addr)
{
	struct mlx5e_l2_hash_node *hn;
	int ix = mlx5e_hash_l2(addr);
	int found = 0;

	hlist_for_each_entry(hn, &hash[ix], hlist)
		if (ether_addr_equal_64bits(hn->ai.addr, addr)) {
			found = 1;
			break;
		}

	if (found) {
		hn->action = MLX5E_ACTION_NONE;
		return;
	}

	hn = kzalloc(sizeof(*hn), GFP_ATOMIC);
	if (!hn)
		return;

	ether_addr_copy(hn->ai.addr, addr);
	hn->action = MLX5E_ACTION_ADD;

	hlist_add_head(&hn->hlist, &hash[ix]);
}

static void mlx5e_del_l2_from_hash(struct mlx5e_l2_hash_node *hn)
{
	hlist_del(&hn->hlist);
	kfree(hn);
}

static int mlx5e_vport_context_update_vlans(struct mlx5e_priv *priv)
{
	struct net_device *ndev = priv->netdev;
	int max_list_size;
	int list_size;
	u16 *vlans;
	int vlan;
	int err;
	int i;

	list_size = 0;
	for_each_set_bit(vlan, priv->vlan.active_vlans, VLAN_N_VID)
		list_size++;

	max_list_size = 1 << MLX5_CAP_GEN(priv->mdev, log_max_vlan_list);

	if (list_size > max_list_size) {
		netdev_warn(ndev,
			    "netdev vlans list size (%d) > (%d) max vport list size, some vlans will be dropped\n",
			    list_size, max_list_size);
		list_size = max_list_size;
	}

	vlans = kcalloc(list_size, sizeof(*vlans), GFP_KERNEL);
	if (!vlans)
		return -ENOMEM;

	i = 0;
	for_each_set_bit(vlan, priv->vlan.active_vlans, VLAN_N_VID) {
		if (i >= list_size)
			break;
		vlans[i++] = vlan;
	}

	err = mlx5_modify_nic_vport_vlans(priv->mdev, vlans, list_size);
	if (err)
		netdev_err(ndev, "Failed to modify vport vlans list err(%d)\n",
			   err);

	kfree(vlans);
	return err;
}

enum mlx5e_vlan_rule_type {
	MLX5E_VLAN_RULE_TYPE_UNTAGGED,
	MLX5E_VLAN_RULE_TYPE_ANY_VID,
	MLX5E_VLAN_RULE_TYPE_MATCH_VID,
};

static int __mlx5e_add_vlan_rule(struct mlx5e_priv *priv,
				 enum mlx5e_vlan_rule_type rule_type,
				 u16 vid, u32 *mc, u32 *mv)
{
	struct mlx5_flow_table *ft = priv->fs.vlan.t;
	struct mlx5_flow_destination dest;
	u8 match_criteria_enable = 0;
	struct mlx5_flow_rule **rule_p;
	int err = 0;

	dest.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest.ft = priv->fs.l2.ft.t;

	match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;
	MLX5_SET_TO_ONES(fte_match_param, mc, outer_headers.vlan_tag);

	switch (rule_type) {
	case MLX5E_VLAN_RULE_TYPE_UNTAGGED:
		rule_p = &priv->vlan.untagged_rule;
		break;
	case MLX5E_VLAN_RULE_TYPE_ANY_VID:
		rule_p = &priv->vlan.any_vlan_rule;
		MLX5_SET(fte_match_param, mv, outer_headers.vlan_tag, 1);
		break;
	default: /* MLX5E_VLAN_RULE_TYPE_MATCH_VID */
		rule_p = &priv->vlan.active_vlans_rule[vid];
		MLX5_SET(fte_match_param, mv, outer_headers.vlan_tag, 1);
		MLX5_SET_TO_ONES(fte_match_param, mc, outer_headers.first_vid);
		MLX5_SET(fte_match_param, mv, outer_headers.first_vid, vid);
		break;
	}

	*rule_p = mlx5_add_flow_rule(ft, match_criteria_enable, mc, mv,
				     MLX5_FLOW_CONTEXT_ACTION_FWD_DEST,
				     MLX5_FS_DEFAULT_FLOW_TAG,
				     &dest);

	if (IS_ERR(*rule_p)) {
		err = PTR_ERR(*rule_p);
		*rule_p = NULL;
		netdev_err(priv->netdev, "%s: add rule failed\n", __func__);
	}

	return err;
}

static int mlx5e_add_vlan_rule(struct mlx5e_priv *priv,
			       enum mlx5e_vlan_rule_type rule_type, u16 vid)
{
	u32 *match_criteria;
	u32 *match_value;
	int err = 0;

	match_value	= mlx5_vzalloc(MLX5_ST_SZ_BYTES(fte_match_param));
	match_criteria	= mlx5_vzalloc(MLX5_ST_SZ_BYTES(fte_match_param));
	if (!match_value || !match_criteria) {
		netdev_err(priv->netdev, "%s: alloc failed\n", __func__);
		err = -ENOMEM;
		goto add_vlan_rule_out;
	}

	if (rule_type == MLX5E_VLAN_RULE_TYPE_MATCH_VID)
		mlx5e_vport_context_update_vlans(priv);

	err = __mlx5e_add_vlan_rule(priv, rule_type, vid, match_criteria,
				    match_value);

add_vlan_rule_out:
	kvfree(match_criteria);
	kvfree(match_value);

	return err;
}

static void mlx5e_del_vlan_rule(struct mlx5e_priv *priv,
				enum mlx5e_vlan_rule_type rule_type, u16 vid)
{
	switch (rule_type) {
	case MLX5E_VLAN_RULE_TYPE_UNTAGGED:
		if (priv->vlan.untagged_rule) {
			mlx5_del_flow_rule(priv->vlan.untagged_rule);
			priv->vlan.untagged_rule = NULL;
		}
		break;
	case MLX5E_VLAN_RULE_TYPE_ANY_VID:
		if (priv->vlan.any_vlan_rule) {
			mlx5_del_flow_rule(priv->vlan.any_vlan_rule);
			priv->vlan.any_vlan_rule = NULL;
		}
		break;
	case MLX5E_VLAN_RULE_TYPE_MATCH_VID:
		mlx5e_vport_context_update_vlans(priv);
		if (priv->vlan.active_vlans_rule[vid]) {
			mlx5_del_flow_rule(priv->vlan.active_vlans_rule[vid]);
			priv->vlan.active_vlans_rule[vid] = NULL;
		}
		mlx5e_vport_context_update_vlans(priv);
		break;
	}
}

void mlx5e_enable_vlan_filter(struct mlx5e_priv *priv)
{
	if (!priv->vlan.filter_disabled)
		return;

	priv->vlan.filter_disabled = false;
	if (priv->netdev->flags & IFF_PROMISC)
		return;
	mlx5e_del_vlan_rule(priv, MLX5E_VLAN_RULE_TYPE_ANY_VID, 0);
}

void mlx5e_disable_vlan_filter(struct mlx5e_priv *priv)
{
	if (priv->vlan.filter_disabled)
		return;

	priv->vlan.filter_disabled = true;
	if (priv->netdev->flags & IFF_PROMISC)
		return;
	mlx5e_add_vlan_rule(priv, MLX5E_VLAN_RULE_TYPE_ANY_VID, 0);
}

int mlx5e_vlan_rx_add_vid(struct net_device *dev, __always_unused __be16 proto,
			  u16 vid)
{
	struct mlx5e_priv *priv = netdev_priv(dev);

	set_bit(vid, priv->vlan.active_vlans);

	return mlx5e_add_vlan_rule(priv, MLX5E_VLAN_RULE_TYPE_MATCH_VID, vid);
}

int mlx5e_vlan_rx_kill_vid(struct net_device *dev, __always_unused __be16 proto,
			   u16 vid)
{
	struct mlx5e_priv *priv = netdev_priv(dev);

	clear_bit(vid, priv->vlan.active_vlans);

	mlx5e_del_vlan_rule(priv, MLX5E_VLAN_RULE_TYPE_MATCH_VID, vid);

	return 0;
}

#define mlx5e_for_each_hash_node(hn, tmp, hash, i) \
	for (i = 0; i < MLX5E_L2_ADDR_HASH_SIZE; i++) \
		hlist_for_each_entry_safe(hn, tmp, &hash[i], hlist)

static void mlx5e_execute_l2_action(struct mlx5e_priv *priv,
				    struct mlx5e_l2_hash_node *hn)
{
	switch (hn->action) {
	case MLX5E_ACTION_ADD:
		mlx5e_add_l2_flow_rule(priv, &hn->ai, MLX5E_FULLMATCH);
		hn->action = MLX5E_ACTION_NONE;
		break;

	case MLX5E_ACTION_DEL:
		mlx5e_del_l2_flow_rule(priv, &hn->ai);
		mlx5e_del_l2_from_hash(hn);
		break;
	}
}

static void mlx5e_sync_netdev_addr(struct mlx5e_priv *priv)
{
	struct net_device *netdev = priv->netdev;
	struct netdev_hw_addr *ha;

	netif_addr_lock_bh(netdev);

	mlx5e_add_l2_to_hash(priv->fs.l2.netdev_uc,
			     priv->netdev->dev_addr);

	netdev_for_each_uc_addr(ha, netdev)
		mlx5e_add_l2_to_hash(priv->fs.l2.netdev_uc, ha->addr);

	netdev_for_each_mc_addr(ha, netdev)
		mlx5e_add_l2_to_hash(priv->fs.l2.netdev_mc, ha->addr);

	netif_addr_unlock_bh(netdev);
}

static void mlx5e_fill_addr_array(struct mlx5e_priv *priv, int list_type,
				  u8 addr_array[][ETH_ALEN], int size)
{
	bool is_uc = (list_type == MLX5_NVPRT_LIST_TYPE_UC);
	struct net_device *ndev = priv->netdev;
	struct mlx5e_l2_hash_node *hn;
	struct hlist_head *addr_list;
	struct hlist_node *tmp;
	int i = 0;
	int hi;

	addr_list = is_uc ? priv->fs.l2.netdev_uc : priv->fs.l2.netdev_mc;

	if (is_uc) /* Make sure our own address is pushed first */
		ether_addr_copy(addr_array[i++], ndev->dev_addr);
	else if (priv->fs.l2.broadcast_enabled)
		ether_addr_copy(addr_array[i++], ndev->broadcast);

	mlx5e_for_each_hash_node(hn, tmp, addr_list, hi) {
		if (ether_addr_equal(ndev->dev_addr, hn->ai.addr))
			continue;
		if (i >= size)
			break;
		ether_addr_copy(addr_array[i++], hn->ai.addr);
	}
}

static void mlx5e_vport_context_update_addr_list(struct mlx5e_priv *priv,
						 int list_type)
{
	bool is_uc = (list_type == MLX5_NVPRT_LIST_TYPE_UC);
	struct mlx5e_l2_hash_node *hn;
	u8 (*addr_array)[ETH_ALEN] = NULL;
	struct hlist_head *addr_list;
	struct hlist_node *tmp;
	int max_size;
	int size;
	int err;
	int hi;

	size = is_uc ? 0 : (priv->fs.l2.broadcast_enabled ? 1 : 0);
	max_size = is_uc ?
		1 << MLX5_CAP_GEN(priv->mdev, log_max_current_uc_list) :
		1 << MLX5_CAP_GEN(priv->mdev, log_max_current_mc_list);

	addr_list = is_uc ? priv->fs.l2.netdev_uc : priv->fs.l2.netdev_mc;
	mlx5e_for_each_hash_node(hn, tmp, addr_list, hi)
		size++;

	if (size > max_size) {
		netdev_warn(priv->netdev,
			    "netdev %s list size (%d) > (%d) max vport list size, some addresses will be dropped\n",
			    is_uc ? "UC" : "MC", size, max_size);
		size = max_size;
	}

	if (size) {
		addr_array = kcalloc(size, ETH_ALEN, GFP_KERNEL);
		if (!addr_array) {
			err = -ENOMEM;
			goto out;
		}
		mlx5e_fill_addr_array(priv, list_type, addr_array, size);
	}

	err = mlx5_modify_nic_vport_mac_list(priv->mdev, list_type, addr_array, size);
out:
	if (err)
		netdev_err(priv->netdev,
			   "Failed to modify vport %s list err(%d)\n",
			   is_uc ? "UC" : "MC", err);
	kfree(addr_array);
}

static void mlx5e_vport_context_update(struct mlx5e_priv *priv)
{
	struct mlx5e_l2_table *ea = &priv->fs.l2;

	mlx5e_vport_context_update_addr_list(priv, MLX5_NVPRT_LIST_TYPE_UC);
	mlx5e_vport_context_update_addr_list(priv, MLX5_NVPRT_LIST_TYPE_MC);
	mlx5_modify_nic_vport_promisc(priv->mdev, 0,
				      ea->allmulti_enabled,
				      ea->promisc_enabled);
}

static void mlx5e_apply_netdev_addr(struct mlx5e_priv *priv)
{
	struct mlx5e_l2_hash_node *hn;
	struct hlist_node *tmp;
	int i;

	mlx5e_for_each_hash_node(hn, tmp, priv->fs.l2.netdev_uc, i)
		mlx5e_execute_l2_action(priv, hn);

	mlx5e_for_each_hash_node(hn, tmp, priv->fs.l2.netdev_mc, i)
		mlx5e_execute_l2_action(priv, hn);
}

static void mlx5e_handle_netdev_addr(struct mlx5e_priv *priv)
{
	struct mlx5e_l2_hash_node *hn;
	struct hlist_node *tmp;
	int i;

	mlx5e_for_each_hash_node(hn, tmp, priv->fs.l2.netdev_uc, i)
		hn->action = MLX5E_ACTION_DEL;
	mlx5e_for_each_hash_node(hn, tmp, priv->fs.l2.netdev_mc, i)
		hn->action = MLX5E_ACTION_DEL;

	if (!test_bit(MLX5E_STATE_DESTROYING, &priv->state))
		mlx5e_sync_netdev_addr(priv);

	mlx5e_apply_netdev_addr(priv);
}

void mlx5e_set_rx_mode_work(struct work_struct *work)
{
	struct mlx5e_priv *priv = container_of(work, struct mlx5e_priv,
					       set_rx_mode_work);

	struct mlx5e_l2_table *ea = &priv->fs.l2;
	struct net_device *ndev = priv->netdev;

	bool rx_mode_enable   = !test_bit(MLX5E_STATE_DESTROYING, &priv->state);
	bool promisc_enabled   = rx_mode_enable && (ndev->flags & IFF_PROMISC);
	bool allmulti_enabled  = rx_mode_enable && (ndev->flags & IFF_ALLMULTI);
	bool broadcast_enabled = rx_mode_enable;

	bool enable_promisc    = !ea->promisc_enabled   &&  promisc_enabled;
	bool disable_promisc   =  ea->promisc_enabled   && !promisc_enabled;
	bool enable_allmulti   = !ea->allmulti_enabled  &&  allmulti_enabled;
	bool disable_allmulti  =  ea->allmulti_enabled  && !allmulti_enabled;
	bool enable_broadcast  = !ea->broadcast_enabled &&  broadcast_enabled;
	bool disable_broadcast =  ea->broadcast_enabled && !broadcast_enabled;

	if (enable_promisc) {
		mlx5e_add_l2_flow_rule(priv, &ea->promisc, MLX5E_PROMISC);
		if (!priv->vlan.filter_disabled)
			mlx5e_add_vlan_rule(priv, MLX5E_VLAN_RULE_TYPE_ANY_VID,
					    0);
	}
	if (enable_allmulti)
		mlx5e_add_l2_flow_rule(priv, &ea->allmulti, MLX5E_ALLMULTI);
	if (enable_broadcast)
		mlx5e_add_l2_flow_rule(priv, &ea->broadcast, MLX5E_FULLMATCH);

	mlx5e_handle_netdev_addr(priv);

	if (disable_broadcast)
		mlx5e_del_l2_flow_rule(priv, &ea->broadcast);
	if (disable_allmulti)
		mlx5e_del_l2_flow_rule(priv, &ea->allmulti);
	if (disable_promisc) {
		if (!priv->vlan.filter_disabled)
			mlx5e_del_vlan_rule(priv, MLX5E_VLAN_RULE_TYPE_ANY_VID,
					    0);
		mlx5e_del_l2_flow_rule(priv, &ea->promisc);
	}

	ea->promisc_enabled   = promisc_enabled;
	ea->allmulti_enabled  = allmulti_enabled;
	ea->broadcast_enabled = broadcast_enabled;

	mlx5e_vport_context_update(priv);
}

static void mlx5e_destroy_groups(struct mlx5e_flow_table *ft)
{
	int i;

	for (i = ft->num_groups - 1; i >= 0; i--) {
		if (!IS_ERR_OR_NULL(ft->g[i]))
			mlx5_destroy_flow_group(ft->g[i]);
		ft->g[i] = NULL;
	}
	ft->num_groups = 0;
}

void mlx5e_init_l2_addr(struct mlx5e_priv *priv)
{
	ether_addr_copy(priv->fs.l2.broadcast.addr, priv->netdev->broadcast);
}

static void mlx5e_destroy_flow_table(struct mlx5e_flow_table *ft)
{
	mlx5e_destroy_groups(ft);
	kfree(ft->g);
	mlx5_destroy_flow_table(ft->t);
	ft->t = NULL;
}

#if CONFIG_RFS_ACCEL
static void mlx5e_del_arfs_rules(struct mlx5e_priv *priv)
{
	struct mlx5e_arfs_rule *rule;
	struct mlx5e_arfs_rule *tmp;
	LIST_HEAD(del_list);

	spin_lock_bh(&priv->fs.arfs.arfs_lock);
	list_for_each_entry_safe(rule, tmp, &priv->fs.arfs.rules, list) {
		hlist_del(&rule->hlist);
		list_move(&rule->list, &del_list);
	}
	spin_unlock_bh(&priv->fs.arfs.arfs_lock);

	list_for_each_entry_safe(rule, tmp, &del_list, list) {
		cancel_work_sync(&rule->arfs_work);
		if (rule->rule)
			mlx5_del_flow_rule(rule->rule);
		list_del(&rule->list);
		kfree(rule);
	}
}
#endif

static void mlx5e_destroy_arfs_table(struct mlx5e_arfs_table *arfs_t)
{
	mlx5_del_flow_rule(arfs_t->default_rule);
	mlx5e_destroy_flow_table(&arfs_t->ft);
}

static void mlx5e_destroy_arfs_flow_tables(struct mlx5e_priv *priv)
{
	int i;

#if CONFIG_RFS_ACCEL
	mlx5e_del_arfs_rules(priv);
#endif
	flush_workqueue(priv->fs.arfs.workqueue);
	destroy_workqueue(priv->fs.arfs.workqueue);
	for (i = 0; i < MLX5E_ARFS_NUM_TYPES; i++) {
		if (!IS_ERR_OR_NULL(priv->fs.arfs.arfs_tables[i].ft.t))
			mlx5e_destroy_arfs_table(&priv->fs.arfs.arfs_tables[i]);
	}
}

static enum mlx5e_traffic_types mlx5e_get_arfs_tt(enum mlx5e_arfs_type type)
{
	switch (type) {
	case MLX5E_ARFS_IPV4_TCP:
		return MLX5E_TT_IPV4_TCP;
	case MLX5E_ARFS_IPV4_UDP:
		return MLX5E_TT_IPV4_UDP;
	case MLX5E_ARFS_IPV6_TCP:
		return MLX5E_TT_IPV6_TCP;
	case MLX5E_ARFS_IPV6_UDP:
		return MLX5E_TT_IPV6_UDP;
	default:
		return -EINVAL;
	}
}

static int _mlx5e_disable_arfs(struct mlx5e_priv *priv, enum mlx5e_arfs_type
			       num_types)
{
	struct mlx5_flow_destination dest;
	u32 *tirn = priv->indir_tirn;
	int err = 0;
	int tt;
	int i;

	dest.type = MLX5_FLOW_DESTINATION_TYPE_TIR;
	for (i = 0; i < num_types; i++) {
		dest.tir_num = tirn[i];
		tt = mlx5e_get_arfs_tt(i);
		/* Modify ttc rules destination to bypass the aRFS tables*/
		err = mlx5_modify_rule_destination(priv->fs.ttc.rules[tt],
						   &dest);
		if (err) {
			netdev_err(priv->netdev,
				   "%s: modify ttc destination failed\n",
				   __func__);
			return err;
		}
	}
	return 0;
}

int mlx5e_disable_arfs(struct mlx5e_priv *priv)
{
	mlx5e_del_arfs_rules(priv);

	return _mlx5e_disable_arfs(priv, MLX5E_ARFS_NUM_TYPES);
}

int mlx5e_enable_arfs(struct mlx5e_priv *priv)
{
	struct mlx5_flow_destination dest;
	int err = 0;
	int tt;
	int i;

	dest.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	for (i = 0; i < MLX5E_ARFS_NUM_TYPES; i++) {
		dest.ft = priv->fs.arfs.arfs_tables[i].ft.t;
		tt = mlx5e_get_arfs_tt(i);
		/* Modify ttc rules destination to point on the aRFS FTs */
		err = mlx5_modify_rule_destination(priv->fs.ttc.rules[tt],
						   &dest);
		if (err) {
			netdev_err(priv->netdev,
				   "%s: modify ttc destination failed err=%d\n",
				   __func__, err);
			_mlx5e_disable_arfs(priv, i);
			return err;
		}
	}
	return 0;
}

static int mlx5e_add_arfs_default_rule(struct mlx5e_priv *priv,
				       enum mlx5e_arfs_type type)
{
	struct mlx5e_arfs_table *arfs_t = &priv->fs.arfs.arfs_tables[type];
	struct mlx5_flow_destination dest;
	u8 match_criteria_enable = 0;
	u32 *tirn = priv->indir_tirn;
	u32 *match_criteria;
	u32 *match_value;
	int err = 0;

	match_value	= mlx5_vzalloc(MLX5_ST_SZ_BYTES(fte_match_param));
	match_criteria	= mlx5_vzalloc(MLX5_ST_SZ_BYTES(fte_match_param));
	if (!match_value || !match_criteria) {
		netdev_err(priv->netdev, "%s: alloc failed\n", __func__);
		err = -ENOMEM;
		goto out;
	}

	dest.type = MLX5_FLOW_DESTINATION_TYPE_TIR;
	switch (type) {
	case MLX5E_ARFS_IPV4_TCP:
		dest.tir_num = tirn[MLX5E_TT_IPV4_TCP];
		break;
	case MLX5E_ARFS_IPV4_UDP:
		dest.tir_num = tirn[MLX5E_TT_IPV4_UDP];
		break;
	case MLX5E_ARFS_IPV6_TCP:
		dest.tir_num = tirn[MLX5E_TT_IPV6_TCP];
		break;
	case MLX5E_ARFS_IPV6_UDP:
		dest.tir_num = tirn[MLX5E_TT_IPV6_UDP];
		break;
	default:
		err = -EINVAL;
		goto out;
	}

	arfs_t->default_rule = mlx5_add_flow_rule(arfs_t->ft.t, match_criteria_enable,
						  match_criteria, match_value,
						  MLX5_FLOW_CONTEXT_ACTION_FWD_DEST,
						  MLX5_FS_DEFAULT_FLOW_TAG,
						  &dest);
	if (IS_ERR_OR_NULL(arfs_t->default_rule)) {
		err = PTR_ERR(arfs_t->default_rule);
		arfs_t->default_rule = NULL;
		netdev_err(priv->netdev, "%s: add rule failed, arfs type=%d\n",
			   __func__, type);
	}
out:
	kvfree(match_criteria);
	kvfree(match_value);
	return err;
}

#define MLX5E_ARFS_NUM_GROUPS	2
#define MLX5E_ARFS_GROUP1_SIZE	BIT(12)
#define MLX5E_ARFS_GROUP2_SIZE	BIT(0)
#define MLX5E_ARFS_TABLE_SIZE	(MLX5E_ARFS_GROUP1_SIZE +\
				 MLX5E_ARFS_GROUP2_SIZE)
static int mlx5e_create_arfs_groups(struct mlx5e_flow_table *ft,
				    enum  mlx5e_arfs_type type)
{
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	void *outer_headers_c;
	int ix = 0;
	u32 *in;
	int err;
	u8 *mc;

	ft->g = kcalloc(MLX5E_ARFS_NUM_GROUPS,
			sizeof(*ft->g), GFP_KERNEL);
	if (!ft->g)
		return -ENOMEM;
	in = mlx5_vzalloc(inlen);
	if (!in) {
		kfree(ft->g);
		return -ENOMEM;
	}

	mc = MLX5_ADDR_OF(create_flow_group_in, in, match_criteria);
	outer_headers_c = MLX5_ADDR_OF(fte_match_param, mc,
				       outer_headers);
	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c, ethertype);
	switch (type) {
	case MLX5E_ARFS_IPV4_TCP:
	case MLX5E_ARFS_IPV6_TCP:
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c, tcp_dport);
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c, tcp_sport);
		break;
	case MLX5E_ARFS_IPV4_UDP:
	case MLX5E_ARFS_IPV6_UDP:
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c, udp_dport);
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c, udp_sport);
		break;
	default:
		err = -EINVAL;
		goto free;
	}

	switch (type) {
	case MLX5E_ARFS_IPV4_TCP:
	case MLX5E_ARFS_IPV4_UDP:
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c,
				 src_ipv4_src_ipv6.ipv4_layout.ipv4);
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c,
				 dst_ipv4_dst_ipv6.ipv4_layout.ipv4);
		break;
	case MLX5E_ARFS_IPV6_TCP:
	case MLX5E_ARFS_IPV6_UDP:
		memset(MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_headers_c,
				    src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       0xff, 16);
		memset(MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_headers_c,
				    dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       0xff, 16);
		break;
	default:
		err = -EINVAL;
		goto free;
	}

	MLX5_SET_CFG(in, match_criteria_enable, MLX5_MATCH_OUTER_HEADERS);
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5E_ARFS_GROUP1_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	ft->g[ft->num_groups] = mlx5_create_flow_group(ft->t, in);
	if (IS_ERR(ft->g[ft->num_groups]))
		goto err;
	ft->num_groups++;

	memset(in, 0, inlen);
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5E_ARFS_GROUP2_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	ft->g[ft->num_groups] = mlx5_create_flow_group(ft->t, in);
	if (IS_ERR(ft->g[ft->num_groups]))
		goto err;
	ft->num_groups++;

	kvfree(in);
	return 0;

err:
	err = PTR_ERR(ft->g[ft->num_groups]);
	ft->g[ft->num_groups] = NULL;
free:
	kvfree(in);

	return err;
}

static int mlx5e_create_arfs_flow_table(struct mlx5e_priv *priv,
					enum mlx5e_arfs_type type)
{
	struct mlx5e_arfs *arfs = &priv->fs.arfs;
	struct mlx5e_flow_table *ft = &arfs->arfs_tables[type].ft;
	int err;

	ft->t = mlx5_create_flow_table(priv->fs.ns, 0, MLX5E_ARFS_TABLE_SIZE,
				       MLX5E_ARFS_FT_LEVEL);
	if (IS_ERR(ft->t)) {
		err = PTR_ERR(ft->t);
		ft->t = NULL;
		return err;
	}

	err = mlx5e_create_arfs_groups(ft, type);
	if (err)
		goto err;

	err = mlx5e_add_arfs_default_rule(priv, type);
	if (err)
		goto err;

	return 0;
err:
	mlx5e_destroy_flow_table(ft);
	return err;
}

static int mlx5e_create_arfs_flow_tables(struct mlx5e_priv *priv)
{
	int err = 0;
	int i;

	spin_lock_init(&priv->fs.arfs.arfs_lock);
	INIT_LIST_HEAD(&priv->fs.arfs.rules);
	priv->fs.arfs.workqueue = create_singlethread_workqueue("mlx5e_arfs");
	if (!priv->fs.arfs.workqueue)
		return -ENOMEM;

	for (i = 0; i < MLX5E_ARFS_NUM_TYPES; i++) {
		err = mlx5e_create_arfs_flow_table(priv, i);
		if (err)
			goto err;
	}
	return 0;
err:
	mlx5e_destroy_arfs_flow_tables(priv);

	return err;
}

static void mlx5e_clean_ttc_rules(struct mlx5e_ttc *ttc)
{
	int i;

	for (i = 0; i < MLX5E_NUM_TT; i++) {
		if (!IS_ERR_OR_NULL(ttc->rules[i])) {
			mlx5_del_flow_rule(ttc->rules[i]);
			ttc->rules[i] = NULL;
		}
	}
}

static struct {
	u16 etype;
	u8 proto;
} ttc_rules[] = {
	[MLX5E_TT_IPV4_TCP] = {
		.etype = ETH_P_IP,
		.proto = IPPROTO_TCP,
	},
	[MLX5E_TT_IPV6_TCP] = {
		.etype = ETH_P_IPV6,
		.proto = IPPROTO_TCP,
	},
	[MLX5E_TT_IPV4_UDP] = {
		.etype = ETH_P_IP,
		.proto = IPPROTO_UDP,
	},
	[MLX5E_TT_IPV6_UDP] = {
		.etype = ETH_P_IPV6,
		.proto = IPPROTO_UDP,
	},
	[MLX5E_TT_IPV4_IPSEC_AH] = {
		.etype = ETH_P_IP,
		.proto = IPPROTO_AH,
	},
	[MLX5E_TT_IPV6_IPSEC_AH] = {
		.etype = ETH_P_IPV6,
		.proto = IPPROTO_AH,
	},
	[MLX5E_TT_IPV4_IPSEC_ESP] = {
		.etype = ETH_P_IP,
		.proto = IPPROTO_ESP,
	},
	[MLX5E_TT_IPV6_IPSEC_ESP] = {
		.etype = ETH_P_IPV6,
		.proto = IPPROTO_ESP,
	},
	[MLX5E_TT_IPV4] = {
		.etype = ETH_P_IP,
		.proto = 0,
	},
	[MLX5E_TT_IPV6] = {
		.etype = ETH_P_IPV6,
		.proto = 0,
	},
	[MLX5E_TT_ANY] = {
		.etype = 0,
		.proto = 0,
	},
};

static struct mlx5_flow_rule *mlx5e_generate_ttc_rule(struct mlx5e_priv *priv,
						      struct mlx5_flow_table *ft,
						      struct mlx5_flow_destination *dest,
						      u16 etype,
						      u8 proto)
{
	struct mlx5_flow_rule *rule;
	u8 match_criteria_enable = 0;
	u32 *match_criteria;
	u32 *match_value;
	int err = 0;

	match_value	= mlx5_vzalloc(MLX5_ST_SZ_BYTES(fte_match_param));
	match_criteria	= mlx5_vzalloc(MLX5_ST_SZ_BYTES(fte_match_param));
	if (!match_value || !match_criteria) {
		netdev_err(priv->netdev, "%s: alloc failed\n", __func__);
		err = -ENOMEM;
		goto out;
	}

	if (proto) {
		match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;
		MLX5_SET_TO_ONES(fte_match_param, match_criteria, outer_headers.ip_protocol);
		MLX5_SET(fte_match_param, match_value, outer_headers.ip_protocol, proto);
	}
	if (etype) {
		match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;
		MLX5_SET_TO_ONES(fte_match_param, match_criteria, outer_headers.ethertype);
		MLX5_SET(fte_match_param, match_value, outer_headers.ethertype, etype);
	}

	rule = mlx5_add_flow_rule(ft, match_criteria_enable,
				  match_criteria, match_value,
				  MLX5_FLOW_CONTEXT_ACTION_FWD_DEST,
				  MLX5_FS_DEFAULT_FLOW_TAG,
				  dest);
	if (IS_ERR(rule)) {
		err = PTR_ERR(rule);
		netdev_err(priv->netdev, "%s: add rule failed\n", __func__);
	}
out:
	kvfree(match_criteria);
	kvfree(match_value);
	return err ? ERR_PTR(err) : rule;
}

static int mlx5e_generate_ttc_rules(struct mlx5e_priv *priv)
{
	struct mlx5_flow_destination dest;
	struct mlx5e_ttc *ttc;
	struct mlx5_flow_rule **rules;
	struct mlx5_flow_table *ft;
	int tt;
	int err;

	ttc = &priv->fs.ttc;
	ft = ttc->ft.t;
	rules = ttc->rules;

	dest.type = MLX5_FLOW_DESTINATION_TYPE_TIR;
	for (tt = 0; tt < MLX5E_NUM_TT; tt++) {
		if (tt == MLX5E_TT_ANY)
			dest.tir_num = priv->direct_tir[0].tirn;
		else
			dest.tir_num = priv->indir_tirn[tt];
		rules[tt] = mlx5e_generate_ttc_rule(priv, ft, &dest,
						    ttc_rules[tt].etype,
						    ttc_rules[tt].proto);
		if (IS_ERR(rules[tt]))
			goto del_rules;
	}

	return 0;

del_rules:
	err = PTR_ERR(rules[tt]);
	rules[tt] = NULL;
	mlx5e_clean_ttc_rules(ttc);
	return err;
}

#define MLX5E_TTC_NUM_GROUPS	3
#define MLX5E_TTC_GROUP1_SIZE	BIT(3)
#define MLX5E_TTC_GROUP2_SIZE	BIT(1)
#define MLX5E_TTC_GROUP3_SIZE	BIT(0)
#define MLX5E_TTC_TABLE_SIZE	(MLX5E_TTC_GROUP1_SIZE +\
				 MLX5E_TTC_GROUP2_SIZE +\
				 MLX5E_TTC_GROUP3_SIZE)
static int mlx5e_create_ttc_groups(struct mlx5e_flow_table *ft)
{
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	int ix = 0;
	u32 *in;
	int err;
	u8 *mc;

	ft->g = kcalloc(MLX5E_TTC_NUM_GROUPS,
			sizeof(*ft->g), GFP_KERNEL);
	if (!ft->g)
		return -ENOMEM;
	in = mlx5_vzalloc(inlen);
	if (!in) {
		kfree(ft->g);
		return -ENOMEM;
	}

	mc = MLX5_ADDR_OF(create_flow_group_in, in, match_criteria);
	MLX5_SET_TO_ONES(fte_match_param, mc, outer_headers.ip_protocol);
	MLX5_SET_TO_ONES(fte_match_param, mc, outer_headers.ethertype);
	MLX5_SET_CFG(in, match_criteria_enable, MLX5_MATCH_OUTER_HEADERS);
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5E_TTC_GROUP1_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	ft->g[ft->num_groups] = mlx5_create_flow_group(ft->t, in);
	if (IS_ERR(ft->g[ft->num_groups]))
		goto err;
	ft->num_groups++;

	MLX5_SET(fte_match_param, mc, outer_headers.ip_protocol, 0);
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5E_TTC_GROUP2_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	ft->g[ft->num_groups] = mlx5_create_flow_group(ft->t, in);
	if (IS_ERR(ft->g[ft->num_groups]))
		goto err;
	ft->num_groups++;

	memset(in, 0, inlen);
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5E_TTC_GROUP3_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	ft->g[ft->num_groups] = mlx5_create_flow_group(ft->t, in);
	if (IS_ERR(ft->g[ft->num_groups]))
		goto err;
	ft->num_groups++;

	kvfree(in);
	return 0;

err:
	err = PTR_ERR(ft->g[ft->num_groups]);
	ft->g[ft->num_groups] = NULL;
	kvfree(in);

	return err;
}

static void mlx5e_destroy_ttc_flow_table(struct mlx5e_priv *priv)
{
	struct mlx5e_ttc *ttc = &priv->fs.ttc;

	mlx5e_clean_ttc_rules(ttc);
	mlx5e_destroy_flow_table(&ttc->ft);
}

static int mlx5e_create_ttc_flow_table(struct mlx5e_priv *priv)
{
	struct mlx5e_ttc *ttc = &priv->fs.ttc;
	struct mlx5e_flow_table *ft = &ttc->ft;
	int err;

	ft->t = mlx5_create_flow_table(priv->fs.ns, 0, MLX5E_TTC_TABLE_SIZE,
				       MLX5E_TTC_FT_LEVEL);
	if (IS_ERR(ft->t)) {
		err = PTR_ERR(ft->t);
		ft->t = NULL;
		return err;
	}

	err = mlx5e_create_ttc_groups(ft);
	if (err)
		goto err;

	err = mlx5e_generate_ttc_rules(priv);
	if (err)
		goto err;

	return 0;
err:
	mlx5e_destroy_flow_table(ft);
	return err;
}

static void mlx5e_del_l2_flow_rule(struct mlx5e_priv *priv,
				   struct mlx5e_l2_rule *ai)
{
	mlx5_del_flow_rule(ai->rule);
}

static int __mlx5e_add_l2_flow_rule(struct mlx5e_priv *priv,
				    struct mlx5e_l2_rule *ai,
				    int type, u32 *mc, u32 *mv)
{
	struct mlx5_flow_destination dest;
	u8 match_criteria_enable = 0;
	struct mlx5_flow_table *ft = priv->fs.l2.ft.t;
	u8 *mc_dmac = MLX5_ADDR_OF(fte_match_param, mc,
				   outer_headers.dmac_47_16);
	u8 *mv_dmac = MLX5_ADDR_OF(fte_match_param, mv,
				   outer_headers.dmac_47_16);
	int err = 0;

	dest.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest.ft = priv->fs.ttc.ft.t;

	switch (type) {
	case MLX5E_FULLMATCH:
		match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;
		eth_broadcast_addr(mc_dmac);
		ether_addr_copy(mv_dmac, ai->addr);
		break;

	case MLX5E_ALLMULTI:
		match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;
		mc_dmac[0] = 0x01;
		mv_dmac[0] = 0x01;
		break;

	case MLX5E_PROMISC:
		break;
	}

	ai->rule = mlx5_add_flow_rule(ft, match_criteria_enable, mc, mv,
				      MLX5_FLOW_CONTEXT_ACTION_FWD_DEST,
				      MLX5_FS_DEFAULT_FLOW_TAG, &dest);
	if (IS_ERR_OR_NULL(ai->rule)) {
		err = PTR_ERR(ai->rule);
		ai->rule = NULL;
		return err;
	}

	return 0;
}

static int mlx5e_add_l2_flow_rule(struct mlx5e_priv *priv,
				  struct mlx5e_l2_rule *ai, int type)
{
	u32 *match_criteria;
	u32 *match_value;
	int err = 0;

	match_value    = mlx5_vzalloc(MLX5_ST_SZ_BYTES(fte_match_param));
	match_criteria = mlx5_vzalloc(MLX5_ST_SZ_BYTES(fte_match_param));
	if (!match_value || !match_criteria) {
		netdev_err(priv->netdev, "%s: alloc failed\n", __func__);
		err = -ENOMEM;
		goto add_l2_rule_out;
	}

	err = __mlx5e_add_l2_flow_rule(priv, ai, type, match_criteria,
				       match_value);

add_l2_rule_out:
	kvfree(match_criteria);
	kvfree(match_value);

	return err;
}

#define MLX5E_NUM_L2_GROUPS	   3
#define MLX5E_L2_GROUP1_SIZE	   BIT(0)
#define MLX5E_L2_GROUP2_SIZE	   BIT(15)
#define MLX5E_L2_GROUP3_SIZE	   BIT(0)
#define MLX5E_L2_TABLE_SIZE	   (MLX5E_L2_GROUP1_SIZE +\
				    MLX5E_L2_GROUP2_SIZE +\
				    MLX5E_L2_GROUP3_SIZE)
static int mlx5e_create_l2_groups(struct mlx5e_flow_table *ft)
{
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	int ix = 0;
	u8 *mc_dmac;
	u32 *in;
	int err;
	u8 *mc;

	ft->g = kcalloc(MLX5E_NUM_L2_GROUPS, sizeof(*ft->g), GFP_KERNEL);
	if (!ft->g)
		return -ENOMEM;
	in = mlx5_vzalloc(inlen);
	if (!in) {
		kfree(ft->g);
		return -ENOMEM;
	}

	mc = MLX5_ADDR_OF(create_flow_group_in, in, match_criteria);
	mc_dmac = MLX5_ADDR_OF(fte_match_param, mc,
			       outer_headers.dmac_47_16);
	/* Flow Group for promiscuous */
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5E_L2_GROUP1_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	ft->g[ft->num_groups] = mlx5_create_flow_group(ft->t, in);
	if (IS_ERR(ft->g[ft->num_groups]))
		goto err_destroy_groups;
	ft->num_groups++;

	/* Flow Group for full match */
	eth_broadcast_addr(mc_dmac);
	MLX5_SET_CFG(in, match_criteria_enable, MLX5_MATCH_OUTER_HEADERS);
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5E_L2_GROUP2_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	ft->g[ft->num_groups] = mlx5_create_flow_group(ft->t, in);
	if (IS_ERR(ft->g[ft->num_groups]))
		goto err_destroy_groups;
	ft->num_groups++;

	/* Flow Group for allmulti */
	eth_zero_addr(mc_dmac);
	mc_dmac[0] = 0x01;
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5E_L2_GROUP3_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	ft->g[ft->num_groups] = mlx5_create_flow_group(ft->t, in);
	if (IS_ERR(ft->g[ft->num_groups]))
		goto err_destroy_groups;
	ft->num_groups++;

	kvfree(in);
	return 0;

err_destroy_groups:
	err = PTR_ERR(ft->g[ft->num_groups]);
	ft->g[ft->num_groups] = NULL;
	mlx5e_destroy_groups(ft);
	kvfree(in);

	return err;
}

static void mlx5e_destroy_l2_flow_table(struct mlx5e_priv *priv)
{
	mlx5e_destroy_flow_table(&priv->fs.l2.ft);
}

static int mlx5e_create_l2_flow_table(struct mlx5e_priv *priv)
{
	struct mlx5e_flow_table *ft = &priv->fs.l2.ft;
	int err;

	ft->num_groups = 0;
	ft->t = mlx5_create_flow_table(priv->fs.ns, 0, MLX5E_L2_TABLE_SIZE,
				       MLX5E_L2_FT_LEVEL);

	if (IS_ERR(ft->t)) {
		err = PTR_ERR(ft->t);
		ft->t = NULL;
		return err;
	}

	err = mlx5e_create_l2_groups(ft);
	if (err)
		goto err_destroy_flow_table;

	return 0;

err_destroy_flow_table:
	mlx5_destroy_flow_table(ft->t);
	ft->t = NULL;

	return err;
}

#define MLX5E_NUM_VLAN_GROUPS	2
#define MLX5E_VLAN_GROUP0_SIZE	BIT(12)
#define MLX5E_VLAN_GROUP1_SIZE	BIT(1)
#define MLX5E_VLAN_TABLE_SIZE	(MLX5E_VLAN_GROUP0_SIZE +\
				 MLX5E_VLAN_GROUP1_SIZE)

static int __mlx5e_create_vlan_groups(struct mlx5e_flow_table *ft, u32 *in,
				      int inlen)
{
	int err;
	int ix = 0;
	u8 *mc = MLX5_ADDR_OF(create_flow_group_in, in, match_criteria);

	memset(in, 0, inlen);
	MLX5_SET_CFG(in, match_criteria_enable, MLX5_MATCH_OUTER_HEADERS);
	MLX5_SET_TO_ONES(fte_match_param, mc, outer_headers.vlan_tag);
	MLX5_SET_TO_ONES(fte_match_param, mc, outer_headers.first_vid);
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5E_VLAN_GROUP0_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	ft->g[ft->num_groups] = mlx5_create_flow_group(ft->t, in);
	if (IS_ERR(ft->g[ft->num_groups]))
		goto err_destroy_groups;
	ft->num_groups++;

	memset(in, 0, inlen);
	MLX5_SET_CFG(in, match_criteria_enable, MLX5_MATCH_OUTER_HEADERS);
	MLX5_SET_TO_ONES(fte_match_param, mc, outer_headers.vlan_tag);
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5E_VLAN_GROUP1_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	ft->g[ft->num_groups] = mlx5_create_flow_group(ft->t, in);
	if (IS_ERR(ft->g[ft->num_groups]))
		goto err_destroy_groups;
	ft->num_groups++;

	return 0;

err_destroy_groups:
	err = PTR_ERR(ft->g[ft->num_groups]);
	ft->g[ft->num_groups] = NULL;
	mlx5e_destroy_groups(ft);

	return err;
}

static int mlx5e_create_vlan_groups(struct mlx5e_flow_table *ft)
{
	u32 *in;
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	int err;

	in = mlx5_vzalloc(inlen);
	if (!in)
		return -ENOMEM;

	err = __mlx5e_create_vlan_groups(ft, in, inlen);

	kvfree(in);
	return err;
}

static int mlx5e_create_vlan_flow_table(struct mlx5e_priv *priv)
{
	struct mlx5e_flow_table *ft = &priv->fs.vlan;
	int err;

	ft->num_groups = 0;
	ft->t = mlx5_create_flow_table(priv->fs.ns, 0, MLX5E_VLAN_TABLE_SIZE,
				       MLX5E_VLAN_FT_LEVEL);

	if (IS_ERR(ft->t)) {
		err = PTR_ERR(ft->t);
		ft->t = NULL;
		return err;
	}
	ft->g = kcalloc(MLX5E_NUM_VLAN_GROUPS, sizeof(*ft->g), GFP_KERNEL);
	if (!ft->g) {
		err = -ENOMEM;
		goto err_destroy_vlan_flow_table;
	}

	err = mlx5e_create_vlan_groups(ft);
	if (err)
		goto err_free_g;

	err = mlx5e_add_vlan_rule(priv, MLX5E_VLAN_RULE_TYPE_UNTAGGED, 0);
	if (err)
		goto err_destroy_vlan_flow_groups;

	return 0;

err_destroy_vlan_flow_groups:
	mlx5e_destroy_groups(ft);
err_free_g:
	kfree(ft->g);
err_destroy_vlan_flow_table:
	mlx5_destroy_flow_table(ft->t);
	ft->t = NULL;

	return err;
}

static void mlx5e_destroy_vlan_flow_table(struct mlx5e_priv *priv)
{
	mlx5e_destroy_flow_table(&priv->fs.vlan);
}

int mlx5e_create_flow_tables(struct mlx5e_priv *priv)
{
	int err;

	priv->fs.ns = mlx5_get_flow_namespace(priv->mdev,
					       MLX5_FLOW_NAMESPACE_KERNEL);

	if (!priv->fs.ns)
		return -EINVAL;

	err = mlx5e_create_arfs_flow_tables(priv);
	if (err)
		return err;

	err = mlx5e_create_ttc_flow_table(priv);
	if (err)
		goto err_destroy_arfs_flow_tables;

	err = mlx5e_create_l2_flow_table(priv);
	if (err)
		goto err_destroy_ttc_flow_table;

	err = mlx5e_create_vlan_flow_table(priv);
	if (err)
		goto err_destroy_l2_flow_table;

	return 0;

err_destroy_l2_flow_table:
	mlx5e_destroy_l2_flow_table(priv);
err_destroy_ttc_flow_table:
	mlx5e_destroy_ttc_flow_table(priv);
err_destroy_arfs_flow_tables:
	mlx5e_destroy_arfs_flow_tables(priv);

	return err;
}

void mlx5e_destroy_flow_tables(struct mlx5e_priv *priv)
{
	mlx5e_del_vlan_rule(priv, MLX5E_VLAN_RULE_TYPE_UNTAGGED, 0);
	mlx5e_destroy_vlan_flow_table(priv);
	mlx5e_destroy_l2_flow_table(priv);
	mlx5e_destroy_ttc_flow_table(priv);
	mlx5e_destroy_arfs_flow_tables(priv);
}

#if CONFIG_RFS_ACCEL
static struct hlist_head *
arfs_hash_bucket(struct mlx5e_arfs_table *arfs_t, __be16 src_port,
		 __be16 dst_port)
{
	unsigned long l;
	int bucket_idx;

	l = (__force unsigned long)src_port |
	    ((__force unsigned long)dst_port << 2);

	bucket_idx = hash_long(l, MLX5E_ARFS_HASH_SHIFT);

	return &arfs_t->rules_hash[bucket_idx];
}

static u8 mlx5e_get_ip_proto(const struct sk_buff *skb)
{
	return (skb->protocol == htons(ETH_P_IP)) ?
		ip_hdr(skb)->protocol : ipv6_hdr(skb)->nexthdr;
}

static struct mlx5e_arfs_table *get_arfs_table(struct mlx5e_arfs *arfs,
					       u8 ip_proto, __be16 etype)
{
	if (etype == htons(ETH_P_IP) && ip_proto == IPPROTO_TCP)
		return &arfs->arfs_tables[MLX5E_ARFS_IPV4_TCP];
	if (etype == htons(ETH_P_IP) && ip_proto == IPPROTO_UDP)
		return &arfs->arfs_tables[MLX5E_ARFS_IPV4_UDP];
	if (etype == htons(ETH_P_IPV6) && ip_proto == IPPROTO_TCP)
		return &arfs->arfs_tables[MLX5E_ARFS_IPV6_TCP];
	if (etype == htons(ETH_P_IPV6) && ip_proto == IPPROTO_UDP)
		return &arfs->arfs_tables[MLX5E_ARFS_IPV6_UDP];

	return NULL;
}

static struct mlx5_flow_rule *mlx5e_add_arfs_rule(struct mlx5e_priv *priv,
						  struct mlx5e_arfs_rule *arfs_rule)
{
	struct mlx5e_tuple *tuple = &arfs_rule->tuple;
	struct mlx5e_arfs *arfs = &priv->fs.arfs;
	struct mlx5_flow_destination dest;
	struct mlx5_flow_rule *rule = NULL;
	u8 match_criteria_enable = 0;
	struct mlx5e_arfs_table *arfs_table;
	struct mlx5_flow_table *ft;
	u32 *match_criteria;
	u32 *match_value;
	int err = 0;

	match_value	= mlx5_vzalloc(MLX5_ST_SZ_BYTES(fte_match_param));
	match_criteria	= mlx5_vzalloc(MLX5_ST_SZ_BYTES(fte_match_param));
	if (!match_value || !match_criteria) {
		netdev_err(priv->netdev, "%s: alloc failed\n", __func__);
		err = -ENOMEM;
		goto out;
	}

	match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;
	MLX5_SET_TO_ONES(fte_match_param, match_criteria,
			 outer_headers.ethertype);
	MLX5_SET(fte_match_param, match_value, outer_headers.ethertype,
		 ntohs(tuple->etype));
	arfs_table = get_arfs_table(arfs, tuple->ip_proto, tuple->etype);
	ft = arfs_table->ft.t;
	if (tuple->ip_proto == IPPROTO_TCP) {
		MLX5_SET_TO_ONES(fte_match_param, match_criteria,
				 outer_headers.tcp_dport);
		MLX5_SET_TO_ONES(fte_match_param, match_criteria,
				 outer_headers.tcp_sport);
		MLX5_SET(fte_match_param, match_value, outer_headers.tcp_dport,
			 ntohs(tuple->dst_port));
		MLX5_SET(fte_match_param, match_value, outer_headers.tcp_sport,
			 ntohs(tuple->src_port));
	} else {
		MLX5_SET_TO_ONES(fte_match_param, match_criteria,
				 outer_headers.udp_dport);
		MLX5_SET_TO_ONES(fte_match_param, match_criteria,
				 outer_headers.udp_sport);
		MLX5_SET(fte_match_param, match_value, outer_headers.udp_dport,
			 ntohs(tuple->dst_port));
		MLX5_SET(fte_match_param, match_value, outer_headers.udp_sport,
			 ntohs(tuple->src_port));
	}
	if (tuple->etype == htons(ETH_P_IP)) {
		memcpy(MLX5_ADDR_OF(fte_match_param, match_value,
				    outer_headers.src_ipv4_src_ipv6.ipv4_layout.ipv4),
		       &tuple->src_ipv4,
		       4);
		memcpy(MLX5_ADDR_OF(fte_match_param, match_value,
				    outer_headers.dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
		       &tuple->dst_ipv4,
		       4);
		MLX5_SET_TO_ONES(fte_match_param, match_criteria,
				 outer_headers.src_ipv4_src_ipv6.ipv4_layout.ipv4);
		MLX5_SET_TO_ONES(fte_match_param, match_criteria,
				 outer_headers.dst_ipv4_dst_ipv6.ipv4_layout.ipv4);
	} else {
		memcpy(MLX5_ADDR_OF(fte_match_param, match_value,
				    outer_headers.src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       &tuple->src_ipv6,
		       16);
		memcpy(MLX5_ADDR_OF(fte_match_param, match_value,
				    outer_headers.dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       &tuple->dst_ipv6,
		       16);
		memset(MLX5_ADDR_OF(fte_match_param, match_criteria,
				    outer_headers.src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       0xff,
		       16);
		memset(MLX5_ADDR_OF(fte_match_param, match_criteria,
				    outer_headers.dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       0xff,
		       16);
	}
	dest.type = MLX5_FLOW_DESTINATION_TYPE_TIR;
	dest.tir_num = priv->direct_tir[arfs_rule->rxq_index].tirn;
	rule = mlx5_add_flow_rule(ft, match_criteria_enable, match_criteria,
				  match_value, MLX5_FLOW_CONTEXT_ACTION_FWD_DEST,
				  MLX5_FS_DEFAULT_FLOW_TAG,
				  &dest);
	if (IS_ERR(rule)) {
		err = PTR_ERR(rule);
		netdev_err(priv->netdev, "%s: add rule failed, err=%d\n",
			   __func__, err);
	}

out:
	kvfree(match_criteria);
	kvfree(match_value);
	return err ? ERR_PTR(err) : rule;
}

#define MLX5E_ARFS_EXPIRY_QUOTA 60

static void mlx5e_may_expire_flow(struct mlx5e_priv *priv)
{
	struct mlx5e_arfs_rule *rule;
	struct mlx5e_arfs_rule *tmp;
	int i = 0;
	LIST_HEAD(del_list);

	spin_lock_bh(&priv->fs.arfs.arfs_lock);
	list_for_each_entry_safe(rule, tmp, &priv->fs.arfs.rules, list) {
		if (i++ > MLX5E_ARFS_EXPIRY_QUOTA)
			break;
		if (!work_pending(&rule->arfs_work) &&
		    rps_may_expire_flow(priv->netdev,
					rule->rxq_index, rule->flow_id,
					rule->filter_id)) {
			hlist_del(&rule->hlist);
			list_move(&rule->list, &del_list);
		}
	}
	spin_unlock_bh(&priv->fs.arfs.arfs_lock);
	list_for_each_entry_safe(rule, tmp, &del_list, list) {
		if (rule->rule)
			mlx5_del_flow_rule(rule->rule);
		list_del(&rule->list);
		kfree(rule);
	}
}

static void mlx5e_modify_arfs_rule_rq(struct mlx5e_priv *priv,
				      struct mlx5_flow_rule *rule, u16 rxq_index)
{
	struct mlx5_flow_destination dst;
	int err = 0;

	dst.type = MLX5_FLOW_DESTINATION_TYPE_TIR;
	dst.tir_num = priv->direct_tir[rxq_index].tirn;
	err =  mlx5_modify_rule_destination(rule, &dst);
	if (err)
		netdev_warn(priv->netdev,
			    "Failed to modfiy aRFS destination\n");
}

static void mlx5e_handle_arfs_work(struct work_struct *work)
{
	struct mlx5e_arfs_rule *arfs_rule = container_of(work,
							 struct mlx5e_arfs_rule,
							 arfs_work);
	struct mlx5e_priv *priv = arfs_rule->priv;
	struct mlx5_flow_rule *rule;

	if (!arfs_rule->rule) {
		rule = mlx5e_add_arfs_rule(priv, arfs_rule);
		if (IS_ERR(rule)) {
			rule = NULL;
			goto out;
		}
		arfs_rule->rule = rule;
	} else {
		mlx5e_modify_arfs_rule_rq(priv, arfs_rule->rule,
					  arfs_rule->rxq_index);
	}
out:
	mlx5e_may_expire_flow(priv);
}

/* return L4 destination port from ip4/6 packets */
static __be16 mlx5e_get_dst_port(const struct sk_buff *skb)
{
	char *transport_header;

	transport_header = skb_transport_header(skb);
	if (mlx5e_get_ip_proto(skb) == IPPROTO_TCP)
		return ((struct tcphdr *)transport_header)->dest;
	return ((struct udphdr *)transport_header)->dest;
}

/* return L4 source port from ip4/6 packets */
static __be16 mlx5e_get_src_port(const struct sk_buff *skb)
{
	char *transport_header;

	transport_header = skb_transport_header(skb);
	if (mlx5e_get_ip_proto(skb) == IPPROTO_TCP)
		return ((struct tcphdr *)transport_header)->source;
	return ((struct udphdr *)transport_header)->source;
}

static struct mlx5e_arfs_rule *mlx5e_alloc_arfs_rule(struct mlx5e_priv *priv,
						     struct mlx5e_arfs_table *arfs_t,
						     const struct sk_buff *skb,
						     u16 rxq_index, u32 flow_id)
{
	struct mlx5e_arfs_rule *rule;
	struct mlx5e_tuple *tuple;

	rule = kzalloc(sizeof(*rule), GFP_ATOMIC);
	if (!rule)
		return NULL;

	rule->priv = priv;
	rule->rxq_index = rxq_index;
	INIT_WORK(&rule->arfs_work, mlx5e_handle_arfs_work);

	tuple = &rule->tuple;
	tuple->etype = skb->protocol;
	if (tuple->etype == htons(ETH_P_IP)) {
		tuple->src_ipv4 = ip_hdr(skb)->saddr;
		tuple->dst_ipv4 = ip_hdr(skb)->daddr;
	} else {
		memcpy(&tuple->src_ipv6, &ipv6_hdr(skb)->saddr,
		       sizeof(struct in6_addr));
		memcpy(&tuple->dst_ipv6, &ipv6_hdr(skb)->daddr,
		       sizeof(struct in6_addr));
	}
	tuple->ip_proto = mlx5e_get_ip_proto(skb);
	tuple->src_port = mlx5e_get_src_port(skb);
	tuple->dst_port = mlx5e_get_dst_port(skb);

	rule->flow_id = flow_id;
	rule->filter_id = priv->fs.arfs.last_filter_id++ % RPS_NO_FILTER;

	hlist_add_head(&rule->hlist,
		       arfs_hash_bucket(arfs_t, tuple->src_port,
					tuple->dst_port));
	list_add_tail(&rule->list, &priv->fs.arfs.rules);

	return rule;
}

static bool mlx5e_cmp_ips(struct mlx5e_tuple *tuple,
			  const struct sk_buff *skb)
{
	if (tuple->etype == htons(ETH_P_IP) &&
	    tuple->src_ipv4 == ip_hdr(skb)->saddr &&
	    tuple->dst_ipv4 == ip_hdr(skb)->daddr)
		return true;
	else  if (tuple->etype == htons(ETH_P_IPV6) &&
		  (!memcmp(&tuple->src_ipv6, &ipv6_hdr(skb)->saddr,
			   sizeof(struct in6_addr))) &&
		  (!memcmp(&tuple->dst_ipv6, &ipv6_hdr(skb)->daddr,
			   sizeof(struct in6_addr))))
		return true;
	return false;
}

static struct mlx5e_arfs_rule *mlx5e_find_arfs_rule(struct mlx5e_arfs_table *arfs_t,
						    const struct sk_buff *skb)
{
	struct mlx5e_arfs_rule *arfs_rule;
	struct hlist_head *head;
	__be16 src_port = mlx5e_get_src_port(skb);
	__be16 dst_port = mlx5e_get_dst_port(skb);

	head = arfs_hash_bucket(arfs_t, src_port, dst_port);
	hlist_for_each_entry(arfs_rule, head, hlist) {
		if (arfs_rule->tuple.src_port == src_port &&
		    arfs_rule->tuple.dst_port == dst_port &&
		    mlx5e_cmp_ips(&arfs_rule->tuple, skb)) {
			return arfs_rule;
		}
	}

	return NULL;
}

int mlx5e_rx_flow_steer(struct net_device *dev, const struct sk_buff *skb,
			u16 rxq_index, u32 flow_id)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5e_arfs *arfs = &priv->fs.arfs;
	struct mlx5e_arfs_table *arfs_t;
	struct mlx5e_arfs_rule *arfs_rule;

	if (skb->protocol == htons(ETH_P_IP) &&
	    skb->protocol == htons(ETH_P_IPV6))
		return -EPROTONOSUPPORT;

	arfs_t = get_arfs_table(arfs, mlx5e_get_ip_proto(skb), skb->protocol);
	if (!arfs_t)
		return -EPROTONOSUPPORT;

	spin_lock_bh(&arfs->arfs_lock);
	arfs_rule = mlx5e_find_arfs_rule(arfs_t, skb);
	if (arfs_rule) {
		if (arfs_rule->rxq_index == rxq_index) {
			spin_unlock_bh(&arfs->arfs_lock);
			return arfs_rule->filter_id;
		}
		arfs_rule->rxq_index = rxq_index;
	} else {
		arfs_rule = mlx5e_alloc_arfs_rule(priv, arfs_t, skb,
						  rxq_index, flow_id);
		if (!arfs_rule) {
			spin_unlock_bh(&arfs->arfs_lock);
			return -ENOMEM;
		}
	}
	queue_work(priv->fs.arfs.workqueue, &arfs_rule->arfs_work);
	spin_unlock_bh(&arfs->arfs_lock);
	return arfs_rule->filter_id;
}
#endif

/*
 * Copyright (c) 2016, Mellanox Technologies. All rights reserved.
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

#include <generated/utsrelease.h>
#include <linux/mlx5/fs.h>
#include <net/switchdev.h>
#include <net/pkt_cls.h>
#include <net/netevent.h>
#include <net/arp.h>

#include "eswitch.h"
#include "en.h"
#include "en_tc.h"

static const char mlx5e_rep_driver_name[] = "mlx5e_rep";

static void mlx5e_rep_get_drvinfo(struct net_device *dev,
				  struct ethtool_drvinfo *drvinfo)
{
	strlcpy(drvinfo->driver, mlx5e_rep_driver_name,
		sizeof(drvinfo->driver));
	strlcpy(drvinfo->version, UTS_RELEASE, sizeof(drvinfo->version));
}

static const struct counter_desc sw_rep_stats_desc[] = {
	{ MLX5E_DECLARE_STAT(struct mlx5e_sw_stats, rx_packets) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_sw_stats, rx_bytes) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_sw_stats, tx_packets) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_sw_stats, tx_bytes) },
};

#define NUM_VPORT_REP_COUNTERS	ARRAY_SIZE(sw_rep_stats_desc)

static void mlx5e_rep_get_strings(struct net_device *dev,
				  u32 stringset, uint8_t *data)
{
	int i;

	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < NUM_VPORT_REP_COUNTERS; i++)
			strcpy(data + (i * ETH_GSTRING_LEN),
			       sw_rep_stats_desc[i].format);
		break;
	}
}

static void mlx5e_rep_update_hw_counters(struct mlx5e_priv *priv)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5_eswitch_rep *rep = priv->ppriv;
	struct rtnl_link_stats64 *vport_stats;
	struct ifla_vf_stats vf_stats;
	int err;

	err = mlx5_eswitch_get_vport_stats(esw, rep->vport, &vf_stats);
	if (err) {
		pr_warn("vport %d error %d reading stats\n", rep->vport, err);
		return;
	}

	vport_stats = &priv->stats.vf_vport;
	/* flip tx/rx as we are reporting the counters for the switch vport */
	vport_stats->rx_packets = vf_stats.tx_packets;
	vport_stats->rx_bytes   = vf_stats.tx_bytes;
	vport_stats->tx_packets = vf_stats.rx_packets;
	vport_stats->tx_bytes   = vf_stats.rx_bytes;
}

static void mlx5e_rep_update_sw_counters(struct mlx5e_priv *priv)
{
	struct mlx5e_sw_stats *s = &priv->stats.sw;
	struct mlx5e_rq_stats *rq_stats;
	struct mlx5e_sq_stats *sq_stats;
	int i, j;

	memset(s, 0, sizeof(*s));
	for (i = 0; i < priv->params.num_channels; i++) {
		rq_stats = &priv->channel[i]->rq.stats;

		s->rx_packets	+= rq_stats->packets;
		s->rx_bytes	+= rq_stats->bytes;

		for (j = 0; j < priv->params.num_tc; j++) {
			sq_stats = &priv->channel[i]->sq[j].stats;

			s->tx_packets		+= sq_stats->packets;
			s->tx_bytes		+= sq_stats->bytes;
		}
	}
}

static void mlx5e_rep_update_stats(struct mlx5e_priv *priv)
{
	mlx5e_rep_update_sw_counters(priv);
	mlx5e_rep_update_hw_counters(priv);
}

static void mlx5e_rep_get_ethtool_stats(struct net_device *dev,
					struct ethtool_stats *stats, u64 *data)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	int i;

	if (!data)
		return;

	mutex_lock(&priv->state_lock);
	if (test_bit(MLX5E_STATE_OPENED, &priv->state))
		mlx5e_rep_update_sw_counters(priv);
	mutex_unlock(&priv->state_lock);

	for (i = 0; i < NUM_VPORT_REP_COUNTERS; i++)
		data[i] = MLX5E_READ_CTR64_CPU(&priv->stats.sw,
					       sw_rep_stats_desc, i);
}

static int mlx5e_rep_get_sset_count(struct net_device *dev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return NUM_VPORT_REP_COUNTERS;
	default:
		return -EOPNOTSUPP;
	}
}

static const struct ethtool_ops mlx5e_rep_ethtool_ops = {
	.get_drvinfo	   = mlx5e_rep_get_drvinfo,
	.get_link	   = ethtool_op_get_link,
	.get_strings       = mlx5e_rep_get_strings,
	.get_sset_count    = mlx5e_rep_get_sset_count,
	.get_ethtool_stats = mlx5e_rep_get_ethtool_stats,
};

int mlx5e_attr_get(struct net_device *dev, struct switchdev_attr *attr)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_eswitch_rep *rep = priv->ppriv;
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;

	if (esw->mode == SRIOV_NONE)
		return -EOPNOTSUPP;

	switch (attr->id) {
	case SWITCHDEV_ATTR_ID_PORT_PARENT_ID:
		attr->u.ppid.id_len = ETH_ALEN;
		ether_addr_copy(attr->u.ppid.id, rep->hw_id);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

int mlx5e_add_sqs_fwd_rules(struct mlx5e_priv *priv)

{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5_eswitch_rep *rep = priv->ppriv;
	struct mlx5e_channel *c;
	int n, tc, err, num_sqs = 0;
	u16 *sqs;

	sqs = kcalloc(priv->params.num_channels * priv->params.num_tc, sizeof(u16), GFP_KERNEL);
	if (!sqs)
		return -ENOMEM;

	for (n = 0; n < priv->params.num_channels; n++) {
		c = priv->channel[n];
		for (tc = 0; tc < c->num_tc; tc++)
			sqs[num_sqs++] = c->sq[tc].sqn;
	}

	err = mlx5_eswitch_sqs2vport_start(esw, rep, sqs, num_sqs);

	kfree(sqs);
	return err;
}

void mlx5e_remove_sqs_fwd_rules(struct mlx5e_priv *priv)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5_eswitch_rep *rep = priv->ppriv;

	mlx5_eswitch_sqs2vport_stop(esw, rep);
}

static void mlx5e_rep_update_flows(struct mlx5e_priv *priv,
				   struct mlx5_encap_entry *e,
				   bool neigh_connected,
				   unsigned char ha[ETH_ALEN])
{
	bool destroy = !!(e->flags & MLX5_ENCAP_ENTRY_DESTROY);
	struct ethhdr *eth = (struct ethhdr *)e->encap_header;
	int err = 0;

	ASSERT_RTNL();

	if ((!neigh_connected && (e->flags & MLX5_ENCAP_ENTRY_VALID)) ||
	    !ether_addr_equal(e->h_dest, ha))
		mlx5e_del_encap_flows(priv, e);

	if (neigh_connected && !(e->flags & MLX5_ENCAP_ENTRY_VALID) && !destroy) {
		ether_addr_copy(e->h_dest, ha);
		ether_addr_copy(eth->h_dest, ha);

		err = mlx5e_add_encap_flows(priv, e);
		if (err)
			mlx5_core_warn(priv->mdev, "Fail to update flows, %d\n", err);
	}
}

void mlx5e_rep_neigh_update(struct work_struct *work)
{
	struct mlx5_encap_entry *e =
		container_of(work, struct mlx5_encap_entry, neigh_update_work);
	struct mlx5e_priv *priv = netdev_priv(e->out_dev);
	struct neighbour *n = e->n;
	unsigned char ha[ETH_ALEN];
	bool neigh_connected;
	u8 nud_state, dead;
	bool encap_connected;

	rtnl_lock();

	/* If these parameters are changed after we release the lock,
	 * we'll receive another event letting us know about it.
	 * We use this lock to avoid inconsistency between the neigh validity
	 * and it's hw address.
	 */
	read_lock_bh(&n->lock);
	memcpy(ha, n->ha, ETH_ALEN);
	nud_state = n->nud_state;
	dead = n->dead;
	read_unlock_bh(&n->lock);

	neigh_connected = (nud_state & NUD_VALID) && !dead;
	encap_connected = !!(e->flags & MLX5_ENCAP_ENTRY_VALID);

	if (encap_connected != neigh_connected ||
	    !ether_addr_equal(e->h_dest, ha))
		mlx5e_rep_update_flows(priv, e, neigh_connected, ha);

	mlx5e_encap_release(e);
	rtnl_unlock();
	neigh_release(n);
}

static struct rhlist_head *mlx5e_neigh_entry_lookup(struct mlx5_eswitch_rep *rep,
						    struct neighbour *n);

static int mlx5e_rep_netevent_event(struct notifier_block *nb,
				    unsigned long event, void *ptr)
{
	struct mlx5_eswitch_rep *rep = container_of(nb, struct mlx5_eswitch_rep,
						    neigh_update.netevent_nb);
	struct mlx5_neigh_update *neigh_update = &rep->neigh_update;
	struct net_device *netdev = rep->netdev;
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct rhlist_head *tmp, *e_list = NULL;
	struct mlx5_encap_entry *e;
	struct neighbour *n;

	switch (event) {
	case NETEVENT_NEIGH_UPDATE:
		n = ptr;

		if (n->tbl != ipv6_stub->nd_tbl && n->tbl != &arp_tbl)
			return NOTIFY_DONE;

		spin_lock_bh(&neigh_update->encap_lock);
		e_list = mlx5e_neigh_entry_lookup(rep, n);
		if (!e_list) {
			spin_unlock_bh(&neigh_update->encap_lock);
			return NOTIFY_DONE;
		}

		rhl_for_each_entry_rcu(e, tmp, e_list, rhlist_node) {
			/* This assignment is valid as long as the the neigh reference
			 * is taken
			 */
			e->n = n;

			/* Take a reference to ensure the neighbour and mlx5 encap
			 * entry won't be destructed until we drop the reference in
			 * delayed work.
			 */
			neigh_hold(n);
			mlx5e_encap_hold(e);
			if (!queue_work(priv->wq, &e->neigh_update_work)) {
				mlx5e_encap_release(e);
				neigh_release(n);
			}
		}
		spin_unlock_bh(&neigh_update->encap_lock);
		break;
	}
	return NOTIFY_DONE;
}

static const struct rhashtable_params mlx5e_neigh_ht_params = {
	.head_offset = offsetof(struct mlx5_encap_entry, rhlist_node),
	.key_offset = offsetof(struct mlx5_encap_entry, n_entry),
	.key_len = sizeof(struct mlx5_neigh_entry),
	.automatic_shrinking = true,
};

static int mlx5e_rep_neigh_init(struct mlx5_eswitch_rep *rep)
{
	struct mlx5_neigh_update *neigh_update = &rep->neigh_update;
	int err;

	err = rhltable_init(&neigh_update->neigh_ht, &mlx5e_neigh_ht_params);
	if (err)
		return err;

	INIT_LIST_HEAD(&neigh_update->neigh_list);
	spin_lock_init(&neigh_update->encap_lock);

	rep->neigh_update.netevent_nb.notifier_call = mlx5e_rep_netevent_event;
	err = register_netevent_notifier(&rep->neigh_update.netevent_nb);
	if (err)
		goto out_err;
	return 0;

out_err:
	rhltable_destroy(&neigh_update->neigh_ht);
	return err;
}

static void mlx5e_rep_neigh_cleanup(struct mlx5_eswitch_rep *rep)
{
	struct mlx5_neigh_update *neigh_update = &rep->neigh_update;

	unregister_netevent_notifier(&neigh_update->netevent_nb);

	rhltable_destroy(&neigh_update->neigh_ht);
}

int mlx5e_rep_insert_neigh_entry(struct mlx5e_priv *priv,
				 struct mlx5_encap_entry *e)
{
	struct mlx5_eswitch_rep *rep = priv->ppriv;
	int err;

	err = rhltable_insert(&rep->neigh_update.neigh_ht, &e->rhlist_node,
			      mlx5e_neigh_ht_params);
	if (err)
		return err;

	list_add(&e->neigh_list, &rep->neigh_update.neigh_list);
	return err;
}

void mlx5e_rep_remove_neigh_entry(struct mlx5e_priv *priv,
				  struct mlx5_encap_entry *e)
{
	struct mlx5_eswitch_rep *rep = priv->ppriv;

	spin_lock_bh(&rep->neigh_update.encap_lock);
	list_del(&e->neigh_list);
	rhltable_remove(&rep->neigh_update.neigh_ht, &e->rhlist_node,
			mlx5e_neigh_ht_params);
	spin_unlock_bh(&rep->neigh_update.encap_lock);
}

static struct rhlist_head *mlx5e_neigh_entry_lookup(struct mlx5_eswitch_rep *rep,
						    struct neighbour *n)
{
	struct mlx5_neigh_update *neigh_update = &rep->neigh_update;
	struct mlx5_neigh_entry n_entry = {};

	n_entry.neigh_dev = n->dev;
	memcpy(&n_entry.dst_ip, n->primary_key, n->tbl->key_len);

	return rhltable_lookup(&neigh_update->neigh_ht, &n_entry, mlx5e_neigh_ht_params);
}

void mlx5e_encap_destroy(struct mlx5_encap_entry *e)
{
	kfree(e->encap_header);
	kfree(e);
}

int mlx5e_nic_rep_load(struct mlx5_eswitch *esw, struct mlx5_eswitch_rep *rep)
{
	struct net_device *netdev = rep->netdev;
	struct mlx5e_priv *priv = netdev_priv(netdev);
	int err;

	if (test_bit(MLX5E_STATE_OPENED, &priv->state)) {
		err = mlx5e_add_sqs_fwd_rules(priv);
		if (err)
			return err;
	}

	err = mlx5e_rep_neigh_init(rep);
	if (err)
		goto err_remove_sqs;
	return 0;

err_remove_sqs:
	mlx5e_remove_sqs_fwd_rules(priv);
	return err;
}

void mlx5e_nic_rep_unload(struct mlx5_eswitch *esw,
			  struct mlx5_eswitch_rep *rep)
{
	struct net_device *netdev = rep->netdev;
	struct mlx5e_priv *priv = netdev_priv(netdev);

	mlx5e_rep_neigh_cleanup(rep);

	if (test_bit(MLX5E_STATE_OPENED, &priv->state))
		mlx5e_remove_sqs_fwd_rules(priv);

	/* clean (and re-init) existing uplink offloaded TC rules */
	mlx5e_tc_cleanup(priv);
	mlx5e_tc_init(priv);
}

static int mlx5e_rep_open(struct net_device *dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_eswitch_rep *rep = priv->ppriv;
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	int err;

	err = mlx5e_open(dev);
	if (err)
		return err;

	err = mlx5_eswitch_set_vport_state(esw, rep->vport, MLX5_ESW_VPORT_ADMIN_STATE_UP);
	if (!err)
		netif_carrier_on(dev);

	return 0;
}

static int mlx5e_rep_close(struct net_device *dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_eswitch_rep *rep = priv->ppriv;
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;

	(void)mlx5_eswitch_set_vport_state(esw, rep->vport, MLX5_ESW_VPORT_ADMIN_STATE_DOWN);

	return mlx5e_close(dev);
}

static int mlx5e_rep_get_phys_port_name(struct net_device *dev,
					char *buf, size_t len)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_eswitch_rep *rep = priv->ppriv;
	int ret;

	ret = snprintf(buf, len, "%d", rep->vport - 1);
	if (ret >= len)
		return -EOPNOTSUPP;

	return 0;
}

static int mlx5e_rep_ndo_setup_tc(struct net_device *dev, u32 handle,
				  __be16 proto, struct tc_to_netdev *tc)
{
	struct mlx5e_priv *priv = netdev_priv(dev);

	if (TC_H_MAJ(handle) != TC_H_MAJ(TC_H_INGRESS))
		return -EOPNOTSUPP;

	if (tc->egress_dev) {
		struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
		struct net_device *uplink_dev = mlx5_eswitch_get_uplink_netdev(esw);

		return uplink_dev->netdev_ops->ndo_setup_tc(uplink_dev, handle,
							    proto, tc);
	}

	switch (tc->type) {
	case TC_SETUP_CLSFLOWER:
		switch (tc->cls_flower->command) {
		case TC_CLSFLOWER_REPLACE:
			return mlx5e_configure_flower(priv, proto, tc->cls_flower);
		case TC_CLSFLOWER_DESTROY:
			return mlx5e_delete_flower(priv, tc->cls_flower);
		case TC_CLSFLOWER_STATS:
			return mlx5e_stats_flower(priv, tc->cls_flower);
		}
	default:
		return -EOPNOTSUPP;
	}
}

bool mlx5e_is_uplink_rep(struct mlx5e_priv *priv)
{
	struct mlx5_eswitch_rep *rep = (struct mlx5_eswitch_rep *)priv->ppriv;
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;

	if (rep && rep->vport == FDB_UPLINK_VPORT && esw->mode == SRIOV_OFFLOADS)
		return true;

	return false;
}

bool mlx5e_is_vf_vport_rep(struct mlx5e_priv *priv)
{
	struct mlx5_eswitch_rep *rep = (struct mlx5_eswitch_rep *)priv->ppriv;

	if (rep && rep->vport != FDB_UPLINK_VPORT)
		return true;

	return false;
}

bool mlx5e_has_offload_stats(const struct net_device *dev, int attr_id)
{
	struct mlx5e_priv *priv = netdev_priv(dev);

	switch (attr_id) {
	case IFLA_OFFLOAD_XSTATS_CPU_HIT:
		if (mlx5e_is_vf_vport_rep(priv) || mlx5e_is_uplink_rep(priv))
			return true;
	}

	return false;
}

static int
mlx5e_get_sw_stats64(const struct net_device *dev,
		     struct rtnl_link_stats64 *stats)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5e_sw_stats *sstats = &priv->stats.sw;

	stats->rx_packets = sstats->rx_packets;
	stats->rx_bytes   = sstats->rx_bytes;
	stats->tx_packets = sstats->tx_packets;
	stats->tx_bytes   = sstats->tx_bytes;

	stats->tx_dropped = sstats->tx_queue_dropped;

	return 0;
}

int mlx5e_get_offload_stats(int attr_id, const struct net_device *dev,
			    void *sp)
{
	switch (attr_id) {
	case IFLA_OFFLOAD_XSTATS_CPU_HIT:
		return mlx5e_get_sw_stats64(dev, sp);
	}

	return -EINVAL;
}

static struct rtnl_link_stats64 *
mlx5e_rep_get_stats(struct net_device *dev, struct rtnl_link_stats64 *stats)
{
	struct mlx5e_priv *priv = netdev_priv(dev);

	memcpy(stats, &priv->stats.vf_vport, sizeof(*stats));
	return stats;
}

static const struct switchdev_ops mlx5e_rep_switchdev_ops = {
	.switchdev_port_attr_get	= mlx5e_attr_get,
};

static const struct net_device_ops mlx5e_netdev_ops_rep = {
	.ndo_open                = mlx5e_rep_open,
	.ndo_stop                = mlx5e_rep_close,
	.ndo_start_xmit          = mlx5e_xmit,
	.ndo_get_phys_port_name  = mlx5e_rep_get_phys_port_name,
	.ndo_setup_tc            = mlx5e_rep_ndo_setup_tc,
	.ndo_get_stats64         = mlx5e_rep_get_stats,
	.ndo_has_offload_stats	 = mlx5e_has_offload_stats,
	.ndo_get_offload_stats	 = mlx5e_get_offload_stats,
};

static void mlx5e_build_rep_netdev_priv(struct mlx5_core_dev *mdev,
					struct net_device *netdev,
					const struct mlx5e_profile *profile,
					void *ppriv)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	u8 cq_period_mode = MLX5_CAP_GEN(mdev, cq_period_start_from_cqe) ?
					 MLX5_CQ_PERIOD_MODE_START_FROM_CQE :
					 MLX5_CQ_PERIOD_MODE_START_FROM_EQE;

	priv->params.log_sq_size           =
		MLX5E_PARAMS_MINIMUM_LOG_SQ_SIZE;
	priv->params.rq_wq_type = MLX5_WQ_TYPE_LINKED_LIST;
	priv->params.log_rq_size = MLX5E_PARAMS_MINIMUM_LOG_RQ_SIZE;

	priv->params.min_rx_wqes = mlx5_min_rx_wqes(priv->params.rq_wq_type,
					    BIT(priv->params.log_rq_size));

	priv->params.rx_am_enabled = MLX5_CAP_GEN(mdev, cq_moderation);
	mlx5e_set_rx_cq_mode_params(&priv->params, cq_period_mode);

	priv->params.tx_max_inline         = mlx5e_get_max_inline_cap(mdev);
	priv->params.num_tc                = 1;

	priv->params.lro_wqe_sz            =
		MLX5E_PARAMS_DEFAULT_LRO_WQE_SZ;

	priv->mdev                         = mdev;
	priv->netdev                       = netdev;
	priv->params.num_channels          = profile->max_nch(mdev);
	priv->profile                      = profile;
	priv->ppriv                        = ppriv;

	mutex_init(&priv->state_lock);

	INIT_DELAYED_WORK(&priv->update_stats_work, mlx5e_update_stats_work);
}

static void mlx5e_build_rep_netdev(struct net_device *netdev)
{
	netdev->netdev_ops = &mlx5e_netdev_ops_rep;

	netdev->watchdog_timeo    = 15 * HZ;

	netdev->ethtool_ops	  = &mlx5e_rep_ethtool_ops;

#ifdef CONFIG_NET_SWITCHDEV
	netdev->switchdev_ops = &mlx5e_rep_switchdev_ops;
#endif

	netdev->features	 |= NETIF_F_VLAN_CHALLENGED | NETIF_F_HW_TC | NETIF_F_NETNS_LOCAL;
	netdev->hw_features      |= NETIF_F_HW_TC;

	eth_hw_addr_random(netdev);
}

static void mlx5e_init_rep(struct mlx5_core_dev *mdev,
			   struct net_device *netdev,
			   const struct mlx5e_profile *profile,
			   void *ppriv)
{
	mlx5e_build_rep_netdev_priv(mdev, netdev, profile, ppriv);
	mlx5e_build_rep_netdev(netdev);
}

static int mlx5e_init_rep_rx(struct mlx5e_priv *priv)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5_eswitch_rep *rep = priv->ppriv;
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5_flow_handle *flow_rule;
	int err;
	int i;

	err = mlx5e_create_direct_rqts(priv);
	if (err) {
		mlx5_core_warn(mdev, "create direct rqts failed, %d\n", err);
		return err;
	}

	err = mlx5e_create_direct_tirs(priv);
	if (err) {
		mlx5_core_warn(mdev, "create direct tirs failed, %d\n", err);
		goto err_destroy_direct_rqts;
	}

	flow_rule = mlx5_eswitch_create_vport_rx_rule(esw,
						      rep->vport,
						      priv->direct_tir[0].tirn);
	if (IS_ERR(flow_rule)) {
		err = PTR_ERR(flow_rule);
		goto err_destroy_direct_tirs;
	}
	rep->vport_rx_rule = flow_rule;

	err = mlx5e_tc_init(priv);
	if (err)
		goto err_del_flow_rule;

	return 0;

err_del_flow_rule:
	mlx5_del_flow_rules(rep->vport_rx_rule);
err_destroy_direct_tirs:
	mlx5e_destroy_direct_tirs(priv);
err_destroy_direct_rqts:
	for (i = 0; i < priv->params.num_channels; i++)
		mlx5e_destroy_rqt(priv, &priv->direct_tir[i].rqt);
	return err;
}

static void mlx5e_cleanup_rep_rx(struct mlx5e_priv *priv)
{
	struct mlx5_eswitch_rep *rep = priv->ppriv;
	int i;

	mlx5e_tc_cleanup(priv);
	mlx5_del_flow_rules(rep->vport_rx_rule);
	mlx5e_destroy_direct_tirs(priv);
	for (i = 0; i < priv->params.num_channels; i++)
		mlx5e_destroy_rqt(priv, &priv->direct_tir[i].rqt);
}

static int mlx5e_init_rep_tx(struct mlx5e_priv *priv)
{
	int err;

	err = mlx5e_create_tises(priv);
	if (err) {
		mlx5_core_warn(priv->mdev, "create tises failed, %d\n", err);
		return err;
	}
	return 0;
}

static int mlx5e_get_rep_max_num_channels(struct mlx5_core_dev *mdev)
{
#define	MLX5E_PORT_REPRESENTOR_NCH 1
	return MLX5E_PORT_REPRESENTOR_NCH;
}

static struct mlx5e_profile mlx5e_rep_profile = {
	.init			= mlx5e_init_rep,
	.init_rx		= mlx5e_init_rep_rx,
	.cleanup_rx		= mlx5e_cleanup_rep_rx,
	.init_tx		= mlx5e_init_rep_tx,
	.cleanup_tx		= mlx5e_cleanup_nic_tx,
	.update_stats           = mlx5e_rep_update_stats,
	.max_nch		= mlx5e_get_rep_max_num_channels,
	.max_tc			= 1,
};

int mlx5e_vport_rep_load(struct mlx5_eswitch *esw,
			 struct mlx5_eswitch_rep *rep)
{
	struct net_device *netdev;
	int err;

	netdev = mlx5e_create_netdev(esw->dev, &mlx5e_rep_profile, rep);
	if (!netdev) {
		pr_warn("Failed to create representor netdev for vport %d\n",
			rep->vport);
		return -EINVAL;
	}

	rep->netdev = netdev;

	err = mlx5e_attach_netdev(esw->dev, netdev);
	if (err) {
		pr_warn("Failed to attach representor netdev for vport %d\n",
			rep->vport);
		goto err_destroy_netdev;
	}

	err = mlx5e_rep_neigh_init(rep);
	if (err) {
		pr_warn("Failed to initialized neighbours handling for vport %d\n",
			rep->vport);
		goto err_detach_netdev;
	}

	err = register_netdev(netdev);
	if (err) {
		pr_warn("Failed to register representor netdev for vport %d\n",
			rep->vport);
		goto err_neigh_cleanup;
	}

	return 0;

err_neigh_cleanup:
	mlx5e_rep_neigh_cleanup(rep);

err_detach_netdev:
	mlx5e_detach_netdev(esw->dev, netdev);

err_destroy_netdev:
	mlx5e_destroy_netdev(esw->dev, netdev_priv(netdev));

	return err;

}

void mlx5e_vport_rep_unload(struct mlx5_eswitch *esw,
			    struct mlx5_eswitch_rep *rep)
{
	struct net_device *netdev = rep->netdev;

	unregister_netdev(netdev);
	mlx5e_rep_neigh_cleanup(rep);
	mlx5e_detach_netdev(esw->dev, netdev);
	mlx5e_destroy_netdev(esw->dev, netdev_priv(netdev));
}

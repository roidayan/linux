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

#include <net/switchdev.h>
#include <generated/utsrelease.h>
#include <linux/mlx5/flow_table.h>
#include <linux/list.h>
#include <net/sw_flow.h>
#include "en.h"
#include "eswitch.h"
#include "en_rep.h"

int  mlx5e_open_rep_channels(struct mlx5e_priv *priv);
void mlx5e_close_rep_channels(struct mlx5e_priv *priv);

int  mlx5_pf_nic_add_vport_miss_rule(struct mlx5e_priv *pf_dev, u32 vport, u32 *flow_index);

int  mlx5_add_fdb_miss_rule(struct mlx5_core_dev *mdev);

int mlx5_add_fdb_send_to_vport_rule(struct mlx5_core_dev *mdev,
				    u32 group_ix,
				    int vport,
				    u32 sqn,
				    u32 *flow_index);

int  mlx5e_rep_add_l2_fdb_rule(struct mlx5e_vf_rep *vf_rep, const char *addr);

void mlx5_delete_fdb_send_to_vport_rule(struct mlx5_core_dev *mdev,
					u32 flow_index);

/* this is wrong, the miss rules must be in the 1st group of the PF NIC */
//#define NIC_MISS_GROUP_INDEX 10
//#define NIC_MISS_GROUP_START 0x6811

/* this works, but problematic, as the uplink miss rule will over-rule all other
 * rules set by the PF */
#define NIC_MISS_GROUP_INDEX 0
#define NIC_MISS_GROUP_START 0x0

#define NIC_UPLINK_STEERING_VPORT 0xff

u32 uplink_miss_flow_index = 0; /* FIXME - add this to the PF somewhere */
u32 fdb_miss_flow_index    = 0; /* FIXME - same */

#if 0
#define MLX5_REP_HW_ID_LEN 6

struct mlx5e_vf_rep {
	struct net_device *dev;
	struct mlx5e_priv *pf_dev;
	struct mlx5e_sq *reinject_sq;

	u8  hw_id[MLX5_REP_HW_ID_LEN];
	// u8  vf;
	u32 vport;
	u32 miss_flow_index;

	u32 vf_mac_flow_index; /* FIXME - support multiple MACs --> flow indexes */
};
#endif

static const char mlx5e_rep_driver_name[] = "mlx5e_rep";

static void mlx5e_rep_get_drvinfo(struct net_device *dev,
				  struct ethtool_drvinfo *drvinfo)
{
	strlcpy(drvinfo->driver, mlx5e_rep_driver_name, sizeof(drvinfo->driver));
	strlcpy(drvinfo->version, UTS_RELEASE, sizeof(drvinfo->version));
}

#define NUM_VPORT_REP_COUNTERS 4

static const char vport_rep_strings[NUM_VPORT_REP_COUNTERS][ETH_GSTRING_LEN] = {
	"rx_packets",
	"tx_packets",
	"rx_bytes",
	"tx_bytes",
};

static void mlx5e_rep_get_strings(struct net_device *dev,
				  uint32_t stringset, uint8_t *data)
{
	int i;

	switch (stringset) {

	case ETH_SS_STATS:
		for (i = 0; i < NUM_VPORT_REP_COUNTERS; i++)
			strcpy(data + (i * ETH_GSTRING_LEN),
			       vport_rep_strings[i]);
		break;
	}
}


static void mlx5e_rep_get_ethtool_stats(struct net_device *dev,
				        struct ethtool_stats *stats, u64 *data)
{
	int i;

	if (!data)
		return;

	for (i = 0; i < NUM_VPORT_REP_COUNTERS; i++)
		data[i] = ((u64 *)&dev->stats)[i];
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

int __mlx5e_rep_attr_get(struct mlx5e_vf_rep *vf_rep, struct switchdev_attr *attr)
{

	printk(KERN_ERR "%s vport %d id len %d\n", __func__, vf_rep->vport, sizeof(vf_rep->hw_id));

	switch (attr->id) {
	case SWITCHDEV_ATTR_PORT_PARENT_ID:
		attr->u.ppid.id_len = sizeof(vf_rep->hw_id);
		memcpy(&attr->u.ppid.id, &vf_rep->hw_id, attr->u.ppid.id_len);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static int mlx5e_rep_fdb_add(struct mlx5e_vf_rep *vf_rep, struct switchdev_obj_fdb *fdb)
{
	/* add FDB rule addr VF MAC --> VF vport */
	return mlx5e_rep_add_l2_fdb_rule(vf_rep, fdb->addr);
}

static int mlx5e_rep_fdb_del(struct mlx5e_vf_rep *vf_rep, struct switchdev_obj_fdb *fdb)
{
	struct mlx5_eswitch *eswitch = vf_rep->pf_dev->mdev->priv.eswitch;
	struct mlx5_flow_table *ft = eswitch->fdb_table.fdb;

	/* remove FDB vf mac rule */
	mlx5_del_flow_table_entry(ft, vf_rep->vf_mac_flow_index);
	return 0;
}

static int mlx5e_rep_flow_add(struct mlx5e_vf_rep *vf_rep, struct sw_flow *sw_flow)
{
	return mlx5e_flow_act(vf_rep->pf_dev, sw_flow, FLOW_ADD);
}

static int mlx5e_rep_flow_del(struct mlx5e_vf_rep *vf_rep, struct sw_flow *sw_flow)
{
	return mlx5e_flow_act(vf_rep->pf_dev, sw_flow, FLOW_DEL);
}

int __mlx5e_rep_obj_add(struct mlx5e_vf_rep *vf_rep, struct switchdev_obj *obj)
{
	int err = 0;

	switch (obj->trans) {
	case SWITCHDEV_TRANS_PREPARE:
		if (obj->id != SWITCHDEV_OBJ_PORT_FDB &&
		    obj->id != SWITCHDEV_OBJ_FLOW)
			return -EOPNOTSUPP;
		else
			return 0;
	default:
		break;
	}

	switch (obj->id) {
	case SWITCHDEV_OBJ_PORT_FDB:
		err = mlx5e_rep_fdb_add(vf_rep, &obj->u.fdb);
		break;
	case SWITCHDEV_OBJ_FLOW:
		err = mlx5e_rep_flow_add(vf_rep, obj->u.flow);
		break;
	default:
		err = -EOPNOTSUPP;
		break;
	}

	return err;
}

int __mlx5e_rep_obj_del(struct mlx5e_vf_rep *vf_rep, struct switchdev_obj *obj)
{
	int err = 0;

	switch (obj->id) {
	case SWITCHDEV_OBJ_PORT_FDB:
		err = mlx5e_rep_fdb_del(vf_rep, &obj->u.fdb);
		break;
	case SWITCHDEV_OBJ_FLOW:
		err = mlx5e_rep_flow_del(vf_rep, obj->u.flow);
		break;
	default:
		err = -EOPNOTSUPP;
		break;
	}

	return err;
}

static int mlx5e_rep_attr_get(struct net_device *dev, struct switchdev_attr *attr)
{
	struct mlx5e_vf_rep *vf_rep = netdev_priv(dev);

	return __mlx5e_rep_attr_get(vf_rep, attr);
}


static int mlx5e_rep_obj_add(struct net_device *dev, struct switchdev_obj *obj)
{
	struct mlx5e_vf_rep *vf_rep = netdev_priv(dev);

	return __mlx5e_rep_obj_add(vf_rep, obj);
}

static int mlx5e_rep_obj_del(struct net_device *dev,
			     struct switchdev_obj *obj)
{
	struct mlx5e_vf_rep *vf_rep = netdev_priv(dev);

	return __mlx5e_rep_obj_del(vf_rep, obj);
}

static const struct switchdev_ops mlx5e_rep_switchdev_ops = {
	.switchdev_port_attr_get	= mlx5e_rep_attr_get,
	.switchdev_port_obj_add		= mlx5e_rep_obj_add,
	.switchdev_port_obj_del		= mlx5e_rep_obj_del,
};

static int mlx5e_rep_open(struct net_device *dev)
{
	struct mlx5e_vf_rep *priv = netdev_priv(dev);

	netif_start_queue(dev);
	netif_carrier_on(dev);

	printk(KERN_INFO "opened rep device %s for vport %d\n", dev->name, priv->vport);
	return 0;
}

static int mlx5e_rep_close(struct net_device *dev)
{
	struct mlx5e_vf_rep *priv = netdev_priv(dev);

	printk(KERN_INFO "closing rep device %s for vport %d\n", dev->name, priv->vport);

	netif_carrier_off(dev);
	netif_stop_queue(dev);
	return 0;
}

static netdev_tx_t mlx5e_rep_xmit(struct sk_buff *skb, struct net_device *dev)
{
	netdev_tx_t tx_t;

#if 1
	struct mlx5e_vf_rep *priv = netdev_priv(dev);
	struct mlx5e_sq *sq;
	int vport_index;

	if (priv->vport != FDB_UPLINK_VPORT)
		vport_index = priv->vport - 1;
	else  { /* NOTE: PF rep, should never get here */
		pr_err("attempt to xmit on PF rep, why?!\n");
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	sq = &priv->pf_dev->rep_channel[vport_index]->sq[0];

	/* re-inject packet using per vf SQ to the vport */
	tx_t = mlx5e_xmit_from_rep_sq(skb, sq);
#else
	/* just drop, following packets will match the rules added as of the miss */
	dev_kfree_skb_any(skb);
	tx_t = NETDEV_TX_OK;
#endif

	if (tx_t == NETDEV_TX_OK) {
		dev->stats.tx_packets++;
		dev->stats.tx_bytes += skb->len;
	}

	return tx_t;
}

static struct net_device_ops mlx5e_rep_netdev_ops = {
	.ndo_open	= mlx5e_rep_open,
	.ndo_stop	= mlx5e_rep_close,
	.ndo_start_xmit	= mlx5e_rep_xmit,
	.ndo_fdb_add	= switchdev_port_fdb_add,
	.ndo_fdb_del	= switchdev_port_fdb_del,
};

int mlx5e_rep_create_netdev(struct mlx5e_priv *pf_dev, u32 vport)
{
	struct net_device *dev;
	struct mlx5e_vf_rep *priv;
	int err, vf;

	dev = alloc_etherdev(sizeof(struct mlx5e_vf_rep));
	if (!dev)
		return -ENOMEM;

	priv = netdev_priv(dev);

	memcpy(priv->hw_id, pf_dev->netdev->dev_addr, ETH_ALEN);
	priv->pf_dev = pf_dev;
	priv->vport  = vport;
	priv->dev    = dev;

	dev->netdev_ops	= &mlx5e_rep_netdev_ops;
	dev->ethtool_ops = &mlx5e_rep_ethtool_ops;
	dev->switchdev_ops = &mlx5e_rep_switchdev_ops;

	/* vport = vf + 1;  PF vport = 0 --> VF vport is vf+1 */

	if (vport == FDB_UPLINK_VPORT) {
		vf = pf_dev->mdev->priv.sriov.num_vfs;
		goto out;
	} else
		vf = vport - 1;

	ether_addr_copy(dev->dev_addr, pf_dev->netdev->dev_addr);
	dev->dev_addr[ETH_ALEN - 1] += vport;

	/* set PF NIC miss rule mapping source vport --> flow_tag */
	err = mlx5_pf_nic_add_vport_miss_rule(pf_dev, vport, &priv->miss_flow_index);
	if (err)
		goto err_free_netdev;

	netif_carrier_off(dev);

	err = register_netdev(dev);
	printk(KERN_ERR "%s registered netdev %s (%p) for vport %d rep\n", __func__, dev->name, dev, priv->vport);
	if (err)
		goto err_free_netdev;
out:
	pf_dev->vf_reps[vf] = priv;

	return 0;

err_free_netdev:
	free_netdev(dev);
	return err;
}

void mlx5e_rep_destroy_netdev(struct net_device *dev)
{
	struct mlx5e_vf_rep *priv = netdev_priv(dev);
	struct mlx5_flow_table *ft = priv->pf_dev->ft.main;

	/* remove VF FDB miss rule */
	if (priv->miss_flow_index)
		mlx5_del_flow_table_entry(ft, priv->miss_flow_index);

	if (priv->vport != FDB_UPLINK_VPORT)
		unregister_netdev(dev); /* this will call ndo_stop */

	free_netdev(dev);
}

int mlx5e_vf_reps_create(struct mlx5e_priv *pf_dev)
{
	struct mlx5_core_sriov *sriov = &pf_dev->mdev->priv.sriov;
	int vf, err, size, nvf, nvports, vport;
	struct mlx5e_sq *sq;

	nvf = sriov->num_vfs;
	nvports = nvf + 1;
	printk(KERN_INFO "%s creating %d mlx5 vport reps sriov %p sriov->num_vfs %d\n",
		__func__, nvports, sriov, sriov->num_vfs);

	size = sizeof(struct mlx5e_vf_rep *) * nvports;
	pf_dev->vf_reps = kzalloc(size, GFP_KERNEL);
	if (!pf_dev->vf_reps)
		return -ENOMEM;

	for (vf = 0; vf < nvf; vf++) {
		err = mlx5e_rep_create_netdev(pf_dev, vf+1);
		if (err)
			goto err_vport_rep_create;
	}
	err = mlx5e_rep_create_netdev(pf_dev, FDB_UPLINK_VPORT);
	if (err) {
		vf++;
		goto err_vport_rep_create;
	}

	err = mlx5e_open_rep_channels(pf_dev);
	if (err) {
		printk(KERN_INFO "failed to open rep channels, err %d\n", err);
		goto err_vport_rep_channel_open;
	}

	for (vf = 0; vf < nvf; vf++) {
		sq = &pf_dev->rep_channel[vf]->sq[0];
		vport = vf + 1; /* PF vport = 0 --> VF vport is vf+1 */

		/* Set FDB sent to Vport rule, 1 ==  send to vport flow table group */
		err = mlx5_add_fdb_send_to_vport_rule(pf_dev->mdev, 1, vport, sq->sqn,
						      &pf_dev->vf_reps[vf]->tx_to_vport_flow_index);
		if (err) {
			printk(KERN_INFO "failed to add fdb send to vport rule, err %d\n", err);
			goto err_add_fdb_rule;
		}
	}

	return 0;

err_add_fdb_rule:
	for (vf--; vf >= 0; vf--)
		mlx5_delete_fdb_send_to_vport_rule(pf_dev->mdev,
						   pf_dev->vf_reps[vf]->tx_to_vport_flow_index);

err_vport_rep_channel_open:
err_vport_rep_create:
	for (vf = nvports-1; vf >= 0; vf--)
		mlx5e_rep_destroy_netdev(pf_dev->vf_reps[vf]->dev);

	kfree(pf_dev->vf_reps);
	pf_dev->vf_reps = NULL;
	return err;
}

void mlx5e_reps_remove(struct mlx5e_priv *pf_dev)
{
	struct mlx5_core_sriov *sriov = &pf_dev->mdev->priv.sriov;
	int vf, nvports;

	nvports = sriov->num_vfs + 1;
	printk(KERN_INFO "%s removing %d mlx5 vport reps\n", __func__, nvports);

	if (!pf_dev->vf_reps) {
		printk(KERN_INFO "%s no vf reps, bailing out\n", __func__);
		return;
	}

	/* we have vport per VF + one for the uplink */
	for (vf = 0; vf < nvports; vf++) {
		mlx5_delete_fdb_send_to_vport_rule(pf_dev->mdev,
						   pf_dev->vf_reps[vf]->tx_to_vport_flow_index);
		mlx5e_rep_destroy_netdev(pf_dev->vf_reps[vf]->dev);
	}

	mlx5e_close_rep_channels(pf_dev);

	kfree(pf_dev->vf_reps);
	pf_dev->vf_reps = NULL;
}

int mlx5e_start_flow_offloads(struct mlx5e_priv *pf_dev)
{
	int err;
	int n,tc;
	struct mlx5e_channel *c;
	int nch = pf_dev->params.num_channels;

	err = mlx5e_vf_reps_create(pf_dev);
	if (err)  {
		printk(KERN_ERR "failed creating vf reps - err %d\n", err);
		return err;
	}

	/* set NIC miss rule mapping uplink --> flow_tag */
	err = mlx5_pf_nic_add_vport_miss_rule(pf_dev, FDB_UPLINK_VPORT, &uplink_miss_flow_index);
	if (err)  {
		printk(KERN_ERR "failed adding uplink PF NIC miss rule err %d\n", err);
		goto pf_nic_err;
	}

	err = mlx5_add_fdb_miss_rule(pf_dev->mdev);
	if (err)  {
		printk(KERN_ERR "failed adding FDB miss rule err %d\n", err);
		goto fdb_err;
	}

	/* Add re-inject rule to all the PF sqs */
	for (n = 0; n < nch; n++) {
		c = pf_dev->channel[n];
		for (tc = 0; tc < c->num_tc; tc++) {
			err = mlx5_add_fdb_send_to_vport_rule(pf_dev->mdev, 1,
							      FDB_UPLINK_VPORT, c->sq[tc].sqn,
							      &c->sq[tc].tx_to_vport_flow_index);
			if (err)
				goto err_pf_vport_rules;
		}
	}

	INIT_LIST_HEAD(&pf_dev->mlx5_flow_groups);
	spin_lock_init(&pf_dev->flows_lock);

	return 0;

err_pf_vport_rules:
	for (n--; n >= 0; n--) {
		c = pf_dev->channel[n];
		for (tc--; tc >= 0; tc--)
			mlx5_delete_fdb_send_to_vport_rule(pf_dev->mdev,
							   c->sq[tc].tx_to_vport_flow_index);
	}

fdb_err:
	mlx5_del_flow_table_entry(pf_dev->ft.main, uplink_miss_flow_index);
	uplink_miss_flow_index = 0;

pf_nic_err:
	mlx5e_reps_remove(pf_dev);

	return err;

}

void mlx5e_stop_flow_offloads(struct mlx5e_priv *pf_dev)
{
	struct mlx5_eswitch *eswitch = pf_dev->mdev->priv.eswitch;
	void *ft;
	int nch = pf_dev->params.num_channels;
	int n, tc;
	struct mlx5e_channel *c;

	/* FIXME: alarm/clean if there are offloaded flows left */

	/* remove FDB miss rule */
	if (fdb_miss_flow_index) {
		ft = eswitch->fdb_table.fdb;
		mlx5_del_flow_table_entry(ft, fdb_miss_flow_index);
		fdb_miss_flow_index = 0;
	}

	/* remove uplink PF NIC miss rule */
	if (uplink_miss_flow_index) {
		ft = pf_dev->ft.main;
		mlx5_del_flow_table_entry(ft, uplink_miss_flow_index);
		uplink_miss_flow_index = 0;
	}


	for (n = 0; n < nch; n++) {
		c = pf_dev->channel[n];
		for (tc = 0; tc < c->num_tc; tc++) {
			if (c->sq[tc].tx_to_vport_flow_index)
				mlx5_delete_fdb_send_to_vport_rule(pf_dev->mdev,
								   c->sq[tc].tx_to_vport_flow_index);
		}
	}

	mlx5e_reps_remove(pf_dev);
}

int mlx5_pf_nic_add_vport_miss_rule(struct mlx5e_priv *pf_dev, u32 vport, u32 *flow_index)
{
	u32 *flow_context;
	void *match_value, *misc, *dest;
	int  err;
	u32 vport_flow, vport_tag;
	struct mlx5_flow_table *ft = pf_dev->ft.main;

	if (vport == FDB_UPLINK_VPORT) {
		mlx5_core_warn(pf_dev->mdev, "no need to add miss rule for uplink, skipping\n");
		return 0;
	}

	if (vport == FDB_UPLINK_VPORT) {
		vport_flow = NIC_MISS_GROUP_START + NIC_UPLINK_STEERING_VPORT;
		vport_tag  = FDB_TAG | NIC_UPLINK_STEERING_VPORT;
	} else {
		vport_flow = NIC_MISS_GROUP_START + vport;
		vport_tag  = FDB_TAG | vport;
	}

	mlx5_core_warn(pf_dev->mdev, "add PF NIC miss rule: vport %x flow tag %x flow_index %x\n",
		       vport, vport_tag, vport_flow);

	flow_context   = mlx5_vzalloc(MLX5_ST_SZ_BYTES(flow_context) +
				MLX5_ST_SZ_BYTES(dest_format_struct));
	if (!flow_context) {
		mlx5_core_warn(pf_dev->mdev, "%s: alloc failed\n", __func__);
		err = -ENOMEM;
		goto out;
	}

	MLX5_SET(flow_context, flow_context, flow_tag , vport_tag);
	MLX5_SET(flow_context, flow_context, destination_list_size, 1);
	MLX5_SET(flow_context, flow_context, action,
		 MLX5_FLOW_CONTEXT_ACTION_FWD_DEST);

	match_value = MLX5_ADDR_OF(flow_context, flow_context, match_value);
	misc = MLX5_ADDR_OF(fte_match_param, match_value, misc_parameters);
	MLX5_SET(fte_match_set_misc, misc, source_port, vport);

	dest = MLX5_ADDR_OF(flow_context, flow_context, destination);
	MLX5_SET(dest_format_struct, dest, destination_type,
		 MLX5_FLOW_CONTEXT_DEST_TYPE_TIR);

	MLX5_SET(dest_format_struct, dest, destination_id, pf_dev->tirn[MLX5E_TT_ANY]);

	err = mlx5_set_flow_group_entry_index(ft, NIC_MISS_GROUP_INDEX,
				      vport_flow, flow_context);
	if (err) {
		mlx5_core_warn(pf_dev->mdev, "failed to set FDB miss rule for vport %x\n", vport);
		goto out;
	}

	mlx5_core_warn(pf_dev->mdev, "added PF NIC miss rule entry for vport %x flow tag =%x flow_index %x\n",
		       vport, vport_tag, vport_flow);

	*flow_index =  vport_flow;

out:
	kvfree(flow_context);
	return err;
}


//miss rule: ANY --> send to vport 0
//sent-to-vport rule: <source vport = 0, SQN = X> --> send to vport N

int mlx5_add_fdb_send_to_vport_rule(struct mlx5_core_dev *mdev,
				    u32 group_ix,
				    int vport,
				    u32 sqn,
				    u32 *flow_index)
{
	u32 *flow_context;
	void *dest, *match_value, *misc;
	int  err;
	struct mlx5_flow_table *ft  = mdev->priv.eswitch->fdb_table.fdb;

	flow_context   = mlx5_vzalloc(MLX5_ST_SZ_BYTES(flow_context) +
				      MLX5_ST_SZ_BYTES(dest_format_struct));
	if (!flow_context) {
		mlx5_core_warn(mdev, "%s: alloc failed\n", __func__);
		err = -ENOMEM;
		goto out;
	}

	MLX5_SET(flow_context, flow_context, action,
		 MLX5_FLOW_CONTEXT_ACTION_FWD_DEST);
	MLX5_SET(flow_context, flow_context, destination_list_size, 1);

	dest = MLX5_ADDR_OF(flow_context, flow_context, destination);
	MLX5_SET(dest_format_struct, dest, destination_type,
		 MLX5_FLOW_CONTEXT_DEST_TYPE_VPORT);
	MLX5_SET(dest_format_struct, dest, destination_id, vport); /* send to vport */

	match_value = MLX5_ADDR_OF(flow_context, flow_context, match_value);
	misc = MLX5_ADDR_OF(fte_match_param, match_value, misc_parameters);
	MLX5_SET(fte_match_set_misc, misc, source_sqn, sqn);
	MLX5_SET(fte_match_set_misc, misc, source_port, 0x0); /* source vport is 0 */

	err = mlx5_set_flow_group_entry(ft, group_ix, flow_index, flow_context);
	mlx5_core_warn(mdev, "Add FDB entry for send to vport %x flow index=%x\n",
		       vport,*flow_index);

out:
	kvfree(flow_context);
	return err;
}

void mlx5_delete_fdb_send_to_vport_rule(struct mlx5_core_dev *mdev,
					u32 flow_index)
{
	struct mlx5_flow_table *ft  = mdev->priv.sriov.eswitch.ft_fdb;

	mlx5_del_flow_table_entry(ft, flow_index);
}

int mlx5_add_fdb_miss_rule(struct mlx5_core_dev *mdev)
{
	u32 *flow_context;
	void *dest;
	int  err;

	void *ft  = mdev->priv.eswitch->fdb_table.fdb;

	flow_context   = mlx5_vzalloc(MLX5_ST_SZ_BYTES(flow_context) +
				      MLX5_ST_SZ_BYTES(dest_format_struct));
	if (!flow_context) {
		mlx5_core_warn(mdev, "%s: alloc failed\n", __func__);
		err = -ENOMEM;
		goto out;
	}

	MLX5_SET(flow_context, flow_context, action,
		 MLX5_FLOW_CONTEXT_ACTION_FWD_DEST);

	dest = MLX5_ADDR_OF(flow_context, flow_context, destination);

	MLX5_SET(dest_format_struct, dest, destination_type,
		 MLX5_FLOW_CONTEXT_DEST_TYPE_VPORT);

	MLX5_SET(flow_context, flow_context, destination_list_size, 1);
	MLX5_SET(dest_format_struct, dest, destination_id, 0); /* send to PF vport */

	err = mlx5_set_flow_group_entry(ft, MLX5_MISS_GROUP, &fdb_miss_flow_index, flow_context);
	mlx5_core_warn(mdev, "ADD FDB entry for miss flow index=%d\n", fdb_miss_flow_index);

out:
	kvfree(flow_context);
	return err;
}

int mlx5e_rep_add_l2_fdb_rule(struct mlx5e_vf_rep *vf_rep, const char *addr)
{
	struct mlx5_core_dev *mdev   = vf_rep->pf_dev->mdev;
	struct mlx5_eswitch *eswitch = mdev->priv.eswitch;
	struct mlx5_flow_table *ft = eswitch->fdb_table.fdb;
	u32 *flow_context;
	void *match_value, *dest;
	u8   *dmac;
	int  err, vport = vf_rep->vport;


	flow_context   = mlx5_vzalloc(MLX5_ST_SZ_BYTES(flow_context) +
				      MLX5_ST_SZ_BYTES(dest_format_struct));
	if (!flow_context) {
		mlx5_core_warn(mdev, "%s: alloc failed\n", __func__);
		err = -ENOMEM;
		goto out;
	}

	match_value = MLX5_ADDR_OF(flow_context, flow_context, match_value);
	dmac = MLX5_ADDR_OF(fte_match_param, match_value,
			    outer_headers.dmac_47_16);
	dest = MLX5_ADDR_OF(flow_context, flow_context, destination);

	MLX5_SET(flow_context, flow_context, action,
		 MLX5_FLOW_CONTEXT_ACTION_FWD_DEST);

	MLX5_SET(dest_format_struct, dest, destination_type,
		 MLX5_FLOW_CONTEXT_DEST_TYPE_VPORT);

	MLX5_SET(flow_context, flow_context, destination_list_size, 1);
	MLX5_SET(dest_format_struct, dest, destination_id, vport);

	ether_addr_copy(dmac, addr);

	err = mlx5_set_flow_group_entry(ft, 0, &vf_rep->vf_mac_flow_index, flow_context);
	if (err)
		mlx5_core_warn(mdev, "failed to set flow table entry for mac %pM to vport %d\n",
			       addr, vport);

	mlx5_core_warn(mdev, "ADD flow table entry for mac %pM to vport %d flow index=%d\n",
		       addr, vport, vf_rep->vf_mac_flow_index);
out:
	kvfree(flow_context);
	return err;
}


u32 handle_fdb_flow_tag(struct net_device *dev, struct sk_buff *skb, u32 flow_tag)
{
	struct mlx5e_priv *pf_dev = netdev_priv(dev);
	struct mlx5e_vf_rep *vf_rep;
	u32 vport, vf;

	vport = flow_tag & ~FDB_TAG;

	if (vport == NIC_UPLINK_STEERING_VPORT) {
		vport = FDB_UPLINK_VPORT;
		goto out;
	}

	vf = vport - 1;
	vf_rep = pf_dev->vf_reps[vf];

	//if (net_ratelimit())
	//	netdev_warn(dev, "flow tag %x --> needs setting dev to rep of vport %x dev %p name %s\n", flow_tag, vport,
	//	       vf_rep->dev, vf_rep->dev? vf_rep->dev->name: "NULL");

	skb->dev = vf_rep->dev;
	skb->queue_mapping = 1;
	vf_rep->dev->stats.rx_packets++;
	vf_rep->dev->stats.rx_bytes += skb->len;

out:
	return vport;
}

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

#include <linux/etherdevice.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/mlx5_ifc.h>
#include <linux/mlx5/vport.h>
#include <linux/mlx5/fs.h>
#include "mlx5_core.h"
#include "eswitch.h"
#include "en.h"
#include "fs_core.h"

enum {
	FDB_FAST_PATH = 0,
	FDB_SLOW_PATH = (FDB_MAX_CHAIN * 1) * (FDB_MAX_PRIO + 1),
};

static struct mlx5_flow_table *
esw_get_offloads_fast_fdb_table(struct mlx5_eswitch *esw, u32 chain, u32 prio);
static void
esw_put_offloads_fast_fdb_table(struct mlx5_eswitch *esw, u32 chain, u32 prio, bool force);

bool
mlx5_eswitch_is_prio_in_range(struct mlx5_eswitch *esw, u32 prio)
{
	if (prio <= FDB_MAX_PRIO)
		return true;

	esw_warn(esw->dev, "Requested prio %d is out of range (1-%d)\n",
		 prio, FDB_MAX_PRIO);
	return false;
}

struct mlx5_flow_handle *
mlx5_eswitch_add_offloaded_rule(struct mlx5_eswitch *esw,
				struct mlx5_flow_spec *spec,
				struct mlx5_esw_flow_attr *attr)
{
	struct mlx5_flow_destination dest[2] = {};
	struct mlx5_flow_act flow_act = {0};
	struct mlx5_fc *counter = NULL;
	struct mlx5_flow_handle *rule;
	char *outer;
	struct mlx5_flow_table *fdb;
	void *misc;
	int i = 0;

	if (esw->mode != SRIOV_OFFLOADS)
		return ERR_PTR(-EOPNOTSUPP);

	/* per flow vlan pop/push is emulated, don't set that into the firmware */
	flow_act.action = attr->action & ~(MLX5_FLOW_CONTEXT_ACTION_VLAN_PUSH | MLX5_FLOW_CONTEXT_ACTION_VLAN_POP);

	if (flow_act.action & MLX5_FLOW_CONTEXT_ACTION_FWD_DEST) {
		if (MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE == attr->dest_type) {
			struct mlx5_flow_table *ft = esw_get_offloads_fast_fdb_table(esw, attr->dest_chain, 0);
			if (IS_ERR(ft)) {
				rule = ERR_CAST(ft);
				goto err_create_goto_table;
			}
			dest[i].type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
			dest[i].ft = ft;
		} else {
			dest[i].type = MLX5_FLOW_DESTINATION_TYPE_VPORT;
			dest[i].vport_num = attr->out_rep->vport;

			if (MLX5_CAP_ESW(esw->dev, merged_eswitch)) {
				struct mlx5e_priv* priv = netdev_priv(attr->out_rep->netdev);

				dest[i].destination_eswitch_owner_vhca_id = MLX5_CAP_GEN(priv->mdev, vhca_id);
				dest[i].destination_eswitch_owner_vhca_id_valid = 1;
			}
		}

		i++;
	}
	if (flow_act.action & MLX5_FLOW_CONTEXT_ACTION_COUNT) {
		if (!attr->counter_dev) {
			rule = ERR_PTR(-ENODEV);
			goto err_counter_alloc;
		}
		counter = mlx5_fc_create(attr->counter_dev, true);
		if (IS_ERR(counter)) {
			rule = ERR_CAST(counter);
			goto err_counter_alloc;
		}
		dest[i].type = MLX5_FLOW_DESTINATION_TYPE_COUNTER;
		dest[i].counter = counter;
		i++;
	}

	misc = MLX5_ADDR_OF(fte_match_param, spec->match_value, misc_parameters);
	MLX5_SET(fte_match_set_misc, misc, source_port, attr->in_rep->vport);

	if (MLX5_CAP_ESW(esw->dev, merged_eswitch)) {
		struct net_device *up_dev = mlx5_eswitch_get_uplink_netdev(esw);
		struct mlx5e_priv *priv = netdev_priv(up_dev);

		if (attr->in_rep->vport != FDB_UPLINK_VPORT)
			priv = netdev_priv(attr->in_rep->netdev);

		MLX5_SET(fte_match_set_misc, misc,
			 source_eswitch_owner_vhca_id,
			 MLX5_CAP_GEN(priv->mdev, vhca_id));
	}

	misc = MLX5_ADDR_OF(fte_match_param, spec->match_criteria, misc_parameters);
	MLX5_SET_TO_ONES(fte_match_set_misc, misc, source_port);
	MLX5_SET_TO_ONES(fte_match_set_misc, misc, source_eswitch_owner_vhca_id);

	spec->match_criteria_enable = MLX5_MATCH_MISC_PARAMETERS;

	outer = MLX5_ADDR_OF(fte_match_param, spec->match_criteria, outer_headers);
	if (outer[0] ||
	    memcmp(outer, outer + 1,
		   MLX5_ST_SZ_BYTES(fte_match_set_lyr_2_4) - 1))
		spec->match_criteria_enable |= MLX5_MATCH_OUTER_HEADERS;

	if (flow_act.action & MLX5_FLOW_CONTEXT_ACTION_DECAP)
		spec->match_criteria_enable |= MLX5_MATCH_INNER_HEADERS;

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR)
		flow_act.modify_id = attr->mod_hdr_id;

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_ENCAP)
		flow_act.encap_id = attr->encap_id;

	fdb = esw_get_offloads_fast_fdb_table(esw, attr->chain, attr->prio);
	if (IS_ERR(fdb)) {
		rule = ERR_CAST(fdb);
		goto err_esw_create;
	}

	rule = mlx5_add_flow_rules(fdb, spec, &flow_act, dest, i);
	if (IS_ERR(rule))
		goto err_add_rule;
	else
		esw->offloads.num_flows++;

	return rule;

err_add_rule:
	esw_put_offloads_fast_fdb_table(esw, attr->chain, attr->prio, false);
err_esw_create:
	mlx5_fc_destroy(esw->dev, counter);
err_counter_alloc:
	if (MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE == attr->dest_type)
		esw_put_offloads_fast_fdb_table(esw, attr->dest_chain, 0, false);
err_create_goto_table:
	return rule;
}

void
mlx5_eswitch_del_offloaded_rule(struct mlx5_eswitch *esw,
				struct mlx5_flow_handle *rule,
				struct mlx5_esw_flow_attr *attr)
{
	struct mlx5_fc *counter = NULL;

	counter = mlx5_flow_rule_counter(rule);
	mlx5_del_flow_rules(rule);
	mlx5_fc_destroy(attr->counter_dev, counter);
	esw->offloads.num_flows--;
	esw_put_offloads_fast_fdb_table(esw, attr->chain, attr->prio, false);
	if (MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE == attr->dest_type)
		esw_put_offloads_fast_fdb_table(esw, attr->dest_chain, 0, false);
}

static int esw_set_global_vlan_pop(struct mlx5_eswitch *esw, u8 val)
{
	struct mlx5_eswitch_rep *rep;
	int vf_vport, err = 0;

	esw_debug(esw->dev, "%s applying global %s policy\n", __func__, val ? "pop" : "none");
	for (vf_vport = 1; vf_vport < esw->enabled_vports; vf_vport++) {
		rep = &esw->offloads.vport_reps[vf_vport];
		if (!rep->valid)
			continue;

		err = __mlx5_eswitch_set_vport_vlan(esw, rep->vport, 0, 0, val);
		if (err)
			goto out;
	}

out:
	return err;
}

static struct mlx5_eswitch_rep *
esw_vlan_action_get_vport(struct mlx5_esw_flow_attr *attr, bool push, bool pop)
{
	struct mlx5_eswitch_rep *in_rep, *out_rep, *vport = NULL;

	in_rep  = attr->in_rep;
	out_rep = attr->out_rep;

	if (push)
		vport = in_rep;
	else if (pop)
		vport = out_rep;
	else
		vport = in_rep;

	return vport;
}

static int esw_add_vlan_action_check(struct mlx5_esw_flow_attr *attr,
				     bool push, bool pop, bool fwd)
{
	struct mlx5_eswitch_rep *in_rep, *out_rep;

	if ((push || pop) && !fwd)
		goto out_notsupp;

	in_rep  = attr->in_rep;
	out_rep = attr->out_rep;

	if (push && in_rep->vport == FDB_UPLINK_VPORT)
		goto out_notsupp;

	if (pop && out_rep->vport == FDB_UPLINK_VPORT)
		goto out_notsupp;

	/* vport has vlan push configured, can't offload VF --> wire rules w.o it */
	if (!push && !pop && fwd)
		if (in_rep->vlan && out_rep->vport == FDB_UPLINK_VPORT)
			goto out_notsupp;

	/* protects against (1) setting rules with different vlans to push and
	 * (2) setting rules w.o vlans (attr->vlan = 0) && w. vlans to push (!= 0)
	 */
	if (push && in_rep->vlan_refcount && (in_rep->vlan != attr->vlan))
		goto out_notsupp;

	return 0;

out_notsupp:
	return -EOPNOTSUPP;
}

int mlx5_eswitch_add_vlan_action(struct mlx5_eswitch *esw,
				 struct mlx5_esw_flow_attr *attr)
{
	struct offloads_fdb *offloads = &esw->fdb_table.offloads;
	struct mlx5_eswitch_rep *vport = NULL;
	bool push, pop, fwd;
	int err = 0;

	push = !!(attr->action & MLX5_FLOW_CONTEXT_ACTION_VLAN_PUSH);
	pop  = !!(attr->action & MLX5_FLOW_CONTEXT_ACTION_VLAN_POP);
	fwd  = !!((attr->action & MLX5_FLOW_CONTEXT_ACTION_FWD_DEST) && attr->out_rep);

	err = esw_add_vlan_action_check(attr, push, pop, fwd);
	if (err)
		return err;

	attr->vlan_handled = false;

	vport = esw_vlan_action_get_vport(attr, push, pop);

	if (!push && !pop && fwd) {
		/* tracks VF --> wire rules without vlan push action */
		if (!attr->out_rep) {
			return -EOPNOTSUPP;
		}
		if (attr->out_rep->vport == FDB_UPLINK_VPORT) {
			vport->vlan_refcount++;
			attr->vlan_handled = true;
		}

		return 0;
	}

	if (!push && !pop)
		return 0;

	if (!(offloads->vlan_push_pop_refcount)) {
		/* it's the 1st vlan rule, apply global vlan pop policy */
		err = esw_set_global_vlan_pop(esw, SET_VLAN_STRIP);
		if (err)
			goto out;
	}
	offloads->vlan_push_pop_refcount++;

	if (push) {
		if (vport->vlan_refcount)
			goto skip_set_push;

		err = __mlx5_eswitch_set_vport_vlan(esw, vport->vport, attr->vlan, 0,
						    SET_VLAN_INSERT | SET_VLAN_STRIP);
		if (err)
			goto out;
		vport->vlan = attr->vlan;
skip_set_push:
		vport->vlan_refcount++;
	}
out:
	if (!err)
		attr->vlan_handled = true;
	return err;
}

int mlx5_eswitch_del_vlan_action(struct mlx5_eswitch *esw,
				 struct mlx5_esw_flow_attr *attr)
{
	struct offloads_fdb *offloads = &esw->fdb_table.offloads;
	struct mlx5_eswitch_rep *vport = NULL;
	bool push, pop, fwd;
	int err = 0;

	if (!attr->vlan_handled)
		return 0;

	push = !!(attr->action & MLX5_FLOW_CONTEXT_ACTION_VLAN_PUSH);
	pop  = !!(attr->action & MLX5_FLOW_CONTEXT_ACTION_VLAN_POP);
	fwd  = !!((attr->action & MLX5_FLOW_CONTEXT_ACTION_FWD_DEST) && attr->out_rep);

	vport = esw_vlan_action_get_vport(attr, push, pop);

	if (!push && !pop && fwd) {
		/* tracks VF --> wire rules without vlan push action */
		if (attr->out_rep->vport == FDB_UPLINK_VPORT)
			vport->vlan_refcount--;

		return 0;
	}

	if (push) {
		vport->vlan_refcount--;
		if (vport->vlan_refcount)
			goto skip_unset_push;

		vport->vlan = 0;
		err = __mlx5_eswitch_set_vport_vlan(esw, vport->vport,
						    0, 0, SET_VLAN_STRIP);
		if (err)
			goto out;
	}

skip_unset_push:
	offloads->vlan_push_pop_refcount--;
	if (offloads->vlan_push_pop_refcount)
		return 0;

	/* no more vlan rules, stop global vlan pop policy */
	err = esw_set_global_vlan_pop(esw, 0);

out:
	return err;
}

static struct mlx5_flow_handle *
mlx5_eswitch_add_send_to_vport_rule(struct mlx5_eswitch *esw, int vport, u32 sqn)
{
	struct mlx5_flow_act flow_act = {0};
	struct mlx5_flow_destination dest = {};
	struct mlx5_flow_handle *flow_rule;
	struct mlx5_flow_spec *spec;
	void *misc;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec) {
		flow_rule = ERR_PTR(-ENOMEM);
		goto out;
	}

	misc = MLX5_ADDR_OF(fte_match_param, spec->match_value, misc_parameters);
	MLX5_SET(fte_match_set_misc, misc, source_sqn, sqn);
	MLX5_SET(fte_match_set_misc, misc, source_port, 0x0); /* source vport is 0 */

	misc = MLX5_ADDR_OF(fte_match_param, spec->match_criteria, misc_parameters);
	MLX5_SET_TO_ONES(fte_match_set_misc, misc, source_sqn);
	MLX5_SET_TO_ONES(fte_match_set_misc, misc, source_port);

	spec->match_criteria_enable = MLX5_MATCH_MISC_PARAMETERS;
	dest.type = MLX5_FLOW_DESTINATION_TYPE_VPORT;
	dest.vport_num = vport;
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;

	flow_rule = mlx5_add_flow_rules(esw->fdb_table.offloads.fdb, spec,
					&flow_act, &dest, 1);
	if (IS_ERR(flow_rule))
		esw_warn(esw->dev, "FDB: Failed to add send to vport rule err %ld\n", PTR_ERR(flow_rule));
out:
	kvfree(spec);
	return flow_rule;
}

void mlx5_eswitch_sqs2vport_stop(struct mlx5_eswitch *esw,
				 struct mlx5_eswitch_rep *rep)
{
	struct mlx5_esw_sq *esw_sq, *tmp;

	if (esw->mode != SRIOV_OFFLOADS)
		return;

	list_for_each_entry_safe(esw_sq, tmp, &rep->vport_sqs_list, list) {
		mlx5_del_flow_rules(esw_sq->send_to_vport_rule);
		list_del(&esw_sq->list);
		kfree(esw_sq);
	}
}

int mlx5_eswitch_sqs2vport_start(struct mlx5_eswitch *esw,
				 struct mlx5_eswitch_rep *rep,
				 u16 *sqns_array, int sqns_num)
{
	struct mlx5_flow_handle *flow_rule;
	struct mlx5_esw_sq *esw_sq;
	int err;
	int i;

	if (esw->mode != SRIOV_OFFLOADS)
		return 0;

	for (i = 0; i < sqns_num; i++) {
		esw_sq = kzalloc(sizeof(*esw_sq), GFP_KERNEL);
		if (!esw_sq) {
			err = -ENOMEM;
			goto out_err;
		}

		/* Add re-inject rule to the PF/representor sqs */
		flow_rule = mlx5_eswitch_add_send_to_vport_rule(esw,
								rep->vport,
								sqns_array[i]);
		if (IS_ERR(flow_rule)) {
			err = PTR_ERR(flow_rule);
			kfree(esw_sq);
			goto out_err;
		}
		esw_sq->send_to_vport_rule = flow_rule;
		list_add(&esw_sq->list, &rep->vport_sqs_list);
	}
	return 0;

out_err:
	mlx5_eswitch_sqs2vport_stop(esw, rep);
	return err;
}

static int esw_add_fdb_miss_rule(struct mlx5_eswitch *esw)
{
	struct mlx5_flow_act flow_act = {0};
	struct mlx5_flow_destination dest= {};
	struct mlx5_flow_handle *flow_rule = NULL;
	struct mlx5_flow_spec *spec;
	int err = 0;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec) {
		err = -ENOMEM;
		goto out;
	}

	dest.type = MLX5_FLOW_DESTINATION_TYPE_VPORT;
	dest.vport_num = 0;
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;

	flow_rule = mlx5_add_flow_rules(esw->fdb_table.offloads.fdb, spec,
					&flow_act, &dest, 1);
	if (IS_ERR(flow_rule)) {
		err = PTR_ERR(flow_rule);
		esw_warn(esw->dev,  "FDB: Failed to add miss flow rule err %d\n", err);
		goto out;
	}

	esw->fdb_table.offloads.miss_rule = flow_rule;
out:
	kvfree(spec);
	return err;
}

#define ESW_OFFLOADS_NUM_GROUPS  4

static struct mlx5_flow_group *
esw_create_prio_miss_group(struct mlx5_flow_table *ft)
{
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	struct mlx5_flow_group *g;
	u32 *flow_group_in;

	flow_group_in = kvzalloc(inlen, GFP_KERNEL);
	if (!flow_group_in)
		return ERR_PTR(-ENOMEM);

	memset(flow_group_in, 0, inlen);
	MLX5_SET(create_flow_group_in, flow_group_in, match_criteria_enable, 0);

	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, ft->max_fte - 1);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, ft->max_fte - 1);

	g = mlx5_create_flow_group(ft, flow_group_in);

	kfree(flow_group_in);

	return g;
}

static struct mlx5_flow_handle *
mlx5_eswitch_add_prio_miss_rule(struct mlx5_eswitch *esw, u32 chain, u32 prio)
{
	struct mlx5_flow_act flow_act = {0};
	struct mlx5_flow_destination dest= {};
	struct mlx5_flow_handle *rule;
	struct mlx5_flow_spec *spec;
	struct mlx5_flow_table *src;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec) {
		rule = ERR_PTR(-ENOMEM);
		goto out;
	}

	dest.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest.ft = esw->fdb_table.offloads.fdb;
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;

	src = esw->fdb_table.fdb_prio[chain][prio].fdb;
	rule =  mlx5_add_flow_rules(src, spec, &flow_act, &dest, 1);
	if (IS_ERR(rule)) {
		rule = ERR_CAST(rule);
		esw_warn(esw->dev,  "FDB: Failed to add miss flow rule err %d\n",
			 (int) PTR_ERR(rule));
		goto out;
	}

out:
	kvfree(spec);

	return rule;
}

static int esw_update_last_miss_rule(struct mlx5_eswitch *esw, u32 chain,
				     u32 start_prio)
{
	struct mlx5_flow_handle *old_miss_r = esw->fdb_table.miss_r[chain];
	struct mlx5_flow_handle *miss_r;
	u32 prio;

	if (chain >= FDB_MAX_CHAIN)
		return 0;

	for (prio = start_prio; prio >= 0 && prio <= FDB_MAX_PRIO; prio--) {
		if (!esw->fdb_table.fdb_prio[chain][prio].fdb)
			continue;

		miss_r = mlx5_eswitch_add_prio_miss_rule(esw, chain, prio);
		if (IS_ERR(miss_r)) {
			esw_warn(esw->dev, "Failed to update miss rule (table: %d, %d): %d\n",
				 chain, prio, (int) PTR_ERR(miss_r));
			return PTR_ERR(miss_r);
		}
		esw->fdb_table.miss_r[chain] = miss_r;
		esw->fdb_table.last_prio[chain] = prio;

		goto found;
	}

	esw->fdb_table.miss_r[chain] = NULL;
	esw->fdb_table.last_prio[chain] = 0;

found:
	if (old_miss_r)
		mlx5_del_flow_rules(old_miss_r);

	return 0;
}

static struct mlx5_flow_table *
esw_get_offloads_fast_fdb_table(struct mlx5_eswitch *esw, u32 chain, u32 prio)
{
	struct mlx5_core_dev *dev = esw->dev;
	struct mlx5_flow_namespace *root_ns;
	struct mlx5_flow_table *fdb = NULL;
	struct mlx5_flow_group *g;
	int table_prio, sz, num_groups;
	u32 flags = 0;

	if (prio > FDB_MAX_PRIO || chain > FDB_MAX_CHAIN) {
		esw_warn(dev, "max chain or prio\n");
		return ERR_PTR(-EOPNOTSUPP);
	}

	fdb = esw->fdb_table.fdb_prio[chain][prio].fdb;
	if (fdb)
		goto found;

	root_ns = mlx5_get_flow_namespace(dev, MLX5_FLOW_NAMESPACE_FDB);
	if (!root_ns) {
		esw_warn(dev, "Failed to get FDB flow namespace\n");
		fdb = ERR_PTR(-EOPNOTSUPP);
		goto err_ns;
	}

	if (esw->offloads.encap != DEVLINK_ESWITCH_ENCAP_MODE_NONE)
		flags |= MLX5_FLOW_TABLE_TUNNEL_EN;

	sz = (prio == 0 ? 1 : (esw->fdb_left / 2));
	sz = min_t(int, esw->fdb_max, sz);
	if (esw->fdb_fixed && prio) {
		sz = esw->fdb_fixed;
		if (esw->fdb_fixed > esw->fdb_left)
			sz = esw->fdb_left;
	}
	num_groups = (prio == 0 ? 1 : ESW_OFFLOADS_NUM_GROUPS);

	table_prio = FDB_FAST_PATH + (chain * (FDB_MAX_PRIO + 1)) + prio;
	fdb = mlx5_create_auto_grouped_flow_table(root_ns,
						  table_prio,
						  sz,
						  num_groups,
						  0,
						  flags);
	if (IS_ERR(fdb)) {
		esw_warn(dev, "Failed to create Fast path FDB Table err %d, chain: %d prio: %d, size: %d\n",
			 (int) PTR_ERR(fdb), chain, prio, sz);
		goto err_create;
	}

	/* TODO: avoid groups on not last prio, might be cost us an hop,
	 * or just use miss mode instead. */
	g = esw_create_prio_miss_group(fdb);
	if (IS_ERR(g)) {
		fdb = ERR_CAST(g);
		goto err_flow_g;
	}

	esw->fdb_left -= fdb->max_fte;
	esw->fdb_table.fdb_prio[chain][prio].fdb = fdb;
	esw->fdb_table.fdb_prio[chain][prio].miss_g = g;
	esw->fdb_table.fdb_prio[chain][prio].num_rules = 0;

	if (esw->fdb_table.last_prio[chain] <= prio)
		esw_update_last_miss_rule(esw, chain, prio);

found:
	esw->fdb_table.fdb_prio[chain][prio].num_rules++;
	return fdb;

err_flow_g:
	mlx5_destroy_flow_table(fdb);
err_create:
err_ns:
	return fdb;
}

void esw_put_offloads_fast_fdb_table(struct mlx5_eswitch *esw, u32 chain,
				     u32 prio, bool force)
{
	struct mlx5_flow_table *fdb = esw->fdb_table.fdb_prio[chain][prio].fdb;

	if (prio > FDB_MAX_PRIO || chain > FDB_MAX_CHAIN)
		return;

	if (!esw->fdb_table.fdb_prio[chain][prio].num_rules)
		return;

	if (--(esw->fdb_table.fdb_prio[chain][prio].num_rules) > 0 && !force)
		return;

	if (prio == esw->fdb_table.last_prio[chain])
		esw_update_last_miss_rule(esw, chain, prio - 1);

	mlx5_destroy_flow_group(esw->fdb_table.fdb_prio[chain][prio].miss_g);
	mlx5_destroy_flow_table(esw->fdb_table.fdb_prio[chain][prio].fdb);
	esw->fdb_table.fdb_prio[chain][prio].fdb = NULL;
	esw->fdb_table.fdb_prio[chain][prio].miss_g = NULL;
	esw->fdb_table.fdb_prio[chain][prio].num_rules = 0;
	esw->fdb_left += fdb->max_fte;
}

static void esw_destroy_offloads_fast_fdb_tables(struct mlx5_eswitch *esw)
{
	u32 prio, chain;

	for (chain = 0; chain <= FDB_MAX_CHAIN; chain++)
		for (prio = 0; prio <= FDB_MAX_PRIO; prio++)
			esw_put_offloads_fast_fdb_table(esw, chain, prio, true);
}

#define MAX_PF_SQ 256

static int esw_create_offloads_fdb_tables(struct mlx5_eswitch *esw, int nvports)
{
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	struct mlx5_flow_table_attr ft_attr = {};
	struct mlx5_core_dev *dev = esw->dev;
	struct mlx5_flow_namespace *root_ns;
	struct mlx5_flow_table *fdb = NULL;
	int table_size, ix, err = 0, max_flow;
	struct mlx5_flow_group *g;
	void *match_criteria;
	u32 *flow_group_in, max_flow_counter;
	u32 flags = 0;

	esw_debug(esw->dev, "Create offloads FDB Tables\n");
	flow_group_in = kvzalloc(inlen, GFP_KERNEL);
	if (!flow_group_in)
		return -ENOMEM;

	root_ns = mlx5_get_flow_namespace(dev, MLX5_FLOW_NAMESPACE_FDB);
	if (!root_ns) {
		esw_warn(dev, "Failed to get FDB flow namespace\n");
		err = -EOPNOTSUPP;
		goto ns_err;
	}

	max_flow_counter = (MLX5_CAP_GEN(dev, max_flow_counter_31_16) << 16) |
			    MLX5_CAP_GEN(dev, max_flow_counter_15_0);

	esw_warn(dev, "Create offloads FDB table, min (max esw size(2^%d), max_esw_num(2^%d), ft_max_dests(2^%d), log_max_flow: 2^%d  max counters(%d)*groups(%d))\n",
		  MLX5_CAP_ESW_FLOWTABLE_FDB(dev, log_max_ft_size),
		  MLX5_CAP_ESW_FLOWTABLE_FDB(dev, log_max_ft_num),
		  MLX5_CAP_ESW_FLOWTABLE_FDB(dev, log_max_destination),
		  MLX5_CAP_ESW_FLOWTABLE_FDB(dev, log_max_flow),
		  max_flow_counter, ESW_OFFLOADS_NUM_GROUPS);

	/* TODO: Make this better, maybe up to max counter size */
	max_flow = 1 << MLX5_CAP_ESW_FLOWTABLE_FDB(dev, log_max_flow);
	esw->fdb_left = min_t(int, max_flow_counter, max_flow);
	esw->fdb_max = 1 << MLX5_CAP_ESW_FLOWTABLE_FDB(dev, log_max_ft_size);
	esw_warn(dev, "FDB budget: %d (max per FDB: %d)\n",
		 esw->fdb_left, esw->fdb_max);

	table_size = nvports + MAX_PF_SQ + 1 + esw->total_vports;

	if (esw->offloads.encap != DEVLINK_ESWITCH_ENCAP_MODE_NONE)
		flags |= MLX5_FLOW_TABLE_TUNNEL_EN;

	ft_attr.flags = flags;
	ft_attr.max_fte = table_size;
	ft_attr.prio = FDB_SLOW_PATH;

	fdb = mlx5_create_flow_table(root_ns, &ft_attr);
	if (IS_ERR(fdb)) {
		err = PTR_ERR(fdb);
		esw_warn(dev, "Failed to create slow path FDB Table err %d\n", err);
		goto slow_fdb_err;
	}
	esw->fdb_table.offloads.fdb = fdb;

	if (true) { //fixed size
		int chain, prio;
		int chains = FDB_MAX_CHAIN + 1; //4
		int large_tables = chains * FDB_MAX_PRIO; //4 * 16 = 64

		//esw->fdb_fixed = rounddown_pow_of_two((esw->fdb_left - chains) / large_tables); // rounddown_pow2((8453984 - 4) / (4 * 16)) = 128K because 8453984 > 8M but FW max is actual 8M
		esw->fdb_fixed = rounddown_pow_of_two(rounddown_pow_of_two(esw->fdb_left) / large_tables); // rounddown_pow2(8M / (4 * 16)) = 128k
		esw->fdb_left = rounddown_pow_of_two(esw->fdb_left); //8M
		esw->fdb_fixed = 64*1024;
		esw_warn(dev, "Creating fixed size FDB tables of: %d flows (rem: %d)\n",
			 esw->fdb_fixed, esw->fdb_left);

		/* Create all ahead */
		for (chain = 0; chain <= FDB_MAX_CHAIN; chain++) {
			for (prio = 0; prio <= FDB_MAX_PRIO; prio++) {
				esw_get_offloads_fast_fdb_table(esw, chain, prio);
			}
		}
	}

	/* create send-to-vport group */
	memset(flow_group_in, 0, inlen);
	MLX5_SET(create_flow_group_in, flow_group_in, match_criteria_enable,
		 MLX5_MATCH_MISC_PARAMETERS);

	match_criteria = MLX5_ADDR_OF(create_flow_group_in, flow_group_in, match_criteria);

	MLX5_SET_TO_ONES(fte_match_param, match_criteria, misc_parameters.source_sqn);
	MLX5_SET_TO_ONES(fte_match_param, match_criteria, misc_parameters.source_port);

	ix = nvports + MAX_PF_SQ;
	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, 0);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, ix - 1);

	g = mlx5_create_flow_group(fdb, flow_group_in);
	if (IS_ERR(g)) {
		err = PTR_ERR(g);
		esw_warn(dev, "Failed to create send-to-vport flow group err(%d)\n", err);
		goto send_vport_err;
	}
	esw->fdb_table.offloads.send_to_vport_grp = g;

	/* create peer esw miss group */
	memset(flow_group_in, 0, inlen);
	MLX5_SET(create_flow_group_in, flow_group_in, match_criteria_enable,
		MLX5_MATCH_MISC_PARAMETERS);

	match_criteria = MLX5_ADDR_OF(create_flow_group_in, flow_group_in, match_criteria);

	MLX5_SET_TO_ONES(fte_match_param, match_criteria, misc_parameters.source_port);
	MLX5_SET_TO_ONES(fte_match_param, match_criteria, misc_parameters.source_eswitch_owner_vhca_id);

	MLX5_SET(create_flow_group_in, flow_group_in, source_eswitch_owner_vhca_id_valid, 1);
	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, ix);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, ix + esw->total_vports - 1);
	ix += esw->total_vports;

	g = mlx5_create_flow_group(fdb, flow_group_in);
	if (IS_ERR(g)) {
		err = PTR_ERR(g);
		esw_warn(dev, "Failed to create peer miss flow group err(%d)\n", err);
		goto peer_miss_err;
	}
	esw->fdb_table.offloads.peer_miss_grp = g;

	/* create miss group */
	memset(flow_group_in, 0, inlen);
	MLX5_SET(create_flow_group_in, flow_group_in, match_criteria_enable, 0);

	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, ix);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, ix + 1);

	g = mlx5_create_flow_group(fdb, flow_group_in);
	if (IS_ERR(g)) {
		err = PTR_ERR(g);
		esw_warn(dev, "Failed to create miss flow group err(%d)\n", err);
		goto miss_err;
	}
	esw->fdb_table.offloads.miss_grp = g;

	err = esw_add_fdb_miss_rule(esw);
	if (err)
		goto miss_rule_err;

	return 0;

miss_rule_err:
	mlx5_destroy_flow_group(esw->fdb_table.offloads.miss_grp);
miss_err:
	mlx5_destroy_flow_group(esw->fdb_table.offloads.peer_miss_grp);
peer_miss_err:
	mlx5_destroy_flow_group(esw->fdb_table.offloads.send_to_vport_grp);
send_vport_err:
	mlx5_destroy_flow_table(esw->fdb_table.offloads.fdb);
slow_fdb_err:
	esw_destroy_offloads_fast_fdb_tables(esw);
ns_err:
	kvfree(flow_group_in);
	return err;
}

static struct mlx5_flow_handle *
esw_add_fdb_peer_miss_rule(struct mlx5_eswitch *esw,
			   struct mlx5_core_dev *peer_dev,
			   int vport)
{
	struct mlx5_flow_act flow_act = {0};
	struct mlx5_flow_destination dest= {};
	struct mlx5_flow_handle *flow_rule = NULL;
	struct mlx5_flow_spec *spec;
	void *misc;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec) {
		flow_rule = ERR_PTR(-ENOMEM);
		goto out;
	}

	misc = MLX5_ADDR_OF(fte_match_param, spec->match_value, misc_parameters);

	MLX5_SET(fte_match_set_misc, misc, source_port, vport);
	MLX5_SET(fte_match_set_misc, misc, source_eswitch_owner_vhca_id,
		 MLX5_CAP_GEN(peer_dev, vhca_id));

	spec->match_criteria_enable = MLX5_MATCH_MISC_PARAMETERS;

	misc = MLX5_ADDR_OF(fte_match_param, spec->match_criteria, misc_parameters);
	MLX5_SET_TO_ONES(fte_match_set_misc, misc, source_port);
	MLX5_SET_TO_ONES(fte_match_set_misc, misc, source_eswitch_owner_vhca_id);

	dest.type = MLX5_FLOW_DESTINATION_TYPE_VPORT;
	dest.vport_num = 0;
	dest.destination_eswitch_owner_vhca_id = MLX5_CAP_GEN(peer_dev, vhca_id);
	dest.destination_eswitch_owner_vhca_id_valid = 1;
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;

	return mlx5_add_flow_rules(esw->fdb_table.offloads.fdb, spec,
					&flow_act, &dest, 1);
out:
	kvfree(spec);
	return flow_rule;
}

static void esw_del_peer_miss_rules(struct mlx5_eswitch *esw)
{
	struct mlx5_flow_handle **flows;
	int nvports;
	int i;

	flows = esw->fdb_table.offloads.peer_miss_rules;
	nvports = esw->fdb_table.offloads.peer_miss_rules_count;

	for (i = 1; i < nvports; i++)
		if (flows[i])
			mlx5_del_flow_rules(flows[i]);
	kvfree(flows);
	esw->fdb_table.offloads.peer_miss_rules = NULL;
}

static void esw_add_peer_miss_rules(struct mlx5_eswitch *esw, int nvports)
{
	struct mlx5_core_dev *peer_dev = mlx5_lag_get_peer_mdev(esw->dev);
	struct mlx5_flow_handle *flow_rule;
	struct mlx5_flow_handle **flows;
	int i;

	flows = kvzalloc(nvports * sizeof(*flows), GFP_KERNEL);
	if (!flows) {
		esw_warn(esw->dev, "Error allocating memory for peer miss rules\n");
		// TODO return error
		return;
	}

	esw->fdb_table.offloads.peer_miss_rules = flows;
	esw->fdb_table.offloads.peer_miss_rules_count = nvports;

	for (i = 1; i < nvports; i++) {
		flow_rule = esw_add_fdb_peer_miss_rule(esw, peer_dev, i);
		if (IS_ERR(flow_rule)) {
			esw_warn(esw->dev, "FDB: Failed to add miss flow rule err %d\n", (int) PTR_ERR(flow_rule));
			goto out;
		}
		flows[i] = flow_rule;
	}

	return;
out:
	esw_del_peer_miss_rules(esw);
	// TODO return error
}

static void esw_destroy_offloads_fdb_tables(struct mlx5_eswitch *esw)
{
	if (!esw->fdb_table.offloads.fdb)
		return;

	esw_debug(esw->dev, "Destroy offloads FDB Tables\n");
	mlx5_del_flow_rules(esw->fdb_table.offloads.miss_rule);
	mlx5_destroy_flow_group(esw->fdb_table.offloads.send_to_vport_grp);
	mlx5_destroy_flow_group(esw->fdb_table.offloads.miss_grp);

	if (esw->fdb_fixed) {
		int chain, prio;

		for (chain = 0; chain <= FDB_MAX_CHAIN; chain++)
			for (prio = 0; prio <= FDB_MAX_PRIO; prio++)
				esw_put_offloads_fast_fdb_table(esw, chain,
								prio, false);
	}
	mlx5_destroy_flow_table(esw->fdb_table.offloads.fdb);
	esw_destroy_offloads_fast_fdb_tables(esw);
}

static int esw_create_offloads_table(struct mlx5_eswitch *esw)
{
	struct mlx5_flow_table_attr ft_attr = {};
	struct mlx5_core_dev *dev = esw->dev;
	struct mlx5_flow_table *ft_offloads;
	struct mlx5_flow_namespace *ns;
	int err = 0;

	ns = mlx5_get_flow_namespace(dev, MLX5_FLOW_NAMESPACE_OFFLOADS);
	if (!ns) {
		esw_warn(esw->dev, "Failed to get offloads flow namespace\n");
		return -EOPNOTSUPP;
	}

	ft_attr.max_fte = dev->priv.sriov.num_vfs + 2;

	ft_offloads = mlx5_create_flow_table(ns, &ft_attr);
	if (IS_ERR(ft_offloads)) {
		err = PTR_ERR(ft_offloads);
		esw_warn(esw->dev, "Failed to create offloads table, err %d\n", err);
		return err;
	}

	esw->offloads.ft_offloads = ft_offloads;
	return 0;
}

static void esw_destroy_offloads_table(struct mlx5_eswitch *esw)
{
	struct mlx5_esw_offload *offloads = &esw->offloads;

	mlx5_destroy_flow_table(offloads->ft_offloads);
}

static int esw_create_vport_rx_group(struct mlx5_eswitch *esw)
{
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	struct mlx5_flow_group *g;
	struct mlx5_priv *priv = &esw->dev->priv;
	u32 *flow_group_in;
	void *match_criteria, *misc;
	int err = 0;
	int nvports = priv->sriov.num_vfs + 2;

	flow_group_in = kvzalloc(inlen, GFP_KERNEL);
	if (!flow_group_in)
		return -ENOMEM;

	/* create vport rx group */
	memset(flow_group_in, 0, inlen);
	MLX5_SET(create_flow_group_in, flow_group_in, match_criteria_enable,
		 MLX5_MATCH_MISC_PARAMETERS);

	match_criteria = MLX5_ADDR_OF(create_flow_group_in, flow_group_in, match_criteria);
	misc = MLX5_ADDR_OF(fte_match_param, match_criteria, misc_parameters);
	MLX5_SET_TO_ONES(fte_match_set_misc, misc, source_port);

	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, 0);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, nvports - 1);

	g = mlx5_create_flow_group(esw->offloads.ft_offloads, flow_group_in);

	if (IS_ERR(g)) {
		err = PTR_ERR(g);
		mlx5_core_warn(esw->dev, "Failed to create vport rx group err %d\n", err);
		goto out;
	}

	esw->offloads.vport_rx_group = g;
out:
	kfree(flow_group_in);
	return err;
}

static void esw_destroy_vport_rx_group(struct mlx5_eswitch *esw)
{
	mlx5_destroy_flow_group(esw->offloads.vport_rx_group);
}

struct mlx5_flow_handle *
mlx5_eswitch_create_vport_rx_rule(struct mlx5_eswitch *esw, int vport, u32 tirn)
{
	struct mlx5_flow_act flow_act = {0};
	struct mlx5_flow_destination dest = {};
	struct mlx5_flow_handle *flow_rule;
	struct mlx5_flow_spec *spec;
	void *misc;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec) {
		flow_rule = ERR_PTR(-ENOMEM);
		goto out;
	}

	misc = MLX5_ADDR_OF(fte_match_param, spec->match_value, misc_parameters);
	MLX5_SET(fte_match_set_misc, misc, source_port, vport);

	misc = MLX5_ADDR_OF(fte_match_param, spec->match_criteria, misc_parameters);
	MLX5_SET_TO_ONES(fte_match_set_misc, misc, source_port);

	spec->match_criteria_enable = MLX5_MATCH_MISC_PARAMETERS;
	dest.type = MLX5_FLOW_DESTINATION_TYPE_TIR;
	dest.tir_num = tirn;

	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	flow_rule = mlx5_add_flow_rules(esw->offloads.ft_offloads, spec,
					&flow_act, &dest, 1);
	if (IS_ERR(flow_rule)) {
		esw_warn(esw->dev, "fs offloads: Failed to add vport rx rule err %ld\n", PTR_ERR(flow_rule));
		goto out;
	}

out:
	kvfree(spec);
	return flow_rule;
}

static int esw_offloads_start(struct mlx5_eswitch *esw)
{
	int err, err1, num_vfs = esw->dev->priv.sriov.num_vfs;

	if (esw->mode != SRIOV_LEGACY) {
		esw_warn(esw->dev, "Can't set offloads mode, SRIOV legacy not enabled\n");
		return -EINVAL;
	}

	mlx5_eswitch_disable_sriov(esw);
	err = mlx5_eswitch_enable_sriov(esw, num_vfs, SRIOV_OFFLOADS);
	if (err) {
		esw_warn(esw->dev, "Failed setting eswitch to offloads, err %d\n", err);
		err1 = mlx5_eswitch_enable_sriov(esw, num_vfs, SRIOV_LEGACY);
		if (err1)
			esw_warn(esw->dev, "Failed setting eswitch back to legacy, err %d\n", err1);
	}
	if (esw->offloads.inline_mode == MLX5_INLINE_MODE_NONE) {
		if (mlx5_eswitch_inline_mode_get(esw,
						 num_vfs,
						 &esw->offloads.inline_mode)) {
			esw->offloads.inline_mode = MLX5_INLINE_MODE_L2;
			esw_warn(esw->dev, "Inline mode is different between vports\n");
		}
	}
	return err;
}

int esw_offloads_init(struct mlx5_eswitch *esw, int nvports)
{
	struct mlx5_eswitch_rep *rep;
	int vport;
	int err;

	/* disable PF RoCE so missed packets don't go through RoCE steering */
	mlx5_dev_list_lock();
	mlx5_remove_dev_by_protocol(esw->dev, MLX5_INTERFACE_PROTOCOL_IB);
	mlx5_dev_list_unlock();

	err = esw_create_offloads_fdb_tables(esw, nvports);
	if (err)
		goto create_fdb_err;

	err = esw_create_offloads_table(esw);
	if (err)
		goto create_ft_err;

	err = esw_create_vport_rx_group(esw);
	if (err)
		goto create_fg_err;

	for (vport = 0; vport < nvports; vport++) {
		rep = &esw->offloads.vport_reps[vport];
		if (!rep->valid)
			continue;

		err = rep->load(esw, rep);
		if (err)
			goto err_reps;
	}

	if (MLX5_CAP_ESW(esw->dev, merged_eswitch)) {
		struct mlx5_core_dev *peer_dev = mlx5_lag_get_peer_mdev(esw->dev);
		struct mlx5_eswitch *peer_esw = peer_dev ? peer_dev->priv.eswitch : 0;
		int peer_nvports;

		if (!peer_esw || !MLX5_CAP_GEN(peer_dev, vport_group_manager) ||
		    MLX5_CAP_GEN(peer_dev, port_type) != MLX5_CAP_PORT_TYPE_ETH)
			return 0;

		if (peer_esw->mode != SRIOV_OFFLOADS) {
			return 0;
		}

		peer_nvports = peer_dev->priv.eswitch->enabled_vports;

		// TODO check error
		esw_add_peer_miss_rules(esw, peer_nvports);
		esw_add_peer_miss_rules(peer_esw, nvports);

		if (mlx5_lag_is_multipath(esw->dev))
			mlx5_lag_set_multipath_ready(esw->dev);
	}

	return 0;

err_reps:
	for (vport--; vport >= 0; vport--) {
		rep = &esw->offloads.vport_reps[vport];
		if (!rep->valid)
			continue;
		rep->unload(esw, rep);
	}
	esw_destroy_vport_rx_group(esw);

create_fg_err:
	esw_destroy_offloads_table(esw);

create_ft_err:
	esw_destroy_offloads_fdb_tables(esw);

create_fdb_err:
	/* enable back PF RoCE */
	mlx5_dev_list_lock();
	mlx5_add_dev_by_protocol(esw->dev, MLX5_INTERFACE_PROTOCOL_IB);
	mlx5_dev_list_unlock();

	return err;
}

static int esw_offloads_stop(struct mlx5_eswitch *esw)
{
	int err, err1, num_vfs = esw->dev->priv.sriov.num_vfs;

	mlx5_eswitch_disable_sriov(esw);
	err = mlx5_eswitch_enable_sriov(esw, num_vfs, SRIOV_LEGACY);
	if (err) {
		esw_warn(esw->dev, "Failed setting eswitch to legacy, err %d\n", err);
		err1 = mlx5_eswitch_enable_sriov(esw, num_vfs, SRIOV_OFFLOADS);
		if (err1)
			esw_warn(esw->dev, "Failed setting eswitch back to offloads, err %d\n", err);
	}

	/* enable back PF RoCE */
	mlx5_dev_list_lock();
	mlx5_add_dev_by_protocol(esw->dev, MLX5_INTERFACE_PROTOCOL_IB);
	mlx5_dev_list_unlock();

	return err;
}

void esw_offloads_cleanup(struct mlx5_eswitch *esw, int nvports)
{
	struct mlx5_eswitch_rep *rep;
	int vport;

	mlx5_lag_unset_multipath_ready(esw->dev);

	for (vport = nvports - 1; vport >= 0; vport--) {
		rep = &esw->offloads.vport_reps[vport];
		if (!rep->valid)
			continue;
		rep->unload(esw, rep);
	}

	if (esw->fdb_table.offloads.peer_miss_rules)
		esw_del_peer_miss_rules(esw);

	mlx5_destroy_flow_group(esw->fdb_table.offloads.peer_miss_grp);

	esw_destroy_vport_rx_group(esw);
	esw_destroy_offloads_table(esw);
	esw_destroy_offloads_fdb_tables(esw);
}

static int esw_mode_from_devlink(u16 mode, u16 *mlx5_mode)
{
	switch (mode) {
	case DEVLINK_ESWITCH_MODE_LEGACY:
		*mlx5_mode = SRIOV_LEGACY;
		break;
	case DEVLINK_ESWITCH_MODE_SWITCHDEV:
		*mlx5_mode = SRIOV_OFFLOADS;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int esw_mode_to_devlink(u16 mlx5_mode, u16 *mode)
{
	switch (mlx5_mode) {
	case SRIOV_LEGACY:
		*mode = DEVLINK_ESWITCH_MODE_LEGACY;
		break;
	case SRIOV_OFFLOADS:
		*mode = DEVLINK_ESWITCH_MODE_SWITCHDEV;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int esw_inline_mode_from_devlink(u8 mode, u8 *mlx5_mode)
{
	switch (mode) {
	case DEVLINK_ESWITCH_INLINE_MODE_NONE:
		*mlx5_mode = MLX5_INLINE_MODE_NONE;
		break;
	case DEVLINK_ESWITCH_INLINE_MODE_LINK:
		*mlx5_mode = MLX5_INLINE_MODE_L2;
		break;
	case DEVLINK_ESWITCH_INLINE_MODE_NETWORK:
		*mlx5_mode = MLX5_INLINE_MODE_IP;
		break;
	case DEVLINK_ESWITCH_INLINE_MODE_TRANSPORT:
		*mlx5_mode = MLX5_INLINE_MODE_TCP_UDP;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int esw_inline_mode_to_devlink(u8 mlx5_mode, u8 *mode)
{
	switch (mlx5_mode) {
	case MLX5_INLINE_MODE_NONE:
		*mode = DEVLINK_ESWITCH_INLINE_MODE_NONE;
		break;
	case MLX5_INLINE_MODE_L2:
		*mode = DEVLINK_ESWITCH_INLINE_MODE_LINK;
		break;
	case MLX5_INLINE_MODE_IP:
		*mode = DEVLINK_ESWITCH_INLINE_MODE_NETWORK;
		break;
	case MLX5_INLINE_MODE_TCP_UDP:
		*mode = DEVLINK_ESWITCH_INLINE_MODE_TRANSPORT;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int mlx5_devlink_eswitch_check(struct devlink *devlink)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);

	if (MLX5_CAP_GEN(dev, port_type) != MLX5_CAP_PORT_TYPE_ETH)
		return -EOPNOTSUPP;

	if (!MLX5_CAP_GEN(dev, vport_group_manager))
		return -EOPNOTSUPP;

	if (dev->priv.eswitch->mode == SRIOV_NONE)
		return -EOPNOTSUPP;

	return 0;
}

int mlx5_devlink_eswitch_mode_set(struct devlink *devlink, u16 mode)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	u16 cur_mlx5_mode, mlx5_mode = 0;
	int err;

	err = mlx5_devlink_eswitch_check(devlink);
	if (err)
		return err;

	cur_mlx5_mode = dev->priv.eswitch->mode;

	if (esw_mode_from_devlink(mode, &mlx5_mode))
		return -EINVAL;

	if (cur_mlx5_mode == mlx5_mode)
		return 0;

	if (mode == DEVLINK_ESWITCH_MODE_SWITCHDEV)
		return esw_offloads_start(dev->priv.eswitch);
	else if (mode == DEVLINK_ESWITCH_MODE_LEGACY)
		return esw_offloads_stop(dev->priv.eswitch);
	else
		return -EINVAL;
}

int mlx5_devlink_eswitch_mode_get(struct devlink *devlink, u16 *mode)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	int err;

	err = mlx5_devlink_eswitch_check(devlink);
	if (err)
		return err;

	return esw_mode_to_devlink(dev->priv.eswitch->mode, mode);
}

int mlx5_devlink_eswitch_inline_mode_set(struct devlink *devlink, u8 mode)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	struct mlx5_eswitch *esw = dev->priv.eswitch;
	int err, vport;
	u8 mlx5_mode;

	err = mlx5_devlink_eswitch_check(devlink);
	if (err)
		return err;

	switch (MLX5_CAP_ETH(dev, wqe_inline_mode)) {
	case MLX5_CAP_INLINE_MODE_NOT_REQUIRED:
		if (mode == DEVLINK_ESWITCH_INLINE_MODE_NONE)
			return 0;
		/* fall through */
	case MLX5_CAP_INLINE_MODE_L2:
		esw_warn(dev, "Inline mode can't be set\n");
		return -EOPNOTSUPP;
	case MLX5_CAP_INLINE_MODE_VPORT_CONTEXT:
		break;
	}

	if (esw->offloads.num_flows > 0) {
		esw_warn(dev, "Can't set inline mode when flows are configured\n");
		return -EOPNOTSUPP;
	}

	err = esw_inline_mode_from_devlink(mode, &mlx5_mode);
	if (err)
		goto out;

	for (vport = 1; vport < esw->enabled_vports; vport++) {
		err = mlx5_modify_nic_vport_min_inline(dev, vport, mlx5_mode);
		if (err) {
			esw_warn(dev, "Failed to set min inline on vport %d\n",
				 vport);
			goto revert_inline_mode;
		}
	}

	esw->offloads.inline_mode = mlx5_mode;
	return 0;

revert_inline_mode:
	while (--vport > 0)
		mlx5_modify_nic_vport_min_inline(dev,
						 vport,
						 esw->offloads.inline_mode);
out:
	return err;
}

int mlx5_devlink_eswitch_inline_mode_get(struct devlink *devlink, u8 *mode)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	struct mlx5_eswitch *esw = dev->priv.eswitch;
	int err;

	err = mlx5_devlink_eswitch_check(devlink);
	if (err)
		return err;

	return esw_inline_mode_to_devlink(esw->offloads.inline_mode, mode);
}

int mlx5_eswitch_inline_mode_get(struct mlx5_eswitch *esw, int nvfs, u8 *mode)
{
	u8 prev_mlx5_mode, mlx5_mode = MLX5_INLINE_MODE_L2;
	struct mlx5_core_dev *dev = esw->dev;
	int vport;

	if (!MLX5_CAP_GEN(dev, vport_group_manager))
		return -EOPNOTSUPP;

	if (esw->mode == SRIOV_NONE)
		return -EOPNOTSUPP;

	switch (MLX5_CAP_ETH(dev, wqe_inline_mode)) {
	case MLX5_CAP_INLINE_MODE_NOT_REQUIRED:
		mlx5_mode = MLX5_INLINE_MODE_NONE;
		goto out;
	case MLX5_CAP_INLINE_MODE_L2:
		mlx5_mode = MLX5_INLINE_MODE_L2;
		goto out;
	case MLX5_CAP_INLINE_MODE_VPORT_CONTEXT:
		goto query_vports;
	}

query_vports:
	for (vport = 1; vport <= nvfs; vport++) {
		mlx5_query_nic_vport_min_inline(dev, vport, &mlx5_mode);
		if (vport > 1 && prev_mlx5_mode != mlx5_mode)
			return -EINVAL;
		prev_mlx5_mode = mlx5_mode;
	}

out:
	*mode = mlx5_mode;
	return 0;
}

int mlx5_devlink_eswitch_encap_mode_set(struct devlink *devlink, u8 encap)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	struct mlx5_eswitch *esw = dev->priv.eswitch;
	int err;

	err = mlx5_devlink_eswitch_check(devlink);
	if (err)
		return err;

	if (encap != DEVLINK_ESWITCH_ENCAP_MODE_NONE &&
	    (!MLX5_CAP_ESW_FLOWTABLE_FDB(dev, encap) ||
	     !MLX5_CAP_ESW_FLOWTABLE_FDB(dev, decap)))
		return -EOPNOTSUPP;

	if (encap && encap != DEVLINK_ESWITCH_ENCAP_MODE_BASIC)
		return -EOPNOTSUPP;

	if (esw->mode == SRIOV_LEGACY) {
		esw->offloads.encap = encap;
		return 0;
	}

	if (esw->offloads.encap == encap)
		return 0;

	if (esw->offloads.num_flows > 0) {
		esw_warn(dev, "Can't set encapsulation when flows are configured\n");
		return -EOPNOTSUPP;
	}

	esw->offloads.encap = encap;

	return err;
}

int mlx5_devlink_eswitch_encap_mode_get(struct devlink *devlink, u8 *encap)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	struct mlx5_eswitch *esw = dev->priv.eswitch;
	int err;

	err = mlx5_devlink_eswitch_check(devlink);
	if (err)
		return err;

	*encap = esw->offloads.encap;
	return 0;
}

int mlx5_devlink_eswitch_multipath_mode_set(struct devlink *devlink, u8 mp)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	int err = 0;

	if (MLX5_CAP_GEN(dev, port_type) != MLX5_CAP_PORT_TYPE_ETH)
		return -EOPNOTSUPP;

	if (!MLX5_CAP_GEN(dev, vport_group_manager))
		return -EOPNOTSUPP;

	if (mp && mlx5_lag_is_multipath(dev))
		return 0;

	if (!mp && !mlx5_lag_is_multipath(dev))
		return 0;

	if (mp)
		err = mlx5_lag_activate_multipath(dev);
	else
		err = mlx5_lag_deactivate_multipath(dev);

	return err;
}

int mlx5_devlink_eswitch_multipath_mode_get(struct devlink *devlink, u8 *mp)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	int err;

	err = mlx5_devlink_eswitch_check(devlink);
	if (err)
		return err;

	*mp = mlx5_lag_is_multipath(dev);
	return 0;
}

void mlx5_eswitch_register_vport_rep(struct mlx5_eswitch *esw,
				     int vport_index,
				     struct mlx5_eswitch_rep *__rep)
{
	struct mlx5_esw_offload *offloads = &esw->offloads;
	struct mlx5_eswitch_rep *rep;

	rep = &offloads->vport_reps[vport_index];

	memset(rep, 0, sizeof(*rep));

	rep->load   = __rep->load;
	rep->unload = __rep->unload;
	rep->vport  = __rep->vport;
	rep->netdev = __rep->netdev;
	ether_addr_copy(rep->hw_id, __rep->hw_id);

	INIT_LIST_HEAD(&rep->vport_sqs_list);
	rep->valid = true;
}

void mlx5_eswitch_unregister_vport_rep(struct mlx5_eswitch *esw,
				       int vport_index)
{
	struct mlx5_esw_offload *offloads = &esw->offloads;
	struct mlx5_eswitch_rep *rep;

	rep = &offloads->vport_reps[vport_index];

	if (esw->mode == SRIOV_OFFLOADS && esw->vports[vport_index].enabled)
		rep->unload(esw, rep);

	rep->valid = false;
}

struct net_device *mlx5_eswitch_get_uplink_netdev(struct mlx5_eswitch *esw)
{
#define UPLINK_REP_INDEX 0
	struct mlx5_esw_offload *offloads = &esw->offloads;
	struct mlx5_eswitch_rep *rep;

	rep = &offloads->vport_reps[UPLINK_REP_INDEX];
	return rep->netdev;
}

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
	FDB_SLOW_PATH = 1,
};

#define fdb_prio_table(chain, prio) \
	esw->fdb_table.offloads.fdb_prio[(chain)][(prio)]

static struct mlx5_flow_table *
esw_get_prio_table(struct mlx5_eswitch *esw, u32 chain, u32 prio, bool fast);
static void
esw_put_prio_table(struct mlx5_eswitch *esw, u32 chain, u32 prio, bool fast);

bool
mlx5_eswitch_is_chain_in_range(struct mlx5_eswitch *esw, u32 chain)
{
	if (!esw || esw->mode != SRIOV_OFFLOADS)
		return true;
	if (chain <= FDB_MAX_CHAIN || esw->fdb_fixed)
		return true;

	esw_warn(esw->dev, "Requested chain %d is out of range (0-%d)\n",
		 chain, FDB_MAX_CHAIN);
	return false;
}

bool
mlx5_eswitch_is_prio_in_range(struct mlx5_eswitch *esw, u32 prio)
{
	if (!esw || esw->mode != SRIOV_OFFLOADS)
		return true;
	if (prio <= FDB_MAX_PRIO || esw->fdb_fixed)
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
	struct mlx5_flow_destination dest[MLX5_MAX_FLOW_FWD_VPORTS + 2] = {};
	struct mlx5_flow_act flow_act = {0};
	struct mlx5_fc *counter = NULL;
	struct mlx5_flow_handle *rule;
	struct mlx5_flow_table *fdb;
	bool mirror = (attr->mirror_count > 0);
	int j, i = 0;
	void *misc;

	if (esw->mode != SRIOV_OFFLOADS)
		return ERR_PTR(-EOPNOTSUPP);

	flow_act.action = attr->action;
	/* if per flow vlan pop/push is emulated, don't set that into the firmware */
	if (!mlx5_eswitch_vlan_actions_supported(esw->dev))
		flow_act.action &= ~(MLX5_FLOW_CONTEXT_ACTION_VLAN_PUSH |
				     MLX5_FLOW_CONTEXT_ACTION_VLAN_POP);
	else if (flow_act.action & MLX5_FLOW_CONTEXT_ACTION_VLAN_PUSH) {
		flow_act.vlan.ethtype = ntohs(attr->vlan_proto);
		flow_act.vlan.vid = attr->vlan_vid;
		flow_act.vlan.prio = attr->vlan_prio;
	}

	if (flow_act.action & MLX5_FLOW_CONTEXT_ACTION_FWD_DEST) {
		if (MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE == attr->dest_type) {
			struct mlx5_flow_table *ft;

			if (attr->dest_chain <= attr->chain) {
				esw_warn(esw->dev, "can't forward to the same or earlier chain (%d->%d)\n",
					 attr->chain, attr->dest_chain);
				rule = ERR_PTR(-EINVAL);
				goto err_create_goto_table;
			}

			ft = esw_get_prio_table(esw, attr->dest_chain, 1, true);
			if (IS_ERR(ft)) {
				rule = ERR_CAST(ft);
				goto err_create_goto_table;
			}

			dest[i].type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
			dest[i].ft = ft;
			i++;
		} else {
			for (j = attr->mirror_count; j < attr->out_count; j++) {
				dest[i].type = MLX5_FLOW_DESTINATION_TYPE_VPORT;
				dest[i].vport.num = attr->out_rep[j]->vport;
				dest[i].vport.vhca_id =
					MLX5_CAP_GEN(attr->out_mdev[j], vhca_id);
				dest[i].vport.vhca_id_valid = !!MLX5_CAP_ESW(esw->dev, merged_eswitch);
				i++;
			}
		}
	}
	if (flow_act.action & MLX5_FLOW_CONTEXT_ACTION_COUNT) {
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

	if (MLX5_CAP_ESW(esw->dev, merged_eswitch))
		MLX5_SET(fte_match_set_misc, misc,
			 source_eswitch_owner_vhca_id,
			 MLX5_CAP_GEN(attr->in_mdev, vhca_id));

	misc = MLX5_ADDR_OF(fte_match_param, spec->match_criteria, misc_parameters);
	MLX5_SET_TO_ONES(fte_match_set_misc, misc, source_port);
	if (MLX5_CAP_ESW(esw->dev, merged_eswitch))
		MLX5_SET_TO_ONES(fte_match_set_misc, misc,
				 source_eswitch_owner_vhca_id);

	if (attr->match_level == MLX5_MATCH_NONE)
		spec->match_criteria_enable = MLX5_MATCH_MISC_PARAMETERS;
	else
		spec->match_criteria_enable = MLX5_MATCH_OUTER_HEADERS |
					      MLX5_MATCH_MISC_PARAMETERS;

	if (flow_act.action & MLX5_FLOW_CONTEXT_ACTION_DECAP)
		spec->match_criteria_enable |= MLX5_MATCH_INNER_HEADERS;

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR)
		flow_act.modify_id = attr->mod_hdr_id;

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_ENCAP)
		flow_act.encap_id = attr->encap_id;

	fdb = esw_get_prio_table(esw, attr->chain, attr->prio, !mirror);
	if (IS_ERR(fdb)) {
		rule = ERR_CAST(fdb);
		goto err_esw_create;
	}

	rule = mlx5_add_flow_rules(fdb, spec, &flow_act, dest, i);
	if (IS_ERR(rule))
		goto err_add_rule;

	esw->offloads.num_flows++;

	return rule;

err_add_rule:
	esw_put_prio_table(esw, attr->chain, attr->prio, !mirror);
err_esw_create:
	mlx5_fc_destroy(esw->dev, counter);
err_counter_alloc:
	if (MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE == attr->dest_type)
		esw_put_prio_table(esw, attr->dest_chain, 1, true);
err_create_goto_table:
	return rule;
}

struct mlx5_flow_handle *
mlx5_eswitch_add_fwd_rule(struct mlx5_eswitch *esw,
			  struct mlx5_flow_spec *spec,
			  struct mlx5_esw_flow_attr *attr)
{
	struct mlx5_flow_destination dest[MLX5_MAX_FLOW_FWD_VPORTS + 1] = {};
	struct mlx5_flow_act flow_act = {0};
	struct mlx5_flow_handle *rule;
	struct mlx5_flow_table *fwd_fdb;
	struct mlx5_flow_table *fast_fdb;
	void *misc;
	int i;

	fast_fdb = esw_get_prio_table(esw, attr->chain, attr->prio, true);
	if (IS_ERR(fast_fdb)) {
		rule = ERR_CAST(fast_fdb);
		goto err_get_fast;
	}

	fwd_fdb = esw_get_prio_table(esw, attr->chain, attr->prio, false);
	if (IS_ERR(fwd_fdb)) {
		rule = ERR_CAST(fwd_fdb);
		goto err_get_fwd;
	}

	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	for (i = 0; i < attr->mirror_count; i++) {
		dest[i].type = MLX5_FLOW_DESTINATION_TYPE_VPORT;
		dest[i].vport.num = attr->out_rep[i]->vport;
		dest[i].vport.vhca_id =
			MLX5_CAP_GEN(attr->out_mdev[i], vhca_id);
		dest[i].vport.vhca_id_valid = !!MLX5_CAP_ESW(esw->dev, merged_eswitch);
	}
	dest[i].type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest[i].ft = fwd_fdb,
	i++;

	misc = MLX5_ADDR_OF(fte_match_param, spec->match_value, misc_parameters);
	MLX5_SET(fte_match_set_misc, misc, source_port, attr->in_rep->vport);

	if (MLX5_CAP_ESW(esw->dev, merged_eswitch))
		MLX5_SET(fte_match_set_misc, misc,
			 source_eswitch_owner_vhca_id,
			 MLX5_CAP_GEN(attr->in_mdev, vhca_id));

	misc = MLX5_ADDR_OF(fte_match_param, spec->match_criteria, misc_parameters);
	MLX5_SET_TO_ONES(fte_match_set_misc, misc, source_port);
	if (MLX5_CAP_ESW(esw->dev, merged_eswitch))
		MLX5_SET_TO_ONES(fte_match_set_misc, misc,
				 source_eswitch_owner_vhca_id);

	if (attr->match_level == MLX5_MATCH_NONE)
		spec->match_criteria_enable = MLX5_MATCH_MISC_PARAMETERS;
	else
		spec->match_criteria_enable = MLX5_MATCH_OUTER_HEADERS |
					      MLX5_MATCH_MISC_PARAMETERS;

	rule = mlx5_add_flow_rules(fast_fdb, spec, &flow_act, dest, i);

	if (IS_ERR(rule))
		goto add_err;

	esw->offloads.num_flows++;

	return rule;
add_err:
	esw_put_prio_table(esw, attr->chain, attr->prio, false);
err_get_fast:
	esw_put_prio_table(esw, attr->chain, attr->prio, true);
err_get_fwd:
	return rule;
}

void
mlx5_eswitch_del_offloaded_rule(struct mlx5_eswitch *esw,
				struct mlx5_flow_handle *rule,
				struct mlx5_esw_flow_attr *attr,
				bool fwd_rule)
{
	struct mlx5_fc *counter = NULL;
	bool mirror = (attr->mirror_count > 0);

	counter = mlx5_flow_rule_counter(rule);
	mlx5_del_flow_rules(rule);
	mlx5_fc_destroy(attr->counter_dev, counter);
	esw->offloads.num_flows--;

	if (fwd_rule)  {
		esw_put_prio_table(esw, attr->chain, attr->prio, false);
		esw_put_prio_table(esw, attr->chain, attr->prio, true);
	} else {
		esw_put_prio_table(esw, attr->chain, attr->prio, !mirror);
		if (MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE == attr->dest_type)
			esw_put_prio_table(esw, attr->dest_chain, 1, true);
	}
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
	out_rep = attr->out_rep[0];

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
	out_rep = attr->out_rep[0];

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
	if (push && in_rep->vlan_refcount && (in_rep->vlan != attr->vlan_vid))
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

	/* nop if we're on the vlan push/pop non emulation mode */
	if (mlx5_eswitch_vlan_actions_supported(esw->dev))
		return 0;

	push = !!(attr->action & MLX5_FLOW_CONTEXT_ACTION_VLAN_PUSH);
	pop  = !!(attr->action & MLX5_FLOW_CONTEXT_ACTION_VLAN_POP);
	fwd  = !!((attr->action & MLX5_FLOW_CONTEXT_ACTION_FWD_DEST) && attr->out_rep[0]);

	err = esw_add_vlan_action_check(attr, push, pop, fwd);
	if (err)
		return err;

	attr->vlan_handled = false;

	vport = esw_vlan_action_get_vport(attr, push, pop);

	if (!push && !pop && fwd) {
		/* tracks VF --> wire rules without vlan push action */
		if (!attr->out_rep[0])
			return -EOPNOTSUPP;
		if (attr->out_rep[0]->vport == FDB_UPLINK_VPORT) {
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

		err = __mlx5_eswitch_set_vport_vlan(esw, vport->vport, attr->vlan_vid, 0,
						    SET_VLAN_INSERT | SET_VLAN_STRIP);
		if (err)
			goto out;
		vport->vlan = attr->vlan_vid;
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

	/* nop if we're on the vlan push/pop non emulation mode */
	if (mlx5_eswitch_vlan_actions_supported(esw->dev))
		return 0;

	if (!attr->vlan_handled)
		return 0;

	push = !!(attr->action & MLX5_FLOW_CONTEXT_ACTION_VLAN_PUSH);
	pop  = !!(attr->action & MLX5_FLOW_CONTEXT_ACTION_VLAN_POP);
	fwd  = !!((attr->action & MLX5_FLOW_CONTEXT_ACTION_FWD_DEST) && attr->out_rep);

	vport = esw_vlan_action_get_vport(attr, push, pop);

	if (!push && !pop && fwd) {
		/* tracks VF --> wire rules without vlan push action */
		if (attr->out_rep[0]->vport == FDB_UPLINK_VPORT)
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

struct mlx5_flow_handle *
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
	dest.vport.num = vport;
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;

	flow_rule = mlx5_add_flow_rules(esw->fdb_table.offloads.slow_fdb, spec,
					&flow_act, &dest, 1);
	if (IS_ERR(flow_rule))
		esw_warn(esw->dev, "FDB: Failed to add send to vport rule err %ld\n", PTR_ERR(flow_rule));
out:
	kvfree(spec);
	return flow_rule;
}
EXPORT_SYMBOL(mlx5_eswitch_add_send_to_vport_rule);

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

static void peer_miss_rules_setup(struct mlx5_core_dev *peer_dev,
				  struct mlx5_flow_spec *spec,
				  struct mlx5_flow_destination *dest)
{
	void *misc = MLX5_ADDR_OF(fte_match_param, spec->match_value,
				  misc_parameters);

	MLX5_SET(fte_match_set_misc, misc, source_eswitch_owner_vhca_id,
		 MLX5_CAP_GEN(peer_dev, vhca_id));

	spec->match_criteria_enable = MLX5_MATCH_MISC_PARAMETERS;

	misc = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
			    misc_parameters);
	MLX5_SET_TO_ONES(fte_match_set_misc, misc, source_port);
	MLX5_SET_TO_ONES(fte_match_set_misc, misc,
			 source_eswitch_owner_vhca_id);

	dest->type = MLX5_FLOW_DESTINATION_TYPE_VPORT;
	dest->vport.num = 0;
	dest->vport.vhca_id = MLX5_CAP_GEN(peer_dev, vhca_id);
	dest->vport.vhca_id_valid = 1;
}

static int esw_add_fdb_peer_miss_rules(struct mlx5_eswitch *esw)
{
	struct mlx5_core_dev *peer_dev = mlx5_lag_get_peer_mdev(esw->dev);
	struct mlx5_flow_destination dest = {};
	struct mlx5_flow_act flow_act = {0};
	struct mlx5_flow_handle **flows;
	struct mlx5_flow_handle *flow;
	struct mlx5_flow_spec *spec;
	/* total vports is the same for both e-switches */
	int nvports = esw->total_vports;
	void *misc;
	int err, i;

	if (esw->fdb_table.offloads.flags & FDB_HAS_PEER_MISS_RULES)
		return 0;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec)
		return -ENOMEM;

	peer_miss_rules_setup(peer_dev, spec, &dest);

	flows = kvzalloc(nvports * sizeof(*flows), GFP_KERNEL);
	if (!flows) {
		err = -ENOMEM;
		goto alloc_flows_err;
	}

	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	misc = MLX5_ADDR_OF(fte_match_param, spec->match_value,
			    misc_parameters);

	for (i = 1; i < nvports; i++) {
		MLX5_SET(fte_match_set_misc, misc, source_port, i);
		flow = mlx5_add_flow_rules(esw->fdb_table.offloads.slow_fdb,
					   spec, &flow_act, &dest, 1);
		if (IS_ERR(flow)) {
			err = PTR_ERR(flow);
			esw_warn(esw->dev, "FDB: Failed to add peer miss flow rule err %d\n", err);
			goto add_flow_err;
		}
		flows[i] = flow;
	}

	esw->fdb_table.offloads.peer_miss_rules = flows;
	esw->fdb_table.offloads.flags |= FDB_HAS_PEER_MISS_RULES;

	kvfree(spec);
	return 0;

add_flow_err:
	for (i--; i > 0; i--)
		mlx5_del_flow_rules(flows[i]);
	kvfree(flows);
alloc_flows_err:
	kvfree(spec);
	return err;
}

static void esw_del_fdb_peer_miss_rules(struct mlx5_eswitch *esw)
{
	struct mlx5_flow_handle **flows;
	int i;

	if (!(esw->fdb_table.offloads.flags & FDB_HAS_PEER_MISS_RULES))
		return;

	flows = esw->fdb_table.offloads.peer_miss_rules;

	for (i = 1; i < esw->total_vports; i++)
		mlx5_del_flow_rules(flows[i]);

	kvfree(flows);
	esw->fdb_table.offloads.flags &= ~FDB_HAS_PEER_MISS_RULES;
}

static int esw_offloads_init_peer_miss_rules(struct mlx5_eswitch *esw)
{
	struct mlx5_core_dev *peer_dev;
	struct mlx5_eswitch *peer_esw;
	int err;

	if (!MLX5_CAP_ESW(esw->dev, merged_eswitch))
		return 0;

	peer_dev = mlx5_lag_get_peer_mdev(esw->dev);
	peer_esw = peer_dev ? peer_dev->priv.eswitch : NULL;

	if (!peer_esw || peer_esw->mode != SRIOV_OFFLOADS)
		return 0;

	err = esw_add_fdb_peer_miss_rules(esw);
	if (err)
		goto err_miss_rules;

	err = esw_add_fdb_peer_miss_rules(peer_esw);
	if (err)
		goto err_peer_miss_rules;

	if (mlx5_lag_is_multipath(esw->dev))
		mlx5_lag_set_multipath_ready(esw->dev);

	return 0;

err_peer_miss_rules:
	esw_del_fdb_peer_miss_rules(esw);

err_miss_rules:
	return err;
}

static void esw_offloads_clean_peer_miss_rules(struct mlx5_eswitch *esw)
{
	struct mlx5_core_dev *peer_dev;
	struct mlx5_eswitch *peer_esw;

	esw_del_fdb_peer_miss_rules(esw);

	peer_dev = mlx5_lag_get_peer_mdev(esw->dev);
	peer_esw = peer_dev ? peer_dev->priv.eswitch : NULL;

	if (!peer_esw || peer_esw->mode != SRIOV_OFFLOADS)
		return;

	esw_del_fdb_peer_miss_rules(peer_esw);
}

static int esw_add_fdb_miss_rule(struct mlx5_eswitch *esw)
{
	struct mlx5_flow_act flow_act = {0};
	struct mlx5_flow_destination dest = {};
	struct mlx5_flow_handle *flow_rule = NULL;
	struct mlx5_flow_spec *spec;
	void *headers_c;
	void *headers_v;
	int err = 0;
	u8 *dmac_c;
	u8 *dmac_v;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec) {
		err = -ENOMEM;
		goto out;
	}

	spec->match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;
	headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
				 outer_headers);
	dmac_c = MLX5_ADDR_OF(fte_match_param, headers_c,
			      outer_headers.dmac_47_16);
	dmac_c[0] = 0x01;

	dest.type = MLX5_FLOW_DESTINATION_TYPE_VPORT;
	dest.vport.num = 0;
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;

	flow_rule = mlx5_add_flow_rules(esw->fdb_table.offloads.slow_fdb, spec,
					&flow_act, &dest, 1);
	if (IS_ERR(flow_rule)) {
		err = PTR_ERR(flow_rule);
		esw_warn(esw->dev,  "FDB: Failed to add unicast miss flow rule err %d\n", err);
		goto out;
	}

	esw->fdb_table.offloads.miss_rule_uni = flow_rule;

	headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
				 outer_headers);
	dmac_v = MLX5_ADDR_OF(fte_match_param, headers_v,
			      outer_headers.dmac_47_16);
	dmac_v[0] = 0x01;
	flow_rule = mlx5_add_flow_rules(esw->fdb_table.offloads.slow_fdb, spec,
					&flow_act, &dest, 1);
	if (IS_ERR(flow_rule)) {
		err = PTR_ERR(flow_rule);
		esw_warn(esw->dev, "FDB: Failed to add multicast miss flow rule err %d\n", err);
		mlx5_del_flow_rules(esw->fdb_table.offloads.miss_rule_uni);
		goto out;
	}

	esw->fdb_table.offloads.miss_rule_multi = flow_rule;

out:
	kvfree(spec);
	return err;
}

#define ESW_OFFLOADS_NUM_GROUPS  4

/* sorted from large to small */
#define ESW_SIZE 16*1024*1024
const unsigned int ESW_POOLS[4] = { 4*1024*1024, 1*1024*1024, 64*1024, 4*1024 };

static void
put_sz_to_pool(struct mlx5_eswitch *esw, struct mlx5_flow_table *fdb)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ESW_POOLS); i++) {
		if (fdb->max_fte >= ESW_POOLS[i]) {
			++esw->fdb_left[i];
			break;
		}
	}
}

static int
get_sz_from_pool(struct mlx5_eswitch *esw)
{
	int sz = 0, i;

	for (i = 0; i < ARRAY_SIZE(ESW_POOLS); i++) {
		if (esw->fdb_left[i] && ESW_POOLS[i] <= esw->fdb_max) {
			--esw->fdb_left[i];
			sz = ESW_POOLS[i];
			break;
		}
	}

	return sz;
}

static struct mlx5_flow_table *
esw_get_prio_table(struct mlx5_eswitch *esw, u32 chain, u32 prio, bool fast)
{
	struct mlx5_core_dev *dev = esw->dev;
	struct mlx5_flow_namespace *ns;
	struct mlx5_flow_table *fdb = NULL;
	int table_prio, sz, num_groups;
	u32 flags = 0;
	bool created_fast_fdb = false;

	if (esw->fdb_fixed) {
		chain = 0;
		prio = 1;
	}

	if (prio > FDB_MAX_PRIO || chain > FDB_MAX_CHAIN) {
		esw_warn(dev, "max chain or prio\n");
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (fast)
		fdb = fdb_prio_table(chain, prio).fast_fdb;
	else
		fdb = fdb_prio_table(chain, prio).fwd_fdb;

	if (fdb)
		goto found;

	ns = mlx5_get_fdb_sub_ns(dev, chain);
	if (!ns) {
		esw_warn(dev, "Failed to get FDB flow sub namespace\n");
		fdb = ERR_PTR(-EOPNOTSUPP);
		goto err_ns;
	}

	if (esw->offloads.encap != DEVLINK_ESWITCH_ENCAP_MODE_NONE)
		flags |= MLX5_FLOW_TABLE_TUNNEL_EN;

	num_groups = ESW_OFFLOADS_NUM_GROUPS;
	table_prio = (chain * FDB_MAX_PRIO) + prio;

	/* always create fast for correct fs_core lookup */
	if (!fdb_prio_table(chain, prio).fast_fdb) {
		sz = get_sz_from_pool(esw);
		fdb = mlx5_create_auto_grouped_flow_table(ns,
							  table_prio,
							  sz,
							  num_groups,
							  0,
							  flags);
		if (IS_ERR(fdb)) {
			esw_warn(dev, "Failed to create fast path FDB Table err %d, chain: %d prio: %d, size: %d\n",
				 (int) PTR_ERR(fdb), chain, prio, sz);
			goto err_create_fast;
		}

		fdb_prio_table(chain, prio).fast_fdb = fdb;
		fdb_prio_table(chain, prio).num_rules[1] = 0;
		created_fast_fdb = true;
	}

	if (!fast) {
		sz = get_sz_from_pool(esw);
		fdb = mlx5_create_auto_grouped_flow_table(ns,
							  table_prio,
							  sz,
							  num_groups,
							  1,
							  flags);
		if (IS_ERR(fdb)) {
			esw_warn(dev, "Failed to create fwd FDB Table err %d, chain: %d prio: %d, size: %d\n",
				 (int) PTR_ERR(fdb), chain, prio, sz);
			goto err_create_fwd;
		}

		fdb_prio_table(chain, prio).fwd_fdb = fdb;
		fdb_prio_table(chain, prio).num_rules[0] = 0;
	}

	/* fwd takes ref on fast as well */
	if (created_fast_fdb && !fast)
		fdb_prio_table(chain, prio).num_rules[1]++;

	if (fast)
		fdb = fdb_prio_table(chain, prio).fast_fdb;
	else
		fdb = fdb_prio_table(chain, prio).fwd_fdb;

found:
	fdb_prio_table(chain, prio).num_rules[!!fast]++;
	return fdb;

err_create_fwd:
	if (created_fast_fdb) {
		put_sz_to_pool(esw, fdb_prio_table(chain, prio).fast_fdb);
		mlx5_destroy_flow_table(fdb_prio_table(chain, prio).fast_fdb);
		fdb_prio_table(chain, prio).fast_fdb = NULL;
	}
err_create_fast:
err_ns:
	return fdb;
}

static void esw_put_prio_table(struct mlx5_eswitch *esw, u32 chain, u32 prio,
			       bool fast)
{
	if (esw->fdb_fixed) {
		chain = 0;
		prio = 1;
	}

	if (prio > FDB_MAX_PRIO || chain > FDB_MAX_CHAIN)
		return;

	if (!fdb_prio_table(chain, prio).num_rules[!!fast])
		return;

	if (--(fdb_prio_table(chain, prio).num_rules[!!fast]) > 0)
		return;

	if (!fast) {
		put_sz_to_pool(esw, fdb_prio_table(chain, prio).fwd_fdb);
		mlx5_destroy_flow_table(fdb_prio_table(chain, prio).fwd_fdb);
		fdb_prio_table(chain, prio).fwd_fdb = NULL;

		esw_put_prio_table(esw, chain, prio, true);
		return;
	}

	put_sz_to_pool(esw, fdb_prio_table(chain, prio).fast_fdb);
	mlx5_destroy_flow_table(fdb_prio_table(chain, prio).fast_fdb);
	fdb_prio_table(chain, prio).fast_fdb = NULL;

	fdb_prio_table(chain, prio).num_rules[0] = 0;
	fdb_prio_table(chain, prio).num_rules[1] = 0;
}

static void esw_destroy_offloads_fast_fdb_tables(struct mlx5_eswitch *esw)
{
	if (esw->fdb_fixed) {
		esw_put_prio_table(esw, 0, 1, false);
		esw_put_prio_table(esw, 0, 1, true);
		esw->fdb_fixed = false;
	}
}

#define MAX_PF_SQ 256
#define MAX_SQ_NVPORTS 32

static int esw_create_offloads_fdb_tables(struct mlx5_eswitch *esw, int nvports)
{
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	struct mlx5_flow_table_attr ft_attr = {};
	struct mlx5_core_dev *dev = esw->dev;
	struct mlx5_flow_namespace *root_ns;
	struct mlx5_flow_table *fdb = NULL;
	int table_size, ix, err = 0, max_flow, i;
	struct mlx5_flow_group *g;
	void *match_criteria;
	u32 *flow_group_in, max_flow_counter;
	u8 *dmac;
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
	esw->fdb_max = 1 << MLX5_CAP_ESW_FLOWTABLE_FDB(dev, log_max_ft_size);

	for (i = 0; i < ARRAY_SIZE(ESW_POOLS); i++)
		esw->fdb_left[i] = ESW_SIZE / ESW_POOLS[i];

	table_size = nvports * MAX_SQ_NVPORTS + MAX_PF_SQ + 2 +
		esw->total_vports;

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
	esw->fdb_table.offloads.slow_fdb = fdb;

	if (!MLX5_CAP_ESW_FLOWTABLE(dev, multi_fdb_encap) &&
	    esw->offloads.encap != DEVLINK_ESWITCH_ENCAP_MODE_NONE) {
		esw_warn(dev, "Lazy creation of flow tables isn't possible, ignoring priorities instead.\n");
		esw->fdb_fixed = true;
		esw_get_prio_table(esw, 0, 1, true);
		esw_get_prio_table(esw, 0, 1, false);
	}

	/* create send-to-vport group */
	memset(flow_group_in, 0, inlen);
	MLX5_SET(create_flow_group_in, flow_group_in, match_criteria_enable,
		 MLX5_MATCH_MISC_PARAMETERS);

	match_criteria = MLX5_ADDR_OF(create_flow_group_in, flow_group_in, match_criteria);

	MLX5_SET_TO_ONES(fte_match_param, match_criteria, misc_parameters.source_sqn);
	MLX5_SET_TO_ONES(fte_match_param, match_criteria, misc_parameters.source_port);

	ix = nvports * MAX_SQ_NVPORTS + MAX_PF_SQ;
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

	match_criteria = MLX5_ADDR_OF(create_flow_group_in, flow_group_in,
				      match_criteria);

	MLX5_SET_TO_ONES(fte_match_param, match_criteria,
			 misc_parameters.source_port);
	MLX5_SET_TO_ONES(fte_match_param, match_criteria,
			 misc_parameters.source_eswitch_owner_vhca_id);

	MLX5_SET(create_flow_group_in, flow_group_in,
		 source_eswitch_owner_vhca_id_valid, 1);
	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, ix);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index,
		 ix + esw->total_vports - 1);
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
	MLX5_SET(create_flow_group_in, flow_group_in, match_criteria_enable,
		 MLX5_MATCH_OUTER_HEADERS);
	match_criteria = MLX5_ADDR_OF(create_flow_group_in, flow_group_in,
				      match_criteria);
	dmac = MLX5_ADDR_OF(fte_match_param, match_criteria,
			    outer_headers.dmac_47_16);
	dmac[0] = 0x01;

	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, ix);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, ix + 2);

	g = mlx5_create_flow_group(fdb, flow_group_in);
	if (IS_ERR(g)) {
		err = PTR_ERR(g);
		esw_warn(dev, "Failed to create miss flow group err(%d)\n", err);
		goto miss_err;
	}
	esw->fdb_table.offloads.miss_grp = g;

	err = esw_offloads_init_peer_miss_rules(esw);
	if (err)
		goto peer_miss_rules_err;

	err = esw_add_fdb_miss_rule(esw);
	if (err)
		goto miss_rule_err;

	return 0;

miss_rule_err:
	esw_offloads_clean_peer_miss_rules(esw);
peer_miss_rules_err:
	mlx5_destroy_flow_group(esw->fdb_table.offloads.miss_grp);
miss_err:
	mlx5_destroy_flow_group(esw->fdb_table.offloads.peer_miss_grp);
peer_miss_err:
	mlx5_destroy_flow_group(esw->fdb_table.offloads.send_to_vport_grp);
send_vport_err:
	esw_destroy_offloads_fast_fdb_tables(esw);
	mlx5_destroy_flow_table(esw->fdb_table.offloads.slow_fdb);
slow_fdb_err:
ns_err:
	kvfree(flow_group_in);
	return err;
}

static void esw_destroy_offloads_fdb_tables(struct mlx5_eswitch *esw)
{
	if (!esw->fdb_table.offloads.slow_fdb)
		return;

	esw_debug(esw->dev, "Destroy offloads FDB Tables\n");
	mlx5_del_flow_rules(esw->fdb_table.offloads.miss_rule_multi);
	mlx5_del_flow_rules(esw->fdb_table.offloads.miss_rule_uni);
	mlx5_destroy_flow_group(esw->fdb_table.offloads.send_to_vport_grp);
	mlx5_destroy_flow_group(esw->fdb_table.offloads.miss_grp);

	mlx5_destroy_flow_table(esw->fdb_table.offloads.slow_fdb);
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

	err = esw_create_offloads_fdb_tables(esw, nvports);
	if (err)
		return err;

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

	esw_del_fdb_peer_miss_rules(esw);
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

void *mlx5_eswitch_get_uplink_netdev_priv(struct mlx5_eswitch *esw, u8 rep_type)
{
#define UPLINK_REP_INDEX 0
	struct mlx5_esw_offload *offloads = &esw->offloads;
	struct mlx5_eswitch_rep *rep = &offloads->vport_reps[UPLINK_REP_INDEX];
	struct mlx5e_priv *priv = netdev_priv(rep->netdev);

	return priv->ppriv;
}

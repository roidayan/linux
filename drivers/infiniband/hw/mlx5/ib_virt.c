/*
 * Copyright (c) 2013-2016, Mellanox Technologies. All rights reserved.
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

#include <linux/module.h>
#include "mlx5_ib.h"

static inline enum ib_link_state
mlx_to_ib_policy(enum port_state_policy mlx_policy)
{
	switch (mlx_policy) {
	case MLX5_POLICY_DOWN:
		return IB_LINK_STATE_DOWN;
	case MLX5_POLICY_UP:
		return IB_LINK_STATE_UP;
	case MLX5_POLICY_FOLLOW:
		return IB_LINK_STATE_AUTO;
	default:
		WARN(1, "invalid policy value %d\n", mlx_policy);
		return (enum ib_link_state)-1;
	}
}

int mlx5_ib_get_vf_config(struct ib_device *device, int vf, u8 port,
			  struct ib_vf_info *info)
{
	struct mlx5_ib_dev *dev = to_mdev(device);
	struct mlx5_core_dev *mdev = dev->mdev;
	struct mlx5_hca_vport_context *rep;
	int err;

	if (port != 1) {
		mlx5_ib_warn(dev, "mlx5_ib supports only one port for virtual functions\n");
		return -EINVAL;
	}
	rep = kzalloc(sizeof(*rep), GFP_KERNEL);
	if (!rep)
		return -ENOMEM;

	err = mlx5_core_query_hca_vport_context(mdev, 1, 1,  vf + 1, rep);
	if (err) {
		mlx5_ib_warn(dev, "failed to query port policy for vf %d (%d)\n",
			     vf, err);
		goto free;
	}
	info->state = mlx_to_ib_policy(rep->policy);

free:
	kfree(rep);
	return err;
}

static inline enum port_state_policy
ib_to_mlx_policy(enum ib_link_state ib_policy)
{
	switch (ib_policy) {
	case IB_LINK_STATE_DOWN:
		return MLX5_POLICY_DOWN;
	case IB_LINK_STATE_UP:
		return MLX5_POLICY_UP;
	case IB_LINK_STATE_AUTO:
		return MLX5_POLICY_FOLLOW;
	default:
		WARN(1, "invalid policy value %d\n", ib_policy);
		return (enum port_state_policy)-1;
	}
}

int mlx5_ib_set_vf_link_state(struct ib_device *device, int vf,
			      u8 port, enum ib_link_state state)
{
	struct mlx5_ib_dev *dev = to_mdev(device);
	struct mlx5_core_dev *mdev = dev->mdev;
	struct mlx5_hca_vport_context *in;
	int err;

	if (port != 1) {
		mlx5_ib_warn(dev, "mlx5_ib supports only one port for virtual functions\n");
		return -EINVAL;
	}

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	in->policy = ib_to_mlx_policy(state);
	in->field_select = MLX5_HCA_VPORT_SEL_STATE_POLICY;
	err = mlx5_core_modify_hca_vport_context(mdev, 1, 1, vf + 1, in);
	kfree(in);
	return err;
}

int mlx5_ib_get_vf_stats(struct ib_device *device, int vf,
			 u8 port, struct ib_vf_stats *stats)
{
	int out_sz = MLX5_ST_SZ_BYTES(query_vport_counter_out);
	int in_sz = MLX5_ST_SZ_BYTES(query_vport_counter_in);
	struct mlx5_core_dev *mdev;
	struct mlx5_ib_dev *dev;
	int is_group_manager;
	void *out;
	void *in;
	int err;

	dev = to_mdev(device);
	mdev = dev->mdev;
	is_group_manager = MLX5_CAP_GEN(mdev, vport_group_manager);

	if (port != 1) {
		mlx5_ib_warn(dev, "mlx5_ib supports only one port for virtual functions\n");
		return -EINVAL;
	}

	in = kzalloc(in_sz, GFP_KERNEL);
	out = kzalloc(out_sz, GFP_KERNEL);
	if (!in || !out)
		return -ENOMEM;

	MLX5_SET(query_vport_counter_in, in, opcode, MLX5_CMD_OP_QUERY_VPORT_COUNTER);
	if (is_group_manager) {
		MLX5_SET(query_vport_counter_in, in, other_vport, 1);
		MLX5_SET(query_vport_counter_in, in, vport_number, vf + 1);
	} else {
		err = -EPERM;
		goto ex;
	}
	err = mlx5_cmd_exec(mdev, in, in_sz, out,  out_sz);
	if (err)
		goto ex;

	stats->rx_frames = MLX5_GET64_PR(query_vport_counter_out, out, received_ib_unicast.packets);
	stats->tx_frames = MLX5_GET64_PR(query_vport_counter_out, out, transmitted_ib_unicast.packets);
	stats->rx_bytes = MLX5_GET64_PR(query_vport_counter_out, out, received_ib_unicast.octets);
	stats->tx_bytes = MLX5_GET64_PR(query_vport_counter_out, out, transmitted_ib_unicast.octets);
	stats->rx_errors =  MLX5_GET64_PR(query_vport_counter_out, out, received_errors.octets);
	stats->tx_errors = MLX5_GET64_PR(query_vport_counter_out, out, transmit_errors.packets);
	stats->rx_dropped = 0;
	stats->tx_dropped = 0;
	stats->rx_mcast = MLX5_GET64_PR(query_vport_counter_out, out, received_ib_multicast.packets);

ex:
	kfree(in);
	kfree(out);
	return err;
}

int mlx5_ib_set_vf_node_guid(struct ib_device *device, int vf,
			     u64 guid)
{
	struct mlx5_ib_dev *dev = to_mdev(device);
	struct mlx5_core_dev *mdev = dev->mdev;
	struct mlx5_hca_vport_context *in;
	int err;

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	in->field_select = MLX5_HCA_VPORT_SEL_NODE_GUID;
	in->node_guid = guid;
	err = mlx5_core_modify_hca_vport_context(mdev, 1, 1, vf + 1, in);
	kfree(in);
	return err;
}

int mlx5_ib_set_vf_port_guid(struct ib_device *device, int vf, u8 port,
			     u64 guid)
{
	struct mlx5_ib_dev *dev = to_mdev(device);
	struct mlx5_core_dev *mdev = dev->mdev;
	struct mlx5_hca_vport_context *in;
	int err;

	if (port != 1) {
		mlx5_ib_warn(dev, "mlx5_ib supports only one port for virtual functions\n");
		return -EINVAL;
	}

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	in->field_select = MLX5_HCA_VPORT_SEL_PORT_GUID;
	in->port_guid = guid;
	err = mlx5_core_modify_hca_vport_context(mdev, 1, 1, vf + 1, in);
	kfree(in);
	return err;
}

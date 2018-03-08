/*
 * Copyright (c) 2018, Mellanox Technologies inc.  All rights reserved.
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

#include <rdma/ib_user_verbs.h>
#include <rdma/ib_verbs.h>
#include <rdma/uverbs_types.h>
#include <rdma/uverbs_ioctl.h>
#include <rdma/mlx5_user_ioctl_cmds.h>
#include <rdma/ib_umem.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/fs.h>
#include "mlx5_ib.h"

#define UVERBS_MODULE_NAME mlx5_ib
#include <rdma/uverbs_named_ioctl.h>

static struct mlx5_ib_ucontext *devx_ufile2uctx(struct ib_uverbs_file *file)
{
	return to_mucontext(ib_uverbs_get_ucontext(file));
}

int mlx5_ib_devx_create(struct mlx5_ib_dev *dev, struct mlx5_ib_ucontext *context)
{
	u32 in[MLX5_ST_SZ_DW(create_uctx_in)] = {0};
	u32 out[MLX5_ST_SZ_DW(general_obj_out_cmd_hdr)] = {0};
	u64 general_obj_types;
	void *uctx;
	void *hdr;
	int err;

	uctx = MLX5_ADDR_OF(create_uctx_in, in, uctx);
	hdr = MLX5_ADDR_OF(create_uctx_in, in, hdr);

	general_obj_types = MLX5_CAP_GEN_64(dev->mdev, general_obj_types);
	if (!(general_obj_types & MLX5_GENERAL_OBJ_TYPES_CAP_UCTX) ||
	    !(general_obj_types & MLX5_GENERAL_OBJ_TYPES_CAP_UMEM))
		return -EINVAL;

	if (!capable(CAP_NET_RAW))
		return -EPERM;

	MLX5_SET(general_obj_in_cmd_hdr, hdr, opcode, MLX5_CMD_OP_CREATE_GENERAL_OBJECT);
	MLX5_SET(general_obj_in_cmd_hdr, hdr, obj_type, MLX5_OBJ_TYPE_UCTX);

	err = mlx5_cmd_exec(dev->mdev, in, sizeof(in), out, sizeof(out));
	if (err)
		return err;

	context->devx_uid = MLX5_GET(general_obj_out_cmd_hdr, out, obj_id);
	return 0;
}

void mlx5_ib_devx_destroy(struct mlx5_ib_dev *dev,
			  struct mlx5_ib_ucontext *context)
{
	u32 in[MLX5_ST_SZ_DW(general_obj_in_cmd_hdr)] = {0};
	u32 out[MLX5_ST_SZ_DW(general_obj_out_cmd_hdr)] = {0};

	MLX5_SET(general_obj_in_cmd_hdr, in, opcode, MLX5_CMD_OP_DESTROY_GENERAL_OBJECT);
	MLX5_SET(general_obj_in_cmd_hdr, in, obj_type, MLX5_OBJ_TYPE_UCTX);
	MLX5_SET(general_obj_in_cmd_hdr, in, obj_id, context->devx_uid);

	mlx5_cmd_exec(dev->mdev, in, sizeof(in), out, sizeof(out));
}

static bool devx_is_obj_create_cmd(const void *in)
{
	u16 opcode = MLX5_GET(general_obj_in_cmd_hdr, in, opcode);

	switch (opcode) {
	case MLX5_CMD_OP_CREATE_GENERAL_OBJECT:
	case MLX5_CMD_OP_CREATE_MKEY:
	case MLX5_CMD_OP_CREATE_CQ:
	case MLX5_CMD_OP_ALLOC_PD:
	case MLX5_CMD_OP_ALLOC_TRANSPORT_DOMAIN:
	case MLX5_CMD_OP_CREATE_RMP:
	case MLX5_CMD_OP_CREATE_SQ:
	case MLX5_CMD_OP_CREATE_RQ:
	case MLX5_CMD_OP_CREATE_RQT:
	case MLX5_CMD_OP_CREATE_TIR:
	case MLX5_CMD_OP_CREATE_TIS:
	case MLX5_CMD_OP_ALLOC_Q_COUNTER:
	case MLX5_CMD_OP_CREATE_FLOW_TABLE:
	case MLX5_CMD_OP_CREATE_FLOW_GROUP:
	case MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY:
	case MLX5_CMD_OP_ALLOC_FLOW_COUNTER:
	case MLX5_CMD_OP_ALLOC_ENCAP_HEADER:
	case MLX5_CMD_OP_ALLOC_MODIFY_HEADER_CONTEXT:
	case MLX5_CMD_OP_CREATE_SCHEDULING_ELEMENT:
	case MLX5_CMD_OP_ADD_VXLAN_UDP_DPORT:
	case MLX5_CMD_OP_SET_L2_TABLE_ENTRY:
	case MLX5_CMD_OP_CREATE_QP:
	case MLX5_CMD_OP_CREATE_SRQ:
	case MLX5_CMD_OP_CREATE_XRC_SRQ:
	case MLX5_CMD_OP_CREATE_DCT:
	case MLX5_CMD_OP_CREATE_XRQ:
	case MLX5_CMD_OP_ATTACH_TO_MCG:
	case MLX5_CMD_OP_ALLOC_XRCD:
		return true;
	default:
		return false;
	}
}

static bool devx_is_obj_destroy_cmd(void *in)
{
	u16 opcode = MLX5_GET(general_obj_in_cmd_hdr, in, opcode);

	switch (opcode) {
	case MLX5_CMD_OP_DESTROY_GENERAL_OBJECT:
	case MLX5_CMD_OP_DESTROY_MKEY:
	case MLX5_CMD_OP_DESTROY_CQ:
	case MLX5_CMD_OP_DESTROY_QP:
	case MLX5_CMD_OP_DESTROY_SRQ:
	case MLX5_CMD_OP_DESTROY_XRC_SRQ:
	case MLX5_CMD_OP_DESTROY_DCT:
	case MLX5_CMD_OP_DESTROY_XRQ:
	case MLX5_CMD_OP_DEALLOC_Q_COUNTER:
	case MLX5_CMD_OP_DESTROY_SCHEDULING_ELEMENT:
	case MLX5_CMD_OP_DEALLOC_PD:
	case MLX5_CMD_OP_DETACH_FROM_MCG:
	case MLX5_CMD_OP_DEALLOC_XRCD:
	case MLX5_CMD_OP_DEALLOC_TRANSPORT_DOMAIN:
	case MLX5_CMD_OP_DELETE_VXLAN_UDP_DPORT:
	case MLX5_CMD_OP_DELETE_L2_TABLE_ENTRY:
	case MLX5_CMD_OP_DESTROY_TIR:
	case MLX5_CMD_OP_DESTROY_SQ:
	case MLX5_CMD_OP_DESTROY_RQ:
	case MLX5_CMD_OP_DESTROY_RMP:
	case MLX5_CMD_OP_DESTROY_TIS:
	case MLX5_CMD_OP_DESTROY_RQT:
	case MLX5_CMD_OP_DESTROY_FLOW_TABLE:
	case MLX5_CMD_OP_DESTROY_FLOW_GROUP:
	case MLX5_CMD_OP_DELETE_FLOW_TABLE_ENTRY:
	case MLX5_CMD_OP_DEALLOC_FLOW_COUNTER:
	case MLX5_CMD_OP_DEALLOC_ENCAP_HEADER:
	case MLX5_CMD_OP_DEALLOC_MODIFY_HEADER_CONTEXT:
		return true;
	default:
		return false;
	}
}

static int UVERBS_HANDLER(MLX5_IB_METHOD_DEVX_OTHER)(struct ib_device *ib_dev,
				  struct ib_uverbs_file *file,
				  struct uverbs_attr_bundle *attrs)
{
	struct mlx5_ib_ucontext *c = devx_ufile2uctx(file);
	struct mlx5_ib_dev *dev = to_mdev(ib_dev);
	void *cmd_in = uverbs_attr_get_alloced_ptr(attrs, MLX5_IB_ATTR_DEVX_OTHER_CMD_IN);
	int cmd_out_len = uverbs_attr_get_len(attrs,
					MLX5_IB_ATTR_DEVX_OTHER_CMD_OUT);
	void *cmd_out;
	int err;

	/* A create/destroy command requires a special handling and is done on a
	 * DEVX object, make sure that the general command is not from this
	 * type.
	 * Security talking: the firmware should not allow privilege commands
	 * unless the devx_uid has the required permissions given upon its creation.
	 */
	if (devx_is_obj_create_cmd(cmd_in) ||
	    devx_is_obj_destroy_cmd(cmd_in))
		return -EINVAL;

	cmd_out = kvzalloc(cmd_out_len, GFP_KERNEL);
	if (!cmd_out)
		return -ENOMEM;

	MLX5_SET(general_obj_in_cmd_hdr, cmd_in, uid, c->devx_uid);
	err = mlx5_cmd_exec(dev->mdev, cmd_in,
			    uverbs_attr_get_len(attrs, MLX5_IB_ATTR_DEVX_OTHER_CMD_IN),
			    cmd_out, cmd_out_len);
	if (err)
		goto other_cmd_free;

	err = uverbs_copy_to(attrs, MLX5_IB_ATTR_DEVX_OTHER_CMD_OUT, cmd_out, cmd_out_len);

other_cmd_free:
	kvfree(cmd_out);
	return err;
}

static DECLARE_UVERBS_NAMED_METHOD(MLX5_IB_METHOD_DEVX_OTHER,
	&UVERBS_ATTR_PTR_IN_SZ(MLX5_IB_ATTR_DEVX_OTHER_CMD_IN,
			       UVERBS_ATTR_MIN_SIZE(MLX5_ST_SZ_BYTES(general_obj_in_cmd_hdr)),
			       UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY |
					UVERBS_ATTR_SPEC_F_MIN_SZ_OR_ZERO |
					UVERBS_ATTR_SPEC_F_ALLOC_AND_COPY)),
	&UVERBS_ATTR_PTR_OUT_SZ(MLX5_IB_ATTR_DEVX_OTHER_CMD_OUT,
				UVERBS_ATTR_MIN_SIZE(MLX5_ST_SZ_BYTES(general_obj_out_cmd_hdr)),
				UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY |
					 UVERBS_ATTR_SPEC_F_MIN_SZ_OR_ZERO))
);

static DECLARE_UVERBS_GLOBAL_METHODS(MLX5_IB_OBJECT_DEVX,
	&UVERBS_METHOD(MLX5_IB_METHOD_DEVX_OTHER));

static DECLARE_UVERBS_OBJECT_TREE(devx_objects,
	&UVERBS_OBJECT(MLX5_IB_OBJECT_DEVX));

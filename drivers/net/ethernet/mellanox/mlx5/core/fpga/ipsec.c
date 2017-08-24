/*
 * Copyright (c) 2017 Mellanox Technologies. All rights reserved.
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
 *
 */

#include <linux/mlx5/driver.h>
#include <linux/mlx5/fs_helpers.h>

#include "fs_core.h"
#include "fs_cmd.h"
#include "mlx5_core.h"
#include "fpga/ipsec.h"
#include "fpga/sdk.h"
#include "fpga/core.h"

#define SBU_QP_QUEUE_SIZE 8

enum mlx5_ipsec_response_syndrome {
	MLX5_IPSEC_RESPONSE_SUCCESS = 0,
	MLX5_IPSEC_RESPONSE_ILLEGAL_REQUEST = 1,
	MLX5_IPSEC_RESPONSE_SADB_ISSUE = 2,
	MLX5_IPSEC_RESPONSE_WRITE_RESPONSE_ISSUE = 3,
};

enum mlx5_fpga_ipsec_sacmd_status {
	MLX5_FPGA_IPSEC_SACMD_PENDING,
	MLX5_FPGA_IPSEC_SACMD_SEND_FAIL,
	MLX5_FPGA_IPSEC_SACMD_COMPLETE,
};

struct mlx5_ipsec_command_context {
	struct mlx5_fpga_dma_buf buf;
	struct mlx5_accel_ipsec_sa sa;
	enum mlx5_fpga_ipsec_sacmd_status status;
	int status_code;
	struct completion complete;
	struct mlx5_fpga_device *dev;
	struct list_head list; /* Item in pending_cmds */
};

struct mlx5_ipsec_sadb_resp {
	__be32 syndrome;
	__be32 sw_sa_handle;
	u8 reserved[24];
} __packed;

struct mlx5_fpga_ipsec {
	struct list_head pending_cmds;
	spinlock_t pending_cmds_lock; /* Protects pending_cmds */
	u32 caps[MLX5_ST_SZ_DW(ipsec_extended_cap)];
	struct mlx5_fpga_conn *conn;
};

static bool mlx5_fpga_is_ipsec_device(struct mlx5_core_dev *mdev)
{
	if (!mdev->fpga || !MLX5_CAP_GEN(mdev, fpga))
		return false;

	if (MLX5_CAP_FPGA(mdev, ieee_vendor_id) !=
	    MLX5_FPGA_CAP_SANDBOX_VENDOR_ID_MLNX)
		return false;

	if (MLX5_CAP_FPGA(mdev, sandbox_product_id) !=
	    MLX5_FPGA_CAP_SANDBOX_PRODUCT_ID_IPSEC)
		return false;

	return true;
}

static void mlx5_fpga_ipsec_send_complete(struct mlx5_fpga_conn *conn,
					  struct mlx5_fpga_device *fdev,
					  struct mlx5_fpga_dma_buf *buf,
					  u8 status)
{
	struct mlx5_ipsec_command_context *context;

	if (status) {
		context = container_of(buf, struct mlx5_ipsec_command_context,
				       buf);
		mlx5_fpga_warn(fdev, "IPSec command send failed with status %u\n",
			       status);
		context->status = MLX5_FPGA_IPSEC_SACMD_SEND_FAIL;
		complete(&context->complete);
	}
}

static inline int syndrome_to_errno(enum mlx5_ipsec_response_syndrome syndrome)
{
	switch (syndrome) {
	case MLX5_IPSEC_RESPONSE_SUCCESS:
		return 0;
	case MLX5_IPSEC_RESPONSE_SADB_ISSUE:
		return -EEXIST;
	case MLX5_IPSEC_RESPONSE_ILLEGAL_REQUEST:
		return -EINVAL;
	case MLX5_IPSEC_RESPONSE_WRITE_RESPONSE_ISSUE:
		return -EIO;
	}
	return -EIO;
}

static void mlx5_fpga_ipsec_recv(void *cb_arg, struct mlx5_fpga_dma_buf *buf)
{
	struct mlx5_ipsec_sadb_resp *resp = buf->sg[0].data;
	struct mlx5_ipsec_command_context *context;
	enum mlx5_ipsec_response_syndrome syndrome;
	struct mlx5_fpga_device *fdev = cb_arg;
	unsigned long flags;

	if (buf->sg[0].size < sizeof(*resp)) {
		mlx5_fpga_warn(fdev, "Short receive from FPGA IPSec: %u < %zu bytes\n",
			       buf->sg[0].size, sizeof(*resp));
		return;
	}

	mlx5_fpga_dbg(fdev, "mlx5_ipsec recv_cb syndrome %08x sa_id %x\n",
		      ntohl(resp->syndrome), ntohl(resp->sw_sa_handle));

	spin_lock_irqsave(&fdev->ipsec->pending_cmds_lock, flags);
	context = list_first_entry_or_null(&fdev->ipsec->pending_cmds,
					   struct mlx5_ipsec_command_context,
					   list);
	if (context)
		list_del(&context->list);
	spin_unlock_irqrestore(&fdev->ipsec->pending_cmds_lock, flags);

	if (!context) {
		mlx5_fpga_warn(fdev, "Received IPSec offload response without pending command request\n");
		return;
	}
	mlx5_fpga_dbg(fdev, "Handling response for %p\n", context);

	if (context->sa.sw_sa_handle != resp->sw_sa_handle) {
		mlx5_fpga_err(fdev, "mismatch SA handle. cmd 0x%08x vs resp 0x%08x\n",
			      ntohl(context->sa.sw_sa_handle),
			      ntohl(resp->sw_sa_handle));
		return;
	}

	syndrome = ntohl(resp->syndrome);
	context->status_code = syndrome_to_errno(syndrome);
	context->status = MLX5_FPGA_IPSEC_SACMD_COMPLETE;

	if (context->status_code)
		mlx5_fpga_warn(fdev, "IPSec SADB command failed with syndrome %08x\n",
			       syndrome);
	complete(&context->complete);
}

void *mlx5_fpga_ipsec_sa_cmd_exec(struct mlx5_core_dev *mdev,
				  struct mlx5_accel_ipsec_sa *cmd)
{
	struct mlx5_ipsec_command_context *context;
	struct mlx5_fpga_device *fdev = mdev->fpga;
	unsigned long flags;
	int res = 0;

	BUILD_BUG_ON((sizeof(struct mlx5_accel_ipsec_sa) & 3) != 0);
	if (!fdev || !fdev->ipsec)
		return ERR_PTR(-EOPNOTSUPP);

	context = kzalloc(sizeof(*context), GFP_ATOMIC);
	if (!context)
		return ERR_PTR(-ENOMEM);

	memcpy(&context->sa, cmd, sizeof(*cmd));
	context->buf.complete = mlx5_fpga_ipsec_send_complete;
	context->buf.sg[0].size = sizeof(context->sa);
	context->buf.sg[0].data = &context->sa;
	init_completion(&context->complete);
	context->dev = fdev;
	spin_lock_irqsave(&fdev->ipsec->pending_cmds_lock, flags);
	list_add_tail(&context->list, &fdev->ipsec->pending_cmds);
	spin_unlock_irqrestore(&fdev->ipsec->pending_cmds_lock, flags);

	context->status = MLX5_FPGA_IPSEC_SACMD_PENDING;

	res = mlx5_fpga_sbu_conn_sendmsg(fdev->ipsec->conn, &context->buf);
	if (res) {
		mlx5_fpga_warn(fdev, "Failure sending IPSec command: %d\n",
			       res);
		spin_lock_irqsave(&fdev->ipsec->pending_cmds_lock, flags);
		list_del(&context->list);
		spin_unlock_irqrestore(&fdev->ipsec->pending_cmds_lock, flags);
		kfree(context);
		return ERR_PTR(res);
	}
	/* Context will be freed by wait func after completion */
	return context;
}

int mlx5_fpga_ipsec_sa_cmd_wait(void *ctx)
{
	struct mlx5_ipsec_command_context *context = ctx;
	int res;

	res = wait_for_completion_killable(&context->complete);
	if (res) {
		mlx5_fpga_warn(context->dev, "Failure waiting for IPSec command response\n");
		return -EINTR;
	}

	if (context->status == MLX5_FPGA_IPSEC_SACMD_COMPLETE)
		res = context->status_code;
	else
		res = -EIO;

	kfree(context);
	return res;
}

u32 mlx5_fpga_ipsec_device_caps(struct mlx5_core_dev *mdev)
{
	struct mlx5_fpga_device *fdev = mdev->fpga;
	u32 ret = 0;

	if (mlx5_fpga_is_ipsec_device(mdev))
		ret |= MLX5_ACCEL_IPSEC_DEVICE;
	else
		return ret;

	if (!fdev->ipsec)
		return ret;

	if (MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps, esp))
		ret |= MLX5_ACCEL_IPSEC_ESP;

	if (MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps, ipv6))
		ret |= MLX5_ACCEL_IPSEC_IPV6;

	if (MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps, lso))
		ret |= MLX5_ACCEL_IPSEC_LSO;

	return ret;
}

unsigned int mlx5_fpga_ipsec_counters_count(struct mlx5_core_dev *mdev)
{
	struct mlx5_fpga_device *fdev = mdev->fpga;

	if (!fdev || !fdev->ipsec)
		return 0;

	return MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps,
			number_of_ipsec_counters);
}

int mlx5_fpga_ipsec_counters_read(struct mlx5_core_dev *mdev, u64 *counters,
				  unsigned int counters_count)
{
	struct mlx5_fpga_device *fdev = mdev->fpga;
	unsigned int i;
	__be32 *data;
	u32 count;
	u64 addr;
	int ret;

	if (!fdev || !fdev->ipsec)
		return 0;

	addr = (u64)MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps,
			     ipsec_counters_addr_low) +
	       ((u64)MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps,
			     ipsec_counters_addr_high) << 32);

	count = mlx5_fpga_ipsec_counters_count(mdev);

	data = kzalloc(sizeof(*data) * count * 2, GFP_KERNEL);
	if (!data) {
		ret = -ENOMEM;
		goto out;
	}

	ret = mlx5_fpga_mem_read(fdev, count * sizeof(u64), addr, data,
				 MLX5_FPGA_ACCESS_TYPE_DONTCARE);
	if (ret < 0) {
		mlx5_fpga_err(fdev, "Failed to read IPSec counters from HW: %d\n",
			      ret);
		goto out;
	}
	ret = 0;

	if (count > counters_count)
		count = counters_count;

	/* Each counter is low word, then high. But each word is big-endian */
	for (i = 0; i < count; i++)
		counters[i] = (u64)ntohl(data[i * 2]) |
			      ((u64)ntohl(data[i * 2 + 1]) << 32);

out:
	kfree(data);
	return ret;
}

static const struct mlx5_flow_cmds mlx5_ipsec_flow_cmds = {
	.create_flow_table = mlx5_cmd_def_create_flow_table,
	.destroy_flow_table = mlx5_cmd_def_destroy_flow_table,
	.modify_flow_table = mlx5_cmd_def_modify_flow_table,
	.create_flow_group = mlx5_cmd_def_create_flow_group,
	.destroy_flow_group = mlx5_cmd_def_destroy_flow_group,
	.create_fte = mlx5_cmd_create_ipsec_fte,
	.update_fte = mlx5_cmd_def_update_fte,
	.delete_fte = mlx5_cmd_delete_ipsec_fte,
	.update_root_ft = mlx5_cmd_def_update_root_ft,
};

static void mlx5_fs_ipsec_build_hw_sa(struct mlx5_core_dev *dev, u32 op,
				      struct fs_fte *fte,
				      struct mlx5_flow_group *fg,
				      struct mlx5_accel_ipsec_sa *hw_sa)
{
	struct mlx5_flow_esp_aes_gcm_action  *esp_aes_gcm = fte->esp_aes_gcm;

	memset(hw_sa, 0, sizeof(*hw_sa));

	if (op == MLX5_IPSEC_CMD_ADD_SA) {
		memcpy(&hw_sa->key_enc, esp_aes_gcm->key,
		       esp_aes_gcm->key_length);
		if (esp_aes_gcm->key_length == 16)
			memcpy(&hw_sa->key_enc[16], esp_aes_gcm->key,
			       esp_aes_gcm->key_length);
		hw_sa->gcm.salt = *((__be32 *)esp_aes_gcm->salt);
	}

	hw_sa->cmd = htonl(op);
	hw_sa->flags |= MLX5_IPSEC_SADB_SA_VALID | MLX5_IPSEC_SADB_SPI_EN;
	if (mlx5_fs_is_outer_ipv4_flow(dev, fg->mask.match_criteria, fte->val)) {
		memcpy(&hw_sa->sip[3],
		       MLX5_ADDR_OF(fte_match_set_lyr_2_4, fte->val,
				    src_ipv4_src_ipv6.ipv4_layout.ipv4),
		       sizeof(hw_sa->sip[3]));
		memcpy(&hw_sa->dip[3],
		       MLX5_ADDR_OF(fte_match_set_lyr_2_4, fte->val,
				    dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
		       sizeof(hw_sa->dip[3]));
		hw_sa->sip_masklen = 32;
		hw_sa->dip_masklen = 32;
	} else {
		memcpy(hw_sa->sip,
		       MLX5_ADDR_OF(fte_match_param, fte->val,
				    outer_headers.src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       sizeof(hw_sa->sip));
		memcpy(hw_sa->dip,
		       MLX5_ADDR_OF(fte_match_param, fte->val,
				    outer_headers.dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       sizeof(hw_sa->dip));
		hw_sa->sip_masklen = 128;
		hw_sa->dip_masklen = 128;
		hw_sa->flags |= MLX5_IPSEC_SADB_IPV6;
	}
	hw_sa->spi = MLX5_GET_BE(typeof(hw_sa->spi),
				 fte_match_param, fte->val,
				 misc_parameters.outer_esp_spi);
	hw_sa->sw_sa_handle = 0;
	hw_sa->flags |= MLX5_IPSEC_SADB_IP_ESP;
	switch (esp_aes_gcm->key_length) {
	case 16:
		hw_sa->enc_mode = MLX5_IPSEC_SADB_MODE_AES_GCM_128_AUTH_128;
	case 32:
		hw_sa->enc_mode = MLX5_IPSEC_SADB_MODE_AES_GCM_256_AUTH_128;
	}

	if (fte->action & MLX5_FLOW_CONTEXT_ACTION_ENCRYPT)
		hw_sa->flags |= MLX5_IPSEC_SADB_DIR_SX;
}

static bool mlx5_is_fpga_ipsec_rule(struct mlx5_core_dev *dev,
				    struct fs_fte *fte,
				    struct mlx5_flow_group *fg)
{
	u32 ipsec_dev_caps = mlx5_accel_ipsec_device_caps(dev);
	const u32 *match_c;
	const u32 *match_v;
	bool ipv6_flow;

	match_c = fg->mask.match_criteria;
	match_v = fte->val;
	ipv6_flow = mlx5_fs_is_outer_ipv6_flow(dev, match_c, match_v);

	if (mlx5_fs_is_outer_udp_flow(match_c, match_v) ||
	    mlx5_fs_is_outer_tcp_flow(match_c, match_v) ||
	    mlx5_fs_is_vxlan_flow(match_c) ||
	    (fg->mask.match_criteria_enable & 1 << MLX5_CREATE_FLOW_GROUP_IN_MATCH_CRITERIA_ENABLE_INNER_HEADERS) ||
	    !(mlx5_fs_is_outer_ipv4_flow(dev, match_c, match_v) ||
	      ipv6_flow))
		return false;

	if (!(ipsec_dev_caps & MLX5_ACCEL_IPSEC_DEVICE))
		return false;

	if (!(ipsec_dev_caps & MLX5_ACCEL_IPSEC_ESP) &&
	    mlx5_fs_is_ipsec_flow(match_c))
		return false;

	if (!(ipsec_dev_caps & MLX5_ACCEL_IPSEC_IPV6) &&
	    ipv6_flow)
		return false;

	return true;
}

static bool is_full_mask(const void *p, size_t len)
{
	WARN_ON(len % 4);

	return !memchr_inv(p, 0xff, len);
}

static bool validate_fpga_full_mask(struct mlx5_core_dev *dev,
				    const struct mlx5_flow_group *fg,
				    const struct fs_fte *fte)
{
	const void *misc_params_c = MLX5_ADDR_OF(fte_match_param,
						 fg->mask.match_criteria,
						 misc_parameters);
	const void *headers_c = MLX5_ADDR_OF(fte_match_param,
					     fg->mask.match_criteria,
					     outer_headers);
	const void *headers_v = MLX5_ADDR_OF(fte_match_param,
					     fte->val,
					     outer_headers);

	if (mlx5_fs_is_outer_ipv4_flow(dev, headers_c, headers_v)) {
		const void *s_ipv4_c = MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
						    src_ipv4_src_ipv6.ipv4_layout.ipv4);
		const void *d_ipv4_c = MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
						    dst_ipv4_dst_ipv6.ipv4_layout.ipv4);

		if (!is_full_mask(s_ipv4_c, MLX5_FLD_SZ_BYTES(ipv4_layout,
							      ipv4)) ||
		    !is_full_mask(d_ipv4_c, MLX5_FLD_SZ_BYTES(ipv4_layout,
							      ipv4)))
			return false;
	} else {
		const void *s_ipv6_c = MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
						    src_ipv4_src_ipv6.ipv6_layout.ipv6);
		const void *d_ipv6_c = MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
						    dst_ipv4_dst_ipv6.ipv6_layout.ipv6);

		if (!is_full_mask(s_ipv6_c, MLX5_FLD_SZ_BYTES(ipv6_layout,
							      ipv6)) ||
		    !is_full_mask(d_ipv6_c, MLX5_FLD_SZ_BYTES(ipv6_layout,
							      ipv6)))
			return false;
	}

	if (!is_full_mask(MLX5_ADDR_OF(fte_match_set_misc, misc_params_c,
				       outer_esp_spi),
			  MLX5_FLD_SZ_BYTES(fte_match_set_misc, outer_esp_spi)))
		return false;

	return true;
}

int mlx5_cmd_create_ipsec_fte(struct mlx5_core_dev *dev,
			      struct mlx5_flow_table *ft,
			      struct mlx5_flow_group *fg,
			      struct fs_fte *fte)
{
	struct mlx5_accel_ipsec_sa hw_sa;
	void *context;

	if (!mlx5_is_fpga_ipsec_rule(dev, fte, fg))
		return -EINVAL;

	if (fte->esp_aes_gcm) {
		if (!validate_fpga_full_mask(dev, fg, fte))
			return -EINVAL;

		if (fte->esp_aes_gcm->key_length != 32 &&
		    fte->esp_aes_gcm->key_length != 16) {
			pr_err("only 256 and 128 bit aes-gcm keys are supported\n");
			return -EINVAL;
		}

		if (fte->esp_aes_gcm->is_esn) {
			pr_err("ESN not supported\n");
			return -EINVAL;
		}
	} else {
		return -EINVAL;
	}

	mlx5_fs_ipsec_build_hw_sa(dev, MLX5_IPSEC_CMD_ADD_SA, fte, fg,
				  &hw_sa);
	context = mlx5_accel_ipsec_sa_cmd_exec(dev, &hw_sa);
	if (IS_ERR(context))
		return PTR_ERR(context);

	return mlx5_accel_ipsec_sa_cmd_wait(context);
}

int mlx5_cmd_delete_ipsec_fte(struct mlx5_core_dev *dev,
			      struct mlx5_flow_table *ft,
			      struct fs_fte *fte)
{
	struct mlx5_accel_ipsec_sa hw_sa;
	struct mlx5_flow_group *fg;
	void *context;

	fs_get_obj(fg, fte->node.parent);

	mlx5_fs_ipsec_build_hw_sa(dev, MLX5_IPSEC_CMD_DEL_SA, fte, fg,
				  &hw_sa);
	context = mlx5_accel_ipsec_sa_cmd_exec(dev, &hw_sa);
	if (IS_ERR(context))
		return PTR_ERR(context);

	return mlx5_accel_ipsec_sa_cmd_wait(context);
}

static int init_ipsec_tx_root_ns(struct mlx5_flow_steering *steering)
{
	struct fs_prio *prio;

	steering->ipsec_tx_root_ns = create_root_ns(steering, FS_FT_IPSEC_TX,
						    &mlx5_ipsec_flow_cmds);
	if (!steering->ipsec_tx_root_ns)
		return -ENOMEM;

	/* Create single prio */
	prio = fs_create_prio(&steering->ipsec_tx_root_ns->ns, 1, 1);
	if (IS_ERR(prio)) {
		cleanup_root_ns(steering->ipsec_tx_root_ns);
		return PTR_ERR(prio);
	}
	return 0;
}

static int init_ipsec_rx_root_ns(struct mlx5_flow_steering *steering)
{
	struct fs_prio *prio;

	steering->ipsec_rx_root_ns = create_root_ns(steering, FS_FT_IPSEC_RX,
						    &mlx5_ipsec_flow_cmds);
	if (!steering->ipsec_rx_root_ns)
		return -ENOMEM;

	/* Create single prio */
	prio = fs_create_prio(&steering->ipsec_rx_root_ns->ns, 1, 1);
	if (IS_ERR(prio)) {
		cleanup_root_ns(steering->ipsec_rx_root_ns);
		return PTR_ERR(prio);
	}
	return 0;
}

int init_ipsec_root_ns(struct mlx5_core_dev *mdev)
{
	struct mlx5_flow_steering *steering = mdev->priv.steering;
	int err;

	err = init_ipsec_tx_root_ns(steering);
	if (err)
		goto err;

	err = init_ipsec_rx_root_ns(steering);
	if (err)
		goto err;
	goto out;
err:
	steering->ipsec_rx_root_ns = NULL;
	steering->ipsec_tx_root_ns = NULL;
out:
	return err;
}

int mlx5_fpga_ipsec_init(struct mlx5_core_dev *mdev)
{
	struct mlx5_fpga_conn_attr init_attr = {0};
	struct mlx5_fpga_device *fdev = mdev->fpga;
	struct mlx5_fpga_conn *conn;
	int err;

	if (!mlx5_fpga_is_ipsec_device(mdev))
		return 0;

	err = init_ipsec_root_ns(mdev);
	if (err)
		return err;

	fdev->ipsec = kzalloc(sizeof(*fdev->ipsec), GFP_KERNEL);
	if (!fdev->ipsec)
		return -ENOMEM;

	err = mlx5_fpga_get_sbu_caps(fdev, sizeof(fdev->ipsec->caps),
				     fdev->ipsec->caps);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to retrieve IPSec extended capabilities: %d\n",
			      err);
		goto error;
	}

	INIT_LIST_HEAD(&fdev->ipsec->pending_cmds);
	spin_lock_init(&fdev->ipsec->pending_cmds_lock);

	init_attr.rx_size = SBU_QP_QUEUE_SIZE;
	init_attr.tx_size = SBU_QP_QUEUE_SIZE;
	init_attr.recv_cb = mlx5_fpga_ipsec_recv;
	init_attr.cb_arg = fdev;
	conn = mlx5_fpga_sbu_conn_create(fdev, &init_attr);
	if (IS_ERR(conn)) {
		err = PTR_ERR(conn);
		mlx5_fpga_err(fdev, "Error creating IPSec command connection %d\n",
			      err);
		goto error;
	}
	fdev->ipsec->conn = conn;
	return 0;

error:
	kfree(fdev->ipsec);
	fdev->ipsec = NULL;
	mlx5_fpga_ipsec_cleanup(mdev);
	return err;
}

void mlx5_fpga_ipsec_cleanup(struct mlx5_core_dev *mdev)
{
	struct mlx5_flow_steering *steering = mdev->priv.steering;
	struct mlx5_fpga_device *fdev = mdev->fpga;

	if (!mlx5_fpga_is_ipsec_device(mdev))
		return;

	mlx5_fpga_sbu_conn_destroy(fdev->ipsec->conn);
	kfree(fdev->ipsec);
	fdev->ipsec = NULL;
	cleanup_root_ns(steering->ipsec_rx_root_ns);
	cleanup_root_ns(steering->ipsec_tx_root_ns);
}

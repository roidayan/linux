/*
 * Copyright (c) 2007 Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2007, 2008 Mellanox Technologies. All rights reserved.
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

#include <linux/workqueue.h>
#include <linux/module.h>

#include "mlx4.h"

enum {
	MLX4_CATAS_POLL_INTERVAL	= 5 * HZ,
};



static int internal_err_reset = 1;
module_param(internal_err_reset, int, 0644);
MODULE_PARM_DESC(internal_err_reset,
		 "Reset device on internal errors if non-zero"
		 " (default 1, in SRIOV mode default is 0)");

static int read_vendor_id(struct mlx4_dev *dev)
{
	u16 vendor_id = 0;
	int ret;

	ret = pci_read_config_word(dev->pdev, 0, &vendor_id);
	if (ret) {
		mlx4_err(dev, "Failed to read vendor ID, ret=%d\n", ret);
		return ret;
	}

	if (vendor_id == 0xffff) {
		mlx4_err(dev, "PCI can't be accessed to read vendor id\n");
		return -EINVAL;
	}

	return 0;
}

static int mlx4_reset_master(struct mlx4_dev *dev)
{
	int err = 0;

	if (!pci_channel_offline(dev->pdev)) {
		err = read_vendor_id(dev);
		/* If PCI can't be accessed to read vendor ID we assume that its
		 * link was disabled and chip was already reset.
		 */
		if (err)
			return 0;

		err = mlx4_reset(dev);
		if (err)
			mlx4_err(dev, "Fail to reset HCA\n");
	}

	return err;
}

void mlx4_enter_error_state(struct mlx4_dev *dev)
{
	int err;

	if (!internal_err_reset)
		return;

	mutex_lock(&dev->device_state_mutex);
	if (dev->state & MLX4_DEVICE_STATE_INTERNAL_ERROR)
		goto out;

	mlx4_err(dev, "device is going to be reset\n");
	err = mlx4_reset_master(dev);
	BUG_ON(err != 0);

	dev->state |= MLX4_DEVICE_STATE_INTERNAL_ERROR;
	mlx4_err(dev, "device was reset successfully\n");
	mutex_unlock(&dev->device_state_mutex);

	/* At that step HW was already reset, now notify clients */
	mlx4_dispatch_event(dev, MLX4_DEV_EVENT_CATASTROPHIC_ERROR, 0);
	return;

out:
	mutex_unlock(&dev->device_state_mutex);
}

static void mlx4_handle_error_state(struct mlx4_dev *dev)
{
	int err = 0;

	mlx4_enter_error_state(dev);
	err = mlx4_restart_one(dev->pdev);
	mlx4_info(dev, "mlx4_restart_one was ended, ret=%d\n", err);
}

static void dump_err_buf(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);

	int i;

	mlx4_err(dev, "Internal error detected:\n");
	for (i = 0; i < priv->fw.catas_size; ++i)
		mlx4_err(dev, "  buf[%02x]: %08x\n",
			 i, swab32(readl(priv->catas_err.map + i)));
}

static void poll_catas(unsigned long dev_ptr)
{
	struct mlx4_dev *dev = (struct mlx4_dev *) dev_ptr;
	struct mlx4_priv *priv = mlx4_priv(dev);

	if (readl(priv->catas_err.map)) {
		dump_err_buf(dev);
		goto internal_err;
	}

	if (dev->state & MLX4_DEVICE_STATE_INTERNAL_ERROR) {
		mlx4_warn(dev, "Internal error mark was detected on device\n");
		goto internal_err;
	}

	mod_timer(&priv->catas_err.timer,
		  round_jiffies(jiffies + MLX4_CATAS_POLL_INTERVAL));
	return;

internal_err:
	if (internal_err_reset)
		queue_work(dev->catas_wq, &dev->catas_work);
}

static void catas_reset(struct work_struct *work)
{
	struct mlx4_dev *dev = container_of(work, struct mlx4_dev, catas_work);

	mlx4_handle_error_state(dev);
}

void mlx4_start_catas_poll(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	phys_addr_t addr;

	/*If we are in SRIOV the default of the module param must be 0*/
	if (mlx4_is_mfunc(dev))
		internal_err_reset = 0;

	INIT_LIST_HEAD(&priv->catas_err.list);
	init_timer(&priv->catas_err.timer);
	priv->catas_err.map = NULL;

	addr = pci_resource_start(dev->pdev, priv->fw.catas_bar) +
		priv->fw.catas_offset;

	priv->catas_err.map = ioremap(addr, priv->fw.catas_size * 4);
	if (!priv->catas_err.map) {
		mlx4_warn(dev, "Failed to map internal error buffer at 0x%llx\n",
			  (unsigned long long) addr);
		return;
	}

	priv->catas_err.timer.data     = (unsigned long) dev;
	priv->catas_err.timer.function = poll_catas;
	priv->catas_err.timer.expires  =
		round_jiffies(jiffies + MLX4_CATAS_POLL_INTERVAL);
	add_timer(&priv->catas_err.timer);
}

void mlx4_stop_catas_poll(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);

	del_timer_sync(&priv->catas_err.timer);

	if (priv->catas_err.map) {
		iounmap(priv->catas_err.map);
		priv->catas_err.map = NULL;
	}
}

int  mlx4_catas_init(struct mlx4_dev *dev)
{
	INIT_WORK(&dev->catas_work, catas_reset);
	dev->catas_wq = create_singlethread_workqueue("mlx4_health");
	if (!dev->catas_wq)
		return -ENOMEM;

	return 0;
}

void mlx4_catas_end(struct mlx4_dev *dev)
{
	if (dev->catas_wq) {
		destroy_workqueue(dev->catas_wq);
		dev->catas_wq = NULL;
	}
}

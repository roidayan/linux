/*
 * Copyright (c) 2015 Mellanox Technologies. All rights reserved.
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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/string.h>

#include <linux/configfs.h>
#include <linux/mlx4/device.h>

#include "mlx4.h"

#if IS_ENABLED(CONFIG_MLX4_CONFIGFS_FS)

/**
 * configfs entries for mlx4_core
 *
 * This file adds code for configfs support for mlx4_core driver. This sets
 * up a filesystem under /sys/kernel/config in which configuration changes
 * can be made for the driver's pci devices.
 *
 * The initialization of this code creates the "mlx4_core" entry in the configfs
 * system.  After that, the user needs to use mkdir to create configurations
 * for specific pci device; for example "mkdir 0000:04:00.0". This code will
 * verify that such a device exists and that it is owned by mlx4_core.
 *
 **/

#define MLX4_CFG_CONFIGFS_ATTR(struct_name, name)			\
	static struct struct_name##_attribute struct_name##_##name =	\
		__CONFIGFS_ATTR(name,  S_IRUGO | S_IWUSR,		\
				struct_name##_##name##_show,		\
				struct_name##_##name##_store)

/* Defines item_ops for 'struct_in'
 */
#define MLX4_CONFIG_ITEM_TYPE(struct_in)				\
									\
static struct configfs_item_operations struct_in##_item_ops = {		\
	.release                = struct_in##_release,			\
	.show_attribute         = struct_in##_attr_show,		\
	.store_attribute        = struct_in##_attr_store,		\
};									\
									\
static struct config_item_type struct_in##_item_type = {		\
	.ct_item_ops	= &struct_in##_item_ops,			\
	.ct_attrs	= struct_in##_attrs,				\
	.ct_owner	= THIS_MODULE,					\
}

static ssize_t pdev_config_commit_store(struct pdev_config *cfg,
					const char *page, size_t len)
{
	int err;
	unsigned long res;
	int active_vfs = 0;
	struct mlx4_dev_persistent *persist = pci_get_drvdata(cfg->pdev);
	struct mlx4_dev *dev = persist->dev;
	char *pdev_name = cfg->group.cg_item.ci_name;

	err = kstrtoul(page, 10, &res);
	if (err)
		return err;

	if ((res != 1) && (res != 0)) {
		pr_err("mlx4_core %s: Illegal value for commit: %lu, can't apply configurations.\n",
		       pdev_name, res);
		return -EINVAL;
	}
	if (res) {
		if (mlx4_is_master(dev) && dev->flags & MLX4_FLAG_SRIOV)
			active_vfs = mlx4_how_many_lives_vf(dev);
		if (active_vfs) {
			pr_warn("Can't restart device %s, unload active VFs before committing your changes.\n",
				pdev_name);
			return -EINVAL;

		} else {
			pr_warn("Restart device %s and allow setting of pre-load configurations.\n",
				pdev_name);
			err = mlx4_restart_one(cfg->pdev, 0);
		}
	}
	cfg->commit = res;

	return len;
}

static ssize_t pdev_config_commit_show(struct pdev_config *pdev_cfg, char *page)
{
		return sprintf(page, "%d\n", pdev_cfg->commit);
}

CONFIGFS_ATTR_STRUCT(pdev_config);
CONFIGFS_ATTR_OPS(pdev_config);
MLX4_CFG_CONFIGFS_ATTR(pdev_config, commit);

static void pdev_config_release(struct config_item *item)
{
	struct pdev_config *pdev_cfg = to_pdev_config(item);

	pci_dev_put(pdev_cfg->pdev);
	kfree(pdev_cfg);
}

static struct configfs_attribute *pdev_config_attrs[] = {
	&pdev_config_commit.attr,
	NULL,
};

MLX4_CONFIG_ITEM_TYPE(pdev_config);

static struct pci_dev *find_pdev_by_name(const char *name)
{
	struct pci_dev *pdev;
	char *pdev_name;
	char *tmp_p;
	unsigned long int domain;
	unsigned long int bus;
	unsigned long int dev;
	unsigned long int func;
	int err;

	tmp_p = kzalloc(sizeof(*name), GFP_KERNEL);
	if (!tmp_p)
		return ERR_PTR(-ENOMEM);
	strcpy(tmp_p, name);
	pdev_name = tmp_p;

	err = kstrtoul(strsep(&pdev_name, ":"), 16, &domain);
	if (err)
		goto format_err;

	err = kstrtoul(strsep(&pdev_name, ":"), 16, &bus);
	if (err)
		goto format_err;

	err = kstrtoul(strsep(&pdev_name, "."), 16, &dev);
	if (err)
		goto format_err;

	err = kstrtoul(pdev_name, 16, &func);
	if (err)
		goto format_err;

	pdev = pci_get_domain_bus_and_slot(domain, bus, (dev << 3) | func);
	if (!pdev) {
		pr_err("mlx4_core: Couldn't find pci device: %s\n", name);
		err = -EINVAL;
		goto out_err;
	}
	if (pdev->is_virtfn) {
		pr_err("mlx4_core: Couldn't set configuration for a virtual function. bdf name %s\n",
		       name);
		err = -EINVAL;
		pci_dev_put(pdev);
		goto out_err;
	}
	if (strcmp(pdev->driver->name, DRV_NAME)) {
		pr_err("mlx4_core: pci device %s is not mlx4 device. Can't set configurations.\n",
		       name);
		err = -EINVAL;
		pci_dev_put(pdev);
		goto out_err;
	}

	kfree(tmp_p);
	return pdev;

format_err:
	pr_err("mlx4_core: Wrong pci device format: %s, use: wwww:xx:yy.x, domain:bus:device.function\n",
	       name);
out_err:
	kfree(tmp_p);
	return ERR_PTR(err);
}

static struct config_group *mlx4_set_config(struct config_group *group,
					    const char *name)
{
	struct pdev_config *pdev_config;
	struct pci_dev *pdev;
	int err;

	pdev = find_pdev_by_name(name);
	if (IS_ERR(pdev))
		return ERR_PTR(PTR_ERR(pdev));

	pdev_config = kzalloc(sizeof(*pdev_config), GFP_KERNEL);
	if (!pdev_config) {
		err = -ENOMEM;
		goto out_err;
	}

	config_group_init_type_name(&pdev_config->group, name,
				    &pdev_config_item_type);
	pdev_config->pdev = pdev;
	return &pdev_config->group;

out_err:
	pci_dev_put(pdev);
	return ERR_PTR(err);
}

static struct config_group *device_driver_make(struct config_group *group,
					       const char *name)
{
	return mlx4_set_config(group, name);
}

static struct configfs_group_operations mlx4_group_ops = {
	.make_group	= device_driver_make,
};

static struct config_item_type mlx4_type = {
	.ct_group_ops	= &mlx4_group_ops,
	.ct_owner	= THIS_MODULE,
};

static struct configfs_subsystem mlx4_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = DRV_NAME,
			.ci_type = &mlx4_type,
		},
	},
};

int mlx4_configfs_init(void)
{
	int ret;
	struct configfs_subsystem *subsys = &mlx4_subsys;

	config_group_init(&subsys->su_group);
	mutex_init(&subsys->su_mutex);
	ret = configfs_register_subsystem(subsys);
	if (ret) {
		pr_err("Error %d while registering subsystem %s\n",
		       ret, subsys->su_group.cg_item.ci_namebuf);
		return ret;
	}
	return 0;
}

void mlx4_configfs_exit(void)
{
	configfs_unregister_subsystem(&mlx4_subsys);
}

MODULE_LICENSE("GPL");

#endif /* IS_ENABLED(CONFIG_MLX4_CONFIGFS_FS) */

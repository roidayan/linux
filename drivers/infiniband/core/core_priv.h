/*
 * Copyright (c) 2004 Topspin Communications.  All rights reserved.
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

#ifndef _CORE_PRIV_H
#define _CORE_PRIV_H

#include <linux/list.h>
#include <linux/spinlock.h>

#include <rdma/ib_verbs.h>

#if IS_ENABLED(CONFIG_INFINIBAND_ADDR_TRANS_CONFIGFS)
int cma_configfs_init(void);
void cma_configfs_exit(void);
#endif
struct cma_device;
typedef bool (*cma_device_filter)(struct ib_device *, void *);
struct cma_device *cma_enum_devices_by_ibdev(cma_device_filter	filter,
					     void		*cookie);
enum ib_gid_type cma_get_default_gid_type(struct cma_device *cma_dev);
void cma_set_default_gid_type(struct cma_device *cma_dev,
			      enum ib_gid_type default_gid_type);
void cma_ref_dev(struct cma_device *cma_dev);
void cma_deref_dev(struct cma_device *cma_dev);

int  ib_device_register_sysfs(struct ib_device *device,
			      int (*port_callback)(struct ib_device *,
						   u8, struct kobject *));
void ib_device_unregister_sysfs(struct ib_device *device);

int  ib_sysfs_setup(void);
void ib_sysfs_cleanup(void);

int  ib_cache_setup(void);
void ib_cache_cleanup(void);

int ib_resolve_eth_dmac(struct ib_qp *qp,
			struct ib_qp_attr *qp_attr, int *qp_attr_mask);

typedef void (*roce_netdev_callback)(struct ib_device *device, u8 port,
	      struct net_device *idev, void *cookie);

typedef int (*roce_netdev_filter)(struct ib_device *device, u8 port,
	     struct net_device *idev, void *cookie);

void ib_enum_roce_netdev(struct ib_device *ib_dev,
			 roce_netdev_filter filter,
			 void *filter_cookie,
			 roce_netdev_callback cb,
			 void *cookie);
void ib_enum_all_roce_netdevs(roce_netdev_filter filter,
			      void *filter_cookie,
			      roce_netdev_callback cb,
			      void *cookie);

int ib_cache_gid_find_by_port(struct ib_device *ib_dev,
			      const union ib_gid *gid,
			      enum ib_gid_type gid_type,
			      u8 port, struct net_device *ndev,
			      u16 *index);

enum ib_cache_gid_default_mode {
	IB_CACHE_GID_DEFAULT_MODE_SET,
	IB_CACHE_GID_DEFAULT_MODE_DELETE
};

int ib_cache_gid_parse_type_str(const char *buf);

int ib_cache_gid_find_by_filter(struct ib_device *ib_dev,
				const union ib_gid *gid,
				u8 port,
				bool (*filter)(const union ib_gid *gid,
					       const struct ib_gid_attr *,
					       void *),
				void *context,
				u16 *index);

const char *ib_cache_gid_type_str(enum ib_gid_type gid_type);

void ib_cache_gid_set_default_gid(struct ib_device *ib_dev, u8 port,
				  struct net_device *ndev,
				  unsigned long gid_type_mask,
				  enum ib_cache_gid_default_mode mode);

int ib_cache_gid_add(struct ib_device *ib_dev, u8 port,
		     union ib_gid *gid, struct ib_gid_attr *attr);

int ib_cache_gid_del(struct ib_device *ib_dev, u8 port,
		     union ib_gid *gid, struct ib_gid_attr *attr);

int ib_cache_gid_del_all_netdev_gids(struct ib_device *ib_dev, u8 port,
				     struct net_device *ndev);

int roce_gid_mgmt_init(void);
void roce_gid_mgmt_cleanup(void);

int roce_rescan_device(struct ib_device *ib_dev);
unsigned long roce_gid_type_mask_support(struct ib_device *ib_dev, u8 port);

#endif /* _CORE_PRIV_H */

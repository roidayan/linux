/*
 * Copyright (c) 2014 Mellaniox, LTD. All rights reserved.
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

#ifndef _IPOIB_ALLMULTI_H
#define _IPOIB_ALLMULTI_H

#include <linux/workqueue.h>
#include <linux/mutex.h>

/* MC Promisc debug */
#ifdef CONFIG_INFINIBAND_IPOIB_DEBUG
extern int allmulti_debug_level;
#define ipoib_dbg_mcp_lvl(level, priv, format, arg...) {		\
		if (allmulti_debug_level >= level)		\
			ipoib_printk(KERN_DEBUG, priv,	\
				"MCPromisc: "format , ## arg); \
	}
#define ipoib_dbg_mcp(priv, format, arg...) \
				ipoib_dbg_mcp_lvl(1, priv, format, ## arg)
#else
#define ipoib_dbg_mcp(priv, format, arg...)
#define ipoib_dbg_mcp_lvl(level, priv, format, arg...)
#endif

#define GENL_SKB_DATA_OFFSET 36

#define IPOIB_RULE_DATA_SIZE \
	(sizeof(struct ipoib_mc_rule)-sizeof(struct rb_node))

struct ipoib_dev_priv;

/* GeNetlink metadata */
struct genl_mdata {
	struct list_head ipoib_genl_if;
	unsigned long flags;
};

/* function declarations from ipoib_multicast.c */
struct ipoib_mcast *ipoib_mcast_alloc(struct net_device *dev,
				      int can_sleep);
void ipoib_mcast_free(struct ipoib_mcast *mcast);
struct ipoib_mcast *__ipoib_mcast_find(struct net_device *dev,
				       void *mgid,
				       struct rb_root *root);
int __ipoib_mcast_add(struct net_device *dev, struct ipoib_mcast *mcast,
		      struct rb_root *root);
void ipoib_mcast_join(struct net_device *dev, struct ipoib_mcast *mcast,
		      int create, int join_state);
int ipoib_mcast_leave(struct net_device *dev, struct ipoib_mcast *mcast);

void ipoib_mcp_work_handler(struct work_struct *work);

enum join_state {
	DONT_JOIN = 0,
	FULL_MEMBER = 1,
	NON_MEMBER = 2
};

enum mc_action {
	MC_REGISTER, /* register to SM's inform info notifications */
	MC_CREATE_ACTION, /* MCG was created in SM */
	MC_DELETE_ACTION, /* MCG was deleted in SM */
	MC_ADD_RULE_ACTION, /* add new MCG rule from user */
	MC_VALIDATE_RULES_ACTION, /* validate rules from user */
	MC_GET_MCG_TABLE /* notify current active mcasts */
};

enum notification_type {
	NOTIFY_JOIN,
	NOTIFY_LEAVE,
	NOTIFY_DETAILS
};

enum promisc_mc_flag {
	MC_CREATE_REG = 0,
	MC_DELETE_REG = 1,
	MCP_STOPPED = 2,
	MC_VALIDATE = 3
};

struct promisc_mc {
	unsigned long		reg_delay;
	unsigned long		flags;
	struct ib_inform_info	*create_mcg;
	struct ib_inform_info	*delete_mcg;

	struct rb_root		multicast_tree;

	struct workqueue_struct	*workqueue;

	struct mutex		state_lock; /* mc_promiosc_[start/stop] lock */
	struct mutex		tree_lock; /* for promisc_mc trees access */
	struct rb_root		rules_tree; /* rules in this tree are applied */
	struct rb_root		new_rules_tree; /* rules are only accumulated
						 * here until validation */
};

/* rb_node member must be defined last */
struct ipoib_mc_rule {
	u8 mgid[16];
	u8 mask[16];
	u8 join_state;
	u8 priority;
	struct rb_node rb_node;
};

static inline char *status_to_str(int status)
{
	switch (status) {
	case 0:
		return "DONT JOIN";
	case 1:
		return "FULL MEMBER";
	case 2:
		return "NON MEMBER";
	default:
		return "NO SUCH STATUS";
	}
}

static inline char *command_to_str(int command)
{
	switch (command) {
	case 1:
		return "ENABLE PATH";
	case 2:
		return "REPORT PATH";
	case 3:
		return "ENABLE MC";
	case 4:
		return "GET MCG";
	case 5:
		return "REPORT MCG";
	case 6:
		return "ADD RULE";
	case 7:
		return "VALIDATE RULES";
	default:
		return "NO SUCH COMMAND";
	}
}

#ifdef CONFIG_IPOIB_ALL_MULTI
int ipoib_register_genl(void);
void ipoib_unregister_genl(void);
void ipoib_genl_intf_add(struct genl_mdata *netlink);
void ipoib_genl_intf_init(struct genl_mdata *netlink);
void ipoib_genl_intf_del(struct genl_mdata *netlink);

void ipoib_path_add_notify(struct ipoib_dev_priv *priv,
			    struct ib_sa_path_rec *pathrec);
void ipoib_path_del_notify(struct ipoib_dev_priv *priv,
			    struct ib_sa_path_rec *pathrec);
void ipoib_mc_join_notify(struct ipoib_dev_priv *priv,
			  struct ib_sa_mcmember_rec *rec);
void ipoib_mc_leave_notify(struct ipoib_dev_priv *priv,
			   struct ib_sa_mcmember_rec *rec);
void ipoib_mcg_details_notify(struct ipoib_dev_priv *priv,
			   struct ib_sa_mcmember_rec *rec);
void ipoib_mc_raise_notification(struct ipoib_dev_priv *priv,
				 struct ib_sa_mcmember_rec *rec,
				 enum notification_type type);
int ipoib_promisc_mc_init(struct promisc_mc *promisc);
int ipoib_promisc_mc_start(struct promisc_mc *promisc);
int ipoib_promisc_mc_stop(struct promisc_mc *promisc);
int ipoib_promisc_mc_destroy(struct promisc_mc *promisc);

/*
 * actions to be called from user/sm callbacks context
 * to be queued in promisc_mc.workqueue.
 */

int ipoib_queue_create_mcg_work(struct promisc_mc *promisc_mc, u8 gid[16]);
int ipoib_queue_delete_mcg_work(struct promisc_mc *promisc_mc, u8 gid[16]);
int ipoib_queue_add_rule(struct promisc_mc *promisc, struct ipoib_mc_rule rule);
int ipoib_queue_validate_rules(struct promisc_mc *promisc);
int ipoib_queue_get_mcg_table(struct promisc_mc *promisc);

#else
/* When CONFIG_IPOIB_ALL_MULTI is disabled, the following stubs are used */
static inline int ipoib_register_genl(void)
{
	return 0;
}
static inline void ipoib_unregister_genl(void)
{
	return;
}
static inline void ipoib_genl_intf_add(struct genl_mdata *netlink)
{
	return;
}

static inline void ipoib_genl_intf_init(struct genl_mdata *netlink)
{
	return;
}

static inline void ipoib_genl_intf_del(struct genl_mdata *netlink)
{
	return;
}

static inline void ipoib_path_add_notify(struct ipoib_dev_priv *priv,
			    struct ib_sa_path_rec *pathrec)
{
	return;
}

static inline void ipoib_path_del_notify(struct ipoib_dev_priv *priv,
			    struct ib_sa_path_rec *pathrec)
{
	return;
}

static inline void ipoib_mc_join_notify(struct ipoib_dev_priv *priv,
			  struct ib_sa_mcmember_rec *rec)
{
	return;
}

static inline void ipoib_mc_leave_notify(struct ipoib_dev_priv *priv,
			   struct ib_sa_mcmember_rec *rec)
{
	return;
}

static inline void ipoib_mcg_details_notify(struct ipoib_dev_priv *priv,
			   struct ib_sa_mcmember_rec *rec)
{
	return;
}
static inline void ipoib_mc_raise_notification(struct ipoib_dev_priv *priv,
					struct ib_sa_mcmember_rec *rec,
					enum notification_type type)
{
	return;
}

static inline int ipoib_promisc_mc_init(struct promisc_mc *promisc)
{
	return 0;
}

static inline int ipoib_promisc_mc_start(struct promisc_mc *promisc)
{
	return -ENOTSUPP;
}

static inline void ipoib_promisc_mc_flush(struct promisc_mc *promisc)
{
	return;
}

static inline int ipoib_promisc_mc_stop(struct promisc_mc *promisc)
{
	return 0;
}

static inline int ipoib_promisc_mc_destroy(struct promisc_mc *promisc)
{
	return 0;
}
static inline int ipoib_get_mcg_table(struct promisc_mc *promisc)
{
	return 0;
}
#endif
#endif /* _IPOIB_ALLMULTI_H */

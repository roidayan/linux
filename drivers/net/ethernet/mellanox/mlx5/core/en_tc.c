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

#include <net/flow_dissector.h>
#include <net/sch_generic.h>
#include <net/pkt_cls.h>
#include <net/tc_act/tc_gact.h>
#include <net/tc_act/tc_skbedit.h>
#include <linux/mlx5/fs.h>
#include <linux/mlx5/device.h>
#include <linux/rhashtable.h>
#include <linux/refcount.h>
#include <net/switchdev.h>
#include <net/tc_act/tc_mirred.h>
#include <net/tc_act/tc_vlan.h>
#include <net/tc_act/tc_tunnel_key.h>
#include <net/tc_act/tc_pedit.h>
#include <net/tc_act/tc_csum.h>
#include <net/tc_act/tc_ct.h>
#include <net/vxlan.h>
#include <net/arp.h>
#include "en.h"
#include "en_rep.h"
#include "en_tc.h"
#include "eswitch.h"
#include "lib/vxlan.h"
#include "fs_core.h"
#include "en/port.h"

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nft_gen_flow_offload.h>

#include <linux/yktrace.h>

#define CT_DEBUG_COUNTERS 1

static atomic64_t global_version;

#if CT_DEBUG_COUNTERS
static atomic_t  nr_of_total_mf_succ =  ATOMIC_INIT(0);
static atomic_t  nr_of_total_merge_mf_succ =  ATOMIC_INIT(0);
static atomic_t  nr_of_total_del_mf_succ =  ATOMIC_INIT(0);

static atomic_t  nr_of_total_mf_work_requests =  ATOMIC_INIT(0);
static atomic_t  nr_of_total_merge_mf_work_requests =  ATOMIC_INIT(0);
static atomic_t  nr_of_total_del_mf_work_requests =  ATOMIC_INIT(0);

static atomic_t  nr_of_total_mf_err =  ATOMIC_INIT(0);
static atomic_t  nr_of_total_mf_err_alloc_flow =  ATOMIC_INIT(0);
static atomic_t  nr_of_total_mf_err_resolve_path_flows =  ATOMIC_INIT(0);
static atomic_t  nr_of_total_mf_err_merge_mirred =  ATOMIC_INIT(0);
static atomic_t  nr_of_total_mf_err_merge_hdr =  ATOMIC_INIT(0);
static atomic_t  nr_of_total_mf_err_attach_dummy_counter =  ATOMIC_INIT(0);
static atomic_t  nr_of_total_mf_err_fdb_add =  ATOMIC_INIT(0);
static atomic_t  nr_of_total_mf_err_verify_path =  ATOMIC_INIT(0);
static atomic_t  nr_of_total_mf_err_register =  ATOMIC_INIT(0);

static atomic_t  nr_of_merge_mfe_in_queue =  ATOMIC_INIT(0);
static atomic_t  nr_of_del_mfe_in_queue =  ATOMIC_INIT(0);

//inflight = currently on work (can be more them 1 in parallel)
static atomic_t  nr_of_inflight_mfe =  ATOMIC_INIT(0);
static atomic_t  nr_of_inflight_merge_mfe =  ATOMIC_INIT(0);
static atomic_t  nr_of_inflight_del_mfe =  ATOMIC_INIT(0);

#endif /*CT_DEBUG_COUNTERS*/
static atomic_t  nr_of_mfe_in_queue =  ATOMIC_INIT(0);
static atomic_t  currently_in_hw =  ATOMIC_INIT(0);

/* TODO: there is a circular dep between mlx5_core and nft_gen_flow_offload ??? */
static uint merger_probability = 0;
module_param(merger_probability, uint, 0644);

static int invert_cnt = 0;
module_param(invert_cnt, int, 0644);

static int enable_ct_ageing = 1; /* On by default */
module_param(enable_ct_ageing, int, 0644);

static int max_nr_mf = 1024*1024;
module_param(max_nr_mf, int, 0644);

static char out_ifname[IFNAMSIZ] = "";
module_param_string(out_ifname, out_ifname, sizeof(out_ifname), S_IRUGO|S_IWUSR);

#if CT_DEBUG_COUNTERS
	#define inc_debug_counter(counter_name) \
		atomic_inc(counter_name);
	#define dec_debug_counter(counter_name) \
		atomic_dec(counter_name);
#else
	#define inc_debug_counter(counter_name)
	#define dec_debug_counter(counter_name)
#endif

/* TODO: there is a circular dep between mlx5_core and nft_gen_flow_offload ??? */

#define _sprintf(p, buf, format, arg...)				\
	((PAGE_SIZE - (int)(p - buf)) <= 0 ? 0 :			\
	scnprintf(p, PAGE_SIZE - (int)(p - buf), format, ## arg))

ssize_t mlx5_show_counters_ct(char *buf)
{
	char *p = buf;

#if CT_DEBUG_COUNTERS
	p += _sprintf(p, buf, "nr_of_total_mf_work_requests            : %d\n", atomic_read(&nr_of_total_mf_work_requests));
	p += _sprintf(p, buf, "nr_of_total_merge_mf_work_requests      : %d\n", atomic_read(&nr_of_total_merge_mf_work_requests));
	p += _sprintf(p, buf, "nr_of_total_del_mf_work_requests        : %d\n", atomic_read(&nr_of_total_del_mf_work_requests));
	p += _sprintf(p, buf, "\n");
	p += _sprintf(p, buf, "nr_of_mfe_in_queue                      : %d\n", atomic_read(&nr_of_mfe_in_queue));
	p += _sprintf(p, buf, "nr_of_merge_mfe_in_queue                : %d\n", atomic_read(&nr_of_merge_mfe_in_queue));
	p += _sprintf(p, buf, "nr_of_del_mfe_in_queue                  : %d\n", atomic_read(&nr_of_del_mfe_in_queue));
	p += _sprintf(p, buf, "\n");
	p += _sprintf(p, buf, "nr_of_inflight_mfe                      : %d\n", atomic_read(&nr_of_inflight_mfe));
	p += _sprintf(p, buf, "nr_of_inflight_merge_mfe                : %d\n", atomic_read(&nr_of_inflight_merge_mfe));
	p += _sprintf(p, buf, "nr_of_inflight_del_mfe                  : %d\n", atomic_read(&nr_of_inflight_del_mfe));
	p += _sprintf(p, buf, "\n");
	p += _sprintf(p, buf, "nr_of_total_mf_succ                     : %d\n", atomic_read(&nr_of_total_mf_succ));
	p += _sprintf(p, buf, "nr_of_total_merge_mf_succ               : %d\n", atomic_read(&nr_of_total_merge_mf_succ));
	p += _sprintf(p, buf, "nr_of_total_del_mf_succ                 : %d\n", atomic_read(&nr_of_total_del_mf_succ));
	p += _sprintf(p, buf, "\n");
	p += _sprintf(p, buf, "currently_in_hw                         : %d\n", atomic_read(&currently_in_hw));
	p += _sprintf(p, buf, "\n");
	p += _sprintf(p, buf, "nr_of_total_mf_err                      : %d\n", atomic_read(&nr_of_total_mf_err));
	p += _sprintf(p, buf, "nr_of_total_mf_err_alloc_flow           : %d\n", atomic_read(&nr_of_total_mf_err_alloc_flow));
	p += _sprintf(p, buf, "nr_of_total_mf_err_resolve_path_flows   : %d\n", atomic_read(&nr_of_total_mf_err_resolve_path_flows));
	p += _sprintf(p, buf, "nr_of_total_mf_err_merge_mirred         : %d\n", atomic_read(&nr_of_total_mf_err_merge_mirred));
	p += _sprintf(p, buf, "nr_of_total_mf_err_merge_hdr            : %d\n", atomic_read(&nr_of_total_mf_err_merge_hdr));
	p += _sprintf(p, buf, "nr_of_total_mf_err_attach_dummy_counter : %d\n", atomic_read(&nr_of_total_mf_err_attach_dummy_counter));
	p += _sprintf(p, buf, "nr_of_total_mf_err_fdb_add              : %d\n", atomic_read(&nr_of_total_mf_err_fdb_add));
	p += _sprintf(p, buf, "nr_of_total_mf_err_verify_path          : %d\n", atomic_read(&nr_of_total_mf_err_verify_path));
	p += _sprintf(p, buf, "nr_of_total_mf_err_register             : %d\n", atomic_read(&nr_of_total_mf_err_register));
	p += _sprintf(p, buf, "\n");
	p += _sprintf(p, buf, "enable_ct_ageing                        : %d\n", enable_ct_ageing);
	p += _sprintf(p, buf, "max_nr_mf                               : %d\n", max_nr_mf);
#else
	p += _sprintf(p, buf, "CT_DEBUG_COUNTERS is off\n");
	p += _sprintf(p, buf, "currently_in_hw                         : %d\n", atomic_read(&currently_in_hw));
	p += _sprintf(p, buf, "nr_of_mfe_in_queue                      : %d\n", atomic_read(&nr_of_mfe_in_queue));
	p += _sprintf(p, buf, "\n");
	p += _sprintf(p, buf, "enable_ct_ageing                        : %d\n", enable_ct_ageing);
	p += _sprintf(p, buf, "max_nr_mf                               : %d\n", max_nr_mf);
#endif /*CT_DEBUG_COUNTERS*/
	return (ssize_t)(p - buf);
}

static struct kmem_cache *nic_flow_cache   __read_mostly;
static struct kmem_cache *fdb_flow_cache   __read_mostly;
static struct kmem_cache *parse_attr_cache   __read_mostly;

struct mlx5_nic_flow_attr {
	u32 action;
	u32 flow_tag;
	u32 mod_hdr_id;
	u32 hairpin_tirn;
	u8 match_level;
	struct mlx5_flow_table	*hairpin_ft;
	struct mlx5_fc		*counter;
};

#define MLX5E_TC_FLOW_BASE (MLX5E_TC_LAST_EXPORTED_BIT + 1)

enum {
	MLX5E_TC_FLOW_INGRESS	= MLX5E_TC_INGRESS,
	MLX5E_TC_FLOW_EGRESS	= MLX5E_TC_EGRESS,
	MLX5E_TC_FLOW_ESWITCH	= BIT(MLX5E_TC_FLOW_BASE),
	MLX5E_TC_FLOW_NIC	= BIT(MLX5E_TC_FLOW_BASE + 1),
	MLX5E_TC_FLOW_OFFLOADED	= BIT(MLX5E_TC_FLOW_BASE + 2),
	MLX5E_TC_FLOW_HAIRPIN	= BIT(MLX5E_TC_FLOW_BASE + 3),
	MLX5E_TC_FLOW_HAIRPIN_RSS = BIT(MLX5E_TC_FLOW_BASE + 4),
	MLX5E_TC_FLOW_INIT_DONE	= BIT(MLX5E_TC_FLOW_BASE + 5),
	MLX5E_TC_FLOW_SIMPLE    = BIT(MLX5E_TC_FLOW_BASE + 6),
	MLX5E_TC_FLOW_CT	= BIT(MLX5E_TC_FLOW_BASE + 7),
};

struct mlx5e_miniflow;

struct mlx5e_ct_tuple;

#define MLX5E_TC_MAX_SPLITS 1

struct mlx5e_tc_flow {
	struct rhash_head	node;
	struct mlx5e_priv	*priv;
	u64			cookie;
	u64			version;
	atomic_t		flags;
	spinlock_t		rule_lock; /* protects rule array */
	struct mlx5_flow_handle *rule[MLX5E_TC_MAX_SPLITS + 1];
	struct mlx5e_encap_entry *e; /* attached encap instance */
	struct list_head	encap;   /* flows sharing the same encap ID */
	unsigned long		updated; /* encap updated */
	struct mlx5e_mod_hdr_entry *mh; /* attached mod header instance */
	struct list_head	mod_hdr; /* flows sharing the same mod hdr ID */
	struct mlx5e_hairpin_entry *hpe; /* attached hairpin instance */
	struct list_head	hairpin; /* flows sharing the same hairpin */
	refcount_t		refcnt;

	struct mlx5e_miniflow  *miniflow;
	struct mlx5_fc          *dummy_counter;

	struct list_head        miniflow_list;
	struct list_head        tmp_list;

	struct list_head        nft_node;
	struct rcu_head		rcu;

	union {
		struct mlx5_esw_flow_attr esw_attr[0];
		struct mlx5_nic_flow_attr nic_attr[0];
	};
	/* Don't add any fields here */
};

/* TODO: current_miniflow is global and probelmatic when we'll support
 * multiple HCAs. move it into mdev? */
DEFINE_PER_CPU(struct mlx5e_miniflow *, current_miniflow) = NULL;

static DEFINE_SPINLOCK(miniflow_lock);

/* TOOD: we should init this variable only once, rather than per PF? */
/* we should have a miniflow init/cleanup functions */
static int miniflow_cache_allocated;
static struct kmem_cache *miniflow_cache  __read_mostly;

/* Derived from current insertion rate (flows/s) */
#define MINIFLOW_WORKQUEUE_MAX_SIZE 40 * 1000

struct workqueue_struct *miniflow_wq;
static atomic_t miniflow_wq_size = ATOMIC_INIT(0);

struct mlx5e_miniflow_node {
	struct list_head node;
	struct mlx5e_miniflow *miniflow;
};

struct mlx5e_ct_tuple {
	struct net *net;
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_zone zone;

	struct mlx5e_tc_flow *flow;
};

#define MINIFLOW_MAX_FLOWS     8
#define MINIFLOW_MAX_CT_TUPLES 2

struct mlx5e_miniflow {
	struct rhash_head node;
	struct work_struct work;
	struct mlx5e_priv *priv;
	struct mlx5e_tc_flow *flow;

	struct nf_conntrack_tuple tuple;

	int nr_flows;
	u64 version;
	struct {
		unsigned long        cookies[MINIFLOW_MAX_FLOWS];
		struct mlx5e_tc_flow *flows[MINIFLOW_MAX_FLOWS];
	} path;

	int nr_ct_tuples;
	struct mlx5e_ct_tuple ct_tuples[MINIFLOW_MAX_CT_TUPLES];

	struct mlx5e_miniflow_node mnodes[MINIFLOW_MAX_FLOWS];
};

static const struct rhashtable_params mf_ht_params = {
	.head_offset = offsetof(struct mlx5e_miniflow, node),
	.key_offset = offsetof(struct mlx5e_miniflow, path.cookies),
	.key_len = sizeof(((struct mlx5e_miniflow *)0)->path.cookies),
	.automatic_shrinking = true,
};

/* TODO: not used yet */
struct mlx5_ct_conn {
	struct rhash_head node;
	struct work_struct work;
	struct list_head nft_node;

	struct mlx5e_tc_flow *flow[IP_CT_DIR_MAX];
};

struct mlx5e_tc_flow_parse_attr {
	struct ip_tunnel_info tun_info;
	struct mlx5_flow_spec spec;
	int num_mod_hdr_actions;
	void *mod_hdr_actions;
	int mirred_ifindex;
};

enum {
	MLX5_HEADER_TYPE_VXLAN = 0x0,
	MLX5_HEADER_TYPE_NVGRE = 0x1,
};

#define MLX5E_TC_TABLE_NUM_GROUPS 4
#define MLX5E_TC_TABLE_MAX_GROUP_SIZE BIT(16)

struct mlx5e_hairpin {
	struct mlx5_hairpin *pair;

	struct mlx5_core_dev *func_mdev;
	struct mlx5e_priv *func_priv;
	u32 tdn;
	u32 tirn;

	int num_channels;
	struct mlx5e_rqt indir_rqt;
	u32 indir_tirn[MLX5E_NUM_INDIR_TIRS];
	struct mlx5e_ttc_table ttc;
};

struct mlx5e_hairpin_entry {
	/* a node of a hash table which keeps all the  hairpin entries */
	struct hlist_node hairpin_hlist;

	/* protects flows list */
	spinlock_t flows_lock;
	/* flows sharing the same hairpin */
	struct list_head flows;

	u16 peer_vhca_id;
	u8 prio;
	struct mlx5e_hairpin *hp;
	refcount_t refcnt;
	struct rcu_head rcu;
};

struct mod_hdr_key {
	int num_actions;
	void *actions;
};

struct mlx5e_mod_hdr_entry {
	/* a node of a hash table which keeps all the mod_hdr entries */
	struct hlist_node mod_hdr_hlist;

	/* protects flows list */
	spinlock_t flows_lock;
	/* flows sharing the same mod_hdr entry */
	struct list_head flows;

	struct mod_hdr_key key;

	u32 mod_hdr_id;

	refcount_t refcnt;
	struct rcu_head rcu;
};

#define MLX5_MH_ACT_SZ MLX5_UN_SZ_BYTES(set_action_in_add_action_in_auto)

static void mlx5e_tc_del_flow(struct mlx5e_priv *priv,
			      struct mlx5e_tc_flow *flow);

static struct kmem_cache *flow_cache(int flow_flags)
{
	if (flow_flags & MLX5E_TC_FLOW_ESWITCH)
		return fdb_flow_cache;
	else
		return nic_flow_cache;
}

static struct mlx5e_tc_flow *flow_cache_alloc(int flow_flags, gfp_t flags)
{
	return kmem_cache_zalloc(flow_cache(flow_flags), flags);
}

static void flow_cache_free(struct mlx5e_tc_flow *flow)
{
	kmem_cache_free(flow_cache(atomic_read(&flow->flags)), flow);
}

static struct mlx5e_tc_flow *mlx5e_flow_get(struct mlx5e_tc_flow *flow)
{
	if (!flow || !refcount_inc_not_zero(&flow->refcnt))
		return ERR_PTR(-EINVAL);
	return flow;
}

static void mlx5e_flow_put(struct mlx5e_priv *priv,
			   struct mlx5e_tc_flow *flow)
{
	if (refcount_dec_and_test(&flow->refcnt)) {
		mlx5e_tc_del_flow(priv, flow);
		flow_cache_free(flow);
	}
}

static bool mlx5e_is_eswitch_flow(struct mlx5e_tc_flow *flow)
{
	return !!(atomic_read(&flow->flags) & MLX5E_TC_FLOW_ESWITCH);
}

static bool mlx5e_is_offloaded_flow(struct mlx5e_tc_flow *flow)
{
	return !!(atomic_read(&flow->flags) & MLX5E_TC_FLOW_OFFLOADED);
}

static bool mlx5e_is_simple_flow(struct mlx5e_tc_flow *flow)
{
	return !!(atomic_read(&flow->flags) & MLX5E_TC_FLOW_SIMPLE);
}

static inline u32 hash_mod_hdr_info(struct mod_hdr_key *key)
{
	return jhash(key->actions,
		     key->num_actions * MLX5_MH_ACT_SZ, 0);
}

static inline int cmp_mod_hdr_info(struct mod_hdr_key *a,
				   struct mod_hdr_key *b)
{
	if (a->num_actions != b->num_actions)
		return 1;

	return memcmp(a->actions, b->actions, a->num_actions * MLX5_MH_ACT_SZ);
}

static DEFINE_SPINLOCK(fc_lock);
static LLIST_HEAD(fc_list);

struct mlx5_fc *mlx5e_fc_alloc(struct mlx5_core_dev *dev, bool aging)
{
	struct llist_node *node;

	spin_lock(&fc_lock);
	node = llist_del_first(&fc_list);
	spin_unlock(&fc_lock);

	if (!node)
		return mlx5_fc_create(dev, aging);

	return llist_entry(node, struct mlx5_fc, freelist);
}

void mlx5e_fc_free(struct mlx5_core_dev *dev, struct mlx5_fc *counter)
{
	if (counter)
		llist_add(&counter->freelist, &fc_list);
}

void mlx5e_fc_list_cleanup(struct mlx5_core_dev *dev, struct llist_head *fc_list)
{
	struct mlx5_fc *counter, *tmp;
	struct llist_node *head;
	int i = 0; /* TODO: DEBUG */

	head = llist_del_all(fc_list);
	llist_for_each_entry_safe(counter, tmp, head, freelist) {
		mlx5_fc_destroy(dev, counter);
		i++;
	}

	mtrace("Cleaned %d HW counters", i);
}

static struct mlx5e_mod_hdr_entry *
mlx5e_mod_hdr_get(struct mlx5e_priv *priv, int namespace,
		  struct mod_hdr_key *key, u32 hash_key)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5e_mod_hdr_entry *mh;
	bool found = false;

	rcu_read_lock();
	if (namespace == MLX5_FLOW_NAMESPACE_FDB) {
		hash_for_each_possible_rcu(esw->offloads.mod_hdr_tbl, mh,
					   mod_hdr_hlist, hash_key) {
			if (!cmp_mod_hdr_info(&mh->key, key) &&
			    refcount_inc_not_zero(&mh->refcnt)) {
				found = true;
				break;
			}
		}
	} else {
		hash_for_each_possible_rcu(priv->fs.tc.mod_hdr_tbl, mh,
					   mod_hdr_hlist, hash_key) {
			if (!cmp_mod_hdr_info(&mh->key, key) &&
			    refcount_inc_not_zero(&mh->refcnt)) {
				found = true;
				break;
			}
		}
	}
	rcu_read_unlock();

	if (found)
		return mh;
	return NULL;
}

static struct mlx5e_mod_hdr_entry *
mlx5e_mod_hdr_get_create(struct mlx5e_priv *priv, int namespace,
			 struct mod_hdr_key *key, int num_actions,
			 int actions_size)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5e_mod_hdr_entry *mh, *mh_dup = NULL;
	u32 hash_key;
	int err;

	hash_key = hash_mod_hdr_info(key);

	mh = mlx5e_mod_hdr_get(priv, namespace, key, hash_key);
	if (mh)
		return mh;

	mh = kzalloc(sizeof(*mh) + actions_size, GFP_KERNEL);
	if (!mh)
		return ERR_PTR(-ENOMEM);

	mh->key.actions = (void *)mh + sizeof(*mh);
	memcpy(mh->key.actions, key->actions, actions_size);
	mh->key.num_actions = num_actions;
	spin_lock_init(&mh->flows_lock);
	INIT_LIST_HEAD(&mh->flows);
	refcount_set(&mh->refcnt, 1);

	err = mlx5_modify_header_alloc(priv->mdev, namespace,
				       mh->key.num_actions,
				       mh->key.actions,
				       &mh->mod_hdr_id);
	if (err)
		goto out_err;

	if (namespace == MLX5_FLOW_NAMESPACE_FDB) {
		spin_lock(&esw->offloads.mod_hdr_tbl_lock);
		/* check for concurrent insertion of mod header entry with same
		 * params
		 */
		mh_dup = mlx5e_mod_hdr_get(priv, namespace, key, hash_key);
		if (mh_dup) {
			spin_unlock(&esw->offloads.mod_hdr_tbl_lock);
			goto out_err;
		}

		hash_add_rcu(esw->offloads.mod_hdr_tbl, &mh->mod_hdr_hlist,
			     hash_key);
		spin_unlock(&esw->offloads.mod_hdr_tbl_lock);
	} else {
		spin_lock(&priv->fs.tc.mod_hdr_tbl_lock);
		/* check for concurrent insertion of mod header entry with same
		 * params
		 */
		mh_dup = mlx5e_mod_hdr_get(priv, namespace, key, hash_key);
		if (mh_dup) {
			spin_unlock(&priv->fs.tc.mod_hdr_tbl_lock);
			goto out_err;
		}

		hash_add_rcu(priv->fs.tc.mod_hdr_tbl, &mh->mod_hdr_hlist,
			     hash_key);
		spin_unlock(&priv->fs.tc.mod_hdr_tbl_lock);
	}

	return mh;

out_err:
	if (mh->mod_hdr_id)
		mlx5_modify_header_dealloc(priv->mdev, mh->mod_hdr_id);
	kfree(mh);
	if (mh_dup)
		return mh_dup;
	return ERR_PTR(err);
}

static void mlx5e_mod_hdr_put(struct mlx5e_priv *priv,
			      struct mlx5e_mod_hdr_entry *mh,
			      spinlock_t *tbl_lock)
{
	if (refcount_dec_and_test(&mh->refcnt)) {
		WARN_ON(!list_empty(&mh->flows));
		mlx5_modify_header_dealloc(priv->mdev, mh->mod_hdr_id);
		spin_lock(tbl_lock);
		hash_del_rcu(&mh->mod_hdr_hlist);
		spin_unlock(tbl_lock);
		kfree_rcu(mh, rcu);
	}
}

static int mlx5e_attach_mod_hdr(struct mlx5e_priv *priv,
				struct mlx5e_tc_flow *flow,
				struct mlx5e_tc_flow_parse_attr *parse_attr)
{
	int num_actions, actions_size, namespace;
	struct mlx5e_mod_hdr_entry *mh;
	struct mod_hdr_key key;
	bool is_eswitch_flow = mlx5e_is_eswitch_flow(flow);

	num_actions  = parse_attr->num_mod_hdr_actions;
	actions_size = MLX5_MH_ACT_SZ * num_actions;

	key.actions = parse_attr->mod_hdr_actions;
	key.num_actions = num_actions;

	namespace = is_eswitch_flow ?
		MLX5_FLOW_NAMESPACE_FDB : MLX5_FLOW_NAMESPACE_KERNEL;
	mh = mlx5e_mod_hdr_get_create(priv, namespace, &key, num_actions,
				      actions_size);
	if (IS_ERR(mh))
		return PTR_ERR(mh);

	flow->mh = mh;
	spin_lock(&mh->flows_lock);
	list_add(&flow->mod_hdr, &mh->flows);
	spin_unlock(&mh->flows_lock);
	if (is_eswitch_flow)
		flow->esw_attr->mod_hdr_id = mh->mod_hdr_id;
	else
		flow->nic_attr->mod_hdr_id = mh->mod_hdr_id;

	return 0;
}

static void mlx5e_detach_mod_hdr(struct mlx5e_priv *priv,
				 struct mlx5e_tc_flow *flow)
{
	spinlock_t *tbl_lock = mlx5e_is_eswitch_flow(flow) ?
		&priv->mdev->priv.eswitch->offloads.mod_hdr_tbl_lock :
		&priv->fs.tc.mod_hdr_tbl_lock;

	/* flow wasn't fully initialized */
	if (!flow->mh)
		return;

	spin_lock(&flow->mh->flows_lock);
	list_del(&flow->mod_hdr);
	spin_unlock(&flow->mh->flows_lock);

	mlx5e_mod_hdr_put(priv, flow->mh, tbl_lock);
	flow->mh = NULL;
}

static
struct mlx5_core_dev *mlx5e_hairpin_get_mdev(struct net *net, int ifindex)
{
	struct net_device *netdev;
	struct mlx5e_priv *priv;

	netdev = __dev_get_by_index(net, ifindex);
	priv = netdev_priv(netdev);
	return priv->mdev;
}

static int mlx5e_hairpin_create_transport(struct mlx5e_hairpin *hp)
{
	u32 in[MLX5_ST_SZ_DW(create_tir_in)] = {0};
	void *tirc;
	int err;

	err = mlx5_core_alloc_transport_domain(hp->func_mdev, &hp->tdn);
	if (err)
		goto alloc_tdn_err;

	tirc = MLX5_ADDR_OF(create_tir_in, in, ctx);

	MLX5_SET(tirc, tirc, disp_type, MLX5_TIRC_DISP_TYPE_DIRECT);
	MLX5_SET(tirc, tirc, inline_rqn, hp->pair->rqn[0]);
	MLX5_SET(tirc, tirc, transport_domain, hp->tdn);

	err = mlx5_core_create_tir(hp->func_mdev, in, MLX5_ST_SZ_BYTES(create_tir_in), &hp->tirn);
	if (err)
		goto create_tir_err;

	return 0;

create_tir_err:
	mlx5_core_dealloc_transport_domain(hp->func_mdev, hp->tdn);
alloc_tdn_err:
	return err;
}

static void mlx5e_hairpin_destroy_transport(struct mlx5e_hairpin *hp)
{
	mlx5_core_destroy_tir(hp->func_mdev, hp->tirn);
	mlx5_core_dealloc_transport_domain(hp->func_mdev, hp->tdn);
}

static void mlx5e_hairpin_fill_rqt_rqns(struct mlx5e_hairpin *hp, void *rqtc)
{
	u32 indirection_rqt[MLX5E_INDIR_RQT_SIZE], rqn;
	struct mlx5e_priv *priv = hp->func_priv;
	int i, ix, sz = MLX5E_INDIR_RQT_SIZE;

	mlx5e_build_default_indir_rqt(indirection_rqt, sz,
				      hp->num_channels);

	for (i = 0; i < sz; i++) {
		ix = i;
		if (priv->channels.params.rss_hfunc == ETH_RSS_HASH_XOR)
			ix = mlx5e_bits_invert(i, ilog2(sz));
		ix = indirection_rqt[ix];
		rqn = hp->pair->rqn[ix];
		MLX5_SET(rqtc, rqtc, rq_num[i], rqn);
	}
}

static int mlx5e_hairpin_create_indirect_rqt(struct mlx5e_hairpin *hp)
{
	int inlen, err, sz = MLX5E_INDIR_RQT_SIZE;
	struct mlx5e_priv *priv = hp->func_priv;
	struct mlx5_core_dev *mdev = priv->mdev;
	void *rqtc;
	u32 *in;

	inlen = MLX5_ST_SZ_BYTES(create_rqt_in) + sizeof(u32) * sz;
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	rqtc = MLX5_ADDR_OF(create_rqt_in, in, rqt_context);

	MLX5_SET(rqtc, rqtc, rqt_actual_size, sz);
	MLX5_SET(rqtc, rqtc, rqt_max_size, sz);

	mlx5e_hairpin_fill_rqt_rqns(hp, rqtc);

	err = mlx5_core_create_rqt(mdev, in, inlen, &hp->indir_rqt.rqtn);
	if (!err)
		hp->indir_rqt.enabled = true;

	kvfree(in);
	return err;
}

static int mlx5e_hairpin_create_indirect_tirs(struct mlx5e_hairpin *hp)
{
	struct mlx5e_priv *priv = hp->func_priv;
	u32 in[MLX5_ST_SZ_DW(create_tir_in)];
	int tt, i, err;
	void *tirc;

	for (tt = 0; tt < MLX5E_NUM_INDIR_TIRS; tt++) {
		memset(in, 0, MLX5_ST_SZ_BYTES(create_tir_in));
		tirc = MLX5_ADDR_OF(create_tir_in, in, ctx);

		MLX5_SET(tirc, tirc, transport_domain, hp->tdn);
		MLX5_SET(tirc, tirc, disp_type, MLX5_TIRC_DISP_TYPE_INDIRECT);
		MLX5_SET(tirc, tirc, indirect_table, hp->indir_rqt.rqtn);
		mlx5e_build_indir_tir_ctx_hash(&priv->channels.params, tt, tirc, false);

		err = mlx5_core_create_tir(hp->func_mdev, in,
					   MLX5_ST_SZ_BYTES(create_tir_in), &hp->indir_tirn[tt]);
		if (err) {
			mlx5_core_warn(hp->func_mdev, "create indirect tirs failed, %d\n", err);
			goto err_destroy_tirs;
		}
	}
	return 0;

err_destroy_tirs:
	for (i = 0; i < tt; i++)
		mlx5_core_destroy_tir(hp->func_mdev, hp->indir_tirn[i]);
	return err;
}

static void mlx5e_hairpin_destroy_indirect_tirs(struct mlx5e_hairpin *hp)
{
	int tt;

	for (tt = 0; tt < MLX5E_NUM_INDIR_TIRS; tt++)
		mlx5_core_destroy_tir(hp->func_mdev, hp->indir_tirn[tt]);
}

static void mlx5e_hairpin_set_ttc_params(struct mlx5e_hairpin *hp,
					 struct ttc_params *ttc_params)
{
	struct mlx5_flow_table_attr *ft_attr = &ttc_params->ft_attr;
	int tt;

	memset(ttc_params, 0, sizeof(*ttc_params));

	ttc_params->any_tt_tirn = hp->tirn;

	for (tt = 0; tt < MLX5E_NUM_INDIR_TIRS; tt++)
		ttc_params->indir_tirn[tt] = hp->indir_tirn[tt];

	ft_attr->max_fte = MLX5E_NUM_TT;
	ft_attr->level = MLX5E_TC_TTC_FT_LEVEL;
	ft_attr->prio = MLX5E_TC_PRIO;
}

static int mlx5e_hairpin_rss_init(struct mlx5e_hairpin *hp)
{
	struct mlx5e_priv *priv = hp->func_priv;
	struct ttc_params ttc_params;
	int err;

	err = mlx5e_hairpin_create_indirect_rqt(hp);
	if (err)
		return err;

	err = mlx5e_hairpin_create_indirect_tirs(hp);
	if (err)
		goto err_create_indirect_tirs;

	mlx5e_hairpin_set_ttc_params(hp, &ttc_params);
	err = mlx5e_create_ttc_table(priv, &ttc_params, &hp->ttc);
	if (err)
		goto err_create_ttc_table;

	netdev_dbg(priv->netdev, "add hairpin: using %d channels rss ttc table id %x\n",
		   hp->num_channels, hp->ttc.ft.t->id);

	return 0;

err_create_ttc_table:
	mlx5e_hairpin_destroy_indirect_tirs(hp);
err_create_indirect_tirs:
	mlx5e_destroy_rqt(priv, &hp->indir_rqt);

	return err;
}

static void mlx5e_hairpin_rss_cleanup(struct mlx5e_hairpin *hp)
{
	struct mlx5e_priv *priv = hp->func_priv;

	mlx5e_destroy_ttc_table(priv, &hp->ttc);
	mlx5e_hairpin_destroy_indirect_tirs(hp);
	mlx5e_destroy_rqt(priv, &hp->indir_rqt);
}

static struct mlx5e_hairpin *
mlx5e_hairpin_create(struct mlx5e_priv *priv, struct mlx5_hairpin_params *params,
		     int peer_ifindex)
{
	struct mlx5_core_dev *func_mdev, *peer_mdev;
	struct mlx5e_hairpin *hp;
	struct mlx5_hairpin *pair;
	int err;

	hp = kzalloc(sizeof(*hp), GFP_KERNEL);
	if (!hp)
		return ERR_PTR(-ENOMEM);

	func_mdev = priv->mdev;
	peer_mdev = mlx5e_hairpin_get_mdev(dev_net(priv->netdev), peer_ifindex);

	pair = mlx5_core_hairpin_create(func_mdev, peer_mdev, params);
	if (IS_ERR(pair)) {
		err = PTR_ERR(pair);
		goto create_pair_err;
	}
	hp->pair = pair;
	hp->func_mdev = func_mdev;
	hp->func_priv = priv;
	hp->num_channels = params->num_channels;

	err = mlx5e_hairpin_create_transport(hp);
	if (err)
		goto create_transport_err;

	if (hp->num_channels > 1) {
		err = mlx5e_hairpin_rss_init(hp);
		if (err)
			goto rss_init_err;
	}

	return hp;

rss_init_err:
	mlx5e_hairpin_destroy_transport(hp);
create_transport_err:
	mlx5_core_hairpin_destroy(hp->pair);
create_pair_err:
	kfree(hp);
	return ERR_PTR(err);
}

static void mlx5e_hairpin_destroy(struct mlx5e_hairpin *hp)
{
	if (hp->num_channels > 1)
		mlx5e_hairpin_rss_cleanup(hp);
	mlx5e_hairpin_destroy_transport(hp);
	mlx5_core_hairpin_destroy(hp->pair);
	kvfree(hp);
}

static inline u32 hash_hairpin_info(u16 peer_vhca_id, u8 prio)
{
	return (peer_vhca_id << 16 | prio);
}

static struct mlx5e_hairpin_entry *mlx5e_hairpin_get(struct mlx5e_priv *priv,
						     u16 peer_vhca_id, u8 prio)
{
	struct mlx5e_hairpin_entry *hpe;
	u32 hash_key = hash_hairpin_info(peer_vhca_id, prio);

	rcu_read_lock();
	hash_for_each_possible_rcu(priv->fs.tc.hairpin_tbl, hpe,
				   hairpin_hlist, hash_key) {
		if (hpe->peer_vhca_id == peer_vhca_id && hpe->prio == prio &&
		    refcount_inc_not_zero(&hpe->refcnt)) {
			rcu_read_unlock();
			return hpe;
		}
	}
	rcu_read_unlock();

	return NULL;
}

static struct mlx5e_hairpin_entry *
mlx5e_hairpin_get_create(struct mlx5e_priv *priv, int peer_ifindex, u16 peer_id,
			 u8 match_prio)
{
	struct mlx5e_hairpin_entry *hpe, *hpe_dup = NULL;
	struct mlx5_hairpin_params params;
	struct mlx5e_hairpin *hp;
	u64 link_speed64;
	u32 link_speed;
	int err;

	hpe = mlx5e_hairpin_get(priv, peer_id, match_prio);
	if (hpe)
		return hpe;

	hpe = kzalloc(sizeof(*hpe), GFP_KERNEL);
	if (!hpe)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&hpe->flows_lock);
	INIT_LIST_HEAD(&hpe->flows);
	hpe->peer_vhca_id = peer_id;
	hpe->prio = match_prio;
	refcount_set(&hpe->refcnt, 1);

	params.log_data_size = 15;
	params.log_data_size = min_t(u8, params.log_data_size,
				     MLX5_CAP_GEN(priv->mdev,
						  log_max_hairpin_wq_data_sz));
	params.log_data_size = max_t(u8, params.log_data_size,
				     MLX5_CAP_GEN(priv->mdev,
						  log_min_hairpin_wq_data_sz));

	params.log_num_packets = params.log_data_size -
				 MLX5_MPWRQ_MIN_LOG_STRIDE_SZ(priv->mdev);
	params.log_num_packets = min_t(u8, params.log_num_packets,
				       MLX5_CAP_GEN(priv->mdev,
						    log_max_hairpin_num_packets));

	params.q_counter = priv->q_counter;
	/* set hairpin pair per each 50Gbs share of the link */
	mlx5e_port_max_linkspeed(priv->mdev, &link_speed);
	link_speed = max_t(u32, link_speed, 50000);
	link_speed64 = link_speed;
	do_div(link_speed64, 50000);
	params.num_channels = link_speed64;

	hp = mlx5e_hairpin_create(priv, &params, peer_ifindex);
	if (IS_ERR(hp)) {
		err = PTR_ERR(hp);
		goto create_hairpin_err;
	}

	netdev_dbg(priv->netdev, "add hairpin: tirn %x rqn %x peer %s sqn %x prio %d (log) data %d packets %d\n",
		   hp->tirn, hp->pair->rqn[0], hp->pair->peer_mdev->priv.name,
		   hp->pair->sqn[0], match_prio, params.log_data_size,
		   params.log_num_packets);

	hpe->hp = hp;

	spin_lock(&priv->fs.tc.hairpin_tbl_lock);
	/* check for concurrent insertion of hairpin entry with same params */
	hpe_dup = mlx5e_hairpin_get(priv, peer_id, match_prio);
	if (hpe_dup)
		goto create_hairpin_err_locked;

	hash_add_rcu(priv->fs.tc.hairpin_tbl, &hpe->hairpin_hlist,
		     hash_hairpin_info(peer_id, match_prio));
	spin_unlock(&priv->fs.tc.hairpin_tbl_lock);

	return hpe;

create_hairpin_err_locked:
	spin_unlock(&priv->fs.tc.hairpin_tbl_lock);
	mlx5e_hairpin_destroy(hpe->hp);
create_hairpin_err:
	kfree(hpe);
	if (hpe_dup)
		return hpe_dup;
	return ERR_PTR(err);
}

static void mlx5e_hairpin_put(struct mlx5e_priv *priv,
			      struct mlx5e_hairpin_entry *hpe)
{
	/* no more hairpin flows for us, release the hairpin pair */
	if (refcount_dec_and_test(&hpe->refcnt)) {
		netdev_dbg(priv->netdev, "del hairpin: peer %s\n",
			   hpe->hp->pair->peer_mdev->priv.name);

		WARN_ON(!list_empty(&hpe->flows));
		mlx5e_hairpin_destroy(hpe->hp);
		spin_lock(&priv->fs.tc.hairpin_tbl_lock);
		hash_del_rcu(&hpe->hairpin_hlist);
		spin_unlock(&priv->fs.tc.hairpin_tbl_lock);
		kfree_rcu(hpe, rcu);
	}
}

#define UNKNOWN_MATCH_PRIO 8

static int mlx5e_hairpin_get_prio(struct mlx5e_priv *priv,
				  struct mlx5_flow_spec *spec, u8 *match_prio)
{
	void *headers_c, *headers_v;
	/* TODO: merge change */
	u8 prio_val = 0, prio_mask = 0;
	bool vlan_present;

#ifdef CONFIG_MLX5_CORE_EN_DCB
	if (priv->dcbx_dp.trust_state != MLX5_QPTS_TRUST_PCP) {
		netdev_warn(priv->netdev,
			    "only PCP trust state supported for hairpin\n");
		return -EOPNOTSUPP;
	}
#endif
	headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria, outer_headers);
	headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value, outer_headers);

	vlan_present = MLX5_GET(fte_match_set_lyr_2_4, headers_v, cvlan_tag);
	if (vlan_present) {
		prio_mask = MLX5_GET(fte_match_set_lyr_2_4, headers_c, first_prio);
		prio_val = MLX5_GET(fte_match_set_lyr_2_4, headers_v, first_prio);
	}

	if (!vlan_present || !prio_mask) {
		prio_val = UNKNOWN_MATCH_PRIO;
	} else if (prio_mask != 0x7) {
		netdev_warn(priv->netdev,
			    "masked priority match not supported for hairpin\n");
		return -EOPNOTSUPP;
	}

	*match_prio = prio_val;
	return 0;
}

static int mlx5e_hairpin_flow_add(struct mlx5e_priv *priv,
				  struct mlx5e_tc_flow *flow,
				  struct mlx5e_tc_flow_parse_attr *parse_attr)
{
	int peer_ifindex = parse_attr->mirred_ifindex;
	struct mlx5_core_dev *peer_mdev;
	struct mlx5e_hairpin_entry *hpe;
	u8 match_prio;
	u16 peer_id;
	int err;

	peer_mdev = mlx5e_hairpin_get_mdev(dev_net(priv->netdev), peer_ifindex);
	if (!MLX5_CAP_GEN(priv->mdev, hairpin) || !MLX5_CAP_GEN(peer_mdev, hairpin)) {
		netdev_warn(priv->netdev, "hairpin is not supported\n");
		return -EOPNOTSUPP;
	}

	peer_id = MLX5_CAP_GEN(peer_mdev, vhca_id);
	err = mlx5e_hairpin_get_prio(priv, &parse_attr->spec, &match_prio);
	if (err)
		return err;
	hpe = mlx5e_hairpin_get_create(priv, peer_ifindex, peer_id, match_prio);
	if (IS_ERR(hpe))
		return PTR_ERR(hpe);

	if (hpe->hp->num_channels > 1) {
		atomic_or(MLX5E_TC_FLOW_HAIRPIN_RSS, &flow->flags);
		flow->nic_attr->hairpin_ft = hpe->hp->ttc.ft.t;
	} else {
		flow->nic_attr->hairpin_tirn = hpe->hp->tirn;
	}
	flow->hpe = hpe;
	spin_lock(&hpe->flows_lock);
	list_add(&flow->hairpin, &hpe->flows);
	spin_unlock(&hpe->flows_lock);

	return 0;
}

static void mlx5e_hairpin_flow_del(struct mlx5e_priv *priv,
				   struct mlx5e_tc_flow *flow)
{
	/* flow wasn't fully initialized */
	if (!flow->hpe)
		return;

	spin_lock(&flow->hpe->flows_lock);
	list_del(&flow->hairpin);
	spin_unlock(&flow->hpe->flows_lock);

	mlx5e_hairpin_put(priv, flow->hpe);
	flow->hpe = NULL;
}

static struct mlx5_flow_handle *
mlx5e_tc_add_nic_flow(struct mlx5e_priv *priv,
		      struct mlx5e_tc_flow_parse_attr *parse_attr,
		      struct mlx5e_tc_flow *flow)
{
	struct mlx5_nic_flow_attr *attr = flow->nic_attr;
	struct mlx5_core_dev *dev = priv->mdev;
	struct mlx5_flow_destination dest[2] = {};
	struct mlx5_flow_act flow_act = {
		.action = attr->action,
		.flow_tag = attr->flow_tag,
		.encap_id = 0,
		.flags    = FLOW_ACT_HAS_TAG | FLOW_ACT_NO_APPEND,
	};
	struct mlx5_fc *counter = NULL;
	struct mlx5_flow_handle *rule;
	bool table_created = false;
	int err, dest_ix = 0;

	if (atomic_read(&flow->flags) & MLX5E_TC_FLOW_HAIRPIN) {
		err = mlx5e_hairpin_flow_add(priv, flow, parse_attr);
		if (err) {
			rule = ERR_PTR(err);
			goto err_out;
		}
		if (atomic_read(&flow->flags) & MLX5E_TC_FLOW_HAIRPIN_RSS) {
			dest[dest_ix].type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
			dest[dest_ix].ft = attr->hairpin_ft;
		} else {
			dest[dest_ix].type = MLX5_FLOW_DESTINATION_TYPE_TIR;
			dest[dest_ix].tir_num = attr->hairpin_tirn;
		}
		dest_ix++;
	} else if (attr->action & MLX5_FLOW_CONTEXT_ACTION_FWD_DEST) {
		dest[dest_ix].type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
		dest[dest_ix].ft = priv->fs.vlan.ft.t;
		dest_ix++;
	}

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_COUNT) {
		counter = mlx5_fc_create(dev, true);
		if (IS_ERR(counter)) {
			rule = ERR_CAST(counter);
			goto err_out;
		}
		dest[dest_ix].type = MLX5_FLOW_DESTINATION_TYPE_COUNTER;
		dest[dest_ix].counter_id = mlx5_fc_id(counter);
		dest_ix++;
		attr->counter = counter;
	}

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR) {
		err = mlx5e_attach_mod_hdr(priv, flow, parse_attr);
		flow_act.modify_id = attr->mod_hdr_id;
		kfree(parse_attr->mod_hdr_actions);
		parse_attr->mod_hdr_actions = NULL;
		if (err) {
			rule = ERR_PTR(err);
			goto err_out;
		}
	}

	mutex_lock(&priv->fs.tc.t_lock);
	if (IS_ERR_OR_NULL(priv->fs.tc.t)) {
		int tc_grp_size, tc_tbl_size;
		u32 max_flow_counter;

		max_flow_counter = (MLX5_CAP_GEN(dev, max_flow_counter_31_16) << 16) |
				    MLX5_CAP_GEN(dev, max_flow_counter_15_0);

		tc_grp_size = min_t(int, max_flow_counter, MLX5E_TC_TABLE_MAX_GROUP_SIZE);

		tc_tbl_size = min_t(int, tc_grp_size * MLX5E_TC_TABLE_NUM_GROUPS,
				    BIT(MLX5_CAP_FLOWTABLE_NIC_RX(dev, log_max_ft_size)));

		priv->fs.tc.t =
			mlx5_create_auto_grouped_flow_table(priv->fs.ns,
							    MLX5E_TC_PRIO,
							    tc_tbl_size,
							    MLX5E_TC_TABLE_NUM_GROUPS,
							    MLX5E_TC_FT_LEVEL, 0);
		if (IS_ERR(priv->fs.tc.t)) {
			netdev_err(priv->netdev,
				   "Failed to create tc offload table\n");
			rule = ERR_CAST(priv->fs.tc.t);
			goto err_out_cleanup_unlock;
		}

		table_created = true;
	}

	if (attr->match_level != MLX5_MATCH_NONE)
		parse_attr->spec.match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;

	rule = mlx5_add_flow_rules(priv->fs.tc.t, &parse_attr->spec,
				   &flow_act, dest, dest_ix);
	mutex_unlock(&priv->fs.tc.t_lock);

	if (IS_ERR(rule))
		goto err_out;

	return rule;

err_out_cleanup_unlock:
	mutex_unlock(&priv->fs.tc.t_lock);
err_out:
	return rule;
}

static void mlx5e_tc_del_nic_flow(struct mlx5e_priv *priv,
				  struct mlx5e_tc_flow *flow)
{
	struct mlx5_nic_flow_attr *attr = flow->nic_attr;

	if (!IS_ERR_OR_NULL(flow->rule[0])) {
		struct mlx5_fc *counter = attr->counter;

		mlx5_del_flow_rules(flow->rule[0]);
		mlx5_fc_destroy(priv->mdev, counter);
	}

	mutex_lock(&priv->fs.tc.t_lock);
	if (!mlx5e_tc_num_filters(priv) && priv->fs.tc.t) {
		mlx5_destroy_flow_table(priv->fs.tc.t);
		priv->fs.tc.t = NULL;
	}
	mutex_unlock(&priv->fs.tc.t_lock);

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR)
		mlx5e_detach_mod_hdr(priv, flow);

	if (atomic_read(&flow->flags) & MLX5E_TC_FLOW_HAIRPIN)
		mlx5e_hairpin_flow_del(priv, flow);
}

static void mlx5e_detach_encap(struct mlx5e_priv *priv,
			       struct mlx5e_tc_flow *flow);

static int mlx5e_attach_encap(struct mlx5e_priv *priv,
			      struct ip_tunnel_info *tun_info,
			      struct net_device *mirred_dev,
			      struct net_device **encap_dev,
			      struct mlx5e_tc_flow *flow);

static struct mlx5_flow_handle *
mlx5e_tc_add_fdb_flow(struct mlx5e_priv *priv,
		      struct mlx5e_tc_flow_parse_attr *parse_attr,
		      struct mlx5e_tc_flow *flow)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5_esw_flow_attr *attr = flow->esw_attr;
	struct net_device *out_dev, *encap_dev = NULL;
	struct mlx5_flow_handle *rule = NULL;
	struct mlx5_fc *counter = NULL;
	struct mlx5e_rep_priv *rpriv;
	struct mlx5e_priv *out_priv;
	int err;

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_ENCAP) {
		out_dev = __dev_get_by_index(dev_net(priv->netdev),
					     attr->parse_attr->mirred_ifindex);
		err = mlx5e_attach_encap(priv, &parse_attr->tun_info,
					 out_dev, &encap_dev, flow);
		if (err) {
			rule = ERR_PTR(err);
			if (err != -EAGAIN)
				goto err_out;
		}
		out_priv = netdev_priv(encap_dev);
		rpriv = out_priv->ppriv;
		attr->out_rep[attr->out_count] = rpriv->rep;
		attr->out_mdev[attr->out_count++] = out_priv->mdev;
	}

	err = mlx5_eswitch_add_vlan_action(esw, attr);
	if (err) {
		rule = ERR_PTR(err);
		goto err_out;
	}

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR) {
		err = mlx5e_attach_mod_hdr(priv, flow, parse_attr);
		kfree(parse_attr->mod_hdr_actions);
		parse_attr->mod_hdr_actions = NULL;
		if (err) {
			rule = ERR_PTR(err);
			goto err_out;
		}
	}

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_COUNT) {
		counter = mlx5e_fc_alloc(esw->dev, true);
		if (IS_ERR(counter)) {
			rule = ERR_CAST(counter);
			goto err_out;
		}

		attr->counter = counter;
	}

	/* we get here if (1) there's no error (rule being null) or when
	 * (2) there's an encap action and we're on -EAGAIN (no valid neigh)
	 */
	if (rule != ERR_PTR(-EAGAIN)) {
		rule = mlx5_eswitch_add_offloaded_rule(esw, &parse_attr->spec, attr);
		if (IS_ERR(rule))
			goto err_out;

		if (attr->mirror_count) {
			flow->rule[1] = mlx5_eswitch_add_fwd_rule(esw, &parse_attr->spec, attr);
			if (IS_ERR(flow->rule[1]))
				goto err_fwd_rule;
		}
	}

	/* TODO: merge change; small patch to move this line from mlx5e_add_fdb_flow()  */
	//if (!(flow->esw_attr->action &
	//      MLX5_FLOW_CONTEXT_ACTION_PACKET_REFORMAT))
	//	kvfree(parse_attr);

	return rule;

err_fwd_rule:
	mlx5_eswitch_del_offloaded_rule(esw, rule, attr);
	rule = flow->rule[1];
err_out:
	return rule;
}

/* TODO: have a second look */
static struct rhashtable *get_mf_ht(struct mlx5e_priv *priv)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5e_rep_priv *uplink_rpriv;

	uplink_rpriv = mlx5_eswitch_get_uplink_priv(esw, REP_ETH);
	return &uplink_rpriv->mf_ht;
}

static struct mlx5_fc *mlx5e_tc_get_counter(struct mlx5e_tc_flow *flow);

static void miniflow_link_dummy_counters(struct mlx5e_tc_flow *flow, struct mlx5_fc **dummies, int nr_dummies)
{
	struct mlx5_fc *counter;

	counter = mlx5e_tc_get_counter(flow);
	if (!counter)
		return;

	WARN_ON(counter->dummy);
	mlx5_fc_link_dummies(counter, dummies, nr_dummies);
}

static void miniflow_unlink_dummy_counters(struct mlx5e_tc_flow *flow)
{
	struct mlx5_fc *counter;

	counter = mlx5e_tc_get_counter(flow);
	if (!counter)
		return;

	mlx5_fc_unlink_dummies(counter);
}

static void miniflow_detach(struct mlx5e_miniflow *miniflow)
{
	int i;

	/* Detach from all parent flows */
	for (i = 0; i < miniflow->nr_flows; i++)
		list_del(&miniflow->mnodes[i].node);
}

static void mlx5e_tc_del_fdb_flow(struct mlx5e_priv *priv,
				  struct mlx5e_tc_flow *flow);

static void miniflow_free(struct mlx5e_miniflow *miniflow);

static void mlx5e_del_miniflow(struct mlx5e_miniflow *miniflow)
{
	struct rhashtable *mf_ht = get_mf_ht(miniflow->priv);

	trace("mlx5e_del_miniflow: miniflow->nr_flows: %d", miniflow->nr_flows);
	atomic_dec(&currently_in_hw);

	mlx5e_flow_put(miniflow->priv, miniflow->flow);
	rhashtable_remove_fast(mf_ht, &miniflow->node, mf_ht_params);
	miniflow_free(miniflow);

	inc_debug_counter(&nr_of_total_del_mf_succ);
	inc_debug_counter(&nr_of_total_mf_succ);
}

static void mlx5e_del_miniflow_work(struct work_struct *work)
{
	struct mlx5e_miniflow *miniflow = container_of(work, struct mlx5e_miniflow, work);

	atomic_dec(&nr_of_mfe_in_queue);

	inc_debug_counter(&nr_of_inflight_mfe);
	dec_debug_counter(&nr_of_del_mfe_in_queue);
	inc_debug_counter(&nr_of_inflight_del_mfe);

	mlx5e_del_miniflow(miniflow);

	dec_debug_counter(&nr_of_inflight_del_mfe);
	dec_debug_counter(&nr_of_inflight_mfe);
}

static void mlx5e_del_miniflow_list(struct mlx5e_tc_flow *flow)
{
	struct mlx5e_miniflow_node *mnode, *n;
	int i = 0; /* TODO: DEBUG */

	spin_lock_bh(&miniflow_lock);
	list_for_each_entry_safe(mnode, n, &flow->miniflow_list, node) {
		struct mlx5e_miniflow *miniflow = mnode->miniflow;

		miniflow_unlink_dummy_counters(miniflow->flow);
		miniflow_detach(miniflow);

		atomic_inc(&nr_of_mfe_in_queue);
		inc_debug_counter(&nr_of_del_mfe_in_queue);
		inc_debug_counter(&nr_of_total_mf_work_requests);
		inc_debug_counter(&nr_of_total_del_mf_work_requests);

		INIT_WORK(&miniflow->work, mlx5e_del_miniflow_work);
		queue_work(miniflow_wq, &miniflow->work);
		i++;
	}
	spin_unlock_bh(&miniflow_lock);

	if (i > 1) {
		mtrace("miniflow_list size: %d (ct flow: %d)", i,
			!!(atomic_read(&flow->flags) & MLX5E_TC_FLOW_CT));
	}
}

static void mlx5e_tc_del_fdb_flow_simple(struct mlx5e_priv *priv,
					 struct mlx5e_tc_flow *flow)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5_esw_flow_attr *attr = flow->esw_attr;

	if (mlx5e_is_offloaded_flow(flow)) {
		atomic_and(~MLX5E_TC_FLOW_OFFLOADED, &flow->flags);
		if (attr->mirror_count)
			mlx5_eswitch_del_offloaded_rule(esw, flow->rule[1], attr);
		mlx5_eswitch_del_offloaded_rule(esw, flow->rule[0], attr);
	}

	mlx5_eswitch_del_vlan_action(esw, attr);

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_ENCAP)
		mlx5e_detach_encap(priv, flow);

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR)
		mlx5e_detach_mod_hdr(priv, flow);

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_COUNT)
		mlx5e_fc_free(esw->dev, attr->counter);
}

static void mlx5e_tc_del_fdb_flow(struct mlx5e_priv *priv,
				  struct mlx5e_tc_flow *flow)
{
	struct mlx5_esw_flow_attr *attr = flow->esw_attr;

	trace("mlx5e_tc_del_fdb_flow");

	if (mlx5e_is_simple_flow(flow)) {
		mlx5e_tc_del_fdb_flow_simple(priv, flow);
	} else {
		mlx5e_del_miniflow_list(flow);

		if (attr->action & MLX5_FLOW_CONTEXT_ACTION_COUNT)
			mlx5_fc_destroy(priv->mdev, flow->dummy_counter);
	}

	if (attr->parse_attr) {
		if (attr->parse_attr->mod_hdr_actions)
			kfree(attr->parse_attr->mod_hdr_actions);
		kmem_cache_free(parse_attr_cache, attr->parse_attr);
	}
}

static void mlx5e_del_offloaded_flow_rules(struct mlx5e_priv *priv,
					   struct mlx5e_tc_flow *flow)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5_esw_flow_attr *attr = flow->esw_attr;
	struct mlx5_flow_handle *rule, *rule_mir;

	if (mlx5e_is_offloaded_flow(flow)) {
		spin_lock(&flow->rule_lock);
		atomic_and(~MLX5E_TC_FLOW_OFFLOADED, &flow->flags);
		rule = flow->rule[0];
		flow->rule[0] = NULL;
		rule_mir = flow->rule[1];
		flow->rule[1] = NULL;
		spin_unlock(&flow->rule_lock);

		if (attr->mirror_count)
			mlx5_eswitch_del_offloaded_rule(esw,
							rule_mir,
							attr);
		mlx5_eswitch_del_offloaded_rule(esw, rule, attr);
	}
}

static void mlx5e_put_flow_list(struct mlx5e_priv *priv,
				struct list_head *flow_list)
{
	struct mlx5e_tc_flow *flow, *tmp;

	list_for_each_entry_safe(flow, tmp, flow_list, tmp_list) {
		list_del(&flow->tmp_list);
		mlx5e_flow_put(priv, flow);
	}
}

static int mlx5e_tc_encap_flow_add(struct mlx5e_priv *priv,
				   struct mlx5e_tc_flow *flow,
				   struct mlx5e_encap_entry *e)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5_esw_flow_attr *esw_attr;
	int err = 0;

	esw_attr = flow->esw_attr;
	esw_attr->encap_id = e->encap_id;
	/* At this point concurrent access to flow->rule is not possible
	 * because offloaded flag is not set, so no need to take
	 * rule_lock.
	 */
	flow->rule[0] = mlx5_eswitch_add_offloaded_rule(esw, &esw_attr->parse_attr->spec, esw_attr);
	if (IS_ERR(flow->rule[0])) {
		err = PTR_ERR(flow->rule[0]);
		mlx5_core_warn(priv->mdev, "Failed to update cached encapsulation flow, %d\n",
			       err);
		return err;
	}

	if (esw_attr->mirror_count) {
		WARN_ON(!IS_ERR_OR_NULL(flow->rule[1]));
		flow->rule[1] = mlx5_eswitch_add_fwd_rule(esw, &esw_attr->parse_attr->spec, esw_attr);
		if (IS_ERR(flow->rule[1])) {
			mlx5_eswitch_del_offloaded_rule(esw, flow->rule[0], esw_attr);
			err = PTR_ERR(flow->rule[1]);
			mlx5_core_warn(priv->mdev, "Failed to update cached mirror flow, %d\n",
				       err);
			return err;
		}
	}

	/* Ensure that flow->rule[] pointers are updated before flow is
	 * marked as offloaded.
	 */
	wmb();
	/* Flow was successfully offloaded. Set flag and move it to
	 * offloaded flows list.
	 */
	atomic_or(MLX5E_TC_FLOW_OFFLOADED, &flow->flags);

	return err;
}

void mlx5e_tc_encap_flows_add(struct mlx5e_priv *priv,
			      struct mlx5e_encap_entry *e,
			      unsigned long n_updated)
{
	struct mlx5e_tc_flow *flow, *tmp;
	LIST_HEAD(added_flows);
	u32 encap_id;
	int err;

	err = mlx5_encap_alloc(priv->mdev, e->tunnel_type,
			       e->encap_size, e->encap_header,
			       &encap_id);
	if (err) {
		mlx5_core_warn(priv->mdev, "Failed to offload cached encapsulation header, %d\n",
			       err);
		return;
	}

	mlx5e_rep_queue_neigh_stats_work(priv);
	mutex_lock(&e->encap_entry_lock);
	e->encap_id = encap_id;
	e->flags |= MLX5_ENCAP_ENTRY_VALID;
	e->updated = n_updated;

	list_for_each_entry_safe(flow, tmp, &e->flows, encap) {
		if (!(atomic_read(&flow->flags) & MLX5E_TC_FLOW_INIT_DONE) ||
		    IS_ERR(mlx5e_flow_get(flow)))
			continue;

		list_add(&flow->tmp_list, &added_flows);

		mlx5e_tc_encap_flow_add(priv, flow, e);
	}

	mutex_unlock(&e->encap_entry_lock);

	mlx5e_put_flow_list(priv, &added_flows);
}

void mlx5e_tc_encap_flows_del(struct mlx5e_priv *priv,
			      struct mlx5e_encap_entry *e,
			      unsigned long n_updated)
{
	struct mlx5e_tc_flow *flow, *tmp;
	LIST_HEAD(deleted_flows);

	mutex_lock(&e->encap_entry_lock);

	list_for_each_entry_safe(flow, tmp, &e->flows, encap) {
		if (!(atomic_read(&flow->flags) & MLX5E_TC_FLOW_INIT_DONE) ||
		    IS_ERR(mlx5e_flow_get(flow)))
			continue;

		list_add(&flow->tmp_list, &deleted_flows);

		mlx5e_del_offloaded_flow_rules(priv, flow);
	}

	e->updated = n_updated;
	if (e->flags & MLX5_ENCAP_ENTRY_VALID) {
		e->flags &= ~MLX5_ENCAP_ENTRY_VALID;
		mlx5_encap_dealloc(priv->mdev, e->encap_id);
	}
	mutex_unlock(&e->encap_entry_lock);

	mlx5e_put_flow_list(priv, &deleted_flows);
}

static int mlx5e_tc_update_and_init_done_fdb_flow(struct mlx5e_priv *priv,
						  struct mlx5e_tc_flow *flow)
{
	int err = 0;

	if ((flow->esw_attr->action & MLX5_FLOW_CONTEXT_ACTION_ENCAP) &&
	    flow->e){
		struct mlx5e_encap_entry *e = flow->e;

		mutex_lock(&e->encap_entry_lock);
		if (flow->updated != e->updated) {
			/* recreate */
			mlx5e_del_offloaded_flow_rules(priv, flow);
			if (e->flags & MLX5_ENCAP_ENTRY_VALID) {
				err = mlx5e_tc_encap_flow_add(priv, flow, e);
				if (err) {
					mutex_unlock(&e->encap_entry_lock);
					return err;
				}
			}
		}

		/* Ensure that flow->rule[] pointers are updated before flow is
		 * marked as initialized.
		 */
		wmb();
		atomic_or(MLX5E_TC_FLOW_INIT_DONE, &flow->flags);
		mutex_unlock(&e->encap_entry_lock);
	} else {
		wmb();
		atomic_or(MLX5E_TC_FLOW_INIT_DONE, &flow->flags);
	}

	return 0;
}

static struct mlx5e_tc_flow *
mlx5e_get_next_encap_flow(struct mlx5e_encap_entry *e,
			  struct mlx5e_tc_flow *flow)
{
	struct mlx5e_tc_flow *next = NULL;
	bool found = false;

	mutex_lock(&e->encap_entry_lock);

	if (flow) {
		next = flow;
		list_for_each_entry_continue(next, &e->flows, encap)
			if (!IS_ERR(mlx5e_flow_get(next))) {
				found = true;
				break;
			}
	} else {
		list_for_each_entry(next, &e->flows, encap)
			if (!IS_ERR(mlx5e_flow_get(next))) {
				found = true;
				break;
			}
	}

	mutex_unlock(&e->encap_entry_lock);

	if (flow)
		mlx5e_flow_put(netdev_priv(e->out_dev), flow);

	return found ? next : NULL;
}

static struct mlx5e_encap_entry *
mlx5e_get_next_valid_encap(struct mlx5e_neigh_hash_entry *nhe,
			   struct mlx5e_encap_entry *e)
{
	struct mlx5e_encap_entry *next = NULL;

	rcu_read_lock();

	for (next = e ?
		     list_next_or_null_rcu(&nhe->encap_list,
					   &e->encap_list,
					   struct mlx5e_encap_entry,
					   encap_list) :
		     list_first_or_null_rcu(&nhe->encap_list,
					    struct mlx5e_encap_entry,
					    encap_list);
	     next;
	     next = list_next_or_null_rcu(&nhe->encap_list,
					  &next->encap_list,
					  struct mlx5e_encap_entry,
					  encap_list))
		if ((next->flags & MLX5_ENCAP_ENTRY_VALID) &&
		    mlx5e_encap_take(next))
			break;

	rcu_read_unlock();

	if (e)
		mlx5e_encap_put(netdev_priv(e->out_dev), e);

	return next;
}

static struct mlx5_fc *mlx5e_tc_get_counter(struct mlx5e_tc_flow *flow)
{
	if (mlx5e_is_eswitch_flow(flow))
		return flow->esw_attr->counter;
	else
		return flow->nic_attr->counter;
}

void mlx5e_tc_update_neigh_used_value(struct mlx5e_neigh_hash_entry *nhe)
{
	struct mlx5e_neigh *m_neigh = &nhe->m_neigh;
	struct mlx5e_encap_entry *e = NULL;
	struct mlx5e_tc_flow *flow = NULL;
	u64 bytes, packets, lastuse = 0;
	struct mlx5_fc *counter;
	struct neigh_table *tbl;
	bool neigh_used = false;
	struct neighbour *n;

	if (m_neigh->family == AF_INET)
		tbl = &arp_tbl;
#if IS_ENABLED(CONFIG_IPV6)
	else if (m_neigh->family == AF_INET6)
		tbl = &nd_tbl;
#endif
	else
		return;

	while ((e = mlx5e_get_next_valid_encap(nhe, e)) != NULL) {
		while ((flow = mlx5e_get_next_encap_flow(e, flow)) != NULL) {
			spin_lock(&flow->rule_lock);

			if ((atomic_read(&flow->flags) & MLX5E_TC_FLOW_INIT_DONE) &&
			    mlx5e_is_offloaded_flow(flow)) {
				counter = mlx5e_tc_get_counter(flow);
				mlx5_fc_query_cached(counter, &bytes, &packets, &lastuse);
				if (time_after((unsigned long)lastuse, nhe->reported_lastuse)) {
					spin_unlock(&flow->rule_lock);
					mlx5e_flow_put(netdev_priv(e->out_dev),
						       flow);
					neigh_used = true;
					break;
				}
			}

			spin_unlock(&flow->rule_lock);
		}
		if (neigh_used) {
			mlx5e_encap_put(netdev_priv(e->out_dev), e);
			break;
		}
	}

	if (neigh_used) {
		nhe->reported_lastuse = jiffies;

		/* find the relevant neigh according to the cached device and
		 * dst ip pair
		 */
		n = neigh_lookup(tbl, &m_neigh->dst_ip, m_neigh->dev);
		if (!n)
			return;

		neigh_event_send(n, NULL);
		neigh_release(n);
	}
}

void mlx5e_encap_put(struct mlx5e_priv *priv, struct mlx5e_encap_entry *e)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;

	if (refcount_dec_and_test(&e->refcnt)) {
		WARN_ON(!list_empty(&e->flows));
		/* encap can be deleted before attachment to dev if error
		 * happens during encap initialization
		 */
		if (e->out_dev)
			mlx5e_rep_encap_entry_detach(netdev_priv(e->out_dev),
						     e);

		if (e->flags & MLX5_ENCAP_ENTRY_VALID)
			mlx5_encap_dealloc(priv->mdev, e->encap_id);

		mutex_destroy(&e->encap_entry_lock);
		spin_lock(&esw->offloads.encap_tbl_lock);
		hash_del_rcu(&e->encap_hlist);
		spin_unlock(&esw->offloads.encap_tbl_lock);
		kfree(e->encap_header);
		kfree_rcu(e, rcu);
	}
}

static void mlx5e_detach_encap(struct mlx5e_priv *priv,
			       struct mlx5e_tc_flow *flow)
{
	struct mlx5e_encap_entry *e = flow->e;

	/* flow wasn't fully initialized */
	if (!e)
		return;

	mutex_lock(&e->encap_entry_lock);
	list_del(&flow->encap);
	mutex_unlock(&e->encap_entry_lock);

	mlx5e_encap_put(priv, e);
	flow->e = NULL;
}

static void mlx5e_tc_del_flow(struct mlx5e_priv *priv,
			      struct mlx5e_tc_flow *flow)
{
	if (mlx5e_is_eswitch_flow(flow))
		mlx5e_tc_del_fdb_flow(priv, flow);
	else
		mlx5e_tc_del_nic_flow(priv, flow);
}

static void parse_vxlan_attr(struct mlx5_flow_spec *spec,
			     struct tc_cls_flower_offload *f)
{
	void *headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
				       outer_headers);
	void *headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
				       outer_headers);
	void *misc_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
				    misc_parameters);
	void *misc_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
				    misc_parameters);

	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ip_protocol);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_protocol, IPPROTO_UDP);

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_ENC_KEYID)) {
		struct flow_dissector_key_keyid *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ENC_KEYID,
						  f->key);
		struct flow_dissector_key_keyid *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ENC_KEYID,
						  f->mask);
		MLX5_SET(fte_match_set_misc, misc_c, vxlan_vni,
			 be32_to_cpu(mask->keyid));
		MLX5_SET(fte_match_set_misc, misc_v, vxlan_vni,
			 be32_to_cpu(key->keyid));
	}
}

static int parse_tunnel_attr(struct mlx5e_priv *priv,
			     struct mlx5_flow_spec *spec,
			     struct tc_cls_flower_offload *f, u8 *match_level)
{
	void *headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
				       outer_headers);
	void *headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
				       outer_headers);

	struct flow_dissector_key_control *enc_control =
		skb_flow_dissector_target(f->dissector,
					  FLOW_DISSECTOR_KEY_ENC_CONTROL,
					  f->key);

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_ENC_PORTS)) {
		struct flow_dissector_key_ports *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ENC_PORTS,
						  f->key);
		struct flow_dissector_key_ports *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ENC_PORTS,
						  f->mask);

		/* Full udp dst port must be given */
		if (memchr_inv(&mask->dst, 0xff, sizeof(mask->dst)))
			goto vxlan_match_offload_err;

		if (mlx5_vxlan_lookup_port(priv->mdev->vxlan, be16_to_cpu(key->dst)) &&
		    MLX5_CAP_ESW(priv->mdev, vxlan_encap_decap))
			parse_vxlan_attr(spec, f);
		else {
			netdev_warn(priv->netdev,
				    "%d isn't an offloaded vxlan udp dport\n", be16_to_cpu(key->dst));
			return -EOPNOTSUPP;
		}

		*match_level = MLX5_MATCH_L4;
		MLX5_SET(fte_match_set_lyr_2_4, headers_c,
			 udp_dport, ntohs(mask->dst));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v,
			 udp_dport, ntohs(key->dst));

		MLX5_SET(fte_match_set_lyr_2_4, headers_c,
			 udp_sport, ntohs(mask->src));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v,
			 udp_sport, ntohs(key->src));
	} else { /* udp dst port must be given */
vxlan_match_offload_err:
		netdev_warn(priv->netdev,
			    "IP tunnel decap offload supported only for vxlan, must set UDP dport\n");
		return -EOPNOTSUPP;
	}

	if (enc_control->addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_dissector_key_ipv4_addrs *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS,
						  f->key);
		struct flow_dissector_key_ipv4_addrs *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS,
						  f->mask);
		MLX5_SET(fte_match_set_lyr_2_4, headers_c,
			 src_ipv4_src_ipv6.ipv4_layout.ipv4,
			 ntohl(mask->src));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v,
			 src_ipv4_src_ipv6.ipv4_layout.ipv4,
			 ntohl(key->src));

		MLX5_SET(fte_match_set_lyr_2_4, headers_c,
			 dst_ipv4_dst_ipv6.ipv4_layout.ipv4,
			 ntohl(mask->dst));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v,
			 dst_ipv4_dst_ipv6.ipv4_layout.ipv4,
			 ntohl(key->dst));

		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ethertype);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ethertype, ETH_P_IP);
	} else if (enc_control->addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_dissector_key_ipv6_addrs *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS,
						  f->key);
		struct flow_dissector_key_ipv6_addrs *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS,
						  f->mask);

		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       &mask->src, MLX5_FLD_SZ_BYTES(ipv6_layout, ipv6));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       &key->src, MLX5_FLD_SZ_BYTES(ipv6_layout, ipv6));

		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       &mask->dst, MLX5_FLD_SZ_BYTES(ipv6_layout, ipv6));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       &key->dst, MLX5_FLD_SZ_BYTES(ipv6_layout, ipv6));

		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ethertype);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ethertype, ETH_P_IPV6);
	}

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_ENC_IP)) {
		struct flow_dissector_key_ip *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ENC_IP,
						  f->key);
		struct flow_dissector_key_ip *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ENC_IP,
						  f->mask);

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ip_ecn, mask->tos & 0x3);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_ecn, key->tos & 0x3);

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ip_dscp, mask->tos >> 2);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_dscp, key->tos  >> 2);

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ttl_hoplimit, mask->ttl);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ttl_hoplimit, key->ttl);
	}

	/* Enforce DMAC when offloading incoming tunneled flows.
	 * Flow counters require a match on the DMAC.
	 */
	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, dmac_47_16);
	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, dmac_15_0);
	ether_addr_copy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				     dmac_47_16), priv->netdev->dev_addr);

	/* let software handle IP fragments */
	MLX5_SET(fte_match_set_lyr_2_4, headers_c, frag, 1);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, frag, 0);

	return 0;
}

static int __parse_cls_flower(struct mlx5e_priv *priv,
			      struct mlx5_flow_spec *spec,
			      struct tc_cls_flower_offload *f,
			      u8 *match_level, u8 *tunnel_match_level)
{
	void *headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
				       outer_headers);
	void *headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
				       outer_headers);
	void *misc_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
				    misc_parameters);
	void *misc_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
				    misc_parameters);
	u16 addr_type = 0;
	u8 ip_proto = 0;

	*match_level = MLX5_MATCH_NONE;

	if (f->dissector->used_keys &
	    ~(BIT(FLOW_DISSECTOR_KEY_CONTROL) |
	      BIT(FLOW_DISSECTOR_KEY_BASIC) |
	      BIT(FLOW_DISSECTOR_KEY_ETH_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_VLAN) |
	      BIT(FLOW_DISSECTOR_KEY_CVLAN) |
	      BIT(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_PORTS) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_KEYID) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_PORTS)	|
	      BIT(FLOW_DISSECTOR_KEY_ENC_CONTROL) |
	      BIT(FLOW_DISSECTOR_KEY_TCP) |
	      BIT(FLOW_DISSECTOR_KEY_IP)  |
	      BIT(FLOW_DISSECTOR_KEY_ENC_IP))) {
		netdev_warn(priv->netdev, "Unsupported key used: 0x%x\n",
			    f->dissector->used_keys);
		return -EOPNOTSUPP;
	}

	if ((dissector_uses_key(f->dissector,
				FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS) ||
	     dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_ENC_KEYID) ||
	     dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_ENC_PORTS)) &&
	    dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_ENC_CONTROL)) {
		struct flow_dissector_key_control *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ENC_CONTROL,
						  f->key);
		switch (key->addr_type) {
		case FLOW_DISSECTOR_KEY_IPV4_ADDRS:
		case FLOW_DISSECTOR_KEY_IPV6_ADDRS:
			if (parse_tunnel_attr(priv, spec, f, tunnel_match_level))
				return -EOPNOTSUPP;
			break;
		default:
			return -EOPNOTSUPP;
		}

		/* In decap flow, header pointers should point to the inner
		 * headers, outer header were already set by parse_tunnel_attr
		 */
		headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
					 inner_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
					 inner_headers);
	}

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		struct flow_dissector_key_eth_addrs *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ETH_ADDRS,
						  f->key);
		struct flow_dissector_key_eth_addrs *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ETH_ADDRS,
						  f->mask);

		ether_addr_copy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
					     dmac_47_16),
				mask->dst);
		ether_addr_copy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
					     dmac_47_16),
				key->dst);

		ether_addr_copy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
					     smac_47_16),
				mask->src);
		ether_addr_copy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
					     smac_47_16),
				key->src);

		if (!is_zero_ether_addr(mask->src) || !is_zero_ether_addr(mask->dst))
			*match_level = MLX5_MATCH_L2;
	}

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_VLAN)) {
		struct flow_dissector_key_vlan *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_VLAN,
						  f->key);
		struct flow_dissector_key_vlan *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_VLAN,
						  f->mask);
		if (mask->vlan_id || mask->vlan_priority || mask->vlan_tpid) {
			if (key->vlan_tpid == htons(ETH_P_8021AD)) {
				MLX5_SET(fte_match_set_lyr_2_4, headers_c,
					 svlan_tag, 1);
				MLX5_SET(fte_match_set_lyr_2_4, headers_v,
					 svlan_tag, 1);
			} else {
				MLX5_SET(fte_match_set_lyr_2_4, headers_c,
					 cvlan_tag, 1);
				MLX5_SET(fte_match_set_lyr_2_4, headers_v,
					 cvlan_tag, 1);
			}

			MLX5_SET(fte_match_set_lyr_2_4, headers_c, first_vid, mask->vlan_id);
			MLX5_SET(fte_match_set_lyr_2_4, headers_v, first_vid, key->vlan_id);

			MLX5_SET(fte_match_set_lyr_2_4, headers_c, first_prio, mask->vlan_priority);
			MLX5_SET(fte_match_set_lyr_2_4, headers_v, first_prio, key->vlan_priority);

			*match_level = MLX5_MATCH_L2;
		}
	}

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_CVLAN)) {
		struct flow_dissector_key_vlan *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_CVLAN,
						  f->key);
		struct flow_dissector_key_vlan *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_CVLAN,
						  f->mask);
		if (mask->vlan_id || mask->vlan_priority || mask->vlan_tpid) {
			if (key->vlan_tpid == htons(ETH_P_8021AD)) {
				MLX5_SET(fte_match_set_misc, misc_c,
					 outer_second_svlan_tag, 1);
				MLX5_SET(fte_match_set_misc, misc_v,
					 outer_second_svlan_tag, 1);
			} else {
				MLX5_SET(fte_match_set_misc, misc_c,
					 outer_second_cvlan_tag, 1);
				MLX5_SET(fte_match_set_misc, misc_v,
					 outer_second_cvlan_tag, 1);
			}

			MLX5_SET(fte_match_set_misc, misc_c, outer_second_vid,
				 mask->vlan_id);
			MLX5_SET(fte_match_set_misc, misc_v, outer_second_vid,
				 key->vlan_id);
			MLX5_SET(fte_match_set_misc, misc_c, outer_second_prio,
				 mask->vlan_priority);
			MLX5_SET(fte_match_set_misc, misc_v, outer_second_prio,
				 key->vlan_priority);

			*match_level = MLX5_MATCH_L2;
		}
	}

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_dissector_key_basic *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_BASIC,
						  f->key);
		struct flow_dissector_key_basic *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_BASIC,
						  f->mask);
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ethertype,
			 ntohs(mask->n_proto));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ethertype,
			 ntohs(key->n_proto));

		if (mask->n_proto)
			*match_level = MLX5_MATCH_L2;
	}

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_CONTROL)) {
		struct flow_dissector_key_control *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_CONTROL,
						  f->key);

		struct flow_dissector_key_control *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_CONTROL,
						  f->mask);
		addr_type = key->addr_type;

		/* the HW doesn't support frag first/later */
		if (mask->flags & FLOW_DIS_FIRST_FRAG)
			return -EOPNOTSUPP;

		if (mask->flags & FLOW_DIS_IS_FRAGMENT) {
			MLX5_SET(fte_match_set_lyr_2_4, headers_c, frag, 1);
			MLX5_SET(fte_match_set_lyr_2_4, headers_v, frag,
				 key->flags & FLOW_DIS_IS_FRAGMENT);

			/* the HW doesn't need L3 inline to match on frag=no */
			if (!(key->flags & FLOW_DIS_IS_FRAGMENT))
				*match_level = MLX5_INLINE_MODE_L2;
	/* ***  L2 attributes parsing up to here *** */
			else
				*match_level = MLX5_INLINE_MODE_IP;
		}
	}

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_dissector_key_basic *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_BASIC,
						  f->key);
		struct flow_dissector_key_basic *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_BASIC,
						  f->mask);
		ip_proto = key->ip_proto;

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ip_protocol,
			 mask->ip_proto);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_protocol,
			 key->ip_proto);

		if (mask->ip_proto)
			*match_level = MLX5_MATCH_L3;
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_dissector_key_ipv4_addrs *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_IPV4_ADDRS,
						  f->key);
		struct flow_dissector_key_ipv4_addrs *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_IPV4_ADDRS,
						  f->mask);

		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    src_ipv4_src_ipv6.ipv4_layout.ipv4),
		       &mask->src, sizeof(mask->src));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    src_ipv4_src_ipv6.ipv4_layout.ipv4),
		       &key->src, sizeof(key->src));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
		       &mask->dst, sizeof(mask->dst));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
		       &key->dst, sizeof(key->dst));

		if (mask->src || mask->dst)
			*match_level = MLX5_MATCH_L3;
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_dissector_key_ipv6_addrs *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_IPV6_ADDRS,
						  f->key);
		struct flow_dissector_key_ipv6_addrs *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_IPV6_ADDRS,
						  f->mask);

		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       &mask->src, sizeof(mask->src));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       &key->src, sizeof(key->src));

		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       &mask->dst, sizeof(mask->dst));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       &key->dst, sizeof(key->dst));

		if (ipv6_addr_type(&mask->src) != IPV6_ADDR_ANY ||
		    ipv6_addr_type(&mask->dst) != IPV6_ADDR_ANY)
			*match_level = MLX5_MATCH_L3;
	}

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_IP)) {
		struct flow_dissector_key_ip *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_IP,
						  f->key);
		struct flow_dissector_key_ip *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_IP,
						  f->mask);

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ip_ecn, mask->tos & 0x3);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_ecn, key->tos & 0x3);

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ip_dscp, mask->tos >> 2);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_dscp, key->tos  >> 2);

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ttl_hoplimit, mask->ttl);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ttl_hoplimit, key->ttl);

		if (mask->ttl &&
		    !MLX5_CAP_ESW_FLOWTABLE_FDB(priv->mdev,
						ft_field_support.outer_ipv4_ttl))
			return -EOPNOTSUPP;

		if (mask->tos || mask->ttl)
			*match_level = MLX5_MATCH_L3;
	}

	/* ***  L3 attributes parsing up to here *** */

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_dissector_key_ports *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_PORTS,
						  f->key);
		struct flow_dissector_key_ports *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_PORTS,
						  f->mask);
		switch (ip_proto) {
		case IPPROTO_TCP:
			MLX5_SET(fte_match_set_lyr_2_4, headers_c,
				 tcp_sport, ntohs(mask->src));
			MLX5_SET(fte_match_set_lyr_2_4, headers_v,
				 tcp_sport, ntohs(key->src));

			MLX5_SET(fte_match_set_lyr_2_4, headers_c,
				 tcp_dport, ntohs(mask->dst));
			MLX5_SET(fte_match_set_lyr_2_4, headers_v,
				 tcp_dport, ntohs(key->dst));
			break;

		case IPPROTO_UDP:
			MLX5_SET(fte_match_set_lyr_2_4, headers_c,
				 udp_sport, ntohs(mask->src));
			MLX5_SET(fte_match_set_lyr_2_4, headers_v,
				 udp_sport, ntohs(key->src));

			MLX5_SET(fte_match_set_lyr_2_4, headers_c,
				 udp_dport, ntohs(mask->dst));
			MLX5_SET(fte_match_set_lyr_2_4, headers_v,
				 udp_dport, ntohs(key->dst));
			break;
		default:
			netdev_err(priv->netdev,
				   "Only UDP and TCP transport are supported\n");
			return -EINVAL;
		}

		if (mask->src || mask->dst)
			*match_level = MLX5_MATCH_L4;
	}

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_TCP)) {
		struct flow_dissector_key_tcp *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_TCP,
						  f->key);
		struct flow_dissector_key_tcp *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_TCP,
						  f->mask);

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, tcp_flags,
			 ntohs(mask->flags));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, tcp_flags,
			 ntohs(key->flags));

		if (mask->flags)
			*match_level = MLX5_MATCH_L4;
	}

	return 0;
}

static int parse_cls_flower(struct mlx5e_priv *priv,
			    struct mlx5e_tc_flow *flow,
			    struct mlx5_flow_spec *spec,
			    struct tc_cls_flower_offload *f)
{
	struct mlx5_core_dev *dev = priv->mdev;
	struct mlx5_eswitch *esw = dev->priv.eswitch;
	struct mlx5e_rep_priv *rpriv = priv->ppriv;
	u8 match_level, tunnel_match_level = MLX5_MATCH_NONE;
	struct mlx5_eswitch_rep *rep;
	u8 ct_state;
	int err;
	bool is_eswitch_flow = mlx5e_is_eswitch_flow(flow);

	ct_state = (f->ct_state_key & f->ct_state_mask);

	/* Allow only -trk and +trk+est only */
	if (!(ct_state == 0 ||
	      ct_state == (TCA_FLOWER_KEY_CT_FLAGS_TRACKED |
			   TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED))) {
		/* Leave it as debug */
		netdev_dbg(priv->netdev, "Unsupported ct_state used: key/mask: %x/%x\n",
			    f->ct_state_key, f->ct_state_mask);
		return -EOPNOTSUPP;
       }

	err = __parse_cls_flower(priv, spec, f, &match_level, &tunnel_match_level);

	if (!err && is_eswitch_flow) {
		rep = rpriv->rep;
		if (rep->vport != FDB_UPLINK_VPORT &&
		    (esw->offloads.inline_mode != MLX5_INLINE_MODE_NONE &&
		    esw->offloads.inline_mode < match_level)) {
			netdev_warn(priv->netdev,
				    "Flow is not offloaded due to min inline setting, required %d actual %d\n",
				    match_level, esw->offloads.inline_mode);
			return -EOPNOTSUPP;
		}
	}

	if (is_eswitch_flow) {
		flow->esw_attr->match_level = match_level;
		flow->esw_attr->tunnel_match_level = tunnel_match_level;
	} else {
		flow->nic_attr->match_level = match_level;
	}

	return err;
}

struct pedit_headers {
	struct ethhdr  eth;
	struct iphdr   ip4;
	struct ipv6hdr ip6;
	struct tcphdr  tcp;
	struct udphdr  udp;
};

static int pedit_header_offsets[] = {
	[TCA_PEDIT_KEY_EX_HDR_TYPE_ETH] = offsetof(struct pedit_headers, eth),
	[TCA_PEDIT_KEY_EX_HDR_TYPE_IP4] = offsetof(struct pedit_headers, ip4),
	[TCA_PEDIT_KEY_EX_HDR_TYPE_IP6] = offsetof(struct pedit_headers, ip6),
	[TCA_PEDIT_KEY_EX_HDR_TYPE_TCP] = offsetof(struct pedit_headers, tcp),
	[TCA_PEDIT_KEY_EX_HDR_TYPE_UDP] = offsetof(struct pedit_headers, udp),
};

#define pedit_header(_ph, _htype) ((void *)(_ph) + pedit_header_offsets[_htype])

static int set_pedit_val(u8 hdr_type, u32 mask, u32 val, u32 offset,
			 struct pedit_headers *masks,
			 struct pedit_headers *vals)
{
	u32 *curr_pmask, *curr_pval;

	if (hdr_type >= __PEDIT_HDR_TYPE_MAX)
		goto out_err;

	curr_pmask = (u32 *)(pedit_header(masks, hdr_type) + offset);
	curr_pval  = (u32 *)(pedit_header(vals, hdr_type) + offset);

	if (*curr_pmask & mask)  /* disallow acting twice on the same location */
		goto out_err;

	*curr_pmask |= mask;
	*curr_pval  |= (val & mask);

	return 0;

out_err:
	return -EOPNOTSUPP;
}

struct mlx5_fields {
	u8  field;
	u8  size;
	u32 offset;
};

#define OFFLOAD(fw_field, size, field, off) \
		{MLX5_ACTION_IN_FIELD_OUT_ ## fw_field, size, offsetof(struct pedit_headers, field) + (off)}

static struct mlx5_fields fields[] = {
	OFFLOAD(DMAC_47_16, 4, eth.h_dest[0], 0),
	OFFLOAD(DMAC_15_0,  2, eth.h_dest[4], 0),
	OFFLOAD(SMAC_47_16, 4, eth.h_source[0], 0),
	OFFLOAD(SMAC_15_0,  2, eth.h_source[4], 0),
	OFFLOAD(ETHERTYPE,  2, eth.h_proto, 0),

	OFFLOAD(IP_TTL, 1, ip4.ttl,   0),
	OFFLOAD(SIPV4,  4, ip4.saddr, 0),
	OFFLOAD(DIPV4,  4, ip4.daddr, 0),

	OFFLOAD(SIPV6_127_96, 4, ip6.saddr.s6_addr32[0], 0),
	OFFLOAD(SIPV6_95_64,  4, ip6.saddr.s6_addr32[1], 0),
	OFFLOAD(SIPV6_63_32,  4, ip6.saddr.s6_addr32[2], 0),
	OFFLOAD(SIPV6_31_0,   4, ip6.saddr.s6_addr32[3], 0),
	OFFLOAD(DIPV6_127_96, 4, ip6.daddr.s6_addr32[0], 0),
	OFFLOAD(DIPV6_95_64,  4, ip6.daddr.s6_addr32[1], 0),
	OFFLOAD(DIPV6_63_32,  4, ip6.daddr.s6_addr32[2], 0),
	OFFLOAD(DIPV6_31_0,   4, ip6.daddr.s6_addr32[3], 0),
	OFFLOAD(IPV6_HOPLIMIT, 1, ip6.hop_limit, 0),

	OFFLOAD(TCP_SPORT, 2, tcp.source,  0),
	OFFLOAD(TCP_DPORT, 2, tcp.dest,    0),
	OFFLOAD(TCP_FLAGS, 1, tcp.ack_seq, 5),

	OFFLOAD(UDP_SPORT, 2, udp.source, 0),
	OFFLOAD(UDP_DPORT, 2, udp.dest,   0),
};

/* On input attr->num_mod_hdr_actions tells how many HW actions can be parsed at
 * max from the SW pedit action. On success, it says how many HW actions were
 * actually parsed.
 */
static int offload_pedit_fields(struct pedit_headers *masks,
				struct pedit_headers *vals,
				struct mlx5e_tc_flow_parse_attr *parse_attr)
{
	struct pedit_headers *set_masks, *add_masks, *set_vals, *add_vals;
	int i, action_size, nactions, max_actions, first, last, next_z;
	void *s_masks_p, *a_masks_p, *vals_p;
	struct mlx5_fields *f;
	u8 cmd, field_bsize;
	u32 s_mask, a_mask;
	unsigned long mask;
	__be32 mask_be32;
	__be16 mask_be16;
	void *action;

	set_masks = &masks[TCA_PEDIT_KEY_EX_CMD_SET];
	add_masks = &masks[TCA_PEDIT_KEY_EX_CMD_ADD];
	set_vals = &vals[TCA_PEDIT_KEY_EX_CMD_SET];
	add_vals = &vals[TCA_PEDIT_KEY_EX_CMD_ADD];

	action_size = MLX5_MH_ACT_SZ;
	action = parse_attr->mod_hdr_actions;
	max_actions = parse_attr->num_mod_hdr_actions;
	nactions = 0;

	for (i = 0; i < ARRAY_SIZE(fields); i++) {
		f = &fields[i];
		/* avoid seeing bits set from previous iterations */
		s_mask = 0;
		a_mask = 0;

		s_masks_p = (void *)set_masks + f->offset;
		a_masks_p = (void *)add_masks + f->offset;

		memcpy(&s_mask, s_masks_p, f->size);
		memcpy(&a_mask, a_masks_p, f->size);

		if (!s_mask && !a_mask) /* nothing to offload here */
			continue;

		if (s_mask && a_mask) {
			printk(KERN_WARNING "mlx5: can't set and add to the same HW field (%x)\n", f->field);
			return -EOPNOTSUPP;
		}

		if (nactions == max_actions) {
			printk(KERN_WARNING "mlx5: parsed %d pedit actions, can't do more\n", nactions);
			return -EOPNOTSUPP;
		}

		if (s_mask) {
			cmd  = MLX5_ACTION_TYPE_SET;
			mask = s_mask;
			vals_p = (void *)set_vals + f->offset;
			/* clear to denote we consumed this field */
			memset(s_masks_p, 0, f->size);
		} else {
			cmd  = MLX5_ACTION_TYPE_ADD;
			mask = a_mask;
			vals_p = (void *)add_vals + f->offset;
			/* clear to denote we consumed this field */
			memset(a_masks_p, 0, f->size);
		}

		field_bsize = f->size * BITS_PER_BYTE;

		if (field_bsize == 32) {
			mask_be32 = *(__be32 *)&mask;
			mask = (__force unsigned long)cpu_to_le32(be32_to_cpu(mask_be32));
		} else if (field_bsize == 16) {
			mask_be16 = *(__be16 *)&mask;
			mask = (__force unsigned long)cpu_to_le16(be16_to_cpu(mask_be16));
		}

		first = find_first_bit(&mask, field_bsize);
		next_z = find_next_zero_bit(&mask, field_bsize, first);
		last  = find_last_bit(&mask, field_bsize);
		if (first < next_z && next_z < last) {
			printk(KERN_WARNING "mlx5: rewrite of few sub-fields (mask %lx) isn't offloaded\n",
			       mask);
			return -EOPNOTSUPP;
		}

		MLX5_SET(set_action_in, action, action_type, cmd);
		MLX5_SET(set_action_in, action, field, f->field);

		if (cmd == MLX5_ACTION_TYPE_SET) {
			MLX5_SET(set_action_in, action, offset, first);
			/* length is num of bits to be written, zero means length of 32 */
			MLX5_SET(set_action_in, action, length, (last - first + 1));
		}

		if (field_bsize == 32)
			MLX5_SET(set_action_in, action, data, ntohl(*(__be32 *)vals_p) >> first);
		else if (field_bsize == 16)
			MLX5_SET(set_action_in, action, data, ntohs(*(__be16 *)vals_p) >> first);
		else if (field_bsize == 8)
			MLX5_SET(set_action_in, action, data, *(u8 *)vals_p >> first);

		action += action_size;
		nactions++;
	}

	parse_attr->num_mod_hdr_actions = nactions;
	return 0;
}

static int alloc_mod_hdr_actions(struct mlx5e_priv *priv,
				 int nkeys, int namespace,
				 struct mlx5e_tc_flow_parse_attr *parse_attr,
				 gfp_t flags)
{
	int action_size, max_actions;

	action_size = MLX5_MH_ACT_SZ;

	if (namespace == MLX5_FLOW_NAMESPACE_FDB) /* FDB offloading */
		max_actions = MLX5_CAP_ESW_FLOWTABLE_FDB(priv->mdev, max_modify_header_actions);
	else /* namespace is MLX5_FLOW_NAMESPACE_KERNEL - NIC offloading */
		max_actions = MLX5_CAP_FLOWTABLE_NIC_RX(priv->mdev, max_modify_header_actions);

	/* can get up to crazingly 16 HW actions in 32 bits pedit SW key */
	max_actions = nkeys ? min(max_actions, nkeys * 16) : max_actions;

	parse_attr->mod_hdr_actions = kcalloc(max_actions, action_size, flags);
	if (!parse_attr->mod_hdr_actions)
		return -ENOMEM;

	parse_attr->num_mod_hdr_actions = max_actions;
	return 0;
}

static const struct pedit_headers zero_masks = {};

static int parse_tc_pedit_action(struct mlx5e_priv *priv,
				 const struct tc_action *a, int namespace,
				 struct mlx5e_tc_flow_parse_attr *parse_attr)
{
	struct pedit_headers masks[__PEDIT_CMD_MAX], vals[__PEDIT_CMD_MAX], *cmd_masks;
	int nkeys, i, err = -EOPNOTSUPP;
	u32 mask, val, offset;
	u8 cmd, htype;

	nkeys = tcf_pedit_nkeys(a);

	memset(masks, 0, sizeof(struct pedit_headers) * __PEDIT_CMD_MAX);
	memset(vals,  0, sizeof(struct pedit_headers) * __PEDIT_CMD_MAX);

	for (i = 0; i < nkeys; i++) {
		htype = tcf_pedit_htype(a, i);
		cmd = tcf_pedit_cmd(a, i);
		err = -EOPNOTSUPP; /* can't be all optimistic */

		if (htype == TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK) {
			netdev_warn(priv->netdev, "legacy pedit isn't offloaded\n");
			goto out_err;
		}

		if (cmd != TCA_PEDIT_KEY_EX_CMD_SET && cmd != TCA_PEDIT_KEY_EX_CMD_ADD) {
			netdev_warn(priv->netdev, "pedit cmd %d isn't offloaded\n", cmd);
			goto out_err;
		}

		mask = tcf_pedit_mask(a, i);
		val = tcf_pedit_val(a, i);
		offset = tcf_pedit_offset(a, i);

		err = set_pedit_val(htype, ~mask, val, offset, &masks[cmd], &vals[cmd]);
		if (err)
			goto out_err;
	}

	err = alloc_mod_hdr_actions(priv, nkeys, namespace, parse_attr, GFP_KERNEL);
	if (err)
		goto out_err;

	err = offload_pedit_fields(masks, vals, parse_attr);
	if (err < 0)
		goto out_dealloc_parsed_actions;

	for (cmd = 0; cmd < __PEDIT_CMD_MAX; cmd++) {
		cmd_masks = &masks[cmd];
		if (memcmp(cmd_masks, &zero_masks, sizeof(zero_masks))) {
			netdev_warn(priv->netdev, "attempt to offload an unsupported field (cmd %d)\n", cmd);
			print_hex_dump(KERN_WARNING, "mask: ", DUMP_PREFIX_ADDRESS,
				       16, 1, cmd_masks, sizeof(zero_masks), true);
			err = -EOPNOTSUPP;
			goto out_dealloc_parsed_actions;
		}
	}

	return 0;

out_dealloc_parsed_actions:
	kfree(parse_attr->mod_hdr_actions);
	parse_attr->mod_hdr_actions = NULL;
out_err:
	return err;
}

static bool csum_offload_supported(struct mlx5e_priv *priv, u32 action, u32 update_flags)
{
	u32 prot_flags = TCA_CSUM_UPDATE_FLAG_IPV4HDR | TCA_CSUM_UPDATE_FLAG_TCP |
			 TCA_CSUM_UPDATE_FLAG_UDP;

	/*  The HW recalcs checksums only if re-writing headers */
	if (!(action & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR)) {
		netdev_warn(priv->netdev,
			    "TC csum action is only offloaded with pedit\n");
		return false;
	}

	if (update_flags & ~prot_flags) {
		netdev_warn(priv->netdev,
			    "can't offload TC csum action for some header/s - flags %#x\n",
			    update_flags);
		return false;
	}

	return true;
}

static bool modify_header_match_supported(struct mlx5_flow_spec *spec,
					  struct tcf_exts *exts)
{
	const struct tc_action *a;
	bool modify_ip_header;
	LIST_HEAD(actions);
	u8 htype, ip_proto;
	void *headers_v;
	u16 ethertype;
	int nkeys, i;

	headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value, outer_headers);
	ethertype = MLX5_GET(fte_match_set_lyr_2_4, headers_v, ethertype);

	/* for non-IP we only re-write MACs, so we're okay */
	if (ethertype != ETH_P_IP && ethertype != ETH_P_IPV6)
		goto out_ok;

	modify_ip_header = false;
	tcf_exts_for_each_action(i, a, exts) {
		int k;

		if (!is_tcf_pedit(a))
			continue;

		nkeys = tcf_pedit_nkeys(a);
		for (k = 0; k < nkeys; k++) {
			htype = tcf_pedit_htype(a, k);
			if (htype == TCA_PEDIT_KEY_EX_HDR_TYPE_IP4 ||
			    htype == TCA_PEDIT_KEY_EX_HDR_TYPE_IP6) {
				modify_ip_header = true;
				break;
			}
		}
	}

	ip_proto = MLX5_GET(fte_match_set_lyr_2_4, headers_v, ip_protocol);
	if (modify_ip_header && ip_proto != IPPROTO_TCP &&
	    ip_proto != IPPROTO_UDP && ip_proto != IPPROTO_ICMP) {
		pr_info("can't offload re-write of ip proto %d\n", ip_proto);
		return false;
	}

out_ok:
	return true;
}

static bool actions_match_supported(struct mlx5e_priv *priv,
				    struct tcf_exts *exts,
				    struct mlx5e_tc_flow_parse_attr *parse_attr,
				    struct mlx5e_tc_flow *flow)
{
	u32 actions;

	if (mlx5e_is_eswitch_flow(flow))
		actions = flow->esw_attr->action;
	else
		actions = flow->nic_attr->action;

	if (atomic_read(&flow->flags) & MLX5E_TC_FLOW_EGRESS &&
	    !(actions & MLX5_FLOW_CONTEXT_ACTION_DECAP))
		return false;

	if (actions & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR)
		return modify_header_match_supported(&parse_attr->spec, exts);

	return true;
}

static bool same_hw_devs(struct mlx5e_priv *priv, struct mlx5e_priv *peer_priv)
{
	struct mlx5_core_dev *fmdev, *pmdev;
	u64 fsystem_guid, psystem_guid;

	fmdev = priv->mdev;
	pmdev = peer_priv->mdev;

	mlx5_query_nic_vport_system_image_guid(fmdev, &fsystem_guid);
	mlx5_query_nic_vport_system_image_guid(pmdev, &psystem_guid);

	return (fsystem_guid == psystem_guid);
}

static int parse_tc_nic_actions(struct mlx5e_priv *priv, struct tcf_exts *exts,
				struct mlx5e_tc_flow_parse_attr *parse_attr,
				struct mlx5e_tc_flow *flow)
{
	struct mlx5_nic_flow_attr *attr = flow->nic_attr;
	const struct tc_action *a;
	LIST_HEAD(actions);
	u32 action = 0;
	int err, i;

	if (!tcf_exts_has_actions(exts))
		return -EINVAL;

	attr->flow_tag = MLX5_FS_DEFAULT_FLOW_TAG;

	tcf_exts_for_each_action(i, a, exts) {
		if (is_tcf_gact_shot(a)) {
			action |= MLX5_FLOW_CONTEXT_ACTION_DROP;
			if (MLX5_CAP_FLOWTABLE(priv->mdev,
					       flow_table_properties_nic_receive.flow_counter))
				action |= MLX5_FLOW_CONTEXT_ACTION_COUNT;
			continue;
		}

		if (is_tcf_pedit(a)) {
			err = parse_tc_pedit_action(priv, a, MLX5_FLOW_NAMESPACE_KERNEL,
						    parse_attr);
			if (err)
				return err;

			action |= MLX5_FLOW_CONTEXT_ACTION_MOD_HDR;
			continue;
		}

		if (is_tcf_csum(a)) {
			if (csum_offload_supported(priv, action,
						   tcf_csum_update_flags(a)))
				continue;

			return -EOPNOTSUPP;
		}

		if (is_tcf_mirred_egress_redirect(a)) {
			struct net_device *peer_dev = tcf_mirred_dev(a);

			if (priv->netdev->netdev_ops == peer_dev->netdev_ops &&
			    same_hw_devs(priv, netdev_priv(peer_dev))) {
				parse_attr->mirred_ifindex = peer_dev->ifindex;
				atomic_or(MLX5E_TC_FLOW_HAIRPIN, &flow->flags);
				action |= MLX5_FLOW_CONTEXT_ACTION_FWD_DEST |
					  MLX5_FLOW_CONTEXT_ACTION_COUNT;
			} else {
				netdev_warn(priv->netdev, "device %s not on same HW, can't offload\n",
					    peer_dev->name);
				return -EINVAL;
			}
			continue;
		}

		if (is_tcf_skbedit_mark(a)) {
			u32 mark = tcf_skbedit_mark(a);

			if (mark & ~MLX5E_TC_FLOW_ID_MASK) {
				netdev_warn(priv->netdev, "Bad flow mark - only 16 bit is supported: 0x%x\n",
					    mark);
				return -EINVAL;
			}

			attr->flow_tag = mark;
			action |= MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
			continue;
		}

		return -EINVAL;
	}

	attr->action = action;
	if (!actions_match_supported(priv, exts, parse_attr, flow))
		return -EOPNOTSUPP;

	return 0;
}

static inline int cmp_encap_info(struct ip_tunnel_key *a,
				 struct ip_tunnel_key *b)
{
	return memcmp(a, b, sizeof(*a));
}

static inline int hash_encap_info(struct ip_tunnel_key *key)
{
	return jhash(key, sizeof(*key), 0);
}

static bool mlx5e_same_eswitch_devs(struct mlx5e_priv *priv,
				    struct net_device *peer_netdev)
{
	if (switchdev_port_same_parent_id(priv->netdev, peer_netdev) &&
	    (peer_netdev->netdev_ops == &mlx5e_netdev_ops_rep ||
	    peer_netdev->netdev_ops == &mlx5e_netdev_ops))
		return true;

	return false;
}

static int mlx5e_route_lookup_ipv4(struct mlx5e_priv *priv,
				   struct net_device *mirred_dev,
				   struct net_device **out_dev,
				   struct flowi4 *fl4,
				   struct neighbour **out_n,
				   u8 *out_ttl)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5e_rep_priv *uplink_rpriv;
	struct rtable *rt;
	struct neighbour *n = NULL;

#if IS_ENABLED(CONFIG_INET)
	int ret;

	rt = ip_route_output_key(dev_net(mirred_dev), fl4);
	ret = PTR_ERR_OR_ZERO(rt);
	if (ret)
		return ret;
#else
	return -EOPNOTSUPP;
#endif
	uplink_rpriv = mlx5_eswitch_get_uplink_priv(esw, REP_ETH);
	/* if the egress device isn't on the same HW e-switch, we use the uplink */
	if (!switchdev_port_same_parent_id(priv->netdev, rt->dst.dev))
		*out_dev = uplink_rpriv->netdev;
	else
		*out_dev = rt->dst.dev;

	if (!(*out_ttl))
		*out_ttl = ip4_dst_hoplimit(&rt->dst);
	n = dst_neigh_lookup(&rt->dst, &fl4->daddr);
	ip_rt_put(rt);
	if (!n)
		return -ENOMEM;

	*out_n = n;

	return 0;
}

static bool is_merged_eswitch_dev(struct mlx5e_priv *priv,
				  struct net_device *peer_netdev)
{
	struct mlx5e_priv *peer_priv;

	peer_priv = netdev_priv(peer_netdev);

	return (MLX5_CAP_ESW(priv->mdev, merged_eswitch) &&
		(priv->netdev->netdev_ops == peer_netdev->netdev_ops) &&
		same_hw_devs(priv, peer_priv) &&
		MLX5_VPORT_MANAGER(peer_priv->mdev) &&
		(peer_priv->mdev->priv.eswitch->mode == SRIOV_OFFLOADS));
}

static int mlx5e_route_lookup_ipv6(struct mlx5e_priv *priv,
				   struct net_device *mirred_dev,
				   struct net_device **out_dev,
				   struct flowi6 *fl6,
				   struct neighbour **out_n,
				   u8 *out_ttl)
{
	struct neighbour *n = NULL;
	struct dst_entry *dst;

#if IS_ENABLED(CONFIG_INET) && IS_ENABLED(CONFIG_IPV6)
	struct mlx5e_rep_priv *uplink_rpriv;
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	int ret;

	ret = ipv6_stub->ipv6_dst_lookup(dev_net(mirred_dev), NULL, &dst,
					 fl6);
	if (ret < 0)
		return ret;

	if (!(*out_ttl))
		*out_ttl = ip6_dst_hoplimit(dst);

	uplink_rpriv = mlx5_eswitch_get_uplink_priv(esw, REP_ETH);
	/* if the egress device isn't on the same HW e-switch, we use the uplink */
	if (!switchdev_port_same_parent_id(priv->netdev, dst->dev))
		*out_dev = uplink_rpriv->netdev;
	else
		*out_dev = dst->dev;
#else
	return -EOPNOTSUPP;
#endif

	n = dst_neigh_lookup(dst, &fl6->daddr);
	dst_release(dst);
	if (!n)
		return -ENOMEM;

	*out_n = n;
	return 0;
}

static void gen_vxlan_header_ipv4(struct net_device *out_dev,
				  char buf[], int encap_size,
				  unsigned char h_dest[ETH_ALEN],
				  u8 tos, u8 ttl,
				  __be32 daddr,
				  __be32 saddr,
				  __be16 udp_dst_port,
				  __be32 vx_vni)
{
	struct ethhdr *eth = (struct ethhdr *)buf;
	struct iphdr  *ip = (struct iphdr *)((char *)eth + sizeof(struct ethhdr));
	struct udphdr *udp = (struct udphdr *)((char *)ip + sizeof(struct iphdr));
	struct vxlanhdr *vxh = (struct vxlanhdr *)((char *)udp + sizeof(struct udphdr));

	memset(buf, 0, encap_size);

	ether_addr_copy(eth->h_dest, h_dest);
	ether_addr_copy(eth->h_source, out_dev->dev_addr);
	eth->h_proto = htons(ETH_P_IP);

	ip->daddr = daddr;
	ip->saddr = saddr;

	ip->tos = tos;
	ip->ttl = ttl;
	ip->protocol = IPPROTO_UDP;
	ip->version = 0x4;
	ip->ihl = 0x5;

	udp->dest = udp_dst_port;
	vxh->vx_flags = VXLAN_HF_VNI;
	vxh->vx_vni = vxlan_vni_field(vx_vni);
}

static void gen_vxlan_header_ipv6(struct net_device *out_dev,
				  char buf[], int encap_size,
				  unsigned char h_dest[ETH_ALEN],
				  u8 tos, u8 ttl,
				  struct in6_addr *daddr,
				  struct in6_addr *saddr,
				  __be16 udp_dst_port,
				  __be32 vx_vni)
{
	struct ethhdr *eth = (struct ethhdr *)buf;
	struct ipv6hdr *ip6h = (struct ipv6hdr *)((char *)eth + sizeof(struct ethhdr));
	struct udphdr *udp = (struct udphdr *)((char *)ip6h + sizeof(struct ipv6hdr));
	struct vxlanhdr *vxh = (struct vxlanhdr *)((char *)udp + sizeof(struct udphdr));

	memset(buf, 0, encap_size);

	ether_addr_copy(eth->h_dest, h_dest);
	ether_addr_copy(eth->h_source, out_dev->dev_addr);
	eth->h_proto = htons(ETH_P_IPV6);

	ip6_flow_hdr(ip6h, tos, 0);
	/* the HW fills up ipv6 payload len */
	ip6h->nexthdr     = IPPROTO_UDP;
	ip6h->hop_limit   = ttl;
	ip6h->daddr	  = *daddr;
	ip6h->saddr	  = *saddr;

	udp->dest = udp_dst_port;
	vxh->vx_flags = VXLAN_HF_VNI;
	vxh->vx_vni = vxlan_vni_field(vx_vni);
}

static int mlx5e_encap_entry_attach_update(struct mlx5e_priv *priv,
					   struct net_device *out_dev,
					   struct mlx5e_encap_entry *e,
					   struct neighbour *n,
					   unsigned long n_updated)
{
	unsigned long n_updated_new;
	int err;

	err = mlx5e_rep_encap_entry_attach(netdev_priv(out_dev), e);
	if (err)
		return err;

	read_lock_bh(&n->lock);
	n_updated_new = n->updated;
	read_unlock_bh(&n->lock);

	/* Neigh state changed before encap was attached to nhe.
	 * Schedule update work.
	 */
	if (n_updated != n_updated_new) {
		mlx5e_rep_neigh_entry_hold(e->nhe);
		mlx5e_rep_queue_neigh_update_work(priv, e->nhe, n);
	}

	e->updated = n_updated_new;

	return 0;
}

static int mlx5e_create_encap_header_ipv4(struct mlx5e_priv *priv,
					  struct net_device *mirred_dev,
					  struct mlx5e_encap_entry *e)
{
	int max_encap_size = MLX5_CAP_ESW(priv->mdev, max_encap_header_size);
	int ipv4_encap_size = ETH_HLEN + sizeof(struct iphdr) + VXLAN_HLEN;
	struct ip_tunnel_key *tun_key = &e->tun_info.key;
	struct net_device *out_dev;
	struct neighbour *n = NULL;
	unsigned long n_updated;
	struct flowi4 fl4 = {};
	u8 nud_state, tos, ttl;
	char *encap_header;
	int err;

	if (max_encap_size < ipv4_encap_size) {
		mlx5_core_warn(priv->mdev, "encap size %d too big, max supported is %d\n",
			       ipv4_encap_size, max_encap_size);
		return -EOPNOTSUPP;
	}

	encap_header = kzalloc(ipv4_encap_size, GFP_KERNEL);
	if (!encap_header)
		return -ENOMEM;

	switch (e->tunnel_type) {
	case MLX5_HEADER_TYPE_VXLAN:
		fl4.flowi4_proto = IPPROTO_UDP;
		fl4.fl4_dport = tun_key->tp_dst;
		break;
	default:
		err = -EOPNOTSUPP;
		goto free_encap;
	}

	tos = tun_key->tos;
	ttl = tun_key->ttl;

	fl4.flowi4_tos = tun_key->tos;
	fl4.daddr = tun_key->u.ipv4.dst;
	fl4.saddr = tun_key->u.ipv4.src;

	err = mlx5e_route_lookup_ipv4(priv, mirred_dev, &out_dev,
				      &fl4, &n, &ttl);
	if (err)
		goto free_encap;

	if (sysfs_streq("", out_ifname) == false) {
		if (sysfs_streq(out_ifname, out_dev->name) == false) {
			err = -ENETUNREACH;
			goto free_encap;
		}
	}

	/* used by mlx5e_detach_encap to lookup a neigh hash table
	 * entry in the neigh hash table when a user deletes a rule
	 */
	e->m_neigh.dev = n->dev;
	e->m_neigh.family = n->ops->family;
	memcpy(&e->m_neigh.dst_ip, n->primary_key, n->tbl->key_len);
	e->out_dev = out_dev;

	read_lock_bh(&n->lock);
	nud_state = n->nud_state;
	ether_addr_copy(e->h_dest, n->ha);
	n_updated = n->updated;
	read_unlock_bh(&n->lock);

	switch (e->tunnel_type) {
	case MLX5_HEADER_TYPE_VXLAN:
		gen_vxlan_header_ipv4(out_dev, encap_header,
				      ipv4_encap_size, e->h_dest, tos, ttl,
				      fl4.daddr,
				      fl4.saddr, tun_key->tp_dst,
				      tunnel_id_to_key32(tun_key->tun_id));
		break;
	default:
		err = -EOPNOTSUPP;
		goto free_encap;
	}
	e->encap_size = ipv4_encap_size;
	e->encap_header = encap_header;

	if (!(nud_state & NUD_VALID)) {
		err = mlx5e_encap_entry_attach_update(priv, out_dev, e, n,
						      n_updated);
		if (err)
			goto free_encap;
		neigh_event_send(n, NULL);
		err = -EAGAIN;
		goto out;
	}

	err = mlx5_encap_alloc(priv->mdev, e->tunnel_type,
			       ipv4_encap_size, encap_header, &e->encap_id);
	if (err)
		goto free_encap;

	e->flags |= MLX5_ENCAP_ENTRY_VALID;

	err = mlx5e_encap_entry_attach_update(priv, out_dev, e, n, n_updated);
	if (err)
		goto dealloc_encap;
	mlx5e_rep_queue_neigh_stats_work(netdev_priv(out_dev));
	neigh_release(n);
	return err;

dealloc_encap:
	mlx5_encap_dealloc(priv->mdev, e->encap_id);
free_encap:
	kfree(encap_header);
	if (err == -EAGAIN)
		err = -EINVAL;
out:
	if (n)
		neigh_release(n);
	return err;
}

static int mlx5e_create_encap_header_ipv6(struct mlx5e_priv *priv,
					  struct net_device *mirred_dev,
					  struct mlx5e_encap_entry *e)
{
	int max_encap_size = MLX5_CAP_ESW(priv->mdev, max_encap_header_size);
	int ipv6_encap_size = ETH_HLEN + sizeof(struct ipv6hdr) + VXLAN_HLEN;
	struct ip_tunnel_key *tun_key = &e->tun_info.key;
	struct net_device *out_dev;
	struct neighbour *n = NULL;
	unsigned long n_updated;
	struct flowi6 fl6 = {};
	u8 nud_state, tos, ttl;
	char *encap_header;
	int err;

	if (max_encap_size < ipv6_encap_size) {
		mlx5_core_warn(priv->mdev, "encap size %d too big, max supported is %d\n",
			       ipv6_encap_size, max_encap_size);
		return -EOPNOTSUPP;
	}

	encap_header = kzalloc(ipv6_encap_size, GFP_KERNEL);
	if (!encap_header)
		return -ENOMEM;

	switch (e->tunnel_type) {
	case MLX5_HEADER_TYPE_VXLAN:
		fl6.flowi6_proto = IPPROTO_UDP;
		fl6.fl6_dport = tun_key->tp_dst;
		break;
	default:
		err = -EOPNOTSUPP;
		goto free_encap;
	}

	tos = tun_key->tos;
	ttl = tun_key->ttl;

	fl6.flowlabel = ip6_make_flowinfo(RT_TOS(tun_key->tos), tun_key->label);
	fl6.daddr = tun_key->u.ipv6.dst;
	fl6.saddr = tun_key->u.ipv6.src;

	err = mlx5e_route_lookup_ipv6(priv, mirred_dev, &out_dev,
				      &fl6, &n, &ttl);
	if (err)
		goto free_encap;

	if (sysfs_streq("", out_ifname) == false) {
		if (sysfs_streq(out_ifname, out_dev->name) == false) {
			err = -ENETUNREACH;
			goto free_encap;
		}
	}

	/* used by mlx5e_detach_encap to lookup a neigh hash table
	 * entry in the neigh hash table when a user deletes a rule
	 */
	e->m_neigh.dev = n->dev;
	e->m_neigh.family = n->ops->family;
	memcpy(&e->m_neigh.dst_ip, n->primary_key, n->tbl->key_len);
	e->out_dev = out_dev;

	read_lock_bh(&n->lock);
	nud_state = n->nud_state;
	ether_addr_copy(e->h_dest, n->ha);
	n_updated = n->updated;
	read_unlock_bh(&n->lock);

	switch (e->tunnel_type) {
	case MLX5_HEADER_TYPE_VXLAN:
		gen_vxlan_header_ipv6(out_dev, encap_header,
				      ipv6_encap_size, e->h_dest, tos, ttl,
				      &fl6.daddr,
				      &fl6.saddr, tun_key->tp_dst,
				      tunnel_id_to_key32(tun_key->tun_id));
		break;
	default:
		err = -EOPNOTSUPP;
		goto free_encap;
	}

	e->encap_size = ipv6_encap_size;
	e->encap_header = encap_header;

	if (!(nud_state & NUD_VALID)) {
		err = mlx5e_encap_entry_attach_update(priv, out_dev, e, n,
						      n_updated);
		if (err)
			goto free_encap;

		neigh_event_send(n, NULL);
		err = -EAGAIN;
		goto out;
	}

	err = mlx5_encap_alloc(priv->mdev, e->tunnel_type,
			       ipv6_encap_size, encap_header, &e->encap_id);
	if (err)
		goto free_encap;

	e->flags |= MLX5_ENCAP_ENTRY_VALID;

	err = mlx5e_encap_entry_attach_update(priv, out_dev, e, n,
					      n_updated);
	if (err)
		goto dealloc_encap;
	mlx5e_rep_queue_neigh_stats_work(netdev_priv(out_dev));
	neigh_release(n);
	return err;

dealloc_encap:
	mlx5_encap_dealloc(priv->mdev, e->encap_id);
free_encap:
	kfree(encap_header);
	if (err == -EAGAIN)
		err = -EINVAL;
out:
	if (n)
		neigh_release(n);
	return err;
}

bool mlx5e_encap_take(struct mlx5e_encap_entry *e)
{
	return refcount_inc_not_zero(&e->refcnt);
}

static struct mlx5e_encap_entry *
mlx5e_encap_get(struct mlx5e_priv *priv, struct ip_tunnel_key *key,
		uintptr_t hash_key)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5e_encap_entry *e;
	bool found = false;

	rcu_read_lock();
	hash_for_each_possible_rcu(esw->offloads.encap_tbl, e,
				   encap_hlist, hash_key) {
		if (!cmp_encap_info(&e->tun_info.key, key) &&
		    mlx5e_encap_take(e)) {
			found = true;
			break;
		}
	}
	rcu_read_unlock();

	if (found)
		return e;
	return NULL;
}

static struct mlx5e_encap_entry *
mlx5e_encap_get_create(struct mlx5e_priv *priv, struct ip_tunnel_info *tun_info,
		       struct net_device *mirred_dev, int tunnel_type)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	unsigned short family = ip_tunnel_info_af(tun_info);
	struct ip_tunnel_key *key = &tun_info->key;
	struct mlx5e_encap_entry *e, *e_dup = NULL;
	int err = 0;
	uintptr_t hash_key = hash_encap_info(key);

	e = mlx5e_encap_get(priv, key, hash_key);

	/* must verify if encap is valid or not */
	if (e)
		return e;

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return ERR_PTR(-ENOMEM);

	mutex_init(&e->encap_entry_lock);
	e->tun_info = *tun_info;
	e->tunnel_type = tunnel_type;
	INIT_LIST_HEAD(&e->flows);
	INIT_LIST_HEAD(&e->neigh_update_list);
	refcount_set(&e->refcnt, 1);

	if (family == AF_INET)
		err = mlx5e_create_encap_header_ipv4(priv, mirred_dev, e);
	else if (family == AF_INET6)
		err = mlx5e_create_encap_header_ipv6(priv, mirred_dev, e);

	if (err && err != -EAGAIN) {
		kfree(e);
		return ERR_PTR(err);
	}

	spin_lock(&esw->offloads.encap_tbl_lock);
	/* check for concurrent insertion of encap entry with same params */
	e_dup = mlx5e_encap_get(priv, key, hash_key);
	if (e_dup)
		goto err_out;
	hash_add_rcu(esw->offloads.encap_tbl, &e->encap_hlist, hash_key);
	spin_unlock(&esw->offloads.encap_tbl_lock);

	return e;
err_out:
	spin_unlock(&esw->offloads.encap_tbl_lock);
	mlx5e_encap_put(priv, e);
	if (e_dup)
		return e_dup;
	return ERR_PTR(err);
}

static int mlx5e_attach_encap(struct mlx5e_priv *priv,
			      struct ip_tunnel_info *tun_info,
			      struct net_device *mirred_dev,
			      struct net_device **encap_dev,
			      struct mlx5e_tc_flow *flow)
{
	struct mlx5_esw_flow_attr *attr = flow->esw_attr;
	struct ip_tunnel_key *key = &tun_info->key;
	struct mlx5e_encap_entry *e;
	int tunnel_type, err = 0;

	/* udp dst port must be set */
	if (!memchr_inv(&key->tp_dst, 0, sizeof(key->tp_dst)))
		goto vxlan_encap_offload_err;

	/* setting udp src port isn't supported */
	if (memchr_inv(&key->tp_src, 0, sizeof(key->tp_src))) {
vxlan_encap_offload_err:
		netdev_warn(priv->netdev,
			    "must set udp dst port and not set udp src port\n");
		return -EOPNOTSUPP;
	}

	if (mlx5_vxlan_lookup_port(priv->mdev->vxlan, be16_to_cpu(key->tp_dst)) &&
	    MLX5_CAP_ESW(priv->mdev, vxlan_encap_decap)) {
		tunnel_type = MLX5_HEADER_TYPE_VXLAN;
	} else {
		netdev_warn(priv->netdev,
			    "%d isn't an offloaded vxlan udp dport\n", be16_to_cpu(key->tp_dst));
		return -EOPNOTSUPP;
	}

	e = mlx5e_encap_get_create(priv, tun_info, mirred_dev, tunnel_type);

	/* must verify if encap is valid or not */
	if (IS_ERR(e))
		return PTR_ERR(e);

	flow->e = e;
	mutex_lock(&e->encap_entry_lock);
	list_add(&flow->encap, &e->flows);
	*encap_dev = e->out_dev;
	if (e->flags & MLX5_ENCAP_ENTRY_VALID)
		attr->encap_id = e->encap_id;
	else
		err = -EAGAIN;
	flow->updated = e->updated;
	mutex_unlock(&e->encap_entry_lock);

	return err;
}

static int parse_tc_vlan_action(struct mlx5e_priv *priv,
				const struct tc_action *a,
				struct mlx5_esw_flow_attr *attr,
				u32 *action)
{
	u8 vlan_idx = attr->total_vlan;

	if (vlan_idx >= MLX5_FS_VLAN_DEPTH)
		return -EOPNOTSUPP;

	if (tcf_vlan_action(a) == TCA_VLAN_ACT_POP) {
		if (vlan_idx) {
			if (!mlx5_eswitch_vlan_actions_supported(priv->mdev,
								 MLX5_FS_VLAN_DEPTH))
				return -EOPNOTSUPP;

			*action |= MLX5_FLOW_CONTEXT_ACTION_VLAN_POP_2;
		} else {
			*action |= MLX5_FLOW_CONTEXT_ACTION_VLAN_POP;
		}
	} else if (tcf_vlan_action(a) == TCA_VLAN_ACT_PUSH) {
		attr->vlan_vid[vlan_idx] = tcf_vlan_push_vid(a);
		attr->vlan_prio[vlan_idx] = tcf_vlan_push_prio(a);
		attr->vlan_proto[vlan_idx] = tcf_vlan_push_proto(a);
		if (!attr->vlan_proto[vlan_idx])
			attr->vlan_proto[vlan_idx] = htons(ETH_P_8021Q);

		if (vlan_idx) {
			if (!mlx5_eswitch_vlan_actions_supported(priv->mdev,
								 MLX5_FS_VLAN_DEPTH))
				return -EOPNOTSUPP;

			*action |= MLX5_FLOW_CONTEXT_ACTION_VLAN_PUSH_2;
		} else {
			if (!mlx5_eswitch_vlan_actions_supported(priv->mdev, 1) &&
			    (tcf_vlan_push_proto(a) != htons(ETH_P_8021Q) ||
			     tcf_vlan_push_prio(a)))
				return -EOPNOTSUPP;

			*action |= MLX5_FLOW_CONTEXT_ACTION_VLAN_PUSH;
		}
	} else { /* action is TCA_VLAN_ACT_MODIFY */
		return -EOPNOTSUPP;
	}

	attr->total_vlan = vlan_idx + 1;

	return 0;
}

static int parse_tc_fdb_actions(struct mlx5e_priv *priv, struct tcf_exts *exts,
				struct mlx5e_tc_flow_parse_attr *parse_attr,
				struct mlx5e_tc_flow *flow)
{
	struct mlx5_esw_flow_attr *attr = flow->esw_attr;
	struct mlx5e_rep_priv *rpriv = priv->ppriv;
	struct ip_tunnel_info *info = NULL;
	const struct tc_action *a;
	LIST_HEAD(actions);
	bool encap = false;
	u32 action = 0;
	int err, i;

	attr->parse_attr = parse_attr;
	if (!tcf_exts_has_actions(exts))
		return -EINVAL;

	attr->in_rep = rpriv->rep;
	attr->in_mdev = priv->mdev;

	tcf_exts_for_each_action(i, a, exts) {
		if (is_tcf_gact_shot(a)) {
			action |= MLX5_FLOW_CONTEXT_ACTION_DROP |
				  MLX5_FLOW_CONTEXT_ACTION_COUNT;
			continue;
		}

		if (is_tcf_pedit(a)) {
			if (action & MLX5_FLOW_CONTEXT_ACTION_CT) {
				etrace("CT action before HDR is not allowed");
				return -EOPNOTSUPP;
			}

			err = parse_tc_pedit_action(priv, a, MLX5_FLOW_NAMESPACE_FDB,
						    parse_attr);
			if (err)
				return err;

			action |= MLX5_FLOW_CONTEXT_ACTION_MOD_HDR;
			attr->mirror_count = attr->out_count;
			continue;
		}

		if (is_tcf_csum(a)) {
			if (csum_offload_supported(priv, action,
						   tcf_csum_update_flags(a)))
				continue;

			return -EOPNOTSUPP;
		}

		if (is_tcf_mirred_egress_redirect(a) || is_tcf_mirred_egress_mirror(a)) {
			struct mlx5e_priv *out_priv;
			struct net_device *out_dev;

			out_dev = tcf_mirred_dev(a);

			if (attr->out_count >= MLX5_MAX_FLOW_FWD_VPORTS) {
				pr_err("can't support more than %d output ports, can't offload forwarding\n",
				       attr->out_count);
				return -EOPNOTSUPP;
			}

			if (mlx5e_same_eswitch_devs(priv, out_dev) ||
			    is_merged_eswitch_dev(priv, out_dev)) {
				action |= MLX5_FLOW_CONTEXT_ACTION_FWD_DEST |
					  MLX5_FLOW_CONTEXT_ACTION_COUNT;
				if (atomic_read(&flow->flags) & MLX5E_TC_FLOW_EGRESS) {
					trace("egress mirred endpoint, adding decap action");
					action |= MLX5_FLOW_CONTEXT_ACTION_DECAP;
				}
				out_priv = netdev_priv(out_dev);
				rpriv = out_priv->ppriv;
				attr->out_rep[attr->out_count] = rpriv->rep;
				attr->out_mdev[attr->out_count++] = out_priv->mdev;
			} else if (encap) {
				parse_attr->mirred_ifindex = out_dev->ifindex;
				parse_attr->tun_info = *info;
				action |= MLX5_FLOW_CONTEXT_ACTION_ENCAP |
					  MLX5_FLOW_CONTEXT_ACTION_FWD_DEST |
					  MLX5_FLOW_CONTEXT_ACTION_COUNT;
				/* attr->out_rep is resolved when we handle encap */
			} else {
				pr_debug("devices %s %s not on same switch HW, can't offload forwarding\n",
				       priv->netdev->name, out_dev->name);
				return -EINVAL;
			}
			continue;
		}

		if (is_tcf_tunnel_set(a)) {
			info = tcf_tunnel_info(a);
			if (info)
				encap = true;
			else
				return -EOPNOTSUPP;
			attr->mirror_count = attr->out_count;
			continue;
		}

		if (is_tcf_vlan(a)) {
			err = parse_tc_vlan_action(priv, a, attr, &action);

			if (err)
				return err;

			attr->mirror_count = attr->out_count;
			continue;
		}

		if (is_tcf_tunnel_release(a)) {
			action |= MLX5_FLOW_CONTEXT_ACTION_DECAP;
			continue;
		}

		if (is_tcf_ct(a)) {
			trace("offloading CT action, ignoring (info->commit: %d, info->mark: %d)",
			      tcf_ct_info(a)->commit, tcf_ct_info(a)->mark);
			action |= MLX5_FLOW_CONTEXT_ACTION_CT;
			continue;
		}

		if (is_tcf_gact_goto_chain(a)) {
			int chain_index = tcf_gact_goto_chain_index(a);

			trace("offloading chain, ignoring (goto_chain: chain: %d)", chain_index);
			if (chain_index == 0) {
				etrace("Loop to chain 0 is not supported");
				return -EOPNOTSUPP;
			}

			/* TODO: we removed tunnel_release from OVS, let's reconsider */
			if (atomic_read(&flow->flags) & MLX5E_TC_FLOW_EGRESS) {
				trace("goto chain, adding decap action");
				action |= MLX5_FLOW_CONTEXT_ACTION_DECAP;
			}
			action |= MLX5_FLOW_CONTEXT_ACTION_GOTO |
				  MLX5_FLOW_CONTEXT_ACTION_COUNT;
			continue;
		}

		return -EOPNOTSUPP;
	}

	if ((action & MLX5_FLOW_CONTEXT_ACTION_CT) &&
	    !(action & MLX5_FLOW_CONTEXT_ACTION_GOTO)) {
		etrace("CT action is not supported without goto");
		return -EOPNOTSUPP;
	}

	attr->action = action;
	if (!actions_match_supported(priv, exts, parse_attr, flow))
		return -EOPNOTSUPP;

	if (attr->mirror_count > 0 && !mlx5_esw_has_fwd_fdb(priv->mdev)) {
		netdev_warn_once(priv->netdev, "current firmware doesn't support split rule for port mirroring\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

static void get_flags(int flags, int *flow_flags)
{
	int __flow_flags = 0;

	if (flags & MLX5E_TC_INGRESS)
		__flow_flags |= MLX5E_TC_FLOW_INGRESS;
	if (flags & MLX5E_TC_EGRESS)
		__flow_flags |= MLX5E_TC_FLOW_EGRESS;

	*flow_flags = __flow_flags;
}

static const struct rhashtable_params tc_ht_params = {
	.head_offset = offsetof(struct mlx5e_tc_flow, node),
	.key_offset = offsetof(struct mlx5e_tc_flow, cookie),
	.key_len = sizeof(((struct mlx5e_tc_flow *)0)->cookie),
	.automatic_shrinking = true,
};

static struct rhashtable *get_tc_ht(struct mlx5e_priv *priv)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5e_rep_priv *uplink_rpriv;

	if (priv->is_rep ||
	    (MLX5_VPORT_MANAGER(priv->mdev) && esw->mode == SRIOV_OFFLOADS)) {
		uplink_rpriv = mlx5_eswitch_get_uplink_priv(esw, REP_ETH);
		return &uplink_rpriv->tc_ht;
	} else
		return &priv->fs.tc.ht;
}

static int
mlx5e_alloc_flow(struct mlx5e_priv *priv, u64 cookie, u32 handle,
		 int flow_flags, gfp_t flags,
		 struct mlx5e_tc_flow_parse_attr **__parse_attr,
		 struct mlx5e_tc_flow **__flow)
{
	struct mlx5e_tc_flow_parse_attr *parse_attr;
	struct mlx5e_tc_flow *flow;

	flow = flow_cache_alloc(flow_flags, flags);
	if (!flow)
		return -ENOMEM;

	parse_attr = kmem_cache_zalloc(parse_attr_cache, flags);
	if (!parse_attr) {
		flow_cache_free(flow);
		return -ENOMEM;
	}

	flow->cookie = cookie;
	atomic_set(&flow->flags, flow_flags);
	flow->priv = priv;
	parse_attr->spec.handle = handle;
	INIT_LIST_HEAD(&flow->encap);
	INIT_LIST_HEAD(&flow->mod_hdr);
	INIT_LIST_HEAD(&flow->hairpin);
	spin_lock_init(&flow->rule_lock);
	refcount_set(&flow->refcnt, 1);
	INIT_LIST_HEAD(&flow->miniflow_list);
	INIT_LIST_HEAD(&flow->tmp_list);

	*__flow = flow;
	*__parse_attr = parse_attr;

	return 0;
}

static bool is_flow_simple(struct mlx5e_tc_flow *flow, int chain_index)
{
	if (chain_index)
		return false;

	if (flow->esw_attr->action & MLX5_FLOW_CONTEXT_ACTION_GOTO)
		return false;

	return true;
}

static int
__mlx5e_tc_add_fdb_flow(struct mlx5e_priv *priv,
			struct mlx5e_tc_flow_parse_attr *parse_attr,
			struct mlx5e_tc_flow *flow)
{
	int err = 0;

	flow->rule[0] = mlx5e_tc_add_fdb_flow(priv, parse_attr, flow);
	if (IS_ERR(flow->rule[0])) {
		err = PTR_ERR(flow->rule[0]);
		if (err != -EAGAIN)
			goto err;
	}

	if (err != -EAGAIN)
		atomic_or(MLX5E_TC_FLOW_OFFLOADED, &flow->flags);

	if (!(flow->esw_attr->action & MLX5_FLOW_CONTEXT_ACTION_ENCAP)) {
		kmem_cache_free(parse_attr_cache, parse_attr);
		flow->esw_attr->parse_attr = NULL;
	}

err:
	return err;
}

static int
mlx5e_add_fdb_flow(struct mlx5e_priv *priv,
		   struct tc_cls_flower_offload *f,
		   int flow_flags,
		   struct mlx5e_tc_flow **__flow)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5e_tc_flow_parse_attr *parse_attr;
	struct mlx5e_tc_flow *flow;
	int err;

	flow_flags |= MLX5E_TC_FLOW_SIMPLE | MLX5E_TC_FLOW_ESWITCH;

	err = mlx5e_alloc_flow(priv, f->cookie, f->common.handle,
			       flow_flags, GFP_KERNEL, &parse_attr, &flow);
	if (err)
		goto out;

	/* Temporary increment num_flows to prevent concurrent mode change
	 * during flow creation.
	 */
	mlx5_eswitch_inc_num_flows(esw);

	err = parse_cls_flower(priv, flow, &parse_attr->spec, f);
	if (err)
		goto err_parse_flow;

	/* At this point concurrent access to flow->rule is not possible because
	 * neither offloaded nor init done flags were set, so no need to take
	 * rule_lock.
	 */
	err = parse_tc_fdb_actions(priv, f->exts, parse_attr, flow);
	if (err < 0)
		goto err_parse_actions;

	if (is_flow_simple(flow, f->common.chain_index)) {
		trace("flow %px is simple", flow);

		err = __mlx5e_tc_add_fdb_flow(priv, parse_attr, flow);
		if (err && err != -EAGAIN)
			goto err_add_flow;
	} else {
		trace("flow %px is not simple", flow);
		atomic_and(~MLX5E_TC_FLOW_SIMPLE, &flow->flags);
	}

	/* Release temporary num_flows taken at the beginning of this
	 * function.
	 */
	mlx5_eswitch_dec_num_flows(esw);
	*__flow = flow;

	return 0;

err_parse_flow:
	if (parse_attr->mod_hdr_actions)
		kfree(parse_attr->mod_hdr_actions);
	kmem_cache_free(parse_attr_cache, parse_attr);
err_parse_actions:
err_add_flow:
	/* Release temporary num_flows taken at the beginning of this
	 * function.
	 */
	mlx5_eswitch_dec_num_flows(esw);
	mlx5e_flow_put(priv, flow);
out:
	return err;
}

static int
mlx5e_add_nic_flow(struct mlx5e_priv *priv,
		   struct tc_cls_flower_offload *f,
		   int flow_flags,
		   struct mlx5e_tc_flow **__flow)
{
	struct mlx5e_tc_flow_parse_attr *parse_attr;
	struct mlx5e_tc_flow *flow;
	int err;

	flow_flags |= MLX5E_TC_FLOW_NIC | MLX5E_TC_FLOW_SIMPLE;
	err = mlx5e_alloc_flow(priv, f->cookie, f->common.handle,
			       flow_flags, GFP_KERNEL, &parse_attr, &flow);
	if (err)
		goto out;

	err = parse_cls_flower(priv, flow, &parse_attr->spec, f);
	if (err)
		goto err_flow;

	err = parse_tc_nic_actions(priv, f->exts, parse_attr, flow);
	if (err)
		goto err_flow;

	flow->rule[0] = mlx5e_tc_add_nic_flow(priv, parse_attr, flow);
	if (IS_ERR(flow->rule[0])) {
		err = PTR_ERR(flow->rule[0]);
		if (err != -EAGAIN)
			goto err_flow;
	}

	if (err != -EAGAIN)
		atomic_or(MLX5E_TC_FLOW_OFFLOADED, &flow->flags);

	kmem_cache_free(parse_attr_cache, parse_attr);
	*__flow = flow;

	return 0;

err_flow:
	mlx5e_flow_put(priv, flow);
	kmem_cache_free(parse_attr_cache, parse_attr);
out:
	return err;
}

static int
mlx5e_tc_add_flow(struct mlx5e_priv *priv,
		  struct tc_cls_flower_offload *f,
		  int flags,
		  struct mlx5e_tc_flow **flow)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	int flow_flags;
	int err;

	get_flags(flags, &flow_flags);

	if (esw && esw->mode == SRIOV_OFFLOADS)
		err = mlx5e_add_fdb_flow(priv, f, flow_flags, flow);
	else
		err = mlx5e_add_nic_flow(priv, f, flow_flags, flow);

	return err;
}

int mlx5e_configure_flower(struct mlx5e_priv *priv,
			   struct tc_cls_flower_offload *f, int flags)
{
	struct rhashtable *tc_ht = get_tc_ht(priv);
	struct mlx5e_tc_flow *flow;
	int err = 0;

	flow = rhashtable_lookup_fast(tc_ht, &f->cookie, tc_ht_params);
	if (flow) {
		netdev_warn_once(priv->netdev, "flow cookie %lx already exists, ignoring\n", f->cookie);
		goto out;
	}

	err = mlx5e_tc_add_flow(priv, f, flags, &flow);
	if (err)
		goto out;

	flow->version = atomic64_inc_return(&global_version);
	err = rhashtable_insert_fast(tc_ht, &flow->node, tc_ht_params);
	if (err)
		goto err_free;

	err = mlx5e_tc_update_and_init_done_fdb_flow(priv, flow);
	if (err)
		goto err_free;

	return 0;

err_free:
	mlx5e_flow_put(priv, flow);
out:
	return err;
}

static void miniflow_merge_match(struct mlx5e_tc_flow *mflow,
				  struct mlx5e_tc_flow *flow,
				  u32 *merge_mask)
{
	struct mlx5_flow_spec tmp_spec_mask;
	u32 *dst = (u32 *) &mflow->esw_attr->parse_attr->spec;
	u32 *src = (u32 *) &flow->esw_attr->parse_attr->spec;
	u32 *mask= (u32 *) &tmp_spec_mask;
	int i;

	memset(&tmp_spec_mask, 0, sizeof(tmp_spec_mask));
	memcpy(&tmp_spec_mask.match_criteria, merge_mask, sizeof(tmp_spec_mask.match_criteria));
	memcpy(&tmp_spec_mask.match_value, merge_mask, sizeof(tmp_spec_mask.match_value));

    for (i = 0; i < sizeof(struct mlx5_flow_spec) / sizeof(u32); i++)
		*dst++ |= (*src++ & (~*mask++));

	mflow->esw_attr->match_level = max(flow->esw_attr->match_level,
					   mflow->esw_attr->match_level);
	mflow->esw_attr->tunnel_match_level =
		max(flow->esw_attr->tunnel_match_level,
		    mflow->esw_attr->tunnel_match_level);
}

static void miniflow_merge_action(struct mlx5e_tc_flow *mflow,
				   struct mlx5e_tc_flow *flow)
{
	mflow->esw_attr->action |= flow->esw_attr->action;
}

static int miniflow_merge_mirred(struct mlx5e_tc_flow *mflow,
				  struct mlx5e_tc_flow *flow)
{
	struct mlx5_esw_flow_attr *dst_attr = mflow->esw_attr;
	struct mlx5_esw_flow_attr *src_attr = flow->esw_attr;
	int out_count;
	int i, j;

	if (!(src_attr->action & MLX5_FLOW_CONTEXT_ACTION_FWD_DEST))
		return 0;

	out_count = dst_attr->out_count + src_attr->out_count;
	if (out_count > MLX5_MAX_FLOW_FWD_VPORTS)
		return -1;

	for (i = 0, j = dst_attr->out_count; j < out_count; i++, j++) {
		dst_attr->out_rep[j] = src_attr->out_rep[i];
		dst_attr->out_mdev[j] = src_attr->out_mdev[i];
	}

	dst_attr->out_count = out_count;
	dst_attr->mirror_count += src_attr->mirror_count;

	return 0;
}

struct mlx5_field2match {
	u8  bitsize;
	u32 dwoff;
	u32 dwbitoff;
	u32 dwmask;
	u32 vmask;
};

#define FIELD2MATCH(fw_field, match_field) \
	[MLX5_ACTION_IN_FIELD_OUT_ ## fw_field] = { __mlx5_bit_sz(fte_match_set_lyr_2_4, match_field),\
												__mlx5_dw_off(fte_match_set_lyr_2_4, match_field),\
												__mlx5_dw_bit_off(fte_match_set_lyr_2_4, match_field), \
												__mlx5_dw_mask(fte_match_set_lyr_2_4, match_field),\
												__mlx5_mask(fte_match_set_lyr_2_4,match_field)}

static struct mlx5_field2match field2match[] = {
	FIELD2MATCH(DMAC_47_16, dmac_47_16),
	FIELD2MATCH(DMAC_15_0,  dmac_15_0),
	FIELD2MATCH(SMAC_47_16, smac_47_16),
	FIELD2MATCH(SMAC_15_0,  smac_15_0),
	FIELD2MATCH(ETHERTYPE,  ethertype),

	FIELD2MATCH(IP_TTL, ttl_hoplimit),
	FIELD2MATCH(SIPV4,  src_ipv4_src_ipv6.ipv4_layout.ipv4),
	FIELD2MATCH(DIPV4,  dst_ipv4_dst_ipv6.ipv4_layout.ipv4),

	FIELD2MATCH(SIPV6_127_96, src_ipv4_src_ipv6.ipv6_layout.ipv6[0][0]),
	FIELD2MATCH(SIPV6_95_64,  src_ipv4_src_ipv6.ipv6_layout.ipv6[4][0]),
	FIELD2MATCH(SIPV6_63_32,  src_ipv4_src_ipv6.ipv6_layout.ipv6[8][0]),
	FIELD2MATCH(SIPV6_31_0,   src_ipv4_src_ipv6.ipv6_layout.ipv6[12][0]),
	FIELD2MATCH(DIPV6_127_96, dst_ipv4_dst_ipv6.ipv6_layout.ipv6[0][0]),
	FIELD2MATCH(DIPV6_95_64,  dst_ipv4_dst_ipv6.ipv6_layout.ipv6[4][0]),
	FIELD2MATCH(DIPV6_63_32,  dst_ipv4_dst_ipv6.ipv6_layout.ipv6[8][0]),
	FIELD2MATCH(DIPV6_31_0,   dst_ipv4_dst_ipv6.ipv6_layout.ipv6[12][0]),

	FIELD2MATCH(IPV6_HOPLIMIT, ttl_hoplimit),

	FIELD2MATCH(TCP_SPORT, tcp_sport),
	FIELD2MATCH(TCP_DPORT, tcp_dport),
	FIELD2MATCH(TCP_FLAGS, tcp_flags),

	FIELD2MATCH(UDP_SPORT, udp_sport),
	FIELD2MATCH(UDP_DPORT, udp_dport),
};

/*     authoer: gaozengmo@jd.com
   description: calculate the anti-mask useing in merge match*/
static void
miniflow_merge_calculate_mask(struct mlx5e_tc_flow_parse_attr * src_parse_attr, __be32 *tmp_mask)
{
	void    *action;
	uint    action_num;
	uint    loop;
	uint    action_size = MLX5_MH_ACT_SZ;

	action = src_parse_attr->mod_hdr_actions;
	action_num=src_parse_attr->num_mod_hdr_actions;

	for (loop = 0;loop < action_num; ++loop)
	{
		uint8_t  field;

		/* just zero all the field in match, not be precise in bit.
			so if set fied has mask, it will do no effective */
		field  = MLX5_GET(set_action_in, action, field);
		if (((field <= MLX5_ACTION_IN_FIELD_OUT_DIPV4) || (field == MLX5_ACTION_IN_FIELD_OUT_IPV6_HOPLIMIT)) &&
			(field != MLX5_ACTION_IN_FIELD_OUT_IP_DSCP))
		{
			struct mlx5_field2match *tmpf2m = &field2match[field];
			*((tmp_mask) + tmpf2m->dwoff) = cpu_to_be32(be32_to_cpu(*((tmp_mask) + tmpf2m->dwoff)) | tmpf2m->dwmask);
		}
		action += action_size;
	}

	return;
}

static int miniflow_merge_hdr(struct mlx5e_priv *priv,
			       struct mlx5e_tc_flow *mflow,
			       struct mlx5e_tc_flow *flow,
			       u32 *tmp_mask)
{
	struct mlx5e_tc_flow_parse_attr *dst_parse_attr;
	struct mlx5e_tc_flow_parse_attr *src_parse_attr;
	int max_actions, action_size;
	int err;

	if (!(flow->esw_attr->action & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR))
		return 0;

	trace("merge MOD_HDR action");

	action_size = MLX5_MH_ACT_SZ;

	dst_parse_attr = mflow->esw_attr->parse_attr;
	if (!dst_parse_attr->mod_hdr_actions) {
		err = alloc_mod_hdr_actions(priv, 0 /* maximum */, MLX5_FLOW_NAMESPACE_FDB,
					    dst_parse_attr, GFP_ATOMIC);
		if (err) {
			etrace("alloc_mod_hdr_actions failed");
			return -ENOMEM;
		}

		dst_parse_attr->num_mod_hdr_actions = 0;
	}

	max_actions = MLX5_CAP_ESW_FLOWTABLE_FDB(priv->mdev, max_modify_header_actions);
	src_parse_attr = flow->esw_attr->parse_attr;

	if (dst_parse_attr->num_mod_hdr_actions + src_parse_attr->num_mod_hdr_actions >= max_actions) {
		etrace("max num of actions reached");
		kfree(dst_parse_attr->mod_hdr_actions);
		dst_parse_attr->mod_hdr_actions = NULL;
		return -E2BIG;
	}

	memcpy(dst_parse_attr->mod_hdr_actions + dst_parse_attr->num_mod_hdr_actions * action_size,
	       src_parse_attr->mod_hdr_actions,
	       src_parse_attr->num_mod_hdr_actions * action_size);

	dst_parse_attr->num_mod_hdr_actions += src_parse_attr->num_mod_hdr_actions;

	miniflow_merge_calculate_mask(src_parse_attr, tmp_mask);

	return 0;
}

static void miniflow_merge_vxlan(struct mlx5e_tc_flow *mflow,
				 struct mlx5e_tc_flow *flow)
{
	if (!(flow->esw_attr->action & MLX5_FLOW_CONTEXT_ACTION_ENCAP))
		return;

	mflow->esw_attr->parse_attr->mirred_ifindex = flow->esw_attr->parse_attr->mirred_ifindex;
	mflow->esw_attr->parse_attr->tun_info = flow->esw_attr->parse_attr->tun_info;
}

static u8 mlx5e_etype_to_ipv(u16 ethertype)
{
	if (ethertype == ETH_P_IP)
		return 4;

	if (ethertype == ETH_P_IPV6)
		return 6;

	return 0;
}

static void miniflow_merge_tuple(struct mlx5e_tc_flow *mflow,
				  struct nf_conntrack_tuple *nf_tuple)
{
	struct mlx5_flow_spec *spec = &mflow->esw_attr->parse_attr->spec;
	void *headers_c, *headers_v;
	int match_ipv;
	u8 ipv;

	trace("miniflow_tuple_to_spec");

	trace("ct: 5tuple: (ethtype: %X) %d, IPs %pI4, %pI4 ports %d, %d",
                        ntohs(nf_tuple->src.l3num),
                        nf_tuple->dst.protonum,
                        &nf_tuple->src.u3.ip,
                        &nf_tuple->dst.u3.ip,
                        ntohs(nf_tuple->src.u.udp.port),
                        ntohs(nf_tuple->dst.u.udp.port));

	if (mflow->esw_attr->action & MLX5_FLOW_CONTEXT_ACTION_DECAP) {
		trace("merge CT: tunnel info exist");
		headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
					 inner_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
					 inner_headers);
		match_ipv = MLX5_CAP_FLOWTABLE_NIC_RX(mflow->priv->mdev,
					 ft_field_support.inner_ip_version);
	} else {
		trace("merge CT: tunnel info does not exist");
		headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
					 outer_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
					 outer_headers);
		match_ipv = MLX5_CAP_FLOWTABLE_NIC_RX(mflow->priv->mdev,
					 ft_field_support.outer_ip_version);
	}

	ipv = mlx5e_etype_to_ipv(ntohs(nf_tuple->src.l3num));
	if (match_ipv && ipv) {
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ip_version);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_version, ipv);
	} else {
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ethertype);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ethertype, nf_tuple->src.l3num);
	}

	if (nf_tuple->src.l3num == htons(ETH_P_IP)) {
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
					src_ipv4_src_ipv6.ipv4_layout.ipv4),
					&nf_tuple->src.u3.ip,
					4);
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
					dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
					&nf_tuple->dst.u3.ip,
					4);

		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c,
					src_ipv4_src_ipv6.ipv4_layout.ipv4);
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c,
					dst_ipv4_dst_ipv6.ipv4_layout.ipv4);
	}

	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ip_protocol);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_protocol, nf_tuple->dst.protonum);

	switch (nf_tuple->dst.protonum) {
	case IPPROTO_UDP:
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, udp_dport);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, udp_dport, ntohs(nf_tuple->dst.u.udp.port));

		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, udp_sport);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, udp_sport, ntohs(nf_tuple->src.u.udp.port));
	break;
	case IPPROTO_TCP:
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, tcp_dport);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, tcp_dport, ntohs(nf_tuple->dst.u.tcp.port));

		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, tcp_sport);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, tcp_sport, ntohs(nf_tuple->src.u.tcp.port));

		// FIN=1 SYN=2 RST=4 PSH=8 ACK=16 URG=32
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, tcp_flags, 0x17);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, tcp_flags, 0x10);
	break;
	}
}

static struct mlx5_fc *miniflow_alloc_dummy_counter(struct mlx5_core_dev *dev)
{
	struct mlx5_fc *counter;

	counter = mlx5_fc_alloc(dev, GFP_ATOMIC);
	if (!counter)
		return NULL;

	counter->dummy = true;
	counter->aging = true;

	return counter;
}

void miniflow_free_dummy_counter(struct mlx5_core_dev *dev, struct mlx5_fc *counter)
{
	mlx5_fc_dealloc(dev, counter);
}

static int miniflow_attach_dummy_counter(struct mlx5e_tc_flow *flow)
{
	struct mlx5_fc *counter;

	if (flow->dummy_counter)
		return 0;

	if (flow->esw_attr->action & MLX5_FLOW_CONTEXT_ACTION_COUNT) {
		counter = miniflow_alloc_dummy_counter(flow->priv->mdev);
		if (!counter)
			return -1;

		/* TODO: refactor the rule_lock to flow_lock ??*/
		spin_lock(&flow->rule_lock);
		if (flow->dummy_counter)
			miniflow_free_dummy_counter(flow->priv->mdev, counter);
		else
			flow->dummy_counter = counter;
		spin_unlock(&flow->rule_lock);
	}

	return 0;
}

static struct mlx5e_miniflow *miniflow_alloc(void)
{
	struct mlx5e_miniflow *miniflow;
	miniflow = kmem_cache_alloc(miniflow_cache, GFP_ATOMIC);
	if (!miniflow)
		return NULL;

	return miniflow;
}

static void miniflow_free(struct mlx5e_miniflow *miniflow)
{
	if (miniflow)
		kmem_cache_free(miniflow_cache, miniflow);
}

static struct mlx5e_miniflow *miniflow_read(void)
{
	/* TODO: use __this_cpu_read instead? */
	return this_cpu_read(current_miniflow);
}

static void miniflow_write(struct mlx5e_miniflow *miniflow)
{
	this_cpu_write(current_miniflow, miniflow);
}

static void miniflow_init(struct mlx5e_miniflow *miniflow,
			  struct mlx5e_priv *priv)
{
	memset(miniflow, 0, sizeof(*miniflow));

	miniflow->priv = priv;
}

#define MFC_INFOMASK	7UL
#define MFC_PTRMASK  	~(MFC_INFOMASK)

#define MFC_CT_FLOW     BIT(0)

static void miniflow_path_append_cookie(struct mlx5e_miniflow *miniflow, u64 cookie, u8 flags)
{
	WARN_ON(cookie & MFC_INFOMASK);
	miniflow->path.cookies[miniflow->nr_flows++] = cookie | flags;
}

static u8 miniflow_cookie_flags(u64 cookie)
{
	return (cookie & MFC_INFOMASK);
}

static void miniflow_attach(struct mlx5e_miniflow *miniflow)
{
	struct mlx5e_tc_flow *flow;
	int i;

	spin_lock_bh(&miniflow_lock);
	/* Attach to all parent flows */
	for (i=0; i<miniflow->nr_flows; i++) {
		flow = miniflow->path.flows[i];

		miniflow->mnodes[i].miniflow = miniflow;
		list_add(&miniflow->mnodes[i].node, &flow->miniflow_list);
	}
	spin_unlock_bh(&miniflow_lock);
}

static void miniflow_abort(struct mlx5e_miniflow *miniflow)
{
	miniflow->nr_flows = -1;
}

static void miniflow_cleanup(struct mlx5e_miniflow *miniflow)
{
	struct mlx5e_tc_flow *flow;
	int j;

	for (j = 0; j < miniflow->nr_ct_tuples; j++) {
		flow = miniflow->ct_tuples[j].flow;
		if (flow)
			mlx5e_flow_put(flow->priv, flow);
	}
}

static int miniflow_register_ct_flow(struct mlx5e_miniflow *miniflow)
{
	struct mlx5e_ct_tuple *ct_tuple;
	int j;
	int err;

	if (!enable_ct_ageing)
		return 0;

	for (j = 0; j < miniflow->nr_ct_tuples; j++) {
		ct_tuple = &miniflow->ct_tuples[j];

		/* nft_gen_flow_offload_add can fail and we need to remove
		 * previous successful adds.
		 *
		 * No need to unwind, the GC will remove it eventually.
		 */

		/* TODO: lidong: can we split nft_gen_flow_offload_add() into two functions:
		   1) prepare whatever is needed and 2) commit.
		   So we will have an "atomic" like operation? we can discuss this next week.
		*/
		err = nft_gen_flow_offload_add(ct_tuple->net,
					       &ct_tuple->zone,
					       &ct_tuple->tuple, ct_tuple->flow);
		if (err) {
			mtrace("nft_gen_flow_offload_add() failed: err: %d", err);
			return err;
		}

		ct_tuple->flow = NULL;
	}

	return 0;
}

static struct mlx5e_tc_flow *miniflow_ct_flow_alloc(struct mlx5e_priv *priv,
						    struct mlx5e_ct_tuple *ct_tuple)
{
	struct mlx5e_tc_flow_parse_attr *parse_attr;
	struct mlx5e_tc_flow *flow;
	int err;

	err = mlx5e_alloc_flow(priv, 0 /* cookie */, U32_MAX /* handle */,
			       MLX5E_TC_FLOW_ESWITCH | MLX5E_TC_FLOW_CT,
			       GFP_ATOMIC, &parse_attr, &flow);
	if (err)
		return NULL;

	flow->esw_attr->parse_attr = parse_attr;
	flow->esw_attr->action = MLX5_FLOW_CONTEXT_ACTION_COUNT;

	ct_tuple->flow = flow;

	return flow;
}

static int miniflow_resolve_path_flows(struct mlx5e_miniflow *miniflow)
{
	struct mlx5e_priv *priv = miniflow->priv;
	struct rhashtable *tc_ht = get_tc_ht(priv);
	struct mlx5e_tc_flow *flow;
	unsigned long cookie;
	int i, j;

	for (i = 0, j = 0; i < miniflow->nr_flows; i++) {
		cookie = miniflow->path.cookies[i];
		if (miniflow_cookie_flags(cookie) & MFC_CT_FLOW)
			flow = miniflow_ct_flow_alloc(priv, &miniflow->ct_tuples[j++]);
		else
			flow = rhashtable_lookup_fast(tc_ht, &cookie, tc_ht_params);

		if (!flow)
			return -1;

		if (miniflow->version < flow->version)
		{
			atomic_inc((atomic_t *)&invert_cnt);
			return -1;
		}

		miniflow->path.flows[i] = flow;
	}

	return 0;
}

static int miniflow_verify_path_flows(struct mlx5e_miniflow *miniflow)
{
	struct mlx5e_priv *priv = miniflow->priv;
	struct rhashtable *tc_ht = get_tc_ht(priv);
	struct mlx5e_tc_flow *flow;
	unsigned long cookie;
	int i;

	for (i = 0; i < miniflow->nr_flows; i++) {
		cookie = miniflow->path.cookies[i];
		if (miniflow_cookie_flags(cookie) & MFC_CT_FLOW)
			continue;

		flow = rhashtable_lookup_fast(tc_ht, &cookie, tc_ht_params);
		if (!flow)
			return -1;

		if (miniflow->version < flow->version)
		{
			atomic_inc((atomic_t *)&invert_cnt);
			return -1;
		}

	}

	return 0;
}

static int __miniflow_merge(struct mlx5e_miniflow *miniflow)
{
	struct mlx5_fc *dummy_counters[MINIFLOW_MAX_FLOWS];
	struct mlx5e_tc_flow_parse_attr *mparse_attr;
	struct mlx5e_priv *priv = miniflow->priv;
	struct rhashtable *mf_ht = get_mf_ht(priv);
	struct mlx5e_rep_priv *rpriv = priv->ppriv;
	struct mlx5e_tc_flow *mflow, *flow;
	u32 tmp_mask[MLX5_ST_SZ_DW(fte_match_param)];
	int flags = MLX5E_TC_FLOW_SIMPLE | MLX5E_TC_FLOW_ESWITCH;
	int i;
	int err;

	err = mlx5e_alloc_flow(priv, 0 /* cookie */, U32_MAX /* handle */,
			       flags, GFP_KERNEL, &mparse_attr, &mflow);
	if (err) {
		rhashtable_remove_fast(mf_ht, &miniflow->node, mf_ht_params);
		miniflow_free(miniflow);
		inc_debug_counter(&nr_of_total_mf_err_alloc_flow);
		return -1;
	}

	mflow->esw_attr->parse_attr = mparse_attr;

	rcu_read_lock();
	err = miniflow_resolve_path_flows(miniflow);
	if (err) {
		ntrace("miniflow_resolve_path_flows failed");
		inc_debug_counter(&nr_of_total_mf_err_resolve_path_flows);
		goto err_rcu;
	}

	miniflow->flow = mflow;

	mflow->miniflow = miniflow;

	mflow->esw_attr->in_rep = rpriv->rep;
	mflow->esw_attr->in_mdev = priv->mdev;

	/* Main merge loop */
	memset(tmp_mask, 0, sizeof(tmp_mask));
	for (i=0; i<miniflow->nr_flows; i++) {
		flow = miniflow->path.flows[i];

		flags |= atomic_read(&flow->flags);

		miniflow_merge_match(mflow, flow, tmp_mask);
		miniflow_merge_action(mflow, flow);

		err = miniflow_merge_mirred(mflow, flow);
		if (err) {
			inc_debug_counter(&nr_of_total_mf_err_merge_mirred);
			goto err_rcu;
		}

		err = miniflow_merge_hdr(priv, mflow, flow, tmp_mask);
		if (err) {
			inc_debug_counter(&nr_of_total_mf_err_merge_hdr);
			goto err_rcu;
		}

		miniflow_merge_vxlan(mflow, flow);
		/* TODO: vlan is not supported yet */

		err = miniflow_attach_dummy_counter(flow);
		if (err) {
			inc_debug_counter(&nr_of_total_mf_err_attach_dummy_counter);
			goto err_rcu;
		}
		dummy_counters[i] = flow->dummy_counter;
	}
	rcu_read_unlock();

	flags &= MLX5E_TC_FLOW_INIT_DONE;
	atomic_set(&mflow->flags, flags);
	miniflow_merge_tuple(mflow, &miniflow->tuple);
	/* TODO: Workaround: crashes otherwise, should fix */
	mflow->esw_attr->action &= ~(MLX5_FLOW_CONTEXT_ACTION_CT |
				     MLX5_FLOW_CONTEXT_ACTION_GOTO);

	err = __mlx5e_tc_add_fdb_flow(priv, mparse_attr, mflow);
	trace("__mlx5e_tc_add_fdb_flow: err: %d", err);
	if (err && err != -EAGAIN) {
		etrace("__mlx5e_tc_add_fdb_flow failed with err: %d", err);
		inc_debug_counter(&nr_of_total_mf_err_fdb_add);
		goto err;
	}

	rcu_read_lock();
	err = miniflow_verify_path_flows(miniflow);
	if (err) {
		/* TODO: refactor this function and the error handling */
		ntrace("miniflow_verify_path_flows failed, interesting :)");
		rcu_read_unlock();
		inc_debug_counter(&nr_of_total_mf_err_verify_path);
		goto err_verify;
	}

	miniflow_link_dummy_counters(miniflow->flow,
				     dummy_counters,
				     miniflow->nr_flows);
	miniflow_attach(miniflow);
	atomic_inc(&currently_in_hw);

	err = miniflow_register_ct_flow(miniflow);
	if (err) {
		mtrace("miniflow_register_ct_flow failed");
		rcu_read_unlock();
		rhashtable_remove_fast(mf_ht, &miniflow->node, mf_ht_params);
		miniflow_cleanup(miniflow);
		inc_debug_counter(&nr_of_total_mf_err_register);
		inc_debug_counter(&nr_of_total_mf_err);
		return -1;
	}

	rcu_read_unlock();
	trace("miniflow_merge: mflow: %px, flows: %d", mflow, miniflow->nr_flows);
	inc_debug_counter(&nr_of_total_mf_succ);
	inc_debug_counter(&nr_of_total_merge_mf_succ);
	return 0;

err_rcu:
	rcu_read_unlock();
err:
err_verify:
	mlx5e_flow_put(priv, mflow);
	rhashtable_remove_fast(mf_ht, &miniflow->node, mf_ht_params);
	miniflow_cleanup(miniflow);
	miniflow_free(miniflow);
	inc_debug_counter(&nr_of_total_mf_err);
	return -1;
}

void miniflow_merge_work(struct work_struct *work)
{
	struct mlx5e_miniflow *miniflow = container_of(work, struct mlx5e_miniflow, work);
	atomic_dec(&nr_of_mfe_in_queue);

	inc_debug_counter(&nr_of_inflight_mfe);
	dec_debug_counter(&miniflow_wq_size);
	dec_debug_counter(&nr_of_merge_mfe_in_queue);
	inc_debug_counter(&nr_of_inflight_merge_mfe);

	__miniflow_merge(miniflow);

	dec_debug_counter(&nr_of_inflight_mfe);
	dec_debug_counter(&nr_of_inflight_merge_mfe);
}

static int miniflow_merge(struct mlx5e_miniflow *miniflow)
{
	atomic_inc(&nr_of_mfe_in_queue);

	inc_debug_counter(&miniflow_wq_size);
	inc_debug_counter(&nr_of_merge_mfe_in_queue);
	inc_debug_counter(&nr_of_total_mf_work_requests);
	inc_debug_counter(&nr_of_total_merge_mf_work_requests);

	miniflow->version = atomic64_inc_return(&global_version);
	INIT_WORK(&miniflow->work, miniflow_merge_work);
	if (queue_work(miniflow_wq, &miniflow->work))
		return 0;

	return -1;
}

static struct mlx5e_ct_tuple *miniflow_ct_tuple_alloc(struct mlx5e_miniflow *miniflow)
{
	if (miniflow->nr_ct_tuples < MINIFLOW_MAX_CT_TUPLES)
		return &miniflow->ct_tuples[miniflow->nr_ct_tuples++];

	etrace("Failed to allocate ct_tuple, we reached the maximum (%d)", MINIFLOW_MAX_CT_TUPLES);
	return NULL;
}

/* TODO: bug: ct_flow is not stored in tc_ht, memory leak on cleanup if any is still offloaded */
/* Future patch should have a list of ct_flow to free on cleanup */
int mlx5e_configure_ct(struct mlx5e_priv *priv,
		       struct tc_ct_offload *cto)
{
	struct mlx5e_miniflow *miniflow;
	struct mlx5e_ct_tuple *ct_tuple;
	unsigned long cookie;

	cookie = (unsigned long) cto->tuple;

	trace("mlx5e_configure_ct: miniflow_read(): %px", miniflow_read());

	miniflow = miniflow_read();
	if (!miniflow)
		return -1;

	if (miniflow->nr_flows == -1)
		goto err;

	if (unlikely(miniflow->nr_flows == MINIFLOW_MAX_FLOWS))
		goto err;

	if (!cookie)
		goto err;

	ct_tuple = miniflow_ct_tuple_alloc(miniflow);
	if (!ct_tuple)
		goto err;

	ct_tuple->net = cto->net;
	ct_tuple->zone = *cto->zone;
	ct_tuple->tuple = *cto->tuple;

	ct_tuple->flow = NULL;

	miniflow_path_append_cookie(miniflow, cookie, MFC_CT_FLOW);
	return 0;

err:
	miniflow_abort(miniflow);
	return -1;
}

int miniflow_extract_tuple(struct mlx5e_miniflow *miniflow,
			    struct sk_buff *skb)
{
	struct nf_conntrack_tuple *nf_tuple = &miniflow->tuple;
	struct iphdr *iph, _iph;
	__be16 *ports, _ports[2];
	int ihl;

	if (skb->protocol != htons(ETH_P_IP) &&
	    skb->protocol != htons(ETH_P_IPV6))
		goto err;

	if (skb->protocol == htons(ETH_P_IPV6)) {
		ntrace("IPv6 is not supported yet");
		goto err;
	}

	iph = skb_header_pointer(skb, skb_network_offset(skb), sizeof(_iph), &_iph);
	if (iph == NULL)
		goto err;

	ihl = ip_hdrlen(skb);
	if (ihl > sizeof(struct iphdr)) {
		/* TODO: is that right? */
		ntrace("Offload with IPv4 options is not supported yet");
		goto err;
	}

	if (iph->frag_off & htons(IP_MF | IP_OFFSET)) {
		ntrace("IP fragments are not supported");
		goto err;
	}

	nf_tuple->src.l3num = skb->protocol;
	nf_tuple->dst.protonum = iph->protocol;
	nf_tuple->src.u3.ip = iph->saddr;
	nf_tuple->dst.u3.ip = iph->daddr;

	ports = skb_header_pointer(skb, skb_network_offset(skb) + ihl,
				   sizeof(_ports), _ports);
	if (ports == NULL)
		goto err;

	switch (nf_tuple->dst.protonum) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
		nf_tuple->src.u.all = ports[0];
		nf_tuple->dst.u.all = ports[1];
	break;
	case IPPROTO_ICMP:
		ntrace("ICMP is not yet supported");
		goto err;
	default:
		ntrace("Only UDP, TCP and ICMP is supported");
		goto err;
	}

	trace("tuple %px: %u %pI4:%hu -> %pI4:%hu\n",
	       nf_tuple, nf_tuple->dst.protonum,
	       &nf_tuple->src.u3.ip, ntohs(nf_tuple->src.u.all),
	       &nf_tuple->dst.u3.ip, ntohs(nf_tuple->dst.u.all));

	return 0;

err:
	return -1;
}

int microflow_merge_rand_check(void)
{
	unsigned int rand;

	unsigned int probability = atomic_read((atomic_t *)&merger_probability);
	if (probability == 0)
		return 0;

	get_random_bytes(&rand, sizeof(unsigned int));

	if (rand < UINT_MAX/probability)
	{
		return 0;
	}
	return -1;
}

int mlx5e_configure_miniflow(struct mlx5e_priv *priv,
			     struct tc_miniflow_offload *mf)
{
	struct rhashtable *mf_ht = get_mf_ht(priv);
	struct mlx5e_miniflow *miniflow;
	struct sk_buff *skb = mf->skb;
	int err;

	trace("mlx5e_configure_miniflow: mf->last: %d, miniflow_read(): %px", mf->last_flow, miniflow_read());

	miniflow = miniflow_read();
	if (!miniflow) {
		miniflow = miniflow_alloc();
		if (!miniflow)
			return -1;
		miniflow_write(miniflow);
	}

	if (mf->chain_index == 0)
		miniflow_init(miniflow, priv);

	if (miniflow->nr_flows == -1)
		goto err;

	/**
	 * In some conditions merged rule could have another action with drop.
	 * i.e. header rewrite + drop.
	 * Such rule doesn't make sense and also not supported.
	 * For simplicty we will not offload drop rules that are merged rules.
	 */
	if (mf->is_drop)
		goto err;

	/* "Simple" rules should be handled by the normal routines */
	if (miniflow->nr_flows == 0 && mf->last_flow)
		goto err;

	if (unlikely(miniflow->nr_flows == MINIFLOW_MAX_FLOWS))
		goto err;

	if (!mf->cookie)
		goto err;

	if (miniflow->nr_flows == 0) {
		err = miniflow_extract_tuple(miniflow, skb);
		if (err)
			goto err;
	}

	miniflow_path_append_cookie(miniflow, mf->cookie, 0);

	trace("last_flow: %d", mf->last_flow);
	if (!mf->last_flow)
		return 0;

	err = microflow_merge_rand_check();
	if (err) {
		trace("low propability: no need to merge");
		goto err;
	}

	if (atomic_read(&miniflow_wq_size) > MINIFLOW_WORKQUEUE_MAX_SIZE)
		goto err;

	/* If rules in HW + rules in queue exceed the max value, then igore new one.
	 * Note the rules in queue could be the to_be_deleted rules. */
	if ((atomic_read(&currently_in_hw) + atomic_read(&nr_of_mfe_in_queue))> atomic_read((atomic_t *)&max_nr_mf))
		goto err;

	err = rhashtable_lookup_insert_fast(mf_ht, &miniflow->node, mf_ht_params);
	if (err) {
		trace("rhashtable_lookup_insert_fast: error: %d (prevent duplicated miniflows)", err);
		goto err;
	}

	err = miniflow_merge(miniflow);
	if (err)
		goto err_work;

	miniflow_write(NULL);

	return 0;

err_work:
	rhashtable_remove_fast(mf_ht, &miniflow->node, mf_ht_params);
err:
	miniflow_abort(miniflow);
	return -1;
}

#define DIRECTION_MASK (MLX5E_TC_INGRESS | MLX5E_TC_EGRESS)
#define FLOW_DIRECTION_MASK (MLX5E_TC_FLOW_INGRESS | MLX5E_TC_FLOW_EGRESS)

static bool same_flow_direction(struct mlx5e_tc_flow *flow, int flags)
{
	if ((atomic_read(&flow->flags) & FLOW_DIRECTION_MASK) ==
	    (flags & DIRECTION_MASK))
		return true;

	return false;
}

static void mlx5e_flow_defered_put(struct rcu_head *head)
{
	struct mlx5e_tc_flow *flow = container_of(head, struct mlx5e_tc_flow, rcu);

	mlx5e_flow_put(flow->priv, flow);
}

int mlx5e_delete_flower(struct mlx5e_priv *priv,
			struct tc_cls_flower_offload *f, int flags)
{
	struct rhashtable *tc_ht = get_tc_ht(priv);
	struct mlx5e_tc_flow *flow;

	flow = rhashtable_lookup_fast(tc_ht, &f->cookie, tc_ht_params);
	if (!flow || !same_flow_direction(flow, flags))
		return -EINVAL;

	rhashtable_remove_fast(tc_ht, &flow->node, tc_ht_params);

	/* Protect __miniflow_merge() */
	if (!mlx5e_is_simple_flow(flow)) {
		//synchronize_rcu();
		call_rcu(&flow->rcu, mlx5e_flow_defered_put);
	} else {
		mlx5e_flow_put(priv, flow);
	}

	return 0;
}

int mlx5e_stats_flower(struct mlx5e_priv *priv,
		       struct tc_cls_flower_offload *f, int flags)
{
	struct rhashtable *tc_ht = get_tc_ht(priv);
	struct mlx5e_tc_flow *flow;
	struct mlx5_fc *counter;
	u64 bytes;
	u64 packets;
	u64 lastuse;
	int err = 0;

	flow = mlx5e_flow_get(rhashtable_lookup_fast(tc_ht, &f->cookie,
						     tc_ht_params));
	if (IS_ERR(flow)) {
		return PTR_ERR(flow);
	} else if (!(atomic_read(&flow->flags) & MLX5E_TC_FLOW_INIT_DONE) ||
		   !same_flow_direction(flow, flags)) {
		err = -EINVAL;
		goto errout;
	}

	spin_lock(&flow->rule_lock);
	if (mlx5e_is_offloaded_flow(flow))
		counter = mlx5e_tc_get_counter(flow);
	else
		counter = flow->dummy_counter;

	if (!counter)
		goto errout_locked;

	mlx5_fc_query_cached(counter, &bytes, &packets, &lastuse);

	tcf_exts_stats_update(f->exts, bytes, packets, lastuse);
errout_locked:
	spin_unlock(&flow->rule_lock);
errout:
	mlx5e_flow_put(priv, flow);
	return err;
}

int mlx5e_tc_nic_init(struct mlx5e_priv *priv)
{
	struct mlx5e_tc_table *tc = &priv->fs.tc;

	mutex_init(&tc->t_lock);
	spin_lock_init(&tc->mod_hdr_tbl_lock);
	hash_init(tc->mod_hdr_tbl);
	spin_lock_init(&tc->hairpin_tbl_lock);
	hash_init(tc->hairpin_tbl);

	return rhashtable_init(&tc->ht, &tc_ht_params);
}

static void _mlx5e_tc_del_flow(void *ptr, void *arg)
{
	struct mlx5e_tc_flow *flow = ptr;
	struct mlx5e_priv *priv = flow->priv;

	mlx5e_tc_del_flow(priv, flow);
	flow_cache_free(flow);
}

void mlx5e_tc_nic_cleanup(struct mlx5e_priv *priv)
{
	struct mlx5e_tc_table *tc = &priv->fs.tc;

	rhashtable_free_and_destroy(&tc->ht, _mlx5e_tc_del_flow, NULL);

	if (!IS_ERR_OR_NULL(tc->t)) {
		mlx5_destroy_flow_table(tc->t);
		tc->t = NULL;
	}
	mutex_destroy(&tc->t_lock);
}

/* call user to append new dependency */
int ct_flow_offload_add(void *arg, struct list_head *head)
{
	struct mlx5e_tc_flow *flow = arg;

	list_add(&flow->nft_node, head);
	return 0;
}

/* call user to retrieve stats of this connection, statistics data is
   written into nf_gen_flow_ct_stat */
void ct_flow_offload_get_stats(struct nf_gen_flow_ct_stat *ct_stat, struct list_head *head)
{
	struct mlx5e_tc_flow *flow;
	u64 bytes, packets, lastuse;

	trace("ct_flow_offload_get_stats");

	list_for_each_entry(flow, head, nft_node) {
		struct mlx5_fc *counter = flow->dummy_counter;

		mlx5_fc_query_cached(counter, &bytes, &packets, &lastuse);
		ct_stat->bytes += bytes;
		ct_stat->packets += packets;
		ct_stat->last_used = max(ct_stat->last_used, lastuse);
	}

	trace("bytes: %llu, packets: %llu, lastuse: %llu", ct_stat->bytes, ct_stat->packets, ct_stat->last_used);
}

void ct_flow_offload_del_flow(struct mlx5e_tc_flow *flow)
{
	mlx5e_tc_del_fdb_flow(flow->priv, flow);
	flow_cache_free(flow);
}

/* notify user that this connection is dying */
int ct_flow_offload_destroy(struct list_head *head)
{
	struct mlx5e_tc_flow *flow, *n;

	trace("ct_flow_offload_destroy");

	list_for_each_entry_safe(flow, n, head, nft_node) {
		list_del(&flow->nft_node);
		ct_flow_offload_del_flow(flow);
	}

	return 0;
}

struct flow_offload_dep_ops ct_offload_ops = {
	.add = ct_flow_offload_add,
	.get_stats = ct_flow_offload_get_stats,
	.destroy = ct_flow_offload_destroy
};

int mlx5e_tc_esw_init(struct mlx5e_priv *priv)
{
	struct rhashtable *tc_ht = get_tc_ht(priv);
	struct rhashtable *mf_ht = get_mf_ht(priv);
	int err;

	if (miniflow_cache_allocated)
		return -EOPNOTSUPP;

	miniflow_cache = kmem_cache_create("mlx5_miniflow_cache",
					   sizeof(struct mlx5e_miniflow),
					   0, SLAB_HWCACHE_ALIGN, NULL);
	if (!miniflow_cache)
		return -ENOMEM;

	miniflow_cache_allocated = 1;

	err = rhashtable_init(tc_ht, &tc_ht_params);
	if (err)
		goto err_tc_ht;

	err = rhashtable_init(mf_ht, &mf_ht_params);
	if (err)
		goto err_mf_ht;

	miniflow_wq = alloc_workqueue("miniflow", WQ_MEM_RECLAIM | WQ_UNBOUND |
						  WQ_HIGHPRI | WQ_SYSFS, 16);
	if (!miniflow_wq)
		goto err_wq;

	nft_gen_flow_offload_dep_ops_register(&ct_offload_ops);

	return 0;

err_wq:
	rhashtable_free_and_destroy(mf_ht, NULL, NULL);
err_mf_ht:
	rhashtable_free_and_destroy(tc_ht, NULL, NULL);
err_tc_ht:
	kmem_cache_destroy(miniflow_cache);
	miniflow_cache_allocated = 0;
	return err;
}

void mlx5e_tc_esw_cleanup(struct mlx5e_priv *priv)
{
	struct rhashtable *tc_ht = get_tc_ht(priv);
	struct rhashtable *mf_ht = get_mf_ht(priv);
	int cpu;

	nft_gen_flow_offload_dep_ops_unregister(&ct_offload_ops);
	/* TODO: it does not make sense to process the remaining miniflows? */
	flush_workqueue(miniflow_wq);
	destroy_workqueue(miniflow_wq);

	rhashtable_free_and_destroy(tc_ht, _mlx5e_tc_del_flow, NULL);
	rhashtable_free_and_destroy(mf_ht, NULL, NULL);

	/* TODO: use the workqueue to speed it up? */
	mlx5e_fc_list_cleanup(priv->mdev, &fc_list);

	for_each_possible_cpu(cpu) {
		miniflow_free(per_cpu(current_miniflow, cpu));
		per_cpu(current_miniflow, cpu) = NULL;
	}
	kmem_cache_destroy(miniflow_cache);
	miniflow_cache_allocated = 0;
}

int mlx5e_tc_num_filters(struct mlx5e_priv *priv)
{
	struct rhashtable *tc_ht = get_tc_ht(priv);

	return atomic_read(&tc_ht->nelems);
}

int mlx5e_tc_init(void)
{
	atomic64_set(&global_version, 0);
	nic_flow_cache = kmem_cache_create("mlx5_nic_flow_cache",
					   sizeof(struct mlx5e_tc_flow) +
					   sizeof(struct mlx5_nic_flow_attr),
					   0, SLAB_HWCACHE_ALIGN, NULL);
	if (!nic_flow_cache)
		goto err;

	fdb_flow_cache = kmem_cache_create("mlx5_fdb_flow_cache",
					   sizeof(struct mlx5e_tc_flow) +
					   sizeof(struct mlx5_esw_flow_attr),
					   0, SLAB_HWCACHE_ALIGN, NULL);
	if (!fdb_flow_cache)
		goto err_free_nic;

	parse_attr_cache = kmem_cache_create("mlx5_parse_attr_cache",
					     sizeof(struct mlx5e_tc_flow_parse_attr),
					     0, SLAB_HWCACHE_ALIGN, NULL);
	if (!parse_attr_cache)
		goto err_free_fdb;

	return 0;

err_free_fdb:
	kmem_cache_destroy(fdb_flow_cache);
err_free_nic:
	kmem_cache_destroy(nic_flow_cache);
err:
	return -ENOMEM;
}

void mlx5e_tc_cleanup(void)
{
	kmem_cache_destroy(parse_attr_cache);
	kmem_cache_destroy(fdb_flow_cache);
	kmem_cache_destroy(nic_flow_cache);
}

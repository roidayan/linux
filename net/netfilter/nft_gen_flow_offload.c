/*
 * net/netfilter/nft_gen_flow_offload.c  Maintain flows(conntrack connections) offloaded to HW by TC
 *
 * Copyright (c) 2018 Lidong Jiang <jianglidong3@jd.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/rhashtable.h>
#include <net/ip.h> /* for ipv4 options. */

#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <net/netfilter/nf_conntrack_core.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <net/netfilter/nft_gen_flow_offload.h>


static struct nf_gen_flow_offload_table __rcu *_flowtable;

static atomic_t offloaded_flow_cnt;

static unsigned int offloaded_ct_timeout = 30*HZ;
module_param(offloaded_ct_timeout, uint, 0644);

static unsigned int gc_max_cont_time = HZ;
module_param(gc_max_cont_time, uint, 0644);

static unsigned int aging_bucket_num = 32;
module_param(aging_bucket_num, uint, 0644);

static unsigned int flush_stats = 0;
module_param(flush_stats, uint, 0200);


#define MAX_FLOWS_PER_GC_RUN          10000
#define MAX_GC_RUNS_INTERVAL          (HZ / 1)
#define MIN_GC_RUNS_INTERVAL          (HZ / 10)

#define PORTING_FLOW_TABLE

#ifdef PORTING_FLOW_TABLE

struct flow_table_stat {
    struct spinlock lock;
    u32 added;
    u32 add_failed;
    u32 add_racing;
    u32 aged;
};

struct flow_aging_bucket {
    u64                 start;
    u32                 enqueued;
    u32                 proced;
    struct list_head    head;    
};

struct stats_summary {
    u32   max;
    u32   min;
    u32   avg;    
};

static inline void update_stats_summary(struct stats_summary * summary, 
                                                 u32 data, u32 count)
{
    summary->min = min(summary->min, data);
    summary->max = max(summary->max, data);
    summary->avg = ((summary->avg * count) + data) / (count + 1);
}

static inline void show_stats_summary(struct seq_file *m, 
                                            const char *prefix, 
                                            struct stats_summary * summary)
{
    if (summary->min == (u32)-1)
        seq_printf(m, "%s(avg:%u, max:%u, min: INV)\n", prefix, 
                     summary->avg, summary->max);
    else
        seq_printf(m, "%s(avg:%u, max:%u, min: %u)\n", prefix, 
                     summary->avg, summary->max, summary->min);        
}

static inline void clear_stats_summary(struct stats_summary * summary)
{
    summary->min = (u32)-1;
    summary->max = 0;
    summary->avg = 0;
}


struct flow_gc_work {
    struct spinlock          lock; 
    int                      curt_bucket;
    u32                      expiration;
    u32                      bucket_num;
    u32                      bkt_interval;
    u64                      abs_next_run;
    
    u32                      run_times; 
    struct stats_summary     delta;
    struct stats_summary     total;
    struct stats_summary     stat_op;
    struct stats_summary     destroy_op;

    struct stats_summary     flows_per_run;

    u32                      teardown_proced;
    struct list_head         teardowns;
    struct list_head         temp;
    
    struct flow_aging_bucket *buckets;
    struct delayed_work      work;    
};

struct nf_gen_flow_offload_table {
    
    struct rhashtable        rhashtable;
    struct flow_gc_work      gc_work;
    struct workqueue_struct *flow_wq;

    struct flow_table_stat   stats; 
};

enum nf_gen_flow_offload_tuple_dir {
    FLOW_OFFLOAD_DIR_ORIGINAL = IP_CT_DIR_ORIGINAL,
    FLOW_OFFLOAD_DIR_REPLY    = IP_CT_DIR_REPLY,
    FLOW_OFFLOAD_DIR_MAX      = IP_CT_DIR_MAX
};


struct nf_gen_flow_offload_tuple_rhash {
    struct rhash_head           node;
    struct nf_conntrack_tuple   tuple;
    struct nf_conntrack_zone    zone; 
};



#define FLOW_OFFLOAD_DYING      0x1
#define FLOW_OFFLOAD_TEARDOWN   0x2
#define FLOW_OFFLOAD_AGING      0x4
#define FLOW_OFFLOAD_EXPIRED    0x8

struct nf_gen_flow_offload {
    struct nf_gen_flow_offload_tuple_rhash        tuplehash[FLOW_OFFLOAD_DIR_MAX];
    u32              flags;
    u64              timeout;
    struct list_head bkt_node;
};


struct nf_gen_flow_offload_entry {
    struct nf_gen_flow_offload  flow;
    struct nf_conn              *ct;
    struct rcu_head             rcu_head;
    struct spinlock             dep_lock; // FIXME, narrow down spin_lock, don't call user callback with locked.
    struct list_head            deps;
    struct nf_gen_flow_ct_stat  stats;
};

static inline void tstat_added_inc(struct nf_gen_flow_offload_table *tbl)
{
    spin_lock(&tbl->stats.lock);
    tbl->stats.added++;
    spin_unlock(&tbl->stats.lock);
}

static inline u32 tstat_added_get(struct nf_gen_flow_offload_table *tbl)
{
    return tbl->stats.added;
}

static inline void tstat_add_failed_inc(struct nf_gen_flow_offload_table *tbl)
{
    spin_lock(&tbl->stats.lock);
    tbl->stats.add_failed++;
    spin_unlock(&tbl->stats.lock);
}

static inline u32 tstat_add_failed_get(struct nf_gen_flow_offload_table *tbl)
{
    return tbl->stats.add_failed;
}

static inline void tstat_add_racing_inc(struct nf_gen_flow_offload_table *tbl)
{
    spin_lock(&tbl->stats.lock);
    tbl->stats.add_racing++;
    spin_unlock(&tbl->stats.lock);
}

static inline u32 tstat_add_racing_get(struct nf_gen_flow_offload_table *tbl)
{
    return tbl->stats.add_racing;
}

static inline void tstat_aged_inc(struct nf_gen_flow_offload_table *tbl)
{
    spin_lock(&tbl->stats.lock);
    tbl->stats.aged++;
    spin_unlock(&tbl->stats.lock);
}

static inline u32 tstat_aged_get(struct nf_gen_flow_offload_table *tbl)
{
    return tbl->stats.aged;
}

static inline void tstat_clear_all(struct nf_gen_flow_offload_table *tbl)
{
    spin_lock(&tbl->stats.lock);
    tbl->stats.added = 0;
    tbl->stats.add_failed = 0;
    tbl->stats.add_racing = 0;
    tbl->stats.aged = 0;
    spin_unlock(&tbl->stats.lock);
}


static inline void tstat_init(struct nf_gen_flow_offload_table *tbl)
{
    spin_lock_init(&tbl->stats.lock);    
}


static int nft_gen_flow_offload_stats(struct nf_gen_flow_offload *flow);
static int nft_gen_flow_offload_destroy_dep(struct nf_gen_flow_offload *flow);


static void
nf_gen_flow_offload_fill_dir(struct nf_gen_flow_offload *flow,
                                        struct nf_conn *ct,
                                        int zone_id,
                                        enum nf_gen_flow_offload_tuple_dir dir)
{
    flow->tuplehash[dir].tuple = ct->tuplehash[dir].tuple;
    flow->tuplehash[dir].tuple.dst.dir = dir;

    flow->tuplehash[dir].zone.id = zone_id;
}


static struct nf_gen_flow_offload *
nf_gen_flow_offload_alloc(struct nf_conn *ct, int zone_id)
{
    struct nf_gen_flow_offload_entry *entry;
    struct nf_gen_flow_offload *flow;

    if (unlikely(nf_ct_is_dying(ct) ||
        !atomic_inc_not_zero(&ct->ct_general.use)))
        return ERR_PTR(-EINVAL);

    entry = kzalloc((sizeof(*entry)), GFP_ATOMIC);
    if (!entry)
        goto err_ct_refcnt;

    flow = &entry->flow;
    INIT_LIST_HEAD(&flow->bkt_node);

    entry->ct = ct;

    nf_gen_flow_offload_fill_dir(flow, ct, zone_id, FLOW_OFFLOAD_DIR_ORIGINAL);
    nf_gen_flow_offload_fill_dir(flow, ct, zone_id, FLOW_OFFLOAD_DIR_REPLY);

    INIT_LIST_HEAD(&entry->deps);
    spin_lock_init(&entry->dep_lock);

    return flow;

err_ct_refcnt:
    nf_ct_put(ct);

    return ERR_PTR(-ENOMEM);
}

static void nf_gen_flow_offload_fixup_ct_state(struct nf_conn *ct)
{
    const struct nf_conntrack_l4proto *l4proto;
    struct net *net = nf_ct_net(ct);
    unsigned int *timeouts;
    unsigned int timeout;
    int l4num;

    rcu_read_lock();
	
    l4num = nf_ct_protonum(ct);
    l4proto = __nf_ct_l4proto_find(nf_ct_l3num(ct), l4num);
    if (!l4proto)
        goto __fixup_exit;

    timeouts = l4proto->get_timeouts(net);
    if (!timeouts)
        goto __fixup_exit;

    /* FIXME, This is not safe way, since tcp state may be changed during this update */
    if (l4num == IPPROTO_TCP) {
        timeout = timeouts[ct->proto.tcp.state];
    }
    else if (l4num == IPPROTO_UDP)
        timeout = timeouts[UDP_CT_REPLIED];
    else
        goto __fixup_exit;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,0,0)
    {
        unsigned long newtime = jiffies + timeout;

        /* Only update the timeout if the new timeout is at least
           HZ jiffies from the old timeout. Need del_timer for race
           avoidance (may already be dying). */
        if (newtime - ct->timeout.expires >= HZ)
            mod_timer_pending(&ct->timeout, newtime);
    }
#else
    ct->timeout = (u32)jiffies + timeout;
#endif
__fixup_exit:
    rcu_read_unlock();	
}

void nf_gen_flow_offload_free(struct nf_gen_flow_offload *flow)
{
    struct nf_gen_flow_offload_entry *e;

    e = container_of(flow, struct nf_gen_flow_offload_entry, flow);
    if (flow->flags & FLOW_OFFLOAD_DYING)
        nf_ct_delete(e->ct, 0, 0);
    /* pair to ct_get in flow_offload_alloc */
    nf_ct_put(e->ct);
    kfree_rcu(e, rcu_head);
}

static u32 _flow_offload_hash(const void *data, u32 len, u32 seed)
{
    const struct nf_conntrack_tuple *tuple = data;
    unsigned int n;

    n = (sizeof(tuple->src) + sizeof(tuple->dst.u3)) / sizeof(u32);

    /* reuse nf_conntrack hash method */
    return jhash2((u32 *)tuple, n, seed ^
              (((__force __u16)tuple->dst.u.all << 16) |
              tuple->dst.protonum));
}

static u32 _flow_offload_hash_obj(const void *data, u32 len, u32 seed)
{
    const struct nf_gen_flow_offload_tuple_rhash *tuplehash = data;
    unsigned int n;

    n = (sizeof(tuplehash->tuple.src) + sizeof(tuplehash->tuple.dst.u3)) / sizeof(u32);

    return jhash2((u32 *)&tuplehash->tuple, n, seed ^
              (((__force __u16)tuplehash->tuple.dst.u.all << 16) |
              tuplehash->tuple.dst.protonum));
}

static int _flow_offload_hash_cmp(struct rhashtable_compare_arg *arg,
                    const void *ptr)
{
    const struct nf_gen_flow_offload_tuple_rhash *x = ptr;
    struct nf_gen_flow_offload_tuple_rhash *thash;

    thash = container_of(arg->key, struct nf_gen_flow_offload_tuple_rhash, tuple);

    if (memcmp(&x->tuple, &thash->tuple, offsetof(struct nf_conntrack_tuple, dst.dir)) ||
        (x->zone.id != thash->zone.id))
        return 1;

    return 0;
}

static const struct rhashtable_params nf_gen_flow_offload_rhash_params = {
    .head_offset            = offsetof(struct nf_gen_flow_offload_tuple_rhash, node),
    .hashfn                 = _flow_offload_hash,
    .obj_hashfn             = _flow_offload_hash_obj,
    .obj_cmpfn              = _flow_offload_hash_cmp,
    .automatic_shrinking    = true,
};

static int nf_gen_flow_offload_add(struct nf_gen_flow_offload_table *flow_table,
                                                struct nf_gen_flow_offload *flow)
{
    int ret;
    ret = rhashtable_insert_fast(&flow_table->rhashtable,
                   &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].node,
                   nf_gen_flow_offload_rhash_params);
    if (ret)
        return ret;
        
    ret = rhashtable_insert_fast(&flow_table->rhashtable,
               &flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].node,
               nf_gen_flow_offload_rhash_params);
    if (ret)
        rhashtable_remove_fast(&flow_table->rhashtable,
                       &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].node,
                       nf_gen_flow_offload_rhash_params);        

    return ret;
}

static void nf_gen_flow_offload_del(struct nf_gen_flow_offload_table *flow_table,
                 struct nf_gen_flow_offload *flow)
{
    struct nf_gen_flow_offload_entry *e;
    u32 ts;
    
    pr_debug("flow %p deleting", flow);

    rhashtable_remove_fast(&flow_table->rhashtable,
                   &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].node,
                   nf_gen_flow_offload_rhash_params);
    rhashtable_remove_fast(&flow_table->rhashtable,
                   &flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].node,
                   nf_gen_flow_offload_rhash_params);

    e = container_of(flow, struct nf_gen_flow_offload_entry, flow);
    clear_bit(IPS_OFFLOAD_BIT, &e->ct->status);

    atomic_dec(&offloaded_flow_cnt);

    /* fix ct_state after OFFLOAD is cleared due to gc_worker may update
       timeout with OFFLOAD_BIT set */
    nf_gen_flow_offload_fixup_ct_state(e->ct);

    ts = jiffies;
    nft_gen_flow_offload_destroy_dep(flow);
    update_stats_summary(&flow_table->gc_work.destroy_op,
                        (u32)(jiffies-ts), flow_table->gc_work.run_times);
}


static struct nf_gen_flow_offload_tuple_rhash *
nf_gen_flow_offload_lookup(struct nf_gen_flow_offload_table *flow_table,
                                        const struct nf_conntrack_zone *zone,
                                        const struct nf_conntrack_tuple *tuple)
{
    struct nf_gen_flow_offload_tuple_rhash key, *res;
    struct nf_gen_flow_offload *flow;
    int dir;

    key.tuple = *tuple;
    key.zone  = *zone;

    res = rhashtable_lookup_fast(&flow_table->rhashtable, &key.tuple,
                       nf_gen_flow_offload_rhash_params);
    if (!res)
        return NULL;

    dir = res->tuple.dst.dir;
    flow = container_of(res, struct nf_gen_flow_offload, tuplehash[dir]);
    if (flow->flags & (FLOW_OFFLOAD_DYING | FLOW_OFFLOAD_TEARDOWN))
        return NULL;

    return res;
}

int nf_gen_flow_offload_table_iterate(struct nf_gen_flow_offload_table *flow_table,
              void (*iter)(struct nf_gen_flow_offload *flow, void *data),
              void *data)
{
    struct nf_gen_flow_offload_tuple_rhash *tuplehash;
    struct rhashtable_iter hti;
    struct nf_gen_flow_offload *flow;
    int err;

    err = rhashtable_walk_init(&flow_table->rhashtable, &hti, GFP_KERNEL);
    if (err)
        return err;

    rhashtable_walk_start(&hti);

    while ((tuplehash = rhashtable_walk_next(&hti))) {
        if (IS_ERR(tuplehash)) {
            err = PTR_ERR(tuplehash);
            if (err != -EAGAIN)
                goto out;

            continue;
        }
        if (tuplehash->tuple.dst.dir)
            continue;

        flow = container_of(tuplehash, struct nf_gen_flow_offload, tuplehash[0]);

        iter(flow, data);
    }
out:
    rhashtable_walk_stop(&hti);
    rhashtable_walk_exit(&hti);

    return err;
}

static inline bool 
nf_gen_flow_offload_has_expired(const struct nf_gen_flow_offload *flow)
{
    return (flow->timeout <= jiffies);
}

static inline struct flow_aging_bucket *_current_bucket(struct flow_gc_work *gc_work)
{
    return &gc_work->buckets[gc_work->curt_bucket];
}

static inline void _put_into_bucket(struct flow_gc_work *gc_work, int bucket_id,
                                            struct list_head *node, bool in_aging)
{
    if (!in_aging || (bucket_id != gc_work->curt_bucket))
        list_add_tail(node, &gc_work->buckets[bucket_id].head);
    else
        list_add_tail(node, &gc_work->temp);
        
    gc_work->buckets[bucket_id].enqueued++;
}

static inline struct nf_gen_flow_offload *
_get_one_from_teardowns(struct flow_gc_work *gc_work)
{
    struct nf_gen_flow_offload * flow = NULL;
    
    spin_lock(&gc_work->lock);

    if (!list_empty_careful(&gc_work->teardowns)) {
        flow = list_first_entry(&gc_work->teardowns, struct nf_gen_flow_offload, bkt_node); 
        list_del(&flow->bkt_node);

        gc_work->teardown_proced++;
    }

//    pr_debug("get %p from teardown", flow);
    spin_unlock(&gc_work->lock);

    return flow;
}

static inline struct nf_gen_flow_offload *
_get_one_from_bucket(struct flow_gc_work *gc_work)
{
    struct nf_gen_flow_offload * flow = NULL;
    struct flow_aging_bucket * curt_bucket = _current_bucket(gc_work);

    pr_debug("get bucket %d start %llu now %lu", gc_work->curt_bucket, 
                                         curt_bucket->start, jiffies);

    if (jiffies < curt_bucket->start)
        return ERR_PTR(-EAGAIN);
    
    spin_lock(&gc_work->lock);

    if (!list_empty_careful(&curt_bucket->head)) {

        flow = list_first_entry(&curt_bucket->head, struct nf_gen_flow_offload, bkt_node); 
        list_del(&flow->bkt_node);

        /* no need to check TEARDOWN flag, since this entry is in bucket still */
        flow->flags |= FLOW_OFFLOAD_AGING;

        curt_bucket->proced++;
    } else {

        /* check temp list of this run, if not empty, wait for next */
        if (!list_empty_careful(&gc_work->temp)) {
            list_splice_tail_init(&gc_work->temp, &gc_work->buckets[gc_work->curt_bucket].head);
            /* already get_stats in this run, wait a mini interval */
            flow = ERR_PTR(-EAGAIN);
        }
    }

//    pr_debug("get %p from bucket %d", flow, gc_work->curt_bucket);
    
    spin_unlock(&gc_work->lock);

    return flow;
}

static inline void _move_to_next_bucket(struct flow_gc_work *gc_work)
{
    spin_lock(&gc_work->lock);

    gc_work->buckets[gc_work->curt_bucket].start += gc_work->bkt_interval * \
                                                    gc_work->bucket_num;
    /* TODO: do some check on current bucket  */

    gc_work->curt_bucket = (gc_work->curt_bucket + 1) % gc_work->bucket_num;

    pr_debug("move to bucket %d, start %llu", gc_work->curt_bucket, 
                          gc_work->buckets[gc_work->curt_bucket].start);
    spin_unlock(&gc_work->lock);
}

static inline int _get_bucket_id_of_flow(struct flow_gc_work *gc_work, 
                                                 struct nf_gen_flow_offload *flow)
{
    int tgt_bucket;
    u64 curt_bucket_start = gc_work->buckets[gc_work->curt_bucket].start;

    /* this flow got stats and not expired,
       flow->timeout > jiffie > curt_bucket_start*/
    tgt_bucket = (flow->timeout - curt_bucket_start) 
                 / gc_work->bkt_interval;
    
    if (tgt_bucket >= gc_work->bucket_num) 
        tgt_bucket = gc_work->bucket_num - 1;

    /* this flow is going to expired, put it into next bucket
       to avoid frequently geting stats */
    if (tgt_bucket == 0)
        tgt_bucket = 1;

    /* randomize value in [0- 1/2 tgt_bucket], adjusted tgt in [1/2 tgt_bucket, tgt_bucket]
       avoid to set tgt_bucket as 0, so minimal tgt_bucket is 4*/
    if (tgt_bucket > 3) {
        u32 r;
        get_random_bytes(&r, sizeof(r));
        
        /* put randomization here */
        tgt_bucket = tgt_bucket - (r%(tgt_bucket/2));
    } 

    /* get real bucket index */ 
    tgt_bucket = (gc_work->curt_bucket + tgt_bucket) % gc_work->bucket_num;

    return tgt_bucket;
}

static void _reschedule_flow_aging(struct flow_gc_work *gc_work, 
                                             struct nf_gen_flow_offload *flow)
{
    int tgt_bucket;
    struct nf_gen_flow_offload_table *flowtable = \
            container_of(gc_work, struct nf_gen_flow_offload_table, gc_work);

    spin_lock(&gc_work->lock);

    flow->flags &= (~FLOW_OFFLOAD_AGING);

    if (nf_gen_flow_offload_has_expired(flow)) {
        pr_debug("flow %p aged out", flow);
        tstat_aged_inc(flowtable);
        flow->flags |= FLOW_OFFLOAD_TEARDOWN;
        list_add_tail(&flow->bkt_node, &gc_work->teardowns);
        
    } else {
        tgt_bucket = _get_bucket_id_of_flow(gc_work, flow);

        pr_debug("flow %p schedue to %d", flow, tgt_bucket);

        _put_into_bucket(&flowtable->gc_work, tgt_bucket, &flow->bkt_node, true);
    }

    spin_unlock(&gc_work->lock); 
}

static inline int _get_next_run(struct flow_gc_work *gc_work, int target_flows)
{
    struct flow_aging_bucket * curt_bucket = _current_bucket(gc_work);
    int next_run = MIN_GC_RUNS_INTERVAL;
    
    if (target_flows > 0)
    {
        /* no more to process in this run */
        
        if (curt_bucket->start > jiffies) {
            /* wait current bucket started */
            next_run = curt_bucket->start - jiffies;

            if (next_run < MIN_GC_RUNS_INTERVAL)
                next_run = MIN_GC_RUNS_INTERVAL;

            if (next_run > MAX_GC_RUNS_INTERVAL)
                next_run = MAX_GC_RUNS_INTERVAL;
        } else {
           /* some flows in current bucket, wait ??? */ 
        }
        
    } else {
        spin_lock(&gc_work->lock);        
        if (!list_empty_careful(&gc_work->temp)) {
            /* put temp back to curt bucket for next run */
            list_splice_tail_init(&gc_work->temp, &curt_bucket->head);
        }
        spin_unlock(&gc_work->lock);
    }

//    pr_debug("next_run %d", next_run);
    
    return next_run;
}

static inline void nf_gen_flow_offload_set_aging(struct nf_gen_flow_offload_table *flowtable, 
                                                 struct nf_gen_flow_offload *flow)
{
    int tgt_bucket;

    spin_lock(&flowtable->gc_work.lock);

    if (!(flow->flags & FLOW_OFFLOAD_TEARDOWN)) {
        /* not in teardown */
        flow->timeout = jiffies + flowtable->gc_work.expiration;

        if (!(flow->flags & FLOW_OFFLOAD_AGING)) {
            /* no in aging, otherwise, aging process can schedule this entry */
            tgt_bucket = _get_bucket_id_of_flow(&flowtable->gc_work, flow);
            if (!list_empty_careful(&flow->bkt_node))
                list_del(&flow->bkt_node);

            pr_debug("set_aging update bucket to %d", tgt_bucket);
            _put_into_bucket(&flowtable->gc_work, tgt_bucket, &flow->bkt_node, false);
        }
    }

    spin_unlock(&flowtable->gc_work.lock); 
}

static inline void nf_gen_flow_offload_teardown(struct nf_gen_flow_offload_table *flowtable, 
                                                 struct nf_gen_flow_offload *flow)
{
    if (flow->flags & FLOW_OFFLOAD_TEARDOWN)
        return;

    spin_lock(&flowtable->gc_work.lock);
    
    flow->flags |= FLOW_OFFLOAD_TEARDOWN;

    /* not in aging, put it into teardown */
    if (!(flow->flags & FLOW_OFFLOAD_AGING)) {
        list_del(&flow->bkt_node);
        list_add_tail(&flow->bkt_node, &flowtable->gc_work.teardowns);
    }
    
    spin_unlock(&flowtable->gc_work.lock); 
}

static inline void show_buckets(struct seq_file *m, struct flow_gc_work *gc_work)
{
    int i;

    seq_printf(m, "Free %u flows from teardown list\n", gc_work->teardown_proced);
    
    for (i=0; i<gc_work->bucket_num; i++) {
        seq_printf(m, "....bucket[%3d]: %8u enqueued %8u processed, start at %llu(jiffies)\n",  
                      i, gc_work->buckets[i].enqueued, gc_work->buckets[i].proced, 
                      gc_work->buckets[i].start);
    }
}


static inline void _gc_stats_update(struct flow_gc_work *gc_work, u64 raw[])
{
    u32 data = abs(raw[0] - gc_work->abs_next_run);

    if (gc_work->abs_next_run > 0) {
        update_stats_summary(&gc_work->delta, data, gc_work->run_times);
    }

    data = jiffies - raw[0];
    update_stats_summary(&gc_work->total, data, gc_work->run_times);

    data = raw[1];
    if (data != (u32)-1)
        update_stats_summary(&gc_work->stat_op, data, gc_work->run_times);

    data = raw[2];
    if (data != (u32)-1)
        update_stats_summary(&gc_work->flows_per_run, data, gc_work->run_times);
    
    gc_work->run_times++;
}

static int nf_gen_flow_offload_gc_step(struct flow_gc_work *gc_work, int target_flows)
{
    struct nf_gen_flow_offload_table *flowtable = container_of(gc_work, \
                                                  struct nf_gen_flow_offload_table, \
                                                  gc_work);   
    struct nf_gen_flow_offload *flow;
    int next_run, proced_flows;
    u64 stats_data[3], tstamp;

    if (flush_stats == 1) {
        tstat_clear_all(flowtable);
        clear_stats_summary(&gc_work->delta);
        clear_stats_summary(&gc_work->total);
        clear_stats_summary(&gc_work->stat_op);
        clear_stats_summary(&gc_work->destroy_op);
        clear_stats_summary(&gc_work->flows_per_run);
        flush_stats = 0;
    }

    /* 0 - total, 1 - stats, 2 - processed flow per run */
    tstamp        = jiffies;
    stats_data[0] = tstamp;
    stats_data[1] = (u32)-1;
    stats_data[2] = (u32)-1;

    proced_flows = 0;

//    pr_debug("gc_in exp %d bkt_num %d interval %d", gc_work->expiration, gc_work->bucket_num, gc_work->bkt_interval);    
    
    while (proced_flows < target_flows) {

        if (jiffies >= (tstamp + gc_max_cont_time)) {
            cond_resched();
            tstamp = jiffies;
        }
        /* process teardown list first */
        flow = _get_one_from_teardowns(gc_work);
        if (flow) {
            nf_gen_flow_offload_del(flowtable, flow);
           // proced_flows++;
            continue;
        }

        /* aging */
        flow = _get_one_from_bucket(gc_work);
        if (IS_ERR(flow))
            break;

        if (flow) {
            stats_data[1] = jiffies;
            nft_gen_flow_offload_stats(flow);
            stats_data[1] = jiffies - stats_data[1];

            _reschedule_flow_aging(gc_work, flow); 
            proced_flows++;
        } else {
            /* nothing in current bucket */
            _move_to_next_bucket(gc_work);
        }
    }

    next_run = _get_next_run(gc_work, target_flows);

    if(target_flows < INT_MAX)
        stats_data[2] = proced_flows;

    _gc_stats_update(gc_work, stats_data);

    gc_work->abs_next_run = jiffies + next_run;

    return next_run;
}

static void nf_gen_flow_offload_work_gc(struct work_struct *work)
{
    struct nf_gen_flow_offload_table *flow_table;
    int target_flows = MAX_FLOWS_PER_GC_RUN;
    int next_run;

    flow_table = container_of(work, struct nf_gen_flow_offload_table, gc_work.work.work);
    next_run = nf_gen_flow_offload_gc_step(&flow_table->gc_work, target_flows);
    queue_delayed_work(flow_table->flow_wq, &flow_table->gc_work.work, next_run);
}

static int nf_gen_flow_offload_init_buckets(struct flow_gc_work *gc_work, 
                                                        u32 expiration, u32 bucket_num)
{
    int i;
    struct flow_aging_bucket *curt_bucket, *bucket;
    
    /* init lock */
    spin_lock_init(&gc_work->lock);
    
    /* get buckets mem */
    gc_work->buckets = kzalloc((sizeof(gc_work->buckets[0])*bucket_num), GFP_KERNEL);
    if (gc_work->buckets == NULL)
        return -ENOMEM;
 
    /* init bucket, current bucket from 0 */
    /* bucket timestamp is added by offload_timeout/max_buckets */
    gc_work->curt_bucket  = 0;
    gc_work->expiration   = expiration;
    gc_work->bucket_num   = bucket_num;
    gc_work->bkt_interval = expiration / bucket_num;

    gc_work->delta.min      = (u32)-1; 
    gc_work->total.min      = (u32)-1;
    gc_work->stat_op.min    = (u32)-1;
    gc_work->destroy_op.min = (u32)-1;
    
    gc_work->flows_per_run.min = (u32)-1;

    INIT_LIST_HEAD(&gc_work->teardowns);
    INIT_LIST_HEAD(&gc_work->temp);

    curt_bucket = _current_bucket(gc_work);
    curt_bucket->start = jiffies;
    INIT_LIST_HEAD(&curt_bucket->head);
    
    for (i=1; i<bucket_num; i++) {
        bucket = gc_work->buckets + (gc_work->curt_bucket+i)%bucket_num;
        bucket->start = curt_bucket->start + i*gc_work->bkt_interval ;
        INIT_LIST_HEAD(&bucket->head);
    }    

    INIT_DELAYED_WORK(&gc_work->work, nf_gen_flow_offload_work_gc);

    return 0;
}

static void nf_gen_flow_offload_free_buckets(struct flow_gc_work *gc_work)
{
    cancel_delayed_work_sync(&gc_work->work);
    nf_gen_flow_offload_gc_step(gc_work, INT_MAX);
    kfree(gc_work->buckets);
}

int nf_gen_flow_offload_table_init(struct nf_gen_flow_offload_table *flowtable)
{
    int err = 0;

    err = nf_gen_flow_offload_init_buckets(&flowtable->gc_work, 
                                            offloaded_ct_timeout, 
                                            aging_bucket_num);
    if (err < 0)
        return err;

    flowtable->flow_wq = alloc_workqueue("flow_offload", 
                                        WQ_MEM_RECLAIM| WQ_UNBOUND | WQ_SYSFS,
                                        1);
    if (!flowtable->flow_wq)
        goto _flow_wq_alloc_err;

    err = rhashtable_init(&flowtable->rhashtable,
                  &nf_gen_flow_offload_rhash_params);
    if (err < 0)
        goto _table_init_err;

    tstat_init(flowtable);

    queue_delayed_work(flowtable->flow_wq, &flowtable->gc_work.work, HZ);

    return 0;

_table_init_err:    
	destroy_workqueue(flowtable->flow_wq);    
_flow_wq_alloc_err:
    nf_gen_flow_offload_free_buckets(&flowtable->gc_work);

    return err;
}

/*  TO be changed */
static void nf_gen_flow_offload_table_do_cleanup(struct nf_gen_flow_offload *flow, void *data)
{
    nf_gen_flow_offload_teardown((struct nf_gen_flow_offload_table *)data, flow);
}

void nf_gen_flow_offload_table_free(struct nf_gen_flow_offload_table *flowtable)
{
    nf_gen_flow_offload_table_iterate(flowtable, nf_gen_flow_offload_table_do_cleanup, flowtable);
    nf_gen_flow_offload_free_buckets(&flowtable->gc_work);
	destroy_workqueue(flowtable->flow_wq); 
    rhashtable_destroy(&flowtable->rhashtable);
}

#endif

static struct flow_offload_dep_ops __rcu *flow_dep_ops = NULL;

#define FLOW_OFFLOAD_DUMP(prefix_str, zone, tuple) \
    if (tuple->src.l3num == AF_INET) {\
        pr_debug(prefix_str": Tuple(%pI4, %pI4, %d, %d, %d) zone id %d\n",\
                &tuple->src.u3.in, &tuple->dst.u3.in,\
                ntohs(tuple->src.u.all), ntohs(tuple->dst.u.all),\
                tuple->dst.protonum, zone->id);\
    } else {\
        pr_debug(prefix_str": Tuple(%pI6, %pI6, %d, %d, %d) zone id %d\n",\
                &tuple->src.u3.in6, &tuple->dst.u3.in6,\
                ntohs(tuple->src.u.all), ntohs(tuple->dst.u.all),\
                tuple->dst.protonum, zone->id);\
    }


static inline void _flow_offload_debug_op(const struct nf_conntrack_zone *zone,
            const struct nf_conntrack_tuple * tuple, char * op)
{
    if (tuple->src.l3num == AF_INET) {
        pr_debug("%s Tuple(%pI4, %pI4, %d, %d, %d) zone id %d\n",
                op, &tuple->src.u3.in, &tuple->dst.u3.in,
                ntohs(tuple->src.u.all), ntohs(tuple->dst.u.all),
                tuple->dst.protonum, zone->id);
    } else {
        pr_debug("%s Tuple(%pI6, %pI6, %d, %d, %d) zone id %d\n",
                op, &tuple->src.u3.in6, &tuple->dst.u3.in6,
                ntohs(tuple->src.u.all), ntohs(tuple->dst.u.all),
                tuple->dst.protonum, zone->id);
    }
}

static int _flowtable_add_entry(const struct net *net, int zone_id,
            struct nf_conn *ct, struct nf_gen_flow_offload ** ret_flow)
{
    struct nf_gen_flow_offload_table *flowtable;
    struct nf_gen_flow_offload *flow;
    int ret = -ENOENT;

    flow = nf_gen_flow_offload_alloc(ct, zone_id);
    if (IS_ERR(flow)) {
        ret = PTR_ERR(flow);
        pr_debug("flow_alloc failed(%d)", ret);
        goto err_flow_alloc;
    }
    
    rcu_read_lock();
    flowtable = rcu_dereference(_flowtable);
    if (flowtable) {
        ret = nf_gen_flow_offload_add(flowtable, flow);
        if (ret < 0)
            goto err_flow_add;

        if (ret_flow)
            *ret_flow = flow;

        rcu_read_unlock();

        atomic_inc(&offloaded_flow_cnt);

        return ret;
    }

err_flow_add:
    pr_debug("flow_add failed(%d)", ret);
    rcu_read_unlock();
    nf_gen_flow_offload_free(flow);
err_flow_alloc:
    clear_bit(IPS_OFFLOAD_BIT, &ct->status);

    return ret;
}

static int _check_ct_status(struct nf_conn *ct)
{
    if (test_bit(IPS_HELPER_BIT, &ct->status))
        goto err_ct;

    if (test_and_set_bit(IPS_OFFLOAD_BIT, &ct->status)) {
        pr_debug("%s: offloaded already set", __FUNCTION__);
        return -EEXIST;
    }

    return 0;
err_ct:
    pr_debug("%s: err_ct", __FUNCTION__);
    return -EINVAL;
}

// TODO: remove this wrapper
static inline struct nf_gen_flow_offload_tuple_rhash *
_flowtable_lookup(const struct net *net,
                const struct nf_conntrack_zone *zone,
                const struct nf_conntrack_tuple *tuple)
{
    struct nf_gen_flow_offload_table *flowtable;
    struct nf_gen_flow_offload_tuple_rhash *tuplehash = NULL;

    rcu_read_lock();

    flowtable = rcu_dereference(_flowtable);
    if (flowtable) {
        tuplehash = nf_gen_flow_offload_lookup(flowtable, zone, tuple);
        if (tuplehash == NULL) {
            pr_debug("%s: no hit ", __FUNCTION__);
        }
    }

    rcu_read_unlock();

    return tuplehash;
}

/* retrieve stats by callbacks */
static int nft_gen_flow_offload_stats(struct nf_gen_flow_offload *flow)
{
    struct nf_gen_flow_offload_entry *e;
    u64 last_used;
    struct flow_offload_dep_ops * ops;

    e = container_of(flow, struct nf_gen_flow_offload_entry, flow);

    rcu_read_lock();
    ops = rcu_dereference(flow_dep_ops);
    if (ops && ops->get_stats) {
        /* retrieve stats by callbacks */
        spin_lock(&e->dep_lock);
        last_used = e->stats.last_used;
        ops->get_stats(&e->stats, &e->deps);
        spin_unlock(&e->dep_lock);

        /* update timeout with new last_used value, last_used is set as jiffies in drv;
           When TCP is disconnected by FIN, conntrack conneciton may be held by IPS_OFFLOAD
           until it is unset */

        if (e->stats.last_used > last_used)
            flow->timeout = e->stats.last_used + offloaded_ct_timeout;
        pr_debug("get_stats: new timeout %llu", flow->timeout);
    }
    rcu_read_unlock();

    return 0;
}

/* connection is aged out, notify all dependencies  */
static int nft_gen_flow_offload_destroy_dep(struct nf_gen_flow_offload *flow)
{
    struct nf_gen_flow_offload_entry *e;
    struct flow_offload_dep_ops * ops;

    e = container_of(flow, struct nf_gen_flow_offload_entry, flow);

    pr_debug("sync destroy for ct %p", &e->flow);

    rcu_read_lock();
    ops = rcu_dereference(flow_dep_ops);
    if (ops && ops->destroy) {
        spin_lock(&e->dep_lock);
        ops->destroy(&e->deps);
        spin_unlock(&e->dep_lock);
    }
    rcu_read_unlock();

    nf_gen_flow_offload_free(&e->flow);

    return 0;
}


/* EXPORT FUNCTIONS */

void nft_gen_flow_offload_dep_ops_register(struct flow_offload_dep_ops * ops)
{
    rcu_assign_pointer(flow_dep_ops, ops);
}

EXPORT_SYMBOL_GPL(nft_gen_flow_offload_dep_ops_register);


void nft_gen_flow_offload_dep_ops_unregister(struct flow_offload_dep_ops * ops)
{
    struct nf_gen_flow_offload_table *flowtable;

    rcu_read_lock();
    flowtable = rcu_dereference(_flowtable);

    /* cleanup all connections, for dep list member, drv assures no need to free explicitly */
    nf_gen_flow_offload_table_iterate(flowtable, nf_gen_flow_offload_table_do_cleanup, flowtable);
    rcu_read_unlock();


    synchronize_rcu();

    cancel_delayed_work_sync(&flowtable->gc_work.work);
    nf_gen_flow_offload_gc_step(&flowtable->gc_work, INT_MAX);
    rcu_assign_pointer(flow_dep_ops, NULL);
    queue_delayed_work(flowtable->flow_wq, &flowtable->gc_work.work, HZ);
}

EXPORT_SYMBOL_GPL(nft_gen_flow_offload_dep_ops_unregister);



int nft_gen_flow_offload_add(const struct net *net,
            const struct nf_conntrack_zone *zone,
            const struct nf_conntrack_tuple *tuple, void *dep)
{
    const struct nf_conntrack_tuple_hash *thash;
    struct nf_gen_flow_offload_tuple_rhash *fhash;
    enum nf_gen_flow_offload_tuple_dir dir;
    struct nf_gen_flow_offload *flow = NULL;
    struct nf_gen_flow_offload_entry *entry;
    struct nf_conn *ct;
    int ret = 0;
    struct flow_offload_dep_ops * ops;
    struct nf_gen_flow_offload_table *flowtable;
    bool teardown = false;

    if (rcu_access_pointer(flow_dep_ops) == NULL)
        return -EPERM;

    if (rcu_access_pointer(_flowtable) == NULL)
        return -ENOENT;

    _flow_offload_debug_op(zone, tuple, "Add");

    /* lookup */
    fhash = _flowtable_lookup(net, zone, tuple);
    if (fhash) {
        /* flow existing, add one dep */
        dir = fhash->tuple.dst.dir;
        entry = container_of(fhash, struct nf_gen_flow_offload_entry, flow.tuplehash[dir]);
    } else {
        /* create new flow */
        thash = nf_conntrack_find_get((struct net *)net, zone, tuple);
        if (!thash) {
            pr_debug("No CT found");
            ret = -EINVAL;
            goto _flow_add_exit;
        }
        
        ct = nf_ct_tuplehash_to_ctrack(thash);

        ret = _check_ct_status(ct);
        if (ret ==  0) {
            ret = _flowtable_add_entry(net, zone->id, ct, &flow);
        } else if (ret == -EEXIST) {
            /* cocurrency, tell user to try again */
            ret = -EAGAIN;
        }

        nf_ct_put(ct);
        if (ret < 0) goto _flow_add_exit;

        entry = container_of(flow, struct nf_gen_flow_offload_entry, flow);

        /* force clear this flag for new entry */
        entry->flow.flags = 0; 
    }


    rcu_read_lock();
    ops = rcu_dereference(flow_dep_ops);
    if (ops && ops->add) {
        spin_lock(&entry->dep_lock);

        /* checking if it was destroyed before we got spin lock*/
        if (entry->flow.flags & (FLOW_OFFLOAD_TEARDOWN |
                                    FLOW_OFFLOAD_DYING)) {
            spin_unlock(&entry->dep_lock);
            rcu_read_unlock();
            pr_debug("flow in destroy, try again");
            ret = -EAGAIN;
            goto _flow_add_exit;
        }

        ret = ops->add(dep, &entry->deps);
        if (ret && (list_empty_careful(&entry->deps))) {
            teardown = true;

            pr_debug("dep add failed %d", ret);
            spin_unlock(&entry->dep_lock);
            rcu_read_unlock();
            goto _flow_add_exit;
        }

        spin_unlock(&entry->dep_lock);

        if (ops->get_stats) {
            /* update timeout for new dep*/
            rcu_read_lock();
            flowtable = rcu_dereference(_flowtable);
            if (flowtable) {
                nf_gen_flow_offload_set_aging(flowtable, &entry->flow);
            }
            rcu_read_unlock();            
        }
    } else {
        teardown = true;
    }
    
    rcu_read_unlock();
    
_flow_add_exit:  
    rcu_read_lock();
    flowtable = rcu_dereference(_flowtable);
    if (flowtable) {
        tstat_added_inc(flowtable);
        if (ret < 0) {
            FLOW_OFFLOAD_DUMP("offloaded flow add failed", zone, tuple);
            tstat_add_failed_inc(flowtable);
            if (ret == -EAGAIN)
                tstat_add_racing_inc(flowtable);
        }

        if (teardown)
            nf_gen_flow_offload_teardown(flowtable, &entry->flow);
    }
    rcu_read_unlock();

    return ret;
}

EXPORT_SYMBOL_GPL(nft_gen_flow_offload_add);

int nft_gen_flow_offload_remove(const struct net *net,
            const struct nf_conntrack_zone *zone,
            const struct nf_conntrack_tuple * tuple, void *dep)
{
    struct nf_gen_flow_offload_tuple_rhash *fhash;
    enum nf_gen_flow_offload_tuple_dir dir;
    struct nf_gen_flow_offload_entry *entry;
    int ret;
    struct flow_offload_dep_ops * ops;

    if (rcu_access_pointer(flow_dep_ops) == NULL)
        return -EPERM;

    if (rcu_access_pointer(_flowtable) == NULL)
        return -ENOENT;

    _flow_offload_debug_op(zone, tuple, "Rmv");

    /* lookup */
    fhash = _flowtable_lookup(net, zone, tuple);
    if (fhash) {
        dir = fhash->tuple.dst.dir;
        entry = container_of(fhash, struct nf_gen_flow_offload_entry, flow.tuplehash[dir]);

        rcu_read_lock();
        ops = rcu_dereference(flow_dep_ops);
        if (ops && ops->remove) {
            /* try to remove it anyway, RCU holds this entry
                and spin can help with list operation */
            spin_lock(&entry->dep_lock);
            ops->remove(dep, &entry->deps);
            spin_unlock(&entry->dep_lock);
        }
        rcu_read_unlock();

    } else {
        ret = -ENOENT;
    }

    return ret;
}

EXPORT_SYMBOL_GPL(nft_gen_flow_offload_remove);


int nft_gen_flow_offload_destroy(const struct net *net,
            const struct nf_conntrack_zone *zone,
            const struct nf_conntrack_tuple * tuple)
{
    struct nf_gen_flow_offload_tuple_rhash *thash;
    struct nf_gen_flow_offload_table *flowtable;
    struct nf_gen_flow_offload *flow;
    enum nf_gen_flow_offload_tuple_dir dir;

    if (rcu_access_pointer(flow_dep_ops) == NULL)
        return -EPERM;

    _flow_offload_debug_op(zone, tuple, "Destroy");

    rcu_read_lock();
    
    flowtable = rcu_dereference(_flowtable);
    if (flowtable) {
    
        thash = _flowtable_lookup(net, zone, tuple);
        if (thash != NULL) {        
            dir = thash->tuple.dst.dir;

            flow = container_of(thash, struct nf_gen_flow_offload, tuplehash[dir]);

            nf_gen_flow_offload_teardown(flowtable, flow);
        }
    }

    rcu_read_unlock();

    return 0;
}

EXPORT_SYMBOL_GPL(nft_gen_flow_offload_destroy);


static int
nft_gen_flow_offload_init(const struct net *net)
{
    struct nf_gen_flow_offload_table *flowtable;

    flowtable = kzalloc(sizeof(*flowtable), GFP_KERNEL);

    nf_gen_flow_offload_table_init(flowtable);

    rcu_assign_pointer(_flowtable, flowtable);

    return 0;
}

static int _flow_proc_show(struct seq_file *m, void *v)
{
    int flow_cnt;
    struct nf_gen_flow_offload_table * flowtable;
    
    flow_cnt = atomic_read(&offloaded_flow_cnt);

    seq_printf(m, "total %d flows offloaded \n",
                    flow_cnt);

    rcu_read_lock();
    flowtable = rcu_dereference(_flowtable);
    if (flowtable) {
        seq_printf(m, "tstats hashtable: elements %d \n",
                        atomic_read((const atomic_t *)\
                        &flowtable->rhashtable.nelems));
    
        seq_printf(m, "tstats add: success %d failed %d racing %d\n",
                        tstat_added_get(flowtable),
                        tstat_add_failed_get(flowtable),
                        tstat_add_racing_get(flowtable));

        seq_printf(m, "tstats gc: aged %d run %u \n", tstat_aged_get(flowtable),
                                                    flowtable->gc_work.run_times); 

        show_stats_summary(m, "tstats gc: total", &flowtable->gc_work.total);
        show_stats_summary(m, "tstats gc: delta", &flowtable->gc_work.delta);
        show_stats_summary(m, "tstats gc: stat_op", &flowtable->gc_work.stat_op);
        show_stats_summary(m, "tstats gc: destroy_op", &flowtable->gc_work.destroy_op);

        show_stats_summary(m, "tstats gc: flows per run", &flowtable->gc_work.flows_per_run);

        show_buckets(m, &flowtable->gc_work);

        seq_printf(m, "mstats flow: hash %lu bytes flow %lu bytes entry %lu bytes\n",
                        sizeof(struct nf_gen_flow_offload_tuple_rhash),
                        sizeof(struct nf_gen_flow_offload), 
                        sizeof(struct nf_gen_flow_offload_entry));
    }

    rcu_read_unlock();

    return 0;
}


static int _flow_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, _flow_proc_show, PDE_DATA(inode));
}

static const struct file_operations _flow_proc_fops = {
    .open	= _flow_proc_open,
    .read	= seq_read,
    .llseek	= seq_lseek,
    .release	= single_release,
};

int __init nft_gen_flow_offload_proc_init(void)
{
    struct proc_dir_entry *p;
    int rc = -ENOMEM;

    p = proc_create_data("nf_conntrack_offloaded", 0444, 
                                init_net.proc_net,
                                &_flow_proc_fops, NULL);
    if (!p) {
        pr_debug("can't make nf_conntrack_offloaded proc_entry");
        return rc;
    }

    return 0;
}

void __exit nft_gen_flow_offload_proc_exit(void)
{
    remove_proc_entry("nf_conntrack_offloaded", init_net.proc_net);
}

static int __init nft_gen_flow_offload_module_init(void)
{
    atomic_set(&offloaded_flow_cnt, 0);

    rcu_assign_pointer(_flowtable, NULL);

    nft_gen_flow_offload_init(&init_net);

    nft_gen_flow_offload_proc_init();

    return 0;
}



static void __exit nft_gen_flow_offload_module_exit(void)
{
    struct nf_gen_flow_offload_table * flowtable;

    nft_gen_flow_offload_proc_exit();

    flowtable = rcu_access_pointer(_flowtable);
    if (flowtable != NULL) {
        rcu_assign_pointer(_flowtable, NULL);

        synchronize_rcu();

        nf_gen_flow_offload_table_free(flowtable);

        kfree(flowtable);
    }
}

module_init(nft_gen_flow_offload_module_init);
module_exit(nft_gen_flow_offload_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lidong Jiang <jianglidong3@jd.com>");


#ifndef _NFT_GEN_FLOW_OFFLOAD_H_
#define _NFT_GEN_FLOW_OFFLOAD_H_

/*
 * general flow offloaded header
 *
 * Copyright 2018 Lidong Jiang <jianglidong3@jd.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */
 
#include <net/netfilter/nf_conntrack_core.h>



struct nf_gen_flow_ct_stat {
    u64 bytes;
    u64 packets;
    u64 last_used; /* most latest in both directions */    
};




/* gen_offload provides callback to users of one connection
   Few possible application scenario includes,
   1. Notify all users or dependencies when one CT connetion is removed by userspace tool .
   2. Nofity all users or dependencies when one nf_con state is changed, 
      such as TCP state in TCP.RST process 
   3. Do proactive aging on connections if get_stats is supported
   */
   
struct flow_offload_dep_ops {
    /* call user to append new dependency */
    int (*add)(void *, struct list_head *);
    
    /* only used by explicitly remove from user */
    void (*remove)(void *, struct list_head *);
    
    /* call user to retrieve stats of this connection, statistics data is 
       written into nf_gen_flow_ct_stat */
    void (*get_stats)(struct nf_gen_flow_ct_stat *, struct list_head *);
    
    /* notify user that this connection is dying */
    int (*destroy)(struct list_head *);
};

/* Register dep_op interfaces */
extern void nft_gen_flow_offload_dep_ops_register(struct flow_offload_dep_ops * ops);

/* Unegister dep_op interfaces */
extern void nft_gen_flow_offload_dep_ops_unregister(struct flow_offload_dep_ops * ops);

/* Add one dependency on one CT conneciton, 
   if this is the first dependency(user) on this connection,
   CT conneciton is marked as "OFFLOADED" and CT general aging is frozen */
extern int nft_gen_flow_offload_add(const struct net *net, 
            const struct nf_conntrack_zone *zone, 
            const struct nf_conntrack_tuple *tuple, void *arg);

/* Remove one dependency of one CT conneciton, 
   if this is the last dependency(user) on this connection,
   CT conneciton OFFLOADED is unset, CT general aging is restarted */
extern int nft_gen_flow_offload_remove(const struct net *net, 
            const struct nf_conntrack_zone *zone, 
            const struct nf_conntrack_tuple * tuple, void *dep);


/* Destroy one CT conneciton from offloaded flow table, 
   original CT connection "OFFLOADED" flag is unset,  
   and CT general aging is restarted. 
   
   This Interface is called by FIN/RST process of HW offload module */
extern int nft_gen_flow_offload_destroy(const struct net *net, 
                const struct nf_conntrack_zone *zone, 
                const struct nf_conntrack_tuple *tuple);


#endif

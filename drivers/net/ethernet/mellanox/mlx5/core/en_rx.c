/*
 * Copyright (c) 2015, Mellanox Technologies. All rights reserved.
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

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include "en.h"

static inline void mlx5e_read_cqe_slot(struct mlx5e_cq *cq, u32 cqcc,
				       void *data)
{
	u32 ci = cqcc & cq->wq.sz_m1;

	memcpy(data, mlx5_cqwq_get_wqe(&cq->wq, ci), sizeof(struct mlx5_cqe64));
}

static inline void mlx5e_write_cqe_slot(struct mlx5e_cq *cq, u32 cqcc,
					void *data)
{
	u32 ci = cqcc & cq->wq.sz_m1;

	memcpy(mlx5_cqwq_get_wqe(&cq->wq, ci), data, sizeof(struct mlx5_cqe64));
}

static inline bool mlx5e_is_mpwrq(struct mlx5e_rq *rq)
{
	return !!rq->wqe_info;
}

static inline void mlx5e_decompress_cqe(struct mlx5e_cq *cq,
					u32 cqcc,
					struct mlx5_cqe64 *title,
					struct mlx5_mini_cqe8 *mini,
					u16 *wqe_count)
{
	struct mlx5e_rq *rq = container_of(cq, struct mlx5e_rq, cq);

	title->byte_cnt     = mini->byte_cnt;
	title->check_sum    = mini->checksum;
	title->rss_hash_type = 0;
	title->wqe_counter  = cpu_to_be16(*wqe_count);
	title->op_own      &= 0xf0;
	title->op_own      |= 0x01 & (cqcc >> cq->wq.log_sz);

	if (mlx5e_is_mpwrq(rq)) {
		struct mpwrq_cqe_bc *cqe_bc =
			(struct mpwrq_cqe_bc *)&mini->byte_cnt;
		u16 cstrides = get_mpwrq_cqe_bc_consumed_strides(cqe_bc);

		*wqe_count = *wqe_count + cstrides;
	} else {
		*wqe_count = (*wqe_count + 1) & rq->wq.sz_m1;
	}

}

static inline void mlx5e_decompress_cqes(struct mlx5e_cq *cq)
{
	struct mlx5e_rq *rq = container_of(cq, struct mlx5e_rq, cq);
	struct mlx5_mini_cqe8 mini[8];
	struct mlx5_cqe64 title;
	u16 wqe_count;
	u32 cqe_count;
	u32 cqcc = cq->wq.cc;
	u32 i;

	rq->stats.cqe_compress++;

	mlx5e_read_cqe_slot(cq, cqcc, &title);
	mlx5e_read_cqe_slot(cq, cqcc+1, mini);

	wqe_count = be16_to_cpu(title.wqe_counter);
	cqe_count = be32_to_cpu(title.byte_cnt);

	mlx5e_decompress_cqe(cq, cqcc, &title, &mini[0], &wqe_count);
	mlx5e_write_cqe_slot(cq, cqcc, &title);

	for (i = 1; i < cqe_count; i++) {
		u32 ix = i % MLX5_MINI_CQE_ARRAY_SIZE;

		cqcc++;

		if (!ix)
			mlx5e_read_cqe_slot(cq, cqcc, mini);

		mlx5e_decompress_cqe(cq, cqcc, &title, &mini[ix], &wqe_count);
		mlx5e_write_cqe_slot(cq, cqcc, &title);
	}
}

int mlx5e_alloc_rx_wqe(struct mlx5e_rq *rq, struct mlx5e_rx_wqe *wqe, u16 ix)
{
	struct sk_buff *skb;
	dma_addr_t dma_addr;

	skb = netdev_alloc_skb(rq->netdev, rq->wqe_sz);
	if (unlikely(!skb))
		return -ENOMEM;

	dma_addr = dma_map_single(rq->pdev,
				  /* hw start padding */
				  skb->data,
				  /* hw end padding */
				  rq->wqe_sz,
				  DMA_FROM_DEVICE);

	if (unlikely(dma_mapping_error(rq->pdev, dma_addr)))
		goto err_free_skb;

	skb_reserve(skb, MLX5E_NET_IP_ALIGN);

	*((dma_addr_t *)skb->cb) = dma_addr;
	wqe->data.addr = cpu_to_be64(dma_addr + MLX5E_NET_IP_ALIGN);

	rq->skb[ix] = skb;

	return 0;

err_free_skb:
	dev_kfree_skb(skb);

	return -ENOMEM;
}

int mlx5e_alloc_rx_mpwqe(struct mlx5e_rq *rq, struct mlx5e_rx_wqe *wqe, u16 ix)
{
	struct mlx5e_mpw_info *wi = &rq->wqe_info[ix];
	int ret = 0;

	wi->page = alloc_pages(GFP_ATOMIC | __GFP_COMP, MLX5_MPWRQ_PAGE_ORDER);
	if (unlikely(!wi->page))
		return -ENOMEM;

	wi->dma_addr = dma_map_page(rq->pdev, wi->page, 0, rq->wqe_sz,
				    PCI_DMA_FROMDEVICE);
	if (dma_mapping_error(rq->pdev, wi->dma_addr)) {
		ret = -ENOMEM;
		goto err_put_page;
	}

	wi->consumed_strides = 0;
	wqe->data.addr = cpu_to_be64(wi->dma_addr);

	return 0;

err_put_page:
	put_page(wi->page);
	return ret;
}

bool mlx5e_post_rx_wqes(struct mlx5e_rq *rq)
{
	struct mlx5_wq_ll *wq = &rq->wq;

	if (unlikely(!test_bit(MLX5E_RQ_STATE_POST_WQES_ENABLE, &rq->state)))
		return false;

	while (!mlx5_wq_ll_is_full(wq)) {
		struct mlx5e_rx_wqe *wqe = mlx5_wq_ll_get_wqe(wq, wq->head);

		if (unlikely(rq->alloc_wqe(rq, wqe, wq->head)))
			break;

		mlx5_wq_ll_push(wq, be16_to_cpu(wqe->next.next_wqe_index));
	}

	/* ensure wqes are visible to device before updating doorbell record */
	dma_wmb();

	mlx5_wq_ll_update_db_record(wq);

	return !mlx5_wq_ll_is_full(wq);
}

static void mlx5e_lro_update_hdr(struct sk_buff *skb, struct mlx5_cqe64 *cqe)
{
	struct ethhdr	*eth	= (struct ethhdr *)(skb->data);
	struct iphdr	*ipv4	= (struct iphdr *)(skb->data + ETH_HLEN);
	struct ipv6hdr	*ipv6	= (struct ipv6hdr *)(skb->data + ETH_HLEN);
	struct tcphdr	*tcp;

	u8 l4_hdr_type = get_cqe_l4_hdr_type(cqe);
	int tcp_ack = ((CQE_L4_HDR_TYPE_TCP_ACK_NO_DATA  == l4_hdr_type) ||
		       (CQE_L4_HDR_TYPE_TCP_ACK_AND_DATA == l4_hdr_type));

	u16 tot_len = be32_to_cpu(cqe->byte_cnt) - ETH_HLEN;

	if (eth->h_proto == htons(ETH_P_IP)) {
		tcp = (struct tcphdr *)(skb->data + ETH_HLEN +
					sizeof(struct iphdr));
		ipv6 = NULL;
		skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
	} else {
		tcp = (struct tcphdr *)(skb->data + ETH_HLEN +
					sizeof(struct ipv6hdr));
		ipv4 = NULL;
		skb_shinfo(skb)->gso_type = SKB_GSO_TCPV6;
	}

	if (get_cqe_lro_tcppsh(cqe))
		tcp->psh                = 1;

	if (tcp_ack) {
		tcp->ack                = 1;
		tcp->ack_seq            = cqe->lro_ack_seq_num;
		tcp->window             = cqe->lro_tcp_win;
	}

	if (ipv4) {
		ipv4->ttl               = cqe->lro_min_ttl;
		ipv4->tot_len           = cpu_to_be16(tot_len);
		ipv4->check             = 0;
		ipv4->check             = ip_fast_csum((unsigned char *)ipv4,
						       ipv4->ihl);
	} else {
		ipv6->hop_limit         = cqe->lro_min_ttl;
		ipv6->payload_len       = cpu_to_be16(tot_len -
						      sizeof(struct ipv6hdr));
	}
}

static inline void mlx5e_skb_set_hash(struct mlx5_cqe64 *cqe,
				      struct sk_buff *skb)
{
	u8 cht = cqe->rss_hash_type;
	int ht = (cht & CQE_RSS_HTYPE_L4) ? PKT_HASH_TYPE_L4 :
		 (cht & CQE_RSS_HTYPE_IP) ? PKT_HASH_TYPE_L3 :
					    PKT_HASH_TYPE_NONE;
	skb_set_hash(skb, be32_to_cpu(cqe->rss_hash_result), ht);
}

static inline bool is_first_ethertype_ip(struct sk_buff *skb)
{
	__be16 ethertype = ((struct ethhdr *)skb->data)->h_proto;

	return (ethertype == htons(ETH_P_IP) || ethertype == htons(ETH_P_IPV6));
}

static inline void mlx5e_handle_csum(struct net_device *netdev,
				     struct mlx5_cqe64 *cqe,
				     struct mlx5e_rq *rq,
				     struct sk_buff *skb)
{
	if (unlikely(!(netdev->features & NETIF_F_RXCSUM)))
		goto csum_none;

	if (likely(cqe->hds_ip_ext & CQE_L4_OK)) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	} else if (is_first_ethertype_ip(skb)) {
		skb->ip_summed = CHECKSUM_COMPLETE;
		skb->csum = csum_unfold((__force __sum16)cqe->check_sum);
		rq->stats.csum_sw++;
	} else {
		goto csum_none;
	}

	return;

csum_none:
	skb->ip_summed = CHECKSUM_NONE;
	rq->stats.csum_none++;
}

static inline void mlx5e_build_rx_skb(struct mlx5_cqe64 *cqe,
				      struct mlx5e_rq *rq,
				      struct sk_buff *skb)
{
	struct net_device *netdev = rq->netdev;
	u32 cqe_bcnt = be32_to_cpu(cqe->byte_cnt);
	int lro_num_seg;

	lro_num_seg = be32_to_cpu(cqe->srqn) >> 24;
	if (lro_num_seg > 1) {
		mlx5e_lro_update_hdr(skb, cqe);
		skb_shinfo(skb)->gso_size = DIV_ROUND_UP(cqe_bcnt, lro_num_seg);
		rq->stats.lro_packets++;
		rq->stats.lro_bytes += cqe_bcnt;
	}

	mlx5e_handle_csum(netdev, cqe, rq, skb);

	skb->protocol = eth_type_trans(skb, netdev);

	skb_record_rx_queue(skb, rq->ix);

	if (likely(netdev->features & NETIF_F_RXHASH))
		mlx5e_skb_set_hash(cqe, skb);

	if (cqe_has_vlan(cqe))
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
				       be16_to_cpu(cqe->vlan_info));
}

static inline void mlx5e_complete_rx_cqe(struct mlx5e_rq *rq,
					 struct mlx5_cqe64 *cqe,
					 struct sk_buff *skb)
{
	mlx5e_build_rx_skb(cqe, rq, skb);
	rq->stats.packets++;
	napi_gro_receive(rq->cq.napi, skb);
}

void mlx5e_handle_rx_cqe(struct mlx5e_rq *rq, struct mlx5_cqe64 *cqe)
{
	struct mlx5e_rx_wqe *wqe;
	struct sk_buff *skb;
	__be16 wqe_counter_be;
	u16 wqe_counter;

	wqe_counter_be = cqe->wqe_counter;
	wqe_counter    = be16_to_cpu(wqe_counter_be);
	wqe            = mlx5_wq_ll_get_wqe(&rq->wq, wqe_counter);
	skb            = rq->skb[wqe_counter];
	prefetch(skb->data);
	rq->skb[wqe_counter] = NULL;

	dma_unmap_single(rq->pdev,
			 *((dma_addr_t *)skb->cb),
			 rq->wqe_sz,
			 DMA_FROM_DEVICE);

	if (unlikely((cqe->op_own >> 4) != MLX5_CQE_RESP_SEND)) {
		rq->stats.wqe_err++;
		dev_kfree_skb(skb);
		goto wq_ll_pop;
	}

	skb_put(skb, be32_to_cpu(cqe->byte_cnt));

	mlx5e_complete_rx_cqe(rq, cqe, skb);

wq_ll_pop:
	mlx5_wq_ll_pop(&rq->wq, wqe_counter_be,
		       &wqe->next.next_wqe_index);
}

void mlx5e_handle_rx_cqe_mpwrq(struct mlx5e_rq *rq, struct mlx5_cqe64 *cqe)
{
	u16 stride_ix      = get_mpwrq_cqe_stride_index(cqe);
	u16 cstrides       = get_mpwrq_cqe_consumed_strides(cqe);
	u16 byte_cnt       = get_mpwrq_cqe_byte_cnt(cqe);
	u16 wqe_id         = be16_to_cpu(cqe->wqe_id);
	u32 consumed_bytes = cstrides  * MLX5_MPWRQ_STRIDE_SIZE;
	u32 stride_offset  = stride_ix * MLX5_MPWRQ_STRIDE_SIZE;
	u32 data_offset    = stride_offset + MLX5E_NET_IP_ALIGN;
	struct mlx5e_mpw_info *wi = &rq->wqe_info[wqe_id];
	struct mlx5e_rx_wqe  *wqe = mlx5_wq_ll_get_wqe(&rq->wq, wqe_id);
	struct sk_buff *skb;
	u16 headlen;

	wi->consumed_strides += cstrides;

	if (unlikely((cqe->op_own >> 4) != MLX5_CQE_RESP_SEND)) {
		rq->stats.wqe_err++;
		goto mpwrq_cqe_out;
	}

	if (is_mpwrq_filler_cqe(cqe))
		goto mpwrq_cqe_out;

	skb = netdev_alloc_skb(rq->netdev, MLX5_MPWRQ_SMALL_PACKET_THRESHOLD +
					   MLX5E_NET_IP_ALIGN);
	if (unlikely(!skb))
		goto mpwrq_cqe_out;
	skb_reserve(skb, MLX5E_NET_IP_ALIGN);

	dma_sync_single_for_cpu(rq->pdev, wi->dma_addr + stride_offset,
				consumed_bytes, DMA_FROM_DEVICE);

	headlen = min_t(u16, MLX5_MPWRQ_SMALL_PACKET_THRESHOLD, byte_cnt);
	skb_copy_to_linear_data(skb, page_address(wi->page) + data_offset,
				headlen);
	skb_put(skb, headlen);

	byte_cnt -= headlen;
	if (byte_cnt) {
		skb_frag_t *f0 = &skb_shinfo(skb)->frags[0];

		skb_shinfo(skb)->nr_frags = 1;

		skb->data_len  = byte_cnt;
		skb->len      += byte_cnt;
		skb->truesize  = SKB_TRUESIZE(skb->len);

		get_page(wi->page);
		skb_frag_set_page(skb, 0, wi->page);
		skb_frag_size_set(f0, skb->data_len);
		f0->page_offset = data_offset + headlen;
	}

	mlx5e_complete_rx_cqe(rq, cqe, skb);

mpwrq_cqe_out:
	if (likely(wi->consumed_strides < MLX5_MPWRQ_NUM_STRIDES))
		return;

	dma_unmap_page(rq->pdev, wi->dma_addr, rq->wqe_sz, PCI_DMA_FROMDEVICE);
	put_page(wi->page);
	mlx5_wq_ll_pop(&rq->wq, cqe->wqe_id, &wqe->next.next_wqe_index);
}

bool mlx5e_poll_rx_cq(struct mlx5e_cq *cq, int budget)
{
	struct mlx5e_rq *rq = container_of(cq, struct mlx5e_rq, cq);
	int i;

	/* avoid accessing cq (dma coherent memory) if not needed */
	if (!test_and_clear_bit(MLX5E_CQ_HAS_CQES, &cq->flags))
		return false;

	for (i = 0; i < budget; i++) {
		struct mlx5_cqe64 *cqe = mlx5e_get_cqe(cq);

		if (!cqe)
			break;

		if (mlx5_get_cqe_format(cqe) == MLX5_COMPRESSED)
			mlx5e_decompress_cqes(cq);

		mlx5_cqwq_pop(&cq->wq);

		rq->handle_rx_cqe(rq, cqe);
	}

	mlx5_cqwq_update_db_record(&cq->wq);

	/* ensure cq space is freed before enabling more cqes */
	wmb();

	if (i == budget) {
		set_bit(MLX5E_CQ_HAS_CQES, &cq->flags);
		return true;
	}

	return false;
}

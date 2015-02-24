/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Sun Microsystems, Inc. All rights reserved.
 * Copyright (c) 2005 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2004, 2005 Voltaire, Inc. All rights reserved.
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

#include <linux/delay.h>
#include <linux/moduleparam.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>

#include <linux/ip.h>
#include <linux/tcp.h>

#include "ipoib.h"

#include <linux/if_arp.h>	/* For ARPHRD_xxx */

#ifdef CONFIG_INFINIBAND_IPOIB_DEBUG_DATA
static int data_debug_level;

module_param(data_debug_level, int, 0644);
MODULE_PARM_DESC(data_debug_level,
		 "Enable data path debug tracing if > 0");
#endif

static DEFINE_MUTEX(pkey_mutex);

struct ipoib_ah *ipoib_create_ah(struct net_device *dev,
				 struct ib_pd *pd, struct ib_ah_attr *attr)
{
	struct ipoib_ah *ah;
	struct ib_ah *vah;

	ah = kmalloc(sizeof *ah, GFP_KERNEL);
	if (!ah)
		return ERR_PTR(-ENOMEM);

	ah->dev       = dev;
	kref_init(&ah->ref);

	vah = ib_create_ah(pd, attr);
	if (IS_ERR(vah)) {
		kfree(ah);
		ah = (struct ipoib_ah *)vah;
	} else {
		atomic_set(&ah->refcnt, 0);
		ah->ah = vah;
		ipoib_dbg(netdev_priv(dev), "Created ah %p\n", ah->ah);
	}

	return ah;
}

void ipoib_free_ah(struct kref *kref)
{
	struct ipoib_ah *ah = container_of(kref, struct ipoib_ah, ref);
	struct ipoib_dev_priv *priv = netdev_priv(ah->dev);

	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	list_add_tail(&ah->list, &priv->dead_ahs);
	spin_unlock_irqrestore(&priv->lock, flags);
}

static void ipoib_ud_dma_unmap_rx(struct ipoib_dev_priv *priv,
				  u64 mapping[IPOIB_UD_RX_SG])
{
	ib_dma_unmap_single(priv->ca, mapping[0],
			    IPOIB_UD_BUF_SIZE(priv->max_ib_mtu),
			    DMA_FROM_DEVICE);
}

static int ipoib_ib_post_receive(struct net_device *dev,
				 struct ipoib_recv_ring *recv_ring,
				 int id, int skb_idx)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ib_recv_wr *bad_wr;
	struct ipoib_skb *rx_skb = &recv_ring->rx_ring[id].rx_skb[skb_idx];
	int ret;

	recv_ring->rx_wr.wr_id   = id | IPOIB_OP_RECV;
	recv_ring->rx_sge[0].addr = rx_skb->mapping[0];
	recv_ring->rx_sge[1].addr = rx_skb->mapping[1];


	ret = ib_post_recv(recv_ring->recv_qp, &recv_ring->rx_wr, &bad_wr);
	if (unlikely(ret)) {
		ipoib_warn(priv, "receive failed for buf %d (%d)\n", id, ret);
		ipoib_ud_dma_unmap_rx(priv, rx_skb->mapping);
		dev_kfree_skb_any(rx_skb->skb);
		rx_skb->skb = NULL;
	}

	return ret;
}

static struct sk_buff *ipoib_alloc_rx_skb(struct net_device *dev,
					  struct ipoib_skb *rx_skb,
					  enum ipoib_alloc_type type)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct sk_buff *skb;
	int buf_size;
	u64 *mapping;

	buf_size = IPOIB_UD_BUF_SIZE(priv->max_ib_mtu);
	mapping = rx_skb->mapping;

	if (type == IPOIB_ALLOC_REPLACEMENT) {
		ipoib_ud_dma_unmap_rx(priv, mapping);
		consume_skb(rx_skb->skb);
		rx_skb->skb = NULL;
	}

	skb = dev_alloc_skb(buf_size + 4);
	if (unlikely(!skb))
		goto out;

	/*
	 * IB will leave a 40 byte gap for a GRH and IPoIB adds a 4 byte
	 * header.  So we need 4 more bytes to get to 48 and align the
	 * IP header to a multiple of 16.
	 */
	skb_reserve(skb, 4);

	mapping[0] = ib_dma_map_single(priv->ca, skb->data, buf_size,
				       DMA_FROM_DEVICE);
	if (unlikely(ib_dma_mapping_error(priv->ca, mapping[0])))
		goto error;

	rx_skb->skb = skb;
	return skb;

error:
	dev_kfree_skb_any(skb);
out:
	rx_skb->skb = NULL;
	return NULL;
}

static int ipoib_ib_post_ring_receives(struct net_device *dev,
				      struct ipoib_recv_ring *recv_ring)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_skb *rx_skb;
	int i, j;

	for (i = 0; i < priv->recvq_size; ++i) {
		for (j = 0; j < IPOIB_NUM_RX_SKB; ++j) {
			rx_skb = &recv_ring->rx_ring[i].rx_skb[j];
			if (!ipoib_alloc_rx_skb(dev, rx_skb, IPOIB_ALLOC_NEW)) {
				ipoib_warn(priv,
					   "failed to allocate buf (%d,%d)\n",
					   recv_ring->index, i);
				return -ENOMEM;
			}
		}
		if (ipoib_ib_post_receive(dev, recv_ring, i, 0)) {
			ipoib_warn(priv,
				"ipoib_ib_post_receive failed for buf (%d,%d)\n",
				recv_ring->index, i);
			return -EIO;
		}
		recv_ring->rx_ring[i].skb_index = 0;
	}

	return 0;
}

static int ipoib_ib_post_receives(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_recv_ring *recv_ring;
	int err;
	int i;

	recv_ring = priv->recv_ring;
	for (i = 0; i < priv->num_rx_queues; ++i) {
		err = ipoib_ib_post_ring_receives(dev, recv_ring);
		if (err)
			return err;
		recv_ring++;
	}

	return 0;
}

static inline void ipoib_create_repath_ent(struct net_device *dev,
						struct sk_buff *skb,
						u16 lid)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_arp_repath *arp_repath;
	struct arphdr *parphdr;

	parphdr = (struct arphdr *)(skb->data);
	if ((ARPOP_REPLY != be16_to_cpu(parphdr->ar_op)) &&
		(ARPOP_REQUEST != be16_to_cpu(parphdr->ar_op))) {
		return;
	}

	arp_repath = kzalloc(sizeof *arp_repath, GFP_ATOMIC);
	if (!arp_repath) {
		ipoib_warn(priv, "Failed alloc ipoib_arp_repath.\n");
		return;
	}

	INIT_WORK(&arp_repath->work, ipoib_repath_ah);

	arp_repath->lid = lid;
	memcpy(&arp_repath->sgid, skb->data + sizeof(struct arphdr) + 4,
		sizeof(union ib_gid));
		arp_repath->dev = dev;

	if (!test_bit(IPOIB_STOP_REAPER, &priv->flags))
		queue_work(ipoib_workqueue, &arp_repath->work);
	else
		kfree(arp_repath);
}

static void ipoib_skb_drop_fraglist(struct sk_buff *skb)
{
	struct sk_buff *list = skb_shinfo(skb)->frag_list;
	skb_frag_list_init(skb);

	while (list) {
		struct sk_buff *this = list;
		list = list->next;
		consume_skb(this);
	}
}

static void ipoib_reuse_skb(struct net_device *dev,
			    struct ipoib_skb *rx_skb)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	__u8 cur_head_frag = rx_skb->skb->head_frag;

	ib_dma_sync_single_for_cpu(priv->ca,
				   rx_skb->mapping[0],
				   IPOIB_UD_BUF_SIZE(priv->max_ib_mtu),
				   DMA_FROM_DEVICE);

	memset(rx_skb->skb, 0, offsetof(struct sk_buff, tail));

	/* keep origin values of necessary fields */
	rx_skb->skb->head_frag = cur_head_frag;

	rx_skb->skb->data = rx_skb->skb->head + NET_SKB_PAD;
	skb_reset_tail_pointer(rx_skb->skb);
	skb_reserve(rx_skb->skb, 4);
	skb_frag_list_init(rx_skb->skb);
	skb_get(rx_skb->skb);
}

static int ipoib_prepare_next_skb(struct net_device *dev,
				  struct ipoib_rx_buf *rx_ring)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_skb *rx_skb = NULL;
	struct sk_buff *skb = NULL;
	int next_skb_id;
	int buf_size = IPOIB_UD_BUF_SIZE(priv->max_ib_mtu);

	next_skb_id = (rx_ring->skb_index + 1) % IPOIB_NUM_RX_SKB;
	rx_skb = &rx_ring->rx_skb[next_skb_id];
	skb = rx_skb->skb;

	if (!skb || skb_shared(skb) || skb_cloned(skb)) {
		enum ipoib_alloc_type alloc_type;
		alloc_type = skb ? IPOIB_ALLOC_REPLACEMENT : IPOIB_ALLOC_NEW;
		if (!ipoib_alloc_rx_skb(dev, rx_skb, alloc_type))
			return -ENOMEM;
	} else
		ib_dma_sync_single_for_device(priv->ca,
					      rx_skb->mapping[0],
					      buf_size,
					      DMA_FROM_DEVICE);
	if (skb_has_frag_list(rx_skb->skb))
		ipoib_skb_drop_fraglist(rx_skb->skb);

	rx_ring->skb_index = next_skb_id;
	return 0;
}

static void ipoib_ib_handle_rx_wc(struct net_device *dev,
				  struct ipoib_recv_ring *recv_ring,
				  struct ib_wc *wc)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	unsigned int wr_id = wc->wr_id & ~IPOIB_OP_RECV;
	struct sk_buff *skb;
	union ib_gid *dgid;
	struct ipoib_rx_buf *rx_ring = &recv_ring->rx_ring[wr_id];
	struct ipoib_skb *cur_skb = &rx_ring->rx_skb[rx_ring->skb_index];

	ipoib_dbg_data(priv, "recv completion: id %d, status: %d\n",
		       wr_id, wc->status);

	if (unlikely(wr_id >= priv->recvq_size)) {
		ipoib_warn(priv, "recv completion event with wrid %d (> %d)\n",
			   wr_id, priv->recvq_size);
		return;
	}

	skb = cur_skb->skb;

	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		if (wc->status != IB_WC_WR_FLUSH_ERR)
			ipoib_warn(priv, "failed recv event "
				   "(status=%d, wrid=%d vend_err %x)\n",
				   wc->status, wr_id, wc->vendor_err);
		ipoib_ud_dma_unmap_rx(priv, cur_skb->mapping);
		dev_kfree_skb_any(skb);
		cur_skb->skb = NULL;
		return;
	}

	/*
	 * Drop packets that this interface sent, ie multicast packets
	 * that the HCA has replicated.
	 * Note with SW TSS MC were sent using priv->qp so no need to mask
	 */
	if (wc->slid == priv->local_lid && wc->src_qp == priv->qp->qp_num)
		goto repost;

	if (unlikely(ipoib_prepare_next_skb(dev, rx_ring))) {
		++recv_ring->stats.rx_dropped;
		goto repost;
	}

	ipoib_reuse_skb(dev, cur_skb);
	skb_record_rx_queue(skb, recv_ring->index);

	ipoib_dbg_data(priv, "received %d bytes, SLID 0x%04x\n",
		       wc->byte_len, wc->slid);

	skb_put(skb, wc->byte_len);

	/* First byte of dgid signals multicast when 0xff */
	dgid = &((struct ib_grh *)skb->data)->dgid;

	if (!(wc->wc_flags & IB_WC_GRH) || dgid->raw[0] != 0xff)
		skb->pkt_type = PACKET_HOST;
	else if (memcmp(dgid, dev->broadcast + 4, sizeof(union ib_gid)) == 0)
		skb->pkt_type = PACKET_BROADCAST;
	else
		skb->pkt_type = PACKET_MULTICAST;

	skb_pull(skb, IB_GRH_BYTES);

	skb->protocol = ((struct ipoib_header *) skb->data)->proto;
	skb_reset_mac_header(skb);
	skb_pull(skb, IPOIB_ENCAP_LEN);

	/* indicate size for reasmb */
	skb->truesize = skb->len + sizeof(struct sk_buff);

	++recv_ring->stats.rx_packets;
	recv_ring->stats.rx_bytes += skb->len;

	if (unlikely(be16_to_cpu(skb->protocol) == ETH_P_ARP))
		ipoib_create_repath_ent(dev, skb, wc->slid);

	skb->dev = dev;
	if ((dev->features & NETIF_F_RXCSUM) &&
			likely(wc->wc_flags & IB_WC_IP_CSUM_OK))
		skb->ip_summed = CHECKSUM_UNNECESSARY;

	/* if handler is registered on top of ipoib, set skb oob data. */
	if (dev->priv_flags & IFF_EIPOIB_VIF) {
		set_skb_oob_cb_data(skb, wc, &recv_ring->napi);
		/*the registered handler will take care of the skb.*/
		netif_receive_skb(skb);
	} else
		napi_gro_receive(&recv_ring->napi, skb);

repost:
	if (unlikely(ipoib_ib_post_receive(dev, recv_ring, wr_id,
					   rx_ring->skb_index)))
		ipoib_warn(priv, "ipoib_ib_post_receive failed "
			   "for buf %d\n", wr_id);
}

static int ipoib_dma_map_tx(struct ib_device *ca,
			    struct ipoib_tx_buf *tx_req)
{
	struct sk_buff *skb = tx_req->skb;
	u64 *mapping = tx_req->mapping;
	int i;
	int off;

	if (skb_headlen(skb)) {
		mapping[0] = ib_dma_map_single(ca, skb->data, skb_headlen(skb),
					       DMA_TO_DEVICE);
		if (unlikely(ib_dma_mapping_error(ca, mapping[0])))
			return -EIO;

		off = 1;
	} else
		off = 0;

	for (i = 0; i < skb_shinfo(skb)->nr_frags; ++i) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		mapping[i + off] = ib_dma_map_page(ca,
						 skb_frag_page(frag),
						 frag->page_offset, skb_frag_size(frag),
						 DMA_TO_DEVICE);
		if (unlikely(ib_dma_mapping_error(ca, mapping[i + off])))
			goto partial_error;
	}
	return 0;

partial_error:
	for (; i > 0; --i) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i - 1];

		ib_dma_unmap_page(ca, mapping[i - !off], skb_frag_size(frag), DMA_TO_DEVICE);
	}

	if (off)
		ib_dma_unmap_single(ca, mapping[0], skb_headlen(skb), DMA_TO_DEVICE);

	return -EIO;
}

static void ipoib_dma_unmap_tx(struct ib_device *ca,
			       struct ipoib_tx_buf *tx_req)
{
	struct sk_buff *skb = tx_req->skb;
	u64 *mapping = tx_req->mapping;
	int i;
	int off;

	if (skb_headlen(skb)) {
		ib_dma_unmap_single(ca, mapping[0], skb_headlen(skb),
						DMA_TO_DEVICE);
		off = 1;
	} else
		off = 0;

	for (i = 0; i < skb_shinfo(skb)->nr_frags; ++i) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		ib_dma_unmap_page(ca, mapping[i + off],
					skb_frag_size(frag), DMA_TO_DEVICE);
	}
}

/* Whenever QP gets CQE with error that according to the FW bahaviur
 * can caused the QP to change its state to one of the error states.
 * Currently the function checks if the (send)QP is in SQE state and
 * moves it back to RTS, that in order to have it functional again.
 * without that the driver doesn't know about the QP state and all traffic
 * to that QP will be dropped.
 */
static void ipoib_qp_state_validate_work(struct work_struct *work)
{
	struct ipoib_qp_state_validate *qp_work =
		container_of(work, struct ipoib_qp_state_validate, work);

	struct ipoib_dev_priv *priv = qp_work->priv;
	struct ipoib_send_ring *send_ring = qp_work->send_ring;
	struct ib_qp_attr qp_attr;
	struct ib_qp_init_attr query_init_attr;
	int ret;

	if (test_bit(IPOIB_FLAG_INTF_ON_DESTROY, &priv->flags))
		goto free_res;

	ret = ib_query_qp(send_ring->send_qp, &qp_attr, IB_QP_STATE, &query_init_attr);
	if (ret) {
		ipoib_warn(priv, "%s: Failed to query QP ret: %d\n",
			   __func__, ret);
		goto free_res;
	}
	pr_info("%s: QP: 0x%x is in state: %d\n",
		__func__, send_ring->send_qp->qp_num, qp_attr.qp_state);

	/* currently support only in SQE->RTS transition*/
	if (qp_attr.qp_state == IB_QPS_SQE) {
		qp_attr.qp_state = IB_QPS_RTS;

		ret = ib_modify_qp(send_ring->send_qp, &qp_attr, IB_QP_STATE);
		if (ret) {
			pr_warn("failed(%d) modify QP:0x%x SQE->RTS\n",
				ret, send_ring->send_qp->qp_num);
			goto free_res;
		}
		pr_info("%s: QP: 0x%x moved from IB_QPS_SQE to IB_QPS_RTS\n",
			__func__, send_ring->send_qp->qp_num);
	} else {
		pr_warn("QP (%d) will stay in state: %d\n",
			send_ring->send_qp->qp_num, qp_attr.qp_state);
		goto free_res;
	}

free_res:
	kfree(qp_work);
}

static void ipoib_ib_handle_tx_wc(struct ipoib_send_ring *send_ring,
				struct ib_wc *wc)
{
	struct net_device *dev = send_ring->dev;
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	unsigned int wr_id = wc->wr_id;
	struct ipoib_tx_buf *tx_req;
	struct ipoib_ah *ah;

	ipoib_dbg_data(priv, "send completion: id %d, status: %d\n",
		       wr_id, wc->status);

	if (unlikely(wr_id >= priv->sendq_size)) {
		ipoib_warn(priv, "send completion event with wrid %d (> %d)\n",
			   wr_id, priv->sendq_size);
		return;
	}

	tx_req = &send_ring->tx_ring[wr_id];

	ah = tx_req->ah;
	atomic_dec(&ah->refcnt);
	if (!tx_req->is_inline)
		ipoib_dma_unmap_tx(priv->ca, tx_req);

	dev_kfree_skb_any(tx_req->skb);

	++send_ring->tx_tail;
	if (unlikely(atomic_dec_return(&send_ring->tx_outstanding) <= priv->sendq_size >> 1) &&
	    __netif_subqueue_stopped(dev, send_ring->index) &&
	    test_bit(IPOIB_FLAG_ADMIN_UP, &priv->flags))
		netif_wake_subqueue(dev, send_ring->index);

	if (wc->status != IB_WC_SUCCESS &&
	    wc->status != IB_WC_WR_FLUSH_ERR) {
		struct ipoib_qp_state_validate *qp_work;
		ipoib_warn(priv, "failed send event "
			   "(status=%d, wrid=%d vend_err %x)\n",
			   wc->status, wr_id, wc->vendor_err);
		qp_work = kzalloc(sizeof(*qp_work), GFP_ATOMIC);
		if (!qp_work) {
				ipoib_warn(priv, "%s Failed alloc ipoib_qp_state_validate for qp: 0x%x\n"
						 "The QP can be non-functional.",
					   __func__, send_ring->send_qp->qp_num);
				return;
		}
		INIT_WORK(&qp_work->work, ipoib_qp_state_validate_work);
		qp_work->priv = priv;
		qp_work->send_ring = send_ring;
		if (!test_bit(IPOIB_FLAG_INTF_ON_DESTROY, &priv->flags))
			queue_work(ipoib_workqueue, &qp_work->work);
		else
			kfree(qp_work);
	}
}

static int poll_tx_ring(struct ipoib_send_ring *send_ring)
{
	int n, i;

	n = ib_poll_cq(send_ring->send_cq, MAX_SEND_CQE, send_ring->tx_wc);
	for (i = 0; i < n; ++i)
		ipoib_ib_handle_tx_wc(send_ring, send_ring->tx_wc + i);

	return n == MAX_SEND_CQE;
}

int ipoib_rx_poll(struct napi_struct *napi, int budget)
{
	struct ipoib_recv_ring *rx_ring;
	struct net_device *dev;
	int n, i;
	struct ib_wc *wc;

	rx_ring = container_of(napi, struct ipoib_recv_ring, napi);
	dev = rx_ring->dev;

poll_more:

	n = ib_poll_cq(rx_ring->recv_cq, IPOIB_NUM_WC, rx_ring->ibwc);

	for (i = 0; i < n; i++) {
		wc = rx_ring->ibwc + i;

		if (wc->wr_id & IPOIB_OP_CM)
			ipoib_cm_handle_rx_wc(dev, rx_ring, wc);
		else
			ipoib_ib_handle_rx_wc(dev, rx_ring, wc);
	}

	if (n < budget) {
		napi_complete(napi);
		if (unlikely(ib_req_notify_cq(rx_ring->recv_cq,
					      IB_CQ_NEXT_COMP |
					      IB_CQ_REPORT_MISSED_EVENTS)) &&
					    napi_reschedule(napi))
			goto poll_more;
	}

	return (n < 0 ? 0 : n);
}

int ipoib_tx_poll(struct napi_struct *napi, int budget)
{
	struct ipoib_send_ring *send_ring;
	struct net_device *dev;
	int n, i;
	struct ib_wc *wc;

	send_ring = container_of(napi, struct ipoib_send_ring, napi);
	dev = send_ring->dev;

poll_more:

	n = ib_poll_cq(send_ring->send_cq, MAX_SEND_CQE, send_ring->tx_wc);

	for (i = 0; i < n; i++) {
		wc = send_ring->tx_wc + i;
		if (wc->wr_id & IPOIB_OP_CM)
			ipoib_cm_handle_tx_wc(dev, wc);
		else
			ipoib_ib_handle_tx_wc(send_ring, wc);
	}

	if (n < budget) {
		napi_complete(napi);
		if (unlikely(ib_req_notify_cq(send_ring->send_cq, IB_CQ_NEXT_COMP)) &&
		    napi_reschedule(napi))
			goto poll_more;
	}

	return n < 0 ? 0 : n;
}

void ipoib_ib_rx_completion(struct ib_cq *cq, void *ctx_ptr)
{
	struct ipoib_recv_ring *recv_ring = (struct ipoib_recv_ring *)ctx_ptr;

	napi_schedule(&recv_ring->napi);
}

void ipoib_ib_tx_completion(struct ib_cq *cq, void *ctx_ptr)
{
	struct ipoib_send_ring *send_ring = (struct ipoib_send_ring *)ctx_ptr;

	napi_schedule(&send_ring->napi);
}

static inline int post_send(struct ipoib_send_ring *send_ring,
			    unsigned int wr_id,
			    struct ib_ah *address, u32 qpn,
			    struct ipoib_tx_buf *tx_req,
			    void *head, int hlen, int use_inline)
{
	struct ib_send_wr *bad_wr;
	int i, off;
	struct sk_buff *skb = tx_req->skb;
	skb_frag_t *frags = skb_shinfo(skb)->frags;
	int nr_frags = skb_shinfo(skb)->nr_frags;
	u64 *mapping = tx_req->mapping;

	if (use_inline) {
		send_ring->tx_sge[0].addr         =  (u64)skb->data;
		send_ring->tx_sge[0].length       = skb->len;
		send_ring->tx_wr.num_sge	 = 1;
	} else {
		if (skb_headlen(skb)) {
			send_ring->tx_sge[0].addr         = mapping[0];
			send_ring->tx_sge[0].length       = skb_headlen(skb);
			off = 1;
		} else
			off = 0;

		for (i = 0; i < nr_frags; ++i) {
			send_ring->tx_sge[i + off].addr = mapping[i + off];
			send_ring->tx_sge[i + off].length =
					skb_frag_size(&frags[i]);
		}

		send_ring->tx_wr.num_sge	 = nr_frags + off;
	}

	send_ring->tx_wr.wr_id		 = wr_id;
	send_ring->tx_wr.wr.ud.remote_qpn = qpn;
	send_ring->tx_wr.wr.ud.ah	 = address;

	if (head) {
		send_ring->tx_wr.wr.ud.mss	 = skb_shinfo(skb)->gso_size;
		send_ring->tx_wr.wr.ud.header = head;
		send_ring->tx_wr.wr.ud.hlen	 = hlen;
		send_ring->tx_wr.opcode	 = IB_WR_LSO;
	} else
		send_ring->tx_wr.opcode	 = IB_WR_SEND;

	return ib_post_send(send_ring->send_qp, &send_ring->tx_wr, &bad_wr);
}

void ipoib_send(struct net_device *dev, struct sk_buff *skb,
		struct ipoib_ah *address, u32 qpn)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_tx_buf *tx_req;
	struct ipoib_send_ring *send_ring;
	u16 queue_index;
	int hlen, rc;
	void *phead;
	int req_index;

	/* Find the correct QP to submit the IO to */
	queue_index = skb_get_queue_mapping(skb);
	send_ring = priv->send_ring + queue_index;

	if (skb_is_gso(skb)) {
		hlen = skb_transport_offset(skb) + tcp_hdrlen(skb);
		phead = skb->data;
		if (unlikely(!skb_pull(skb, hlen) ||
			     (skb_shinfo(skb)->gso_size > priv->max_ib_mtu))) {
			ipoib_warn(priv, "linear data too small: hlen: %d Or skb_shinfo(skb)->gso_size: %d is bigger than port-mtu: %d\n",
				   hlen, skb_shinfo(skb)->gso_size, priv->max_ib_mtu);
			++send_ring->stats.tx_dropped;
			++send_ring->stats.tx_errors;
			dev_kfree_skb_any(skb);
			return;
		}
	} else {
		if (unlikely(skb->len > priv->mcast_mtu + IPOIB_ENCAP_LEN)) {
			ipoib_warn(priv, "%s: packet len %d (> %d) too long to send, dropping\n",
				   __func__, skb->len, priv->mcast_mtu + IPOIB_ENCAP_LEN);
			++send_ring->stats.tx_dropped;
			++send_ring->stats.tx_errors;
			ipoib_cm_skb_too_long(dev, skb, priv->mcast_mtu);

			dev_kfree_skb_any(skb);
			return;
		}
		phead = NULL;
		hlen  = 0;
	}

	ipoib_dbg_data(priv, "sending packet, length=%d address=%p qpn=0x%06x\n",
		       skb->len, address, qpn);

	/*
	 * We put the skb into the tx_ring _before_ we call post_send()
	 * because it's entirely possible that the completion handler will
	 * run before we execute anything after the post_send().  That
	 * means we have to make sure everything is properly recorded and
	 * our state is consistent before we call post_send().
	 */
	req_index = send_ring->tx_head & (priv->sendq_size - 1);
	tx_req = &send_ring->tx_ring[req_index];
	tx_req->skb = skb;
	tx_req->ah = address;

	if (skb->len < ipoib_inline_thold &&
			!skb_shinfo(skb)->nr_frags) {
		tx_req->is_inline = 1;
		send_ring->tx_wr.send_flags |= IB_SEND_INLINE;
	} else {
		if (unlikely(ipoib_dma_map_tx(priv->ca, tx_req))) {
			++send_ring->stats.tx_errors;
			dev_kfree_skb_any(skb);
			return;
		}
		tx_req->is_inline = 0;
		send_ring->tx_wr.send_flags &= ~IB_SEND_INLINE;
	}

	if (skb->ip_summed == CHECKSUM_PARTIAL)
		send_ring->tx_wr.send_flags |= IB_SEND_IP_CSUM;
	else
		send_ring->tx_wr.send_flags &= ~IB_SEND_IP_CSUM;

	if (atomic_inc_return(&send_ring->tx_outstanding) == priv->sendq_size) {
		ipoib_dbg(priv, "TX ring full, stopping kernel net queue\n");
		if (ib_req_notify_cq(send_ring->send_cq, IB_CQ_NEXT_COMP))
			ipoib_warn(priv, "request notify on send CQ failed\n");
		netif_stop_subqueue(dev, queue_index);
	}

	/*
	 * Incrementing the reference count after submitting
	 * may create race condition
	 * It is better to increment before and decrement in case of error
	 */
	atomic_inc(&address->refcnt);

	skb_orphan(skb);
	skb_dst_drop(skb);

	rc = post_send(send_ring, req_index,
		       address->ah, qpn, tx_req, phead, hlen,
		       tx_req->is_inline);
	if (unlikely(rc)) {
		ipoib_warn(priv, "%s: post_send failed, error %d, queue_index:%d skb->len: %d\n",
			   __func__, rc, queue_index, skb->len);
		++send_ring->stats.tx_errors;
		atomic_dec(&send_ring->tx_outstanding);
		if (!tx_req->is_inline)
			ipoib_dma_unmap_tx(priv->ca, tx_req);
		dev_kfree_skb_any(skb);
		atomic_dec(&address->refcnt);
		if (__netif_subqueue_stopped(dev, queue_index))
			netif_wake_subqueue(dev, queue_index);
	} else {
		netdev_get_tx_queue(dev, queue_index)->trans_start = jiffies;
		++send_ring->stats.tx_packets;
		send_ring->stats.tx_bytes += skb->len;

		++send_ring->tx_head;
	}
}

static void __ipoib_reap_ah(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_ah *ah, *tah;
	LIST_HEAD(remove_list);
	unsigned long flags;

	netif_tx_lock_bh(dev);
	spin_lock_irqsave(&priv->lock, flags);

	list_for_each_entry_safe(ah, tah, &priv->dead_ahs, list)
		if (atomic_read(&ah->refcnt) == 0) {
			list_del(&ah->list);
			ib_destroy_ah(ah->ah);
			kfree(ah);
		}

	spin_unlock_irqrestore(&priv->lock, flags);
	netif_tx_unlock_bh(dev);
}

void ipoib_reap_ah(struct work_struct *work)
{
	struct ipoib_dev_priv *priv =
		container_of(work, struct ipoib_dev_priv, ah_reap_task.work);
	struct net_device *dev = priv->dev;

	__ipoib_reap_ah(dev);

	if (!test_bit(IPOIB_STOP_REAPER, &priv->flags) &&
	    !test_bit(IPOIB_FLAG_INTF_ON_DESTROY, &priv->flags))
		queue_delayed_work(ipoib_workqueue, &priv->ah_reap_task,
				   round_jiffies_relative(HZ));
}

static void ipoib_napi_enable(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_recv_ring *recv_ring;
	struct ipoib_send_ring *send_ring;
	int i;

	recv_ring = priv->recv_ring;
	for (i = 0; i < priv->num_rx_queues; i++) {
		netif_napi_add(dev, &recv_ring->napi,
						ipoib_rx_poll, IPOIB_NUM_WC);
		napi_enable(&recv_ring->napi);
		recv_ring++;
	}

	send_ring = priv->send_ring;
	for (i = 0; i < priv->num_tx_queues; i++) {
		netif_napi_add(dev, &send_ring->napi,
			       ipoib_tx_poll, MAX_SEND_CQE);
		napi_enable(&send_ring->napi);
		send_ring++;
	}
}

static void ipoib_napi_disable(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	int i;

	for (i = 0; i < priv->num_rx_queues; i++) {
		napi_disable(&priv->recv_ring[i].napi);
		netif_napi_del(&priv->recv_ring[i].napi);
	}

	for (i = 0; i < priv->num_tx_queues; i++) {
		napi_disable(&priv->send_ring[i].napi);
		netif_napi_del(&priv->send_ring[i].napi);
	}
}

int ipoib_ib_dev_open(struct net_device *dev, int flush)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	int ret;
	int i;
	struct ipoib_recv_ring *recv_ring;

	if (test_bit(IPOIB_FLAG_INTF_ON_DESTROY, &priv->flags)) {
		pr_warn("%s was called for device: %s which is going to be deleted\n",
			__func__, dev->name);
		return -1;
	}

	if (ib_find_pkey(priv->ca, priv->port, priv->pkey, &priv->pkey_index)) {
		ipoib_warn(priv, "P_Key 0x%04x not found\n", priv->pkey);
		clear_bit(IPOIB_PKEY_ASSIGNED, &priv->flags);
		return -1;
	}
	set_bit(IPOIB_PKEY_ASSIGNED, &priv->flags);

	/* keep from 2 dev_open at the same time */
	if (!test_and_set_bit(IPOIB_FLAG_INITIALIZED, &priv->flags)) {
		/* all qp state change are under mutex */
		mutex_lock(&priv->ring_qp_lock);
		ret = ipoib_init_qp(dev);
		mutex_unlock(&priv->ring_qp_lock);
		if (ret) {
			ipoib_warn(priv, "ipoib_init_qp returned %d\n", ret);
			clear_bit(IPOIB_FLAG_INITIALIZED, &priv->flags);
			return -1;
		}

		ipoib_napi_enable(dev);

		ret = ipoib_ib_post_receives(dev);
		if (ret) {
			ipoib_warn(priv, "ipoib_ib_post_receives returned %d\n", ret);
			goto dev_stop;
		}

		ret = ipoib_cm_dev_open(dev);
		if (ret) {
			ipoib_warn(priv, "ipoib_cm_dev_open returned %d\n", ret);
			goto dev_stop;
		}
	}

	/* make sure the ring is not full, go over all rings and enable napi */
	recv_ring = priv->recv_ring;
	for (i = 0; i < priv->num_rx_queues; i++) {
		napi_reschedule(&recv_ring->napi);
		recv_ring++;
	}

	if (!test_bit(IPOIB_FLAG_INTF_ON_DESTROY, &priv->flags)) {
		clear_bit(IPOIB_STOP_REAPER, &priv->flags);
		queue_delayed_work(ipoib_workqueue, &priv->ah_reap_task,
				   round_jiffies_relative(HZ));
	}

	return 0;
dev_stop:
	ipoib_ib_dev_stop(dev, flush);
	return -1;
}

void ipoib_pkey_dev_check_presence(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	u16 pkey_index = 0;

	if (ib_find_pkey(priv->ca, priv->port, priv->pkey, &pkey_index))
		clear_bit(IPOIB_PKEY_ASSIGNED, &priv->flags);
	else
		set_bit(IPOIB_PKEY_ASSIGNED, &priv->flags);
}

int ipoib_ib_dev_up(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);

	ipoib_pkey_dev_check_presence(dev);

	if (!test_bit(IPOIB_PKEY_ASSIGNED, &priv->flags)) {
		ipoib_dbg(priv, "PKEY is not assigned.\n");
		return 0;
	}

	set_bit(IPOIB_FLAG_OPER_UP, &priv->flags);
	set_bit(IPOIB_FLAG_AUTO_MODER, &priv->flags);

	return ipoib_mcast_start_thread(dev);
}

int ipoib_ib_dev_down(struct net_device *dev, int flush)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);

	ipoib_dbg(priv, "downing ib_dev\n");

	clear_bit(IPOIB_FLAG_OPER_UP, &priv->flags);
	netif_carrier_off(dev);

	/* cancell the adaptive moderation task. */
	if (test_and_clear_bit(IPOIB_FLAG_AUTO_MODER, &priv->flags))
		cancel_delayed_work_sync(&priv->adaptive_moder_task);

	flush_workqueue(ipoib_auto_moder_workqueue);

	ipoib_flush_paths(dev);

	ipoib_mcast_stop_thread(dev, flush);
	ipoib_mcast_dev_flush(dev);

	return 0;
}

/* Clean all the skb's that created for the re-use process*/
static void clean_reused_skb(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_recv_ring *recv_ring;
	int i, j;
	struct ipoib_rx_buf *rx_buf;
	struct ipoib_skb *rx_skb;

	recv_ring = priv->recv_ring;
	for (j = 0; j < priv->num_rx_queues; j++) {
		for (i = 0; i < priv->recvq_size; ++i) {
			rx_buf = &recv_ring->rx_ring[i];
			rx_skb = &rx_buf->rx_skb[(rx_buf->skb_index + 1) % IPOIB_NUM_RX_SKB];
			if (rx_skb->skb) {
				ipoib_ud_dma_unmap_rx(priv, rx_skb->mapping);
				dev_kfree_skb_any(rx_skb->skb);
				rx_skb->skb = NULL;
			}
		}
		recv_ring++;
	}
}

static int recvs_pending(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_recv_ring *recv_ring;
	int pending = 0;
	int i, j, k;

	recv_ring = priv->recv_ring;
	for (j = 0; j < priv->num_rx_queues; j++) {
		for (i = 0; i < priv->recvq_size; ++i) {
			struct ipoib_rx_buf *rx_req = &recv_ring->rx_ring[i];
			for (k = 0; k < IPOIB_NUM_RX_SKB; k++) {
				struct ipoib_skb *rx_skb = &rx_req->rx_skb[k];
				if (rx_skb->skb)
					++pending;
			}
		}
		recv_ring++;
	}

	return pending;
}

static int sends_pending(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_send_ring *send_ring;
	int pending = 0;
	int i;

	send_ring = priv->send_ring;
	for (i = 0; i < priv->num_tx_queues; i++) {
		/*
		* Note that since head and tails are unsigned then
		* the result of the substruction is correct even when
		* the counters wrap around
		*/
		pending += send_ring->tx_head - send_ring->tx_tail;
		send_ring++;
	}

	return pending;
}

static void ipoib_drain_rx_ring(struct ipoib_dev_priv *priv,
				struct ipoib_recv_ring *rx_ring)
{
	struct net_device *dev = priv->dev;
	int i, n;

	/*
	 * We call completion handling routines that expect to be
	 * called from the BH-disabled NAPI poll context, so disable
	 * BHs here too.
	 */
	local_bh_disable();

	do {
		n = ib_poll_cq(rx_ring->recv_cq, IPOIB_NUM_WC, rx_ring->ibwc);
		for (i = 0; i < n; ++i) {
			/*
			 * Convert any successful completions to flush
			 * errors to avoid passing packets up the
			 * stack after bringing the device down.
			 */
			if (rx_ring->ibwc[i].status == IB_WC_SUCCESS)
				rx_ring->ibwc[i].status = IB_WC_WR_FLUSH_ERR;

			if (rx_ring->ibwc[i].wr_id & IPOIB_OP_RECV) {
				if (rx_ring->ibwc[i].wr_id & IPOIB_OP_CM)
					ipoib_cm_handle_rx_wc(dev, rx_ring,
							rx_ring->ibwc + i);
				else
					ipoib_ib_handle_rx_wc(dev, rx_ring,
							rx_ring->ibwc + i);
			} else
				ipoib_cm_handle_tx_wc(dev, rx_ring->ibwc + i);
		}
	} while (n == IPOIB_NUM_WC);

	local_bh_enable();
}

static void drain_rx_rings(struct ipoib_dev_priv *priv)
{
	struct ipoib_recv_ring *recv_ring;
	int i;

	recv_ring = priv->recv_ring;
	for (i = 0; i < priv->num_rx_queues; i++) {
		ipoib_drain_rx_ring(priv, recv_ring);
		recv_ring++;
	}
}


static void drain_tx_rings(struct ipoib_dev_priv *priv)
{
	struct ipoib_send_ring *send_ring;
	int bool_value = 0;
	int i;

	do {
		bool_value = 0;
		send_ring = priv->send_ring;
		for (i = 0; i < priv->num_tx_queues; i++) {
			local_bh_disable();
			bool_value |= poll_tx_ring(send_ring);
			local_bh_enable();
			send_ring++;
		}
	} while (bool_value);
}

/* Rearm Recv and Send CQ */
void ipoib_arm_cq(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_recv_ring *recv_ring;
	struct ipoib_send_ring *send_ring;
	int i;

	recv_ring = priv->recv_ring;
	for (i = 0; i < priv->num_rx_queues; i++) {
		ib_req_notify_cq(recv_ring->recv_cq, IB_CQ_NEXT_COMP);
		recv_ring++;
	}

	send_ring = priv->send_ring;
	for (i = 0; i < priv->num_tx_queues; i++) {
		ib_req_notify_cq(send_ring->send_cq, IB_CQ_NEXT_COMP);
		send_ring++;
	}
}

void ipoib_drain_cq(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);

	drain_rx_rings(priv);

	drain_tx_rings(priv);
}

static void ipoib_ib_send_ring_stop(struct ipoib_dev_priv *priv)
{
	struct ipoib_send_ring *tx_ring;
	struct ipoib_tx_buf *tx_req;
	int i;

	tx_ring = priv->send_ring;
	for (i = 0; i < priv->num_tx_queues; i++) {
		while ((int) tx_ring->tx_tail - (int) tx_ring->tx_head < 0) {
			tx_req = &tx_ring->tx_ring[tx_ring->tx_tail &
				  (priv->sendq_size - 1)];
			if (!tx_req->is_inline)
				ipoib_dma_unmap_tx(priv->ca, tx_req);
			dev_kfree_skb_any(tx_req->skb);
			++tx_ring->tx_tail;
			atomic_dec(&tx_ring->tx_outstanding);
		}
		tx_ring++;
	}
}

static void ipoib_ib_recv_ring_stop(struct ipoib_dev_priv *priv)
{
	struct ipoib_recv_ring *recv_ring;
	int i, j, k;

	recv_ring = priv->recv_ring;
	for (j = 0; j < priv->num_rx_queues; ++j) {
		for (i = 0; i < priv->recvq_size; ++i) {
			struct ipoib_rx_buf *rx_req = &recv_ring->rx_ring[i];
			for (k = 0; k < IPOIB_NUM_RX_SKB; k++) {
				struct ipoib_skb *rx_skb = &rx_req->rx_skb[k];
				if (!rx_skb->skb)
					continue;
				ipoib_ud_dma_unmap_rx(priv, rx_skb->mapping);
				dev_kfree_skb_any(rx_skb->skb);
				rx_skb->skb = NULL;
			}
		}
		recv_ring++;
	}
}

static void check_qp_movment_and_print(struct ipoib_dev_priv *priv, struct ib_qp *qp,
				       enum ib_qp_state new_state)
{
	struct ib_qp_attr qp_attr;
	struct ib_qp_init_attr query_init_attr;
	int ret;

	ret = ib_query_qp(qp, &qp_attr, IB_QP_STATE, &query_init_attr);
	if (ret) {
		ipoib_warn(priv, "%s: Failed to query QP \n", __func__);
		return;
	}
	/* print according to the new-state and the previous state.*/
	if (IB_QPS_ERR == new_state && qp_attr.qp_state == IB_QPS_RESET)
		ipoib_dbg(priv, "Failed to modify QP from"
				" IB_QPS_RESET to IB_QPS_ERR - acceptable.\n");
	else
		ipoib_warn(priv, "Failed to modify QP to state: %d from state: %d\n",
			   new_state, qp_attr.qp_state);
}

static void set_tx_rings_qp_state(struct ipoib_dev_priv *priv,
					enum ib_qp_state new_state)
{
	struct ipoib_send_ring *send_ring;
	struct ib_qp_attr qp_attr;
	int i;

	send_ring = priv->send_ring;
	for (i = 0; i <  priv->num_tx_queues; i++) {
		qp_attr.qp_state = new_state;
		if (ib_modify_qp(send_ring->send_qp, &qp_attr, IB_QP_STATE))
			check_qp_movment_and_print(priv, send_ring->send_qp, new_state);

		send_ring++;
	}
}

static void set_rx_rings_qp_state(struct ipoib_dev_priv *priv,
					enum ib_qp_state new_state)
{
	struct ipoib_recv_ring *recv_ring;
	struct ib_qp_attr qp_attr;
	int i;

	recv_ring = priv->recv_ring;
	for (i = 0; i < priv->num_rx_queues; i++) {
		qp_attr.qp_state = new_state;
		if (ib_modify_qp(recv_ring->recv_qp, &qp_attr, IB_QP_STATE))
			check_qp_movment_and_print(priv, recv_ring->recv_qp, new_state);

		recv_ring++;
	}
}

static void set_rings_qp_state(struct ipoib_dev_priv *priv,
				enum ib_qp_state new_state)
{
	if (priv->hca_caps & IB_DEVICE_UD_TSS) {
		/* TSS HW is supported, parent QP has no ring (send_ring) */
		struct ib_qp_attr qp_attr;
		qp_attr.qp_state = new_state;
		if (ib_modify_qp(priv->qp, &qp_attr, IB_QP_STATE))
			check_qp_movment_and_print(priv, priv->qp, new_state);
	}

	set_tx_rings_qp_state(priv, new_state);

	if (priv->num_rx_queues > 1)
		set_rx_rings_qp_state(priv, new_state);
}
/*
 * The function tries to clean the list of ah's that waiting for deleting.
 * it tries for one HZ if it wasn't clear till then it print message
 *  and out.
 */
static void ipoib_force_reap_ah_clean(struct ipoib_dev_priv *priv)
{
	unsigned long begin;

	begin = jiffies;

	while (!list_empty(&priv->dead_ahs)) {
		__ipoib_reap_ah(priv->dev);

		if (time_after(jiffies, begin + HZ)) {
			ipoib_warn(priv, "timing out; will leak address handles\n");
			break;
		}

		msleep(1);
	}

}

int ipoib_ib_dev_stop(struct net_device *dev, int flush)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_recv_ring *recv_ring;
	struct ipoib_send_ring *send_ring;
	int i;
	unsigned long begin;

	if (test_and_clear_bit(IPOIB_FLAG_INITIALIZED, &priv->flags))
		ipoib_napi_disable(dev);

	ipoib_cm_dev_stop(dev);

	/*
	 * Move our QP to the error state and then reinitialize in
	 * when all work requests have completed or have been flushed.
	 */
	mutex_lock(&priv->ring_qp_lock);

	set_rings_qp_state(priv, IB_QPS_ERR);
	clean_reused_skb(dev);

	/* Wait for all sends and receives to complete */
	begin = jiffies;

	while (sends_pending(dev) || recvs_pending(dev)) {
		ipoib_drain_cq(dev);

		if (time_after(jiffies, begin + 5 * HZ)) {
			ipoib_warn(priv, "timing out; %d sends %d receives not completed\n",
				   sends_pending(dev), recvs_pending(dev));
			/*
			 * assume the HW is wedged and just free up
			 * all our pending work requests.
			 */
			ipoib_ib_send_ring_stop(priv);

			ipoib_ib_recv_ring_stop(priv);

			goto timeout;
		}
		msleep(1);
	}

	ipoib_dbg(priv, "All sends and receives done.\n");

timeout:

	set_rings_qp_state(priv, IB_QPS_RESET);

	mutex_unlock(&priv->ring_qp_lock);

	/* Wait for all AHs to be reaped */
	set_bit(IPOIB_STOP_REAPER, &priv->flags);
	cancel_delayed_work_sync(&priv->ah_reap_task);
	if (flush)
		flush_workqueue(ipoib_workqueue);

	ipoib_force_reap_ah_clean(priv);

	recv_ring = priv->recv_ring;
	for (i = 0; i < priv->num_rx_queues; ++i) {
		ib_req_notify_cq(recv_ring->recv_cq, IB_CQ_NEXT_COMP);
		recv_ring++;
	}

	send_ring = priv->send_ring;
	for (i = 0; i < priv->num_tx_queues; i++) {
		ib_req_notify_cq(send_ring->send_cq, IB_CQ_NEXT_COMP);
		send_ring++;
	}

	return 0;
}

int ipoib_ib_dev_init(struct net_device *dev, struct ib_device *ca, int port)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);

	priv->ca = ca;
	priv->port = port;
	priv->qp = NULL;

	if (ipoib_transport_dev_init(dev, ca)) {
		printk(KERN_WARNING "%s: ipoib_transport_dev_init failed\n", ca->name);
		return -ENODEV;
	}


	if (dev->flags & IFF_UP) {
		if (ipoib_ib_dev_open(dev, 1)) {
			ipoib_transport_dev_cleanup(dev);
			return -ENODEV;
		}
	}

	return 0;
}

/*
 * Takes whatever it is in pkey-index 0.
 * return 0 if the pkey value was changed.
 * the function updates priv->pkey.
 * relevant only for parent interfaces (ib0, ib1, etc.)
 */
static inline int update_pkey_index_0(struct ipoib_dev_priv *priv)
{
	int result;
	u16 prev_pkey;

	prev_pkey = priv->pkey;
	result = ib_query_pkey(priv->ca, priv->port, 0, &priv->pkey);
	if (result) {
		ipoib_warn(priv, "ib_query_pkey port %d failed (ret = %d)\n",
			   priv->port, result);
		return result;
	}

	priv->pkey |= 0x8000;

	if (prev_pkey != priv->pkey) {
		ipoib_dbg(priv, "pkey changed from 0x%x to 0x%x\n",
			  prev_pkey, priv->pkey);
		/*
		 * Update the pkey in the broadcast address, while making sure to set
		 * the full membership bit, so that we join the right broadcast group.
		 */
		priv->dev->broadcast[8] = priv->pkey >> 8;
		priv->dev->broadcast[9] = priv->pkey & 0xff;

		/*
		 * update the broadcast address in the priv->broadcast object,
		 * in case it already exists, otherwise no one will do that.
		 */
		if (priv->broadcast) {
			spin_lock_irq(&priv->lock);
			memcpy(priv->broadcast->mcmember.mgid.raw,
			       priv->dev->broadcast + 4,
			       sizeof(union ib_gid));
			spin_unlock_irq(&priv->lock);
		}

		return 0;
	}

	return 1;
}

static void __ipoib_ib_dev_flush(struct ipoib_dev_priv *priv,
				enum ipoib_flush_level level)
{
	struct ipoib_dev_priv *cpriv;
	struct net_device *dev = priv->dev;
	u16 new_index;
	int result;

	down_read_nested(&priv->vlan_rwsem,
			 test_bit(IPOIB_FLAG_SUBINTERFACE, &priv->flags));

	/*
	 * Flush any child interfaces too -- they might be up even if
	 * the parent is down.
	 */
	list_for_each_entry(cpriv, &priv->child_intfs, list) {
		/* trigger event only on childs that are not going to be deleted */
		if (!test_bit(IPOIB_FLAG_INTF_ON_DESTROY, &cpriv->flags))
			__ipoib_ib_dev_flush(cpriv, level);
	}

	up_read(&priv->vlan_rwsem);

	if (!test_bit(IPOIB_FLAG_INITIALIZED, &priv->flags)) {
		/* check if needs to update the pkey value */
		if (level == IPOIB_FLUSH_HEAVY) {
			if (test_bit(IPOIB_FLAG_SUBINTERFACE, &priv->flags)) {
				if (test_bit(IPOIB_FLAG_ADMIN_UP, &priv->flags))
					ipoib_pkey_open(priv);
			} else {
				update_pkey_index_0(priv);
			}
		}
		ipoib_dbg(priv, "Not flushing - IPOIB_FLAG_INITIALIZED not set.\n");
		return;
	}

	if (!test_bit(IPOIB_FLAG_ADMIN_UP, &priv->flags)) {
		ipoib_dbg(priv, "Not flushing - IPOIB_FLAG_ADMIN_UP not set.\n");
		return;
	}

	if (level == IPOIB_FLUSH_HEAVY) {
		/*
		 * child-interface should chase after its origin pkey value.
		 * parent interface should always takes what it finds in
		 * pkey-index 0.
		 */
		if (test_bit(IPOIB_FLAG_SUBINTERFACE, &priv->flags)) {
			if (ib_find_pkey(priv->ca, priv->port, priv->pkey, &new_index)) {
				clear_bit(IPOIB_PKEY_ASSIGNED, &priv->flags);
				ipoib_ib_dev_down(dev, 0);
				ipoib_ib_dev_stop(dev, 0);
				return;
			}
			/* restart QP only if P_Key index is changed */
			if (test_and_set_bit(IPOIB_PKEY_ASSIGNED, &priv->flags) &&
			    new_index == priv->pkey_index) {
				ipoib_dbg(priv, "Not flushing - P_Key index not changed.\n");
				return;
			}
			priv->pkey_index = new_index;
		} else {
			/* takes whatever find in index 0, return 0 if value changed. */
			result = update_pkey_index_0(priv);
			/* only if pkey value changed, force heavy_flush */
			if (result) {
				ipoib_dbg(priv, "Not flushing - P_Key index not changed.\n");
				return;
			}
		}
	}

	if (level == IPOIB_FLUSH_LIGHT) {
		ipoib_mark_paths_invalid(dev);
		ipoib_mcast_dev_flush(dev);
	}

	if (level >= IPOIB_FLUSH_NORMAL)
		ipoib_ib_dev_down(dev, 0);

	if (level == IPOIB_FLUSH_HEAVY) {
		ipoib_ib_dev_stop(dev, 0);
		ipoib_ib_dev_open(dev, 0);
	}

	/*
	 * The device could have been brought down between the start and when
	 * we get here, don't bring it back up if it's not configured up
	 */
	if (test_bit(IPOIB_FLAG_ADMIN_UP, &priv->flags)) {
		if (level >= IPOIB_FLUSH_NORMAL)
			ipoib_ib_dev_up(dev);
		ipoib_mcast_restart_task(&priv->restart_task);
	}
}

void ipoib_ib_dev_flush_light(struct work_struct *work)
{
	struct ipoib_dev_priv *priv =
		container_of(work, struct ipoib_dev_priv, flush_light);

	__ipoib_ib_dev_flush(priv, IPOIB_FLUSH_LIGHT);
}

void ipoib_ib_dev_flush_normal(struct work_struct *work)
{
	struct ipoib_dev_priv *priv =
		container_of(work, struct ipoib_dev_priv, flush_normal);

	__ipoib_ib_dev_flush(priv, IPOIB_FLUSH_NORMAL);
}

void ipoib_ib_dev_flush_heavy(struct work_struct *work)
{
	struct ipoib_dev_priv *priv =
		container_of(work, struct ipoib_dev_priv, flush_heavy);

	__ipoib_ib_dev_flush(priv, IPOIB_FLUSH_HEAVY);
}

void ipoib_ib_dev_cleanup(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);

	ipoib_dbg(priv, "cleaning up ib_dev\n");

	/* only after the net_device already initialized. */
	if (dev->reg_state != NETREG_UNINITIALIZED) {
		/*
		 * We must make sure there are no more (path)completions
		 * that may wish to touch priv fields that may no longe r be valid.
		 */
		ipoib_flush_paths(dev);

		ipoib_mcast_stop_thread(dev, 1);
		ipoib_mcast_dev_flush(dev);

		ipoib_force_reap_ah_clean(priv);
		set_bit(IPOIB_STOP_REAPER, &priv->flags);
		cancel_delayed_work_sync(&priv->ah_reap_task);
	}

	ipoib_transport_dev_cleanup(dev);
}

/* called from workqueue context, so no flush to workqueue */
void ipoib_pkey_open(struct ipoib_dev_priv *priv)
{
	if (test_bit(IPOIB_FLAG_INITIALIZED, &priv->flags))
		return;

	ipoib_pkey_dev_check_presence(priv->dev);

	if (!test_bit(IPOIB_PKEY_ASSIGNED, &priv->flags))
		return;

	if (ipoib_ib_dev_open(priv->dev, 0)) {
		pr_err("%s: failed to open device: %s\n", __func__, priv->dev->name);
		return;
	}

	if (ipoib_ib_dev_up(priv->dev)) {
		pr_err("%s: failed to start/up device: %s\n", __func__, priv->dev->name);
		ipoib_ib_dev_stop(priv->dev, 0);
		return;
	}

	if (test_bit(IPOIB_FLAG_ADMIN_UP, &priv->flags)) {
		netif_tx_start_all_queues(priv->dev);

		if (priv->ethtool.use_adaptive_rx_coalesce) {
			set_bit(IPOIB_FLAG_AUTO_MODER, &priv->flags);
			queue_delayed_work(ipoib_auto_moder_workqueue,
					   &priv->adaptive_moder_task,
					   ADAPT_MODERATION_DELAY);
		}
	}

	return;


}


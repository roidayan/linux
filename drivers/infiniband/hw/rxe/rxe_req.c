/*
 * Copyright (c) 2009-2011 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2009-2011 System Fabric Works, Inc. All rights reserved.
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
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
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

#include <linux/skbuff.h>

#include "rxe.h"
#include "rxe_loc.h"
#include "rxe_queue.h"

static int next_opcode(struct rxe_qp *qp, struct rxe_send_wqe *wqe,
		       unsigned opcode);

static inline void retry_first_write_send(struct rxe_qp *qp,
					  struct rxe_send_wqe *wqe,
					  unsigned mask, int npsn)
{
	int i;

	for (i = 0; i < npsn; i++) {
		int to_send = (wqe->dma.resid > qp->mtu) ?
				qp->mtu : wqe->dma.resid;

		qp->req.opcode = next_opcode(qp, wqe,
					     wqe->ibwr.opcode);

		if (wqe->ibwr.send_flags & IB_SEND_INLINE) {
			wqe->dma.resid -= to_send;
			wqe->dma.sge_offset += to_send;
		} else {
			advance_dma_data(&wqe->dma, to_send);
		}
		if (mask & WR_WRITE_MASK)
			wqe->iova += qp->mtu;
	}
}

static void req_retry(struct rxe_qp *qp)
{
	struct rxe_send_wqe *wqe;
	unsigned int wqe_index;
	unsigned int mask;
	int npsn;
	int first = 1;

	wqe = queue_head(qp->sq.queue);
	npsn = (qp->comp.psn - wqe->first_psn) & BTH_PSN_MASK;

	qp->req.wqe_index	= consumer_index(qp->sq.queue);
	qp->req.psn		= qp->comp.psn;
	qp->req.opcode		= -1;

	for (wqe_index = consumer_index(qp->sq.queue);
		wqe_index != producer_index(qp->sq.queue);
		wqe_index = next_index(qp->sq.queue, wqe_index)) {
		wqe = addr_from_index(qp->sq.queue, wqe_index);
		mask = wr_opcode_mask(wqe->ibwr.opcode, qp);

		if (wqe->state == wqe_state_posted)
			break;

		if (wqe->state == wqe_state_done)
			continue;

		wqe->iova = (mask & WR_ATOMIC_MASK) ?
			wqe->ibwr.wr.atomic.remote_addr :
			wqe->ibwr.wr.rdma.remote_addr;

		if (!first || (mask & WR_READ_MASK) == 0) {
			wqe->dma.resid = wqe->dma.length;
			wqe->dma.cur_sge = 0;
			wqe->dma.sge_offset = 0;
		}

		if (first) {
			first = 0;

			if (mask & WR_WRITE_OR_SEND_MASK)
				retry_first_write_send(qp, wqe, mask, npsn);

			if (mask & WR_READ_MASK)
				wqe->iova += npsn*qp->mtu;
		}

		wqe->state = wqe_state_posted;
	}
}

void rnr_nak_timer(unsigned long data)
{
	struct rxe_qp *qp = (struct rxe_qp *)data;

	pr_debug("rnr nak timer fired\n");
	rxe_run_task(&qp->req.task, 1);
}

static struct rxe_send_wqe *req_next_wqe(struct rxe_qp *qp)
{
	struct rxe_send_wqe *wqe = queue_head(qp->sq.queue);

	if (unlikely(qp->req.state == QP_STATE_DRAIN)) {
		/* check to see if we are drained;
		 * state_lock used by requester and completer */
		spin_lock_bh(&qp->state_lock);
		do {
			if (qp->req.state != QP_STATE_DRAIN) {
				/* comp just finished */
				spin_unlock_bh(&qp->state_lock);
				break;
			}

			if (wqe && ((qp->req.wqe_index !=
				consumer_index(qp->sq.queue)) ||
				(wqe->state != wqe_state_posted))) {
				/* comp not done yet */
				spin_unlock_bh(&qp->state_lock);
				break;
			}

			qp->req.state = QP_STATE_DRAINED;
			spin_unlock_bh(&qp->state_lock);

			if (qp->ibqp.event_handler) {
				struct ib_event ev;

				ev.device = qp->ibqp.device;
				ev.element.qp = &qp->ibqp;
				ev.event = IB_EVENT_SQ_DRAINED;
				qp->ibqp.event_handler(&ev,
					qp->ibqp.qp_context);
			}
		} while (0);
	}

	if (qp->req.wqe_index == producer_index(qp->sq.queue))
		return NULL;

	wqe = addr_from_index(qp->sq.queue, qp->req.wqe_index);

	if (qp->req.state == QP_STATE_DRAIN ||
	    qp->req.state == QP_STATE_DRAINED)
		if (wqe->state != wqe_state_processing)
			return NULL;

	if ((wqe->ibwr.send_flags & IB_SEND_FENCE) &&
	    (qp->req.wqe_index != consumer_index(qp->sq.queue))) {
		qp->req.wait_fence = 1;
		return NULL;
	}

	wqe->mask = wr_opcode_mask(wqe->ibwr.opcode, qp);
	return wqe;
}

static int next_opcode_rc(struct rxe_qp *qp, unsigned opcode, int fits)
{
	switch (opcode) {
	case IB_WR_RDMA_WRITE:
		if (qp->req.opcode == IB_OPCODE_RC_RDMA_WRITE_FIRST ||
		    qp->req.opcode == IB_OPCODE_RC_RDMA_WRITE_MIDDLE)
			return fits ?
				IB_OPCODE_RC_RDMA_WRITE_LAST :
				IB_OPCODE_RC_RDMA_WRITE_MIDDLE;
		else
			return fits ?
				IB_OPCODE_RC_RDMA_WRITE_ONLY :
				IB_OPCODE_RC_RDMA_WRITE_FIRST;

	case IB_WR_RDMA_WRITE_WITH_IMM:
		if (qp->req.opcode == IB_OPCODE_RC_RDMA_WRITE_FIRST ||
		    qp->req.opcode == IB_OPCODE_RC_RDMA_WRITE_MIDDLE)
			return fits ?
				IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE :
				IB_OPCODE_RC_RDMA_WRITE_MIDDLE;
		else
			return fits ?
				IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE :
				IB_OPCODE_RC_RDMA_WRITE_FIRST;

	case IB_WR_SEND:
		if (qp->req.opcode == IB_OPCODE_RC_SEND_FIRST ||
		    qp->req.opcode == IB_OPCODE_RC_SEND_MIDDLE)
			return fits ?
				IB_OPCODE_RC_SEND_LAST :
				IB_OPCODE_RC_SEND_MIDDLE;
		else
			return fits ?
				IB_OPCODE_RC_SEND_ONLY :
				IB_OPCODE_RC_SEND_FIRST;

	case IB_WR_SEND_WITH_IMM:
		if (qp->req.opcode == IB_OPCODE_RC_SEND_FIRST ||
		    qp->req.opcode == IB_OPCODE_RC_SEND_MIDDLE)
			return fits ?
				IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE :
				IB_OPCODE_RC_SEND_MIDDLE;
		else
			return fits ?
				IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE :
				IB_OPCODE_RC_SEND_FIRST;

	case IB_WR_RDMA_READ:
		return IB_OPCODE_RC_RDMA_READ_REQUEST;

	case IB_WR_ATOMIC_CMP_AND_SWP:
		return IB_OPCODE_RC_COMPARE_SWAP;

	case IB_WR_ATOMIC_FETCH_AND_ADD:
		return IB_OPCODE_RC_FETCH_ADD;

	case IB_WR_SEND_WITH_INV:
		if (qp->req.opcode == IB_OPCODE_RC_SEND_FIRST ||
		    qp->req.opcode == IB_OPCODE_RC_SEND_MIDDLE)
			return fits ? IB_OPCODE_RC_SEND_LAST_INV :
				IB_OPCODE_RC_SEND_MIDDLE;
		else
			return fits ? IB_OPCODE_RC_SEND_ONLY_INV :
				IB_OPCODE_RC_SEND_FIRST;
	}

	return -EINVAL;
}

static int next_opcode_uc(struct rxe_qp *qp, unsigned opcode, int fits)
{
	switch (opcode) {
	case IB_WR_RDMA_WRITE:
		if (qp->req.opcode == IB_OPCODE_UC_RDMA_WRITE_FIRST ||
		    qp->req.opcode == IB_OPCODE_UC_RDMA_WRITE_MIDDLE)
			return fits ?
				IB_OPCODE_UC_RDMA_WRITE_LAST :
				IB_OPCODE_UC_RDMA_WRITE_MIDDLE;
		else
			return fits ?
				IB_OPCODE_UC_RDMA_WRITE_ONLY :
				IB_OPCODE_UC_RDMA_WRITE_FIRST;

	case IB_WR_RDMA_WRITE_WITH_IMM:
		if (qp->req.opcode == IB_OPCODE_UC_RDMA_WRITE_FIRST ||
		    qp->req.opcode == IB_OPCODE_UC_RDMA_WRITE_MIDDLE)
			return fits ?
				IB_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE :
				IB_OPCODE_UC_RDMA_WRITE_MIDDLE;
		else
			return fits ?
				IB_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE :
				IB_OPCODE_UC_RDMA_WRITE_FIRST;

	case IB_WR_SEND:
		if (qp->req.opcode == IB_OPCODE_UC_SEND_FIRST ||
		    qp->req.opcode == IB_OPCODE_UC_SEND_MIDDLE)
			return fits ?
				IB_OPCODE_UC_SEND_LAST :
				IB_OPCODE_UC_SEND_MIDDLE;
		else
			return fits ?
				IB_OPCODE_UC_SEND_ONLY :
				IB_OPCODE_UC_SEND_FIRST;

	case IB_WR_SEND_WITH_IMM:
		if (qp->req.opcode == IB_OPCODE_UC_SEND_FIRST ||
		    qp->req.opcode == IB_OPCODE_UC_SEND_MIDDLE)
			return fits ?
				IB_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE :
				IB_OPCODE_UC_SEND_MIDDLE;
		else
			return fits ?
				IB_OPCODE_UC_SEND_ONLY_WITH_IMMEDIATE :
				IB_OPCODE_UC_SEND_FIRST;
	}

	return -EINVAL;
}

static int next_opcode(struct rxe_qp *qp, struct rxe_send_wqe *wqe,
		       unsigned opcode)
{
	int fits = (wqe->dma.resid <= qp->mtu);

	switch (qp_type(qp)) {
	case IB_QPT_RC:
		return next_opcode_rc(qp, opcode, fits);

	case IB_QPT_UC:
		return next_opcode_uc(qp, opcode, fits);

	case IB_QPT_SMI:
	case IB_QPT_UD:
	case IB_QPT_GSI:
		switch (opcode) {
		case IB_WR_SEND:
			return IB_OPCODE_UD_SEND_ONLY;

		case IB_WR_SEND_WITH_IMM:
			return IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE;
		}
		break;

	default:
		break;
	}

	return -EINVAL;
}

static inline int check_init_depth(struct rxe_qp *qp, struct rxe_send_wqe *wqe)
{
	int depth;

	if (wqe->has_rd_atomic)
		return 0;

	qp->req.need_rd_atomic = 1;
	depth = atomic_dec_return(&qp->req.rd_atomic);

	if (depth >= 0) {
		qp->req.need_rd_atomic = 0;
		wqe->has_rd_atomic = 1;
		return 0;
	}

	atomic_inc(&qp->req.rd_atomic);
	return -EAGAIN;
}

static inline int get_mtu(struct rxe_qp *qp, struct rxe_send_wqe *wqe)
{
	int mtu;
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);

	if ((qp_type(qp) == IB_QPT_RC) || (qp_type(qp) == IB_QPT_UC)) {
		mtu = qp->mtu;
	} else {
		struct rxe_av *av = &wqe->av;
		struct rxe_port *port = &rxe->port[av->attr.port_num - 1];

		mtu = port->mtu_cap;
	}

	return mtu;
}

static struct rxe_pkt_info *init_req_packet(struct rxe_qp *qp,
					    struct rxe_send_wqe *wqe,
					    int opcode, int payload)
{
	struct rxe_dev		*rxe = to_rdev(qp->ibqp.device);
	struct rxe_port		*port = &rxe->port[qp->attr.port_num - 1];
	struct rxe_pkt_info	*pkt;
	struct sk_buff		*skb;
	struct ib_send_wr	*ibwr = &wqe->ibwr;
	struct rxe_av		*av;
	int			pad = (-payload) & 0x3;
	int			paylen;
	int			solicited;
	u16			pkey;
	u32			qp_num;
	int			ack_req;
	unsigned int		lnh;
	unsigned int		length;
	int			align;

	/* length from start of bth to end of icrc */
	paylen = rxe_opcode[opcode].length + payload + pad + RXE_ICRC_SIZE;

	/* alignment of payload from BTH, init_packet finishes */
	align = rxe_opcode[opcode].length & RXE_SKB_ALIGN_PAD_MASK;

	/* TODO support APM someday */
	if (qp_type(qp) == IB_QPT_RC || qp_type(qp) == IB_QPT_UC)
		av = &qp->pri_av;
	else
		av = &wqe->av;

	/* init skb
	 * ifc layer must set lrh/grh flags */
	skb = rxe->ifc_ops->init_packet(rxe, av, paylen, align);
	if (!skb)
		return NULL;

	atomic_inc(&qp->req_skb_out);
	atomic_inc(&rxe->req_skb_out);

	/* pkt->hdr, rxe, port_num, paylen and
	   mask are initialized in ifc layer */
	pkt		= SKB_TO_PKT(skb);
	pkt->opcode	= opcode;
	pkt->qp		= qp;
	pkt->psn	= qp->req.psn;
	pkt->mask	|= rxe_opcode[opcode].mask;
	pkt->paylen	= paylen;
	pkt->offset	= 0;

	/* init lrh */
	if (pkt->mask & RXE_LRH_MASK) {
		pkt->offset += RXE_LRH_BYTES;
		lnh = (pkt->mask & RXE_GRH_MASK) ? LRH_LNH_IBA_GBL
						 : LRH_LNH_IBA_LOC;
		length = paylen + RXE_LRH_BYTES;
		if (pkt->mask & RXE_GRH_MASK)
			length += RXE_GRH_BYTES;

		/* TODO currently we do not implement SL->VL
		   table so just force VL=SL */
		lrh_init(pkt, av->attr.sl, av->attr.sl,
			 lnh, length/4,
			 av->attr.dlid,
			 port->attr.lid);
	}

	/* init grh */
	if (pkt->mask & RXE_GRH_MASK) {
		pkt->offset += RXE_GRH_BYTES;

		/* TODO set class flow hopcount */
		grh_init(pkt, 0, 0, paylen, 0);

		grh_set_sgid(pkt, port->subnet_prefix,
			     port->guid_tbl[av->attr.grh.sgid_index]);
		grh_set_dgid(pkt, av->attr.grh.dgid.global.subnet_prefix,
			     av->attr.grh.dgid.global.interface_id);
	}

	/* init bth */
	solicited = (ibwr->send_flags & IB_SEND_SOLICITED) &&
			(pkt->mask & RXE_END_MASK) &&
			((pkt->mask & (RXE_SEND_MASK)) ||
			(pkt->mask & (RXE_WRITE_MASK | RXE_IMMDT_MASK)) ==
			(RXE_WRITE_MASK | RXE_IMMDT_MASK));

	pkey = (qp_type(qp) == IB_QPT_GSI) ?
		 port->pkey_tbl[ibwr->wr.ud.pkey_index] :
		 port->pkey_tbl[qp->attr.pkey_index];

	qp_num = (pkt->mask & RXE_DETH_MASK) ? ibwr->wr.ud.remote_qpn :
					 qp->attr.dest_qp_num;

	ack_req = ((pkt->mask & RXE_END_MASK) ||
		(qp->req.noack_pkts++ > rxe_max_pkt_per_ack));
	if (ack_req)
		qp->req.noack_pkts = 0;

	bth_init(pkt, pkt->opcode, solicited, 0, pad, pkey, qp_num,
		 ack_req, pkt->psn);

	/* init optional headers */
	if (pkt->mask & RXE_RETH_MASK) {
		reth_set_rkey(pkt, ibwr->wr.rdma.rkey);
		reth_set_va(pkt, wqe->iova);
		reth_set_len(pkt, wqe->dma.length);
	}

	if (pkt->mask & RXE_IMMDT_MASK)
		immdt_set_imm(pkt, ibwr->ex.imm_data);

	if (pkt->mask & RXE_IETH_MASK)
		ieth_set_rkey(pkt, ibwr->ex.invalidate_rkey);

	if (pkt->mask & RXE_ATMETH_MASK) {
		atmeth_set_va(pkt, wqe->iova);
		if (opcode == IB_OPCODE_RC_COMPARE_SWAP ||
		    opcode == IB_OPCODE_RD_COMPARE_SWAP) {
			atmeth_set_swap_add(pkt, ibwr->wr.atomic.swap);
			atmeth_set_comp(pkt, ibwr->wr.atomic.compare_add);
		} else {
			atmeth_set_swap_add(pkt, ibwr->wr.atomic.compare_add);
		}
		atmeth_set_rkey(pkt, ibwr->wr.atomic.rkey);
	}

	if (pkt->mask & RXE_DETH_MASK) {
		if (qp->ibqp.qp_num == 1)
			deth_set_qkey(pkt, GSI_QKEY);
		else
			deth_set_qkey(pkt, ibwr->wr.ud.remote_qkey);
		deth_set_sqp(pkt, qp->ibqp.qp_num);
	}

	return pkt;
}

static int fill_packet(struct rxe_qp *qp, struct rxe_send_wqe *wqe,
		       struct rxe_pkt_info *pkt, int payload)
{
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);
	static const uint8_t zerobuf[4] = {0,};
	int pad;
	u32 crc = 0;
	u8 *p;

	crc = rxe_icrc_hdr(pkt);

	if (pkt->mask & RXE_WRITE_OR_SEND) {
		if (wqe->ibwr.send_flags & IB_SEND_INLINE) {
			p = &wqe->dma.inline_data[wqe->dma.sge_offset];

			crc = crc32_le(crc, p, payload);

			memcpy(payload_addr(pkt), p, payload);

			wqe->dma.resid -= payload;
			wqe->dma.sge_offset += payload;
		} else {
			if (copy_data(rxe, qp->pd, 0, &wqe->dma,
				      payload_addr(pkt), payload,
				      direction_out,
				      &crc)) {
				return -1;
			}
		}
	}

	p = payload_addr(pkt) + payload;
	pad = (-payload) & 0x3;
	if (pad) {
		crc = crc32_le(crc, zerobuf, pad);

		memcpy(p, zerobuf, pad);

		p += pad;
	}

	*p = ~crc;

	return 0;
}

static void update_state(struct rxe_qp *qp, struct rxe_send_wqe *wqe,
			 struct rxe_pkt_info *pkt, int payload)
{
	/* number of packets left to send including current one */
	int num_pkt = (wqe->dma.resid + payload + qp->mtu - 1) / qp->mtu;

	/* handle zero length packet case */
	if (num_pkt == 0)
		num_pkt = 1;

	if (pkt->mask & RXE_START_MASK) {
		wqe->first_psn = qp->req.psn;
		wqe->last_psn = (qp->req.psn + num_pkt - 1) & BTH_PSN_MASK;
	}

	if (pkt->mask & RXE_READ_MASK)
		qp->req.psn = (wqe->first_psn + num_pkt) & BTH_PSN_MASK;
	else
		qp->req.psn = (qp->req.psn + 1) & BTH_PSN_MASK;

	qp->req.opcode = pkt->opcode;

	if (pkt->mask & RXE_END_MASK) {
		if (qp_type(qp) == IB_QPT_RC)
			wqe->state = wqe_state_pending;
		else
			wqe->state = wqe_state_done;

		qp->req.wqe_index = next_index(qp->sq.queue,
						qp->req.wqe_index);
	} else {
		wqe->state = wqe_state_processing;
	}

	if (qp->qp_timeout_jiffies && !timer_pending(&qp->retrans_timer))
		mod_timer(&qp->retrans_timer,
			  jiffies + qp->qp_timeout_jiffies);
}

int rxe_requester(void *arg)
{
	struct rxe_qp *qp = (struct rxe_qp *)arg;
	struct rxe_pkt_info *pkt;
	struct rxe_send_wqe *wqe;
	unsigned mask;
	int payload;
	int mtu;
	int opcode;

	if (!qp->valid || qp->req.state == QP_STATE_ERROR)
		goto exit;

	if (qp->req.state == QP_STATE_RESET) {
		qp->req.wqe_index = consumer_index(qp->sq.queue);
		qp->req.opcode = -1;
		qp->req.need_rd_atomic = 0;
		qp->req.wait_psn = 0;
		qp->req.need_retry = 0;
		goto exit;
	}

	if (qp->req.need_retry) {
		req_retry(qp);
		qp->req.need_retry = 0;
	}

	wqe = req_next_wqe(qp);
	if (!wqe)
		goto exit;

	/* heuristic sliding window algorithm to keep
	   sender from overrunning receiver queues */
	if (qp_type(qp) == IB_QPT_RC)  {
		if (psn_compare(qp->req.psn, qp->comp.psn +
				rxe_max_req_comp_gap) > 0) {
			qp->req.wait_psn = 1;
			goto exit;
		}
	}

	/* heuristic algorithm to prevent sender from
	   overrunning the output queue. to not overrun
	   the receiver's input queue (UC/UD) requires
	   rate control or application level flow control */
	if (atomic_read(&qp->req_skb_out) > rxe_max_skb_per_qp) {
		qp->need_req_skb = 1;
		goto exit;
	}

	opcode = next_opcode(qp, wqe, wqe->ibwr.opcode);
	if (opcode < 0) {
		wqe->status = IB_WC_LOC_QP_OP_ERR;
		/* TODO most be more to do here ?? */
		goto exit;
	}

	mask = rxe_opcode[opcode].mask;
	if (unlikely(mask & RXE_READ_OR_ATOMIC)) {
		if (check_init_depth(qp, wqe))
			goto exit;
	}

	mtu = get_mtu(qp, wqe);
	payload = (mask & RXE_WRITE_OR_SEND) ? wqe->dma.resid : 0;
	if (payload > mtu) {
		if (qp_type(qp) == IB_QPT_UD) {
			/* believe it or not this is
			   what the spec says to do */
			/* TODO handle > 1 ports */

			/*
			 * fake a successful UD send
			 */
			wqe->first_psn = qp->req.psn;
			wqe->last_psn = qp->req.psn;
			qp->req.psn = (qp->req.psn + 1) & BTH_PSN_MASK;
			qp->req.opcode = IB_OPCODE_UD_SEND_ONLY;
			qp->req.wqe_index = next_index(qp->sq.queue,
						       qp->req.wqe_index);
			wqe->state = wqe_state_done;
			wqe->status = IB_WC_SUCCESS;
			goto complete;
		}
		payload = mtu;
	}

	pkt = init_req_packet(qp, wqe, opcode, payload);
	if (!pkt) {
		qp->need_req_skb = 1;
		goto exit;
	}

	if (fill_packet(qp, wqe, pkt, payload)) {
		wqe->status = IB_WC_LOC_PROT_ERR;
		wqe->state = wqe_state_error;
		goto complete;
	}

	update_state(qp, wqe, pkt, payload);

	arbiter_skb_queue(to_rdev(qp->ibqp.device), qp, PKT_TO_SKB(pkt));

	if (mask & RXE_END_MASK)
		goto complete;
	else
		goto done;

complete:
	if (qp_type(qp) != IB_QPT_RC) {
		while (rxe_completer(qp) == 0)
			;
	}
done:
	return 0;

exit:
	return -EAGAIN;
}

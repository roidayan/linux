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

#include <net/switchdev.h>
#include <generated/utsrelease.h>
#include <linux/mlx5/flow_table.h>
#include <net/sw_flow.h>
#include <uapi/linux/openvswitch.h>
#include "en.h"

static int parse_flow_attr(struct sw_flow *flow, u32 *match_c, u32 *match_v)
{
	struct sw_flow_key *key  = &flow->key;
	struct sw_flow_key *mask = &flow->mask->key;

	void *outer_headers_c = MLX5_ADDR_OF(fte_match_param, match_c,
					     outer_headers);
	void *outer_headers_v = MLX5_ADDR_OF(fte_match_param, match_v,
					     outer_headers);

	u8 zero_mac[ETH_ALEN];

	eth_zero_addr(zero_mac);

	if (memcmp(&mask->eth.src, zero_mac, ETH_ALEN)) {
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_headers_c, smac_47_16),
		       &mask->eth.src, ETH_ALEN);
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_headers_v, smac_47_16),
		       &key->eth.src, ETH_ALEN);
	}

	if (memcmp(&mask->eth.dst, zero_mac, ETH_ALEN)) {
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_headers_c, dmac_47_16),
		       &mask->eth.dst, ETH_ALEN);
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_headers_v, dmac_47_16),
		       &key->eth.dst, ETH_ALEN);
	}

	/* NOTE - vlan push/pop actions to be implemented by VST!! */
	if (mask->eth.tci) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, vlan_tag, 1);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, vlan_tag, 1);

		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, first_vid,
			 ntohs(mask->eth.tci) & ~VLAN_TAG_PRESENT);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, first_vid,
			 ntohs(mask->eth.tci) & ~VLAN_TAG_PRESENT);
	}

	if (mask->eth.type) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, ethertype, mask->eth.type);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, ethertype, key->eth.type);
	}

	if (mask->ip.proto) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, ip_protocol, mask->ip.proto);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, ip_protocol, key->ip.proto);
	}

	if (mask->ip.tos >> 2) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, ip_dscp, mask->ip.tos >> 2);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, ip_dscp, key->ip.tos  >> 2);
	}

	if (mask->ip.tos & 0x3) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, ip_ecn, mask->ip.tos & 0x3);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, ip_ecn, key->ip.tos  & 0x3);
	}

	if (mask->ip.ttl) {
		printk(KERN_ERR "%s non zero mask %x (val %d) for IP TTL, unsupported by PRM\n",
		       __func__, mask->ip.ttl, key->ip.ttl);
		goto out_err;
	}

	if (mask->ip.frag && key->ip.frag == OVS_FRAG_TYPE_NONE) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, frag, 1);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, frag, 0);
	} else if (mask->ip.frag && key->ip.frag != OVS_FRAG_TYPE_NONE) {
		printk(KERN_ERR "%s non zero val for OVS_FRAG %d, supported by PRM?!\n",
			__func__, key->ip.frag);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, frag, 1);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, frag, 1);
	}

	/* PRM mandates ip protocol full match to set rules on UDP/TCP ports using one rule */
	if (mask->tp.src && mask->ip.proto && key->ip.proto == IPPROTO_TCP) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, tcp_sport, ntohs(mask->tp.src));
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, tcp_sport, ntohs(key->tp.src));
	}

	if (mask->tp.dst && mask->ip.proto && key->ip.proto == IPPROTO_TCP) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, tcp_dport, ntohs(mask->tp.dst));
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, tcp_dport, ntohs(key->tp.dst));
	}

	if (mask->tp.flags) { /* FIXME: OVS flags are 16 bits, we need "only" 8 bits */
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, tcp_flags, mask->tp.flags);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, tcp_flags, key->tp.flags);
	}

	/* PRM mandates ip protocol full match to set rules on UDP/TCP ports using one rule */
	if (mask->tp.src && mask->ip.proto && key->ip.proto == IPPROTO_UDP) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, udp_sport, ntohs(mask->tp.src));
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, udp_sport, ntohs(key->tp.src));
	}

	if (mask->tp.dst && mask->ip.proto && key->ip.proto == IPPROTO_UDP) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, udp_dport, ntohs(mask->tp.dst));
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, udp_dport, ntohs(key->tp.dst));
	}

	/* FIXME: need to use meta data for realizing if this is IPv4/IPv6 */
	if (mask->ipv4.addr.src) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, src_ip[0], mask->ipv4.addr.src);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, src_ip[0], key->ipv4.addr.src);
	}

	if (mask->ipv4.addr.dst) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, dst_ip[0], mask->ipv4.addr.dst);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, dst_ip[0], key->ipv4.addr.dst);
	}

	/* FIXME: add IPv6 src/dst addressed */
	if (mask->ipv6.label) {
		/* TODO use the misc section and put the flow label there */
	}


	return 0;

out_err:

	return -EINVAL;
}

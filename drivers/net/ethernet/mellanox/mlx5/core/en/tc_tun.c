/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2018 Mellanox Technologies. */

#include <net/vxlan.h>
#include <net/gre.h>
#include "en/tc_tun.h"

struct mlx5e_tc_tunnel *mlx5e_get_tc_tun(struct net_device *tunnel_dev)
{
	if (netif_is_vxlan(tunnel_dev))
		return &vxlan_tunnel;
	else if (netif_is_gretap(tunnel_dev) ||
		 netif_is_ip6gretap(tunnel_dev))
		return &gre_tunnel;
	else
		return NULL;
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

static const char *mlx5e_netdev_kind(struct net_device *dev)
{
	if (dev->rtnl_link_ops)
		return dev->rtnl_link_ops->kind;
	else
		return "";
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

static int mlx5e_gen_ip_tunnel_header(char buf[], __u8 *ip_proto,
				      struct mlx5e_encap_entry *e)
{
	if (!e->tunnel) {
		pr_warn("mlx5: Cannot generate tunnel header for this tunnel\n");
		return -EOPNOTSUPP;
	}

	return e->tunnel->generate_ip_tun_hdr(buf, ip_proto, e);
}

int mlx5e_tc_tun_create_header_ipv4(struct mlx5e_priv *priv,
				    struct net_device *mirred_dev,
				    struct mlx5e_encap_entry *e)
{
	int max_encap_size = MLX5_CAP_ESW(priv->mdev, max_encap_header_size);
	int ipv4_encap_size = ETH_HLEN +
			      sizeof(struct iphdr) +
			      e->tunnel->calc_hlen(e);
	const struct ip_tunnel_key *tun_key = &e->tun_info->key;
	struct net_device *out_dev;
	struct neighbour *n = NULL;
	struct flowi4 fl4 = {};
	char *encap_header;
	struct ethhdr *eth;
	u8 nud_state, ttl;
	struct iphdr *ip;
	int err;

	if (max_encap_size < ipv4_encap_size) {
		mlx5_core_warn(priv->mdev, "encap size %d too big, max supported is %d\n",
			       ipv4_encap_size, max_encap_size);
		return -EOPNOTSUPP;
	}

	encap_header = kzalloc(ipv4_encap_size, GFP_KERNEL);
	if (!encap_header)
		return -ENOMEM;

	/* add the IP fields */
	fl4.flowi4_tos = tun_key->tos;
	fl4.daddr = tun_key->u.ipv4.dst;
	fl4.saddr = tun_key->u.ipv4.src;
	ttl = tun_key->ttl;

	err = mlx5e_route_lookup_ipv4(priv, mirred_dev, &out_dev,
				      &fl4, &n, &ttl);
	if (err)
		goto free_encap;

	/* used by mlx5e_detach_encap to lookup a neigh hash table
	 * entry in the neigh hash table when a user deletes a rule
	 */
	e->m_neigh.dev = n->dev;
	e->m_neigh.family = n->ops->family;
	memcpy(&e->m_neigh.dst_ip, n->primary_key, n->tbl->key_len);
	e->out_dev = out_dev;

	/* It's important to add the neigh to the hash table before checking
	 * the neigh validity state. So if we'll get a notification, in case the
	 * neigh changes it's validity state, we would find the relevant neigh
	 * in the hash.
	 */
	err = mlx5e_rep_encap_entry_attach(netdev_priv(out_dev), e);
	if (err)
		goto free_encap;

	read_lock_bh(&n->lock);
	nud_state = n->nud_state;
	ether_addr_copy(e->h_dest, n->ha);
	read_unlock_bh(&n->lock);

	/* add ethernet header */
	eth = (struct ethhdr *)encap_header;
	ether_addr_copy(eth->h_dest, e->h_dest);
	ether_addr_copy(eth->h_source, out_dev->dev_addr);
	eth->h_proto = htons(ETH_P_IP);

	/* add ip header */
	ip = (struct iphdr *)((char *)eth + sizeof(struct ethhdr));
	ip->tos = tun_key->tos;
	ip->version = 0x4;
	ip->ihl = 0x5;
	ip->ttl = ttl;
	ip->daddr = fl4.daddr;
	ip->saddr = fl4.saddr;

	/* add tunneling protocol header */
	err = mlx5e_gen_ip_tunnel_header((char *)ip + sizeof(struct iphdr),
					 &ip->protocol, e);
	if (err)
		goto destroy_neigh_entry;

	e->encap_size = ipv4_encap_size;
	e->encap_header = encap_header;

	if (!(nud_state & NUD_VALID)) {
		neigh_event_send(n, NULL);
		err = -EAGAIN;
		goto out;
	}

	err = mlx5_packet_reformat_alloc(priv->mdev,
					 e->reformat_type,
					 ipv4_encap_size, encap_header,
					 MLX5_FLOW_NAMESPACE_FDB,
					 &e->encap_id);
	if (err)
		goto destroy_neigh_entry;

	e->flags |= MLX5_ENCAP_ENTRY_VALID;
	mlx5e_rep_queue_neigh_stats_work(netdev_priv(out_dev));
	neigh_release(n);
	return err;

destroy_neigh_entry:
	mlx5e_rep_encap_entry_detach(netdev_priv(e->out_dev), e);
free_encap:
	kfree(encap_header);
out:
	if (n)
		neigh_release(n);
	return err;
}

int mlx5e_tc_tun_create_header_ipv6(struct mlx5e_priv *priv,
				    struct net_device *mirred_dev,
				    struct mlx5e_encap_entry *e)
{
	int max_encap_size = MLX5_CAP_ESW(priv->mdev, max_encap_header_size);
	int ipv6_encap_size = ETH_HLEN +
			      sizeof(struct ipv6hdr) +
			      e->tunnel->calc_hlen(e);
	const struct ip_tunnel_key *tun_key = &e->tun_info->key;
	struct net_device *out_dev;
	struct neighbour *n = NULL;
	struct flowi6 fl6 = {};
	struct ipv6hdr *ip6h;
	char *encap_header;
	struct ethhdr *eth;
	u8 nud_state, ttl;
	int err;

	if (max_encap_size < ipv6_encap_size) {
		mlx5_core_warn(priv->mdev, "encap size %d too big, max supported is %d\n",
			       ipv6_encap_size, max_encap_size);
		return -EOPNOTSUPP;
	}

	encap_header = kzalloc(ipv6_encap_size, GFP_KERNEL);
	if (!encap_header)
		return -ENOMEM;

	ttl = tun_key->ttl;

	fl6.flowlabel = ip6_make_flowinfo(RT_TOS(tun_key->tos), tun_key->label);
	fl6.daddr = tun_key->u.ipv6.dst;
	fl6.saddr = tun_key->u.ipv6.src;

	err = mlx5e_route_lookup_ipv6(priv, mirred_dev, &out_dev,
				      &fl6, &n, &ttl);
	if (err)
		goto free_encap;

	/* used by mlx5e_detach_encap to lookup a neigh hash table
	 * entry in the neigh hash table when a user deletes a rule
	 */
	e->m_neigh.dev = n->dev;
	e->m_neigh.family = n->ops->family;
	memcpy(&e->m_neigh.dst_ip, n->primary_key, n->tbl->key_len);
	e->out_dev = out_dev;

	/* It's importent to add the neigh to the hash table before checking
	 * the neigh validity state. So if we'll get a notification, in case the
	 * neigh changes it's validity state, we would find the relevant neigh
	 * in the hash.
	 */
	err = mlx5e_rep_encap_entry_attach(netdev_priv(out_dev), e);
	if (err)
		goto free_encap;

	read_lock_bh(&n->lock);
	nud_state = n->nud_state;
	ether_addr_copy(e->h_dest, n->ha);
	read_unlock_bh(&n->lock);

	/* add ethernet header */
	eth = (struct ethhdr *)encap_header;
	ether_addr_copy(eth->h_dest, e->h_dest);
	ether_addr_copy(eth->h_source, out_dev->dev_addr);
	eth->h_proto = htons(ETH_P_IPV6);

	/* add ip header */
	ip6h = (struct ipv6hdr *)((char *)eth + sizeof(struct ethhdr));
	ip6_flow_hdr(ip6h, tun_key->tos, 0);
	/* the HW fills up ipv6 payload len */
	ip6h->hop_limit   = ttl;
	ip6h->daddr	  = fl6.daddr;
	ip6h->saddr	  = fl6.saddr;

	/* add tunneling protocol header */
	err = mlx5e_gen_ip_tunnel_header((char *)ip6h + sizeof(struct ipv6hdr),
					 &ip6h->nexthdr, e);
	if (err)
		goto destroy_neigh_entry;

	e->encap_size = ipv6_encap_size;
	e->encap_header = encap_header;

	if (!(nud_state & NUD_VALID)) {
		neigh_event_send(n, NULL);
		err = -EAGAIN;
		goto out;
	}

	err = mlx5_packet_reformat_alloc(priv->mdev,
					 e->reformat_type,
					 ipv6_encap_size, encap_header,
					 MLX5_FLOW_NAMESPACE_FDB,
					 &e->encap_id);
	if (err)
		goto destroy_neigh_entry;

	e->flags |= MLX5_ENCAP_ENTRY_VALID;
	mlx5e_rep_queue_neigh_stats_work(netdev_priv(out_dev));
	neigh_release(n);
	return err;

destroy_neigh_entry:
	mlx5e_rep_encap_entry_detach(netdev_priv(e->out_dev), e);
free_encap:
	kfree(encap_header);
out:
	if (n)
		neigh_release(n);
	return err;
}

bool mlx5e_tc_tun_device_to_offload(struct mlx5e_priv *priv,
				    struct net_device *netdev)
{
	struct mlx5e_tc_tunnel *tunnel = mlx5e_get_tc_tun(netdev);
	if (tunnel && tunnel->can_offload(priv))
		return true;
	else
		return false;
}

int mlx5e_tc_tun_init_encap_attr(struct net_device *tunnel_dev,
				 struct mlx5e_priv *priv,
				 struct mlx5e_encap_entry *e,
				 struct netlink_ext_ack *extack)
{
	struct mlx5e_tc_tunnel *tunnel = mlx5e_get_tc_tun(tunnel_dev);

	if (!tunnel) {
		e->reformat_type = -1;
		return -EOPNOTSUPP;
	}

	return tunnel->init_encap_attr(tunnel_dev, priv, e, extack);
}

int mlx5e_tc_tun_parse(struct net_device *filter_dev,
		       struct mlx5e_priv *priv,
		       struct mlx5_flow_spec *spec,
		       struct tc_cls_flower_offload *f,
		       void *headers_c,
		       void *headers_v,
		       u8 *match_level)
{
	struct mlx5e_tc_tunnel *tunnel = mlx5e_get_tc_tun(filter_dev);
	int err = 0;

	if (!tunnel) {
		netdev_warn(priv->netdev,
			    "decapsulation offload is not supported for %s net device\n",
			    mlx5e_netdev_kind(filter_dev));
			    err = -EOPNOTSUPP;
		goto out;
	}

	if (tunnel->parse_udp_ports) {
		err = tunnel->parse_udp_ports(priv, spec, f,
					      headers_c, headers_v);
		if (err)
			goto out;
	}
	if (tunnel->parse_tunnel) {
		err = tunnel->parse_tunnel(priv, spec, f,
					   headers_c, headers_v);
		if (err)
			goto out;
	}

	*match_level = tunnel->match_level;
out:
	return err;
}

int mlx5e_tc_tun_parse_udp_ports(struct mlx5e_priv *priv,
				 struct mlx5_flow_spec *spec,
				 struct tc_cls_flower_offload *f,
				 void *headers_c,
				 void *headers_v)
{
	struct netlink_ext_ack *extack = f->common.extack;
	struct flow_dissector_key_ports *key =
		skb_flow_dissector_target(f->dissector,
					  FLOW_DISSECTOR_KEY_ENC_PORTS,
					  f->key);
	struct flow_dissector_key_ports *mask =
		skb_flow_dissector_target(f->dissector,
					  FLOW_DISSECTOR_KEY_ENC_PORTS,
					  f->mask);

	/* Full udp dst port must be given */

	if (!dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_ENC_PORTS) ||
	    memchr_inv(&mask->dst, 0xff, sizeof(mask->dst))) {
		NL_SET_ERR_MSG_MOD(extack,
				   "UDP tunnel decap filter must include enc_dst_port condition");
		netdev_warn(priv->netdev,
			    "UDP tunnel decap filter must include enc_dst_port condition\n");
		return -EOPNOTSUPP;
	}

	/* match on UDP protocol and dst port number */

	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ip_protocol);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_protocol, IPPROTO_UDP);

	MLX5_SET(fte_match_set_lyr_2_4, headers_c, udp_dport, ntohs(mask->dst));
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, udp_dport, ntohs(key->dst));

	/* UDP src port on outer header is generated by HW,
	 * so it is probably a bad idea to request matching it.
	 * Nonetheless, it is allowed.
	 */

	MLX5_SET(fte_match_set_lyr_2_4, headers_c, udp_sport, ntohs(mask->src));
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, udp_sport, ntohs(key->src));

	return 0;
}

#ifndef LINUX_IF_VLAN_H
#define LINUX_IF_VLAN_H

#include_next <linux/if_vlan.h>

#ifndef skb_vlan_tag_present
#define skb_vlan_tag_present vlan_tx_tag_present
#define skb_vlan_tag_get vlan_tx_tag_get
#define skb_vlan_tag_get_id vlan_tx_tag_get_id
#endif

#ifndef HAVE_IS_VLAN_DEV
static inline int is_vlan_dev(struct net_device *dev)
{
	return dev->priv_flags & IFF_802_1Q_VLAN;
}
#endif

#endif /* LINUX_IF_VLAN_H */

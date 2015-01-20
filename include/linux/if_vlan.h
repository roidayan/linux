#ifndef LINUX_IF_VLAN_H
#define LINUX_IF_VLAN_H

#include_next <linux/if_vlan.h>

#ifndef skb_vlan_tag_present
#define skb_vlan_tag_present vlan_tx_tag_present
#define skb_vlan_tag_get vlan_tx_tag_get
#define skb_vlan_tag_get_id vlan_tx_tag_get_id
#endif

#endif /* LINUX_IF_VLAN_H */

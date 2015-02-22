#ifndef LINUX_BONDING_H
#define LINUX_BONDING_H

#include_next <net/bonding.h>

#define bond_option_active_slave_get_rcu LINUX_BACKPORT(bond_option_active_slave_get_rcu)
static inline struct net_device *bond_option_active_slave_get_rcu(struct bonding
								  *bond)
{
	struct slave *slave = rcu_dereference(bond->curr_active_slave);

	return bond_uses_primary(bond) && slave ? slave->dev : NULL;
}

#endif /* LINUX_BONDING_H */

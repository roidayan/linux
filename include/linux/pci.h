#ifndef _LINUX_PCI_H
#define _LINUX_PCI_H

#include_next <linux/pci.h>

#ifndef HAVE_PCI_PHYSFN
static inline struct pci_dev *pci_physfn(struct pci_dev *dev)
{
#ifdef CONFIG_PCI_IOV
	if (dev->is_virtfn)
		dev = dev->physfn;
#endif
	return dev;
}
#endif /* HAVE_PCI_PHYSFN */

#endif /* _LINUX_PCI_H */

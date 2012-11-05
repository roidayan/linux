#! /bin/bash
if [ -z $1 ]; then 
	IRQS=$(cat /proc/interrupts | grep eth-mlx | awk '{print $1}' | sed 's/://')
else
	IRQS=$(cat /proc/interrupts | grep $1 | awk '{print $1}' | sed 's/://')
fi

for irq in $IRQS
do
	echo -n "$irq: "
	cat /proc/irq/$irq/smp_affinity
done


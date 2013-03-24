#! /bin/bash
if [ -z $1 ]; then
        echo "usage: $0 <interface> "
        exit 1
fi

ls /sys/class/net/$1 > /dev/null
rc=$?

if [[ "$rc" == "0" && "$( cat /proc/interrupts | grep $1 )" == "" ]];then
        interface=$( ls -l /sys/class/net/$1/device | tr "/"  " " | awk '{ print $NF}' | cut -b -7 )
else
        interface=$1
fi

IRQS=$(cat /proc/interrupts | grep $interface | awk '{print $1}' | sed 's/://')

for irq in $IRQS
do
	echo -n "$irq: "
	cat /proc/irq/$irq/smp_affinity
done


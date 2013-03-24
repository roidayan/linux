#! /bin/bash
if [ -z $2 ]; then
	echo "usage: $0 <node id> <interface> [2nd interface]"
	exit 1
fi
node=$1
interface=$2
interface2=$3

ls /sys/class/net/$interface > /dev/null
rc=$?

if [[ "$rc" == "0" && "$( cat /proc/interrupts | grep $interface )" == "" ]];then
        interface=$( ls -l /sys/class/net/$interface/device | tr "/"  " " | awk '{ print $NF}' | cut -b -7 )
fi

IRQS=$(cat /proc/interrupts | grep $interface | awk '{print $1}' | sed 's/://')

if [ $interface2 ]; then
	
	ls /sys/class/net/$interface2 > /dev/null
	rc=$?
	if [[ "$rc" == "0" && "$( cat /proc/interrupts | grep $interface2 )" == "" ]];then
        	interface2=$( ls -l /sys/class/net/$interface2/device | tr "/"  " " | awk '{ print $NF}' | cut -b -7 )
	fi
	
	IRQS_2=$(cat /proc/interrupts | grep $interface2 | awk '{print $1}' | sed 's/://')
        echo "---------------------------------------"
        echo "Optimizing IRQs for Dual port traffic"
        echo "---------------------------------------"
else
        echo "-------------------------------------"
        echo "Optimizing IRQs for Single port traffic"
        echo "-------------------------------------"
fi

cpulist=$(cat /sys/devices/system/node/node$node/cpulist ) 
if [ "$(echo $?)" != "0" ]; then 
	echo "Node id '$node' does not exists."
	exit 
fi
CORES=$( echo $cpulist | sed 's/,/ /g' | wc -w )
for word in $(seq 1 $CORES)
do
	SEQ=$(echo $cpulist | cut -d "," -f $word | sed 's/-/ /')	
	if [ "$(echo $SEQ | wc -w)" != "1" ]; then
		CPULIST="$CPULIST $( echo $(seq $SEQ) | sed 's/ /,/g' )"
	fi
done
if [ "$CPULIST" != "" ]; then
	cpulist=$(echo $CPULIST | sed 's/ /,/g')
fi
CORES=$( echo $cpulist | sed 's/,/ /g' | wc -w )

if [ -z "$IRQS" ] ; then
        echo No IRQs found for $2.
else
        echo
	echo Discovered irqs for $2: $IRQS
fi

I=1  
for IRQ in $IRQS 
do 
	core_id=$(echo $cpulist | cut -d "," -f $I)
	echo Assign irq $IRQ mask 0x$(printf "%x" $((2**core_id)) )
	echo $(printf "%x" $((2**core_id)) ) > /proc/irq/$IRQ/smp_affinity 
	if [ -z $interface2 ]; then
		I=$(( (I%CORES) + 1 ))
	else
		I=$(( (I%(CORES/2)) + 1 ))
	fi
done

if [ $interface2 ]; then
	if [ -z "$IRQS_2" ] ; then
	        echo No IRQs found for $3.
	else
		echo
		echo Discovered irqs for $3: $IRQS_2
	fi
fi

I=$(( (CORES/2) + 1 ))
for IRQ in $IRQS_2 
do 
	core_id=$(echo $cpulist | cut -d "," -f $I)
	echo Assign irq $IRQ mask 0x$(printf "%x" $((2**core_id)) )
	echo $(printf "%x" $((2**core_id)) ) > /proc/irq/$IRQ/smp_affinity 
	I=$(( (I%(CORES/2)) + 1 + (CORES/2) ))
done
echo
echo done.



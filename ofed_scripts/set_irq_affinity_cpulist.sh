#! /bin/bash
if [ -z $2 ]; then
	echo "usage: $0 <cpu list> <interface> "
	echo "       <cpu list> can be either a comma separated list of single core numbers (0,1,2,3) or core groups (0-3)"
	exit 1
fi
cpulist=$1
interface=$2

ls /sys/class/net/$interface > /dev/null
rc=$?
if [[ "$rc" == "0" && "$( cat /proc/interrupts | grep $interface )" == "" ]];then
	interface=$( ls -l /sys/class/net/$interface/device | tr "/"  " " | awk '{ print $NF}' | cut -b -7 )
fi

IRQS=$(cat /proc/interrupts | grep $interface | awk '{print $1}' | sed 's/://')

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
echo Discovered irqs for $interface: $IRQS
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
echo 
echo done.



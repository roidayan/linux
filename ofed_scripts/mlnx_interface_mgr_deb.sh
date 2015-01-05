#!/bin/bash

i=$1
shift

if [ -z "$i" ]; then
    echo "Usage:"
    echo "      $0 <interface>"
    exit 1
fi

OPENIBD_CONFIG=${OPENIBD_CONFIG:-"/etc/infiniband/openib.conf"}
CONFIG=$OPENIBD_CONFIG
export LANG=en_US.UTF-8

if [ ! -f $CONFIG ]; then
    echo No InfiniBand configuration found
    exit 0
fi

. $CONFIG
IPOIB_MTU=${IPOIB_MTU:-65520}

# set configuration files
conf_files=/etc/network/interfaces
if (grep -w source /etc/network/interfaces 2>/dev/null | grep -qvE "^\s*#" 2>/dev/null); then
    # get absolute file paths
    for line in $(grep -w source /etc/network/interfaces 2>/dev/null | grep -vE "^\s*#" 2>/dev/null);
    do
        ff=$(echo "$line" | awk '{print $NF}')

        # check if it's absolute path
        if [ -f "$ff" ]; then
            conf_files="$conf_files $ff"
            continue
        fi

        # check if it's relative path
        if [ -z "$(ls $ff 2>/dev/null)" ]; then
            ff="/etc/network/$ff"
        fi

        # support wildcards
        for file in $(ls -1 $ff 2>/dev/null)
        do
            if [ -f "$file" ]; then
                conf_files="$conf_files $file"
            fi
        done
    done
fi

log_msg()
{
    logger -i "mlnx_interface_mgr: $@"
}

set_ipoib_cm()
{
    local i=$1
    shift
    local mtu=$1
    shift
    local is_up=""

    if [ ! -e /sys/class/net/${i}/mode ]; then
        log_msg "Failed to configure IPoIB connected mode for ${i}"
        return 1
    fi

    mtu=${mtu:-$IPOIB_MTU}

    #check what was the previous state of the interface
    is_up=`/sbin/ip link show $i | grep -w UP`

    /sbin/ip link set ${i} down

    echo connected > /sys/class/net/${i}/mode
    /sbin/ip link set ${i} mtu ${mtu}

    #if the intf was up returns it to
    if [ -n "$is_up" ]; then
        /sbin/ip link set ${i} up
    fi
}

set_RPS_cpu()
{
    local i=$1
    shift

    if [ ! -e /sys/class/net/${i}/queues/rx-0/rps_cpus ]; then
        log_msg "Failed to configure RPS cpu for ${i}"
        return 1
    fi

    cat /sys/class/net/${i}/device/local_cpus >  /sys/class/net/${i}/queues/rx-0/rps_cpus
}

handle_specific_mlx_intf()
{
    local i=$1
    shift
    local mtu=$1
    shift
    local intf=""
    local num_rx_queue=0

    #handle mlx5 interfaces, assumption: mlx5 interface will be with CM mode.
    local guid=$(cat /sys/class/net/${i}/address 2>/dev/null | cut -b 37- | sed -e 's/://g')
    # check only mlx5 devices
    for ibdev in $(ls -d /sys/class/infiniband/*mlx5* 2>/dev/null); do
        ibdev=$(basename $ibdev)
        for port in $(ls /sys/class/infiniband/$ibdev/ports/ 2>/dev/null); do
            for gid in $(ls /sys/class/infiniband/$ibdev/ports/$port/gids 2>/dev/null); do
                pguid=$(cat /sys/class/infiniband/$ibdev/ports/$port/gids/$gid 2>/dev/null | cut -b 21- | sed -e 's/://g')
                if [ "X$pguid" == "X$guid" ]; then
                    # the interfce $i belongs to mlx5 device
                    set_ipoib_cm ${i} ${mtu}
                fi
            done
        done
    done

    num_rx_queue=$(ls -l /sys/class/net/${i}/queues/ 2>/dev/null | grep rx-  | wc -l | awk '{print $1}')
    if [ $num_rx_queue -eq 1 ]; then
        # Spread the one and only RX queue to more CPUs using RPS.
        set_RPS_cpu ${i}
    fi

    return 0;
}

bring_up()
{
    local i=$1
    shift

    # get current interface status
    local is_up=""
    is_up=`/sbin/ip link show $i | grep -w UP`
    if [ -z "$is_up" ]; then
        /sbin/ifup --force ${i} > /dev/null 2>&1 &
    fi

    MTU=`/usr/sbin/net-interfaces get-mtu ${i}`

    # relevant for IPoIB interfaces only
    if (/sbin/ethtool -i ${i} 2>/dev/null | grep -q ib_ipoib); then
        if [ "X${SET_IPOIB_CM}" == "Xyes" ]; then
            set_ipoib_cm ${i} ${MTU}
        elif [ "X${SET_IPOIB_CM}" == "Xauto" ]; then
            handle_specific_mlx_intf ${i} ${MTU}
        fi
    fi

    local rc=$?

    bond=`/usr/sbin/net-interfaces get-bond-master ${i}`
    if [ ! -z "$bond" ]; then
        /sbin/ifenslave -f $bond ${i} > /dev/null 2>&1
    fi

    return $rc
}

# main
{
log_msg "Setting up InfiniBand network interface: $i"

# bring up the interface
bring_up $i
RC=$?

if ! (grep -wh ${i} $conf_files 2>/dev/null | grep -qvE "^\s*#" 2>/dev/null); then
    log_msg "No configuration found for ${i}"
else
    if [ $RC -eq 0 ]; then
        log_msg "Bringing up interface $i: PASSED"
    else
        log_msg "Bringing up interface $i: FAILED"
    fi
fi

# Bring up child interfaces if configured.
for file in $conf_files
do
    while read _line
    do
        if [[ ! "$_line" =~ ^# && "$_line" =~ $i\.[0-9]* && "$_line" =~ "iface" ]]
        then
            ifname=$(echo $_line | cut -f2 -d" ")

            if [ ! -f /sys/class/net/$i/create_child ]; then
                continue
            fi

            pkey=0x${ifname##*.}

            if [ ! -e /sys/class/net/$ifname ] ; then
                {
                local retry_cnt=0
                echo $pkey > /sys/class/net/$i/create_child
                while [[ $? -ne 0 && $retry_cnt -lt 10 ]]; do
                    sleep 1
                    let retry_cnt++
                    echo $pkey > /sys/class/net/$i/create_child
                done
                } > /dev/null 2>&1
            fi

            bring_up $ifname
            RC=$?
            if [ $RC -eq 0 ]; then
                    log_msg "Bringing up interface $ifname: PASSED"
            else
                    log_msg "Bringing up interface $ifname: FAILED"
            fi
        fi
    done < "$file"
done
}&

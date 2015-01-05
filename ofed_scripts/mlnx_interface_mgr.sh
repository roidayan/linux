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

if [ -f /etc/redhat-release ]; then
    NETWORK_CONF_DIR="/etc/sysconfig/network-scripts"
elif [ -f /etc/rocks-release ]; then
    NETWORK_CONF_DIR="/etc/sysconfig/network-scripts"
elif [ -f /etc/SuSE-release ]; then
    NETWORK_CONF_DIR="/etc/sysconfig/network"
else
    if [ -d /etc/sysconfig/network-scripts ]; then
        NETWORK_CONF_DIR="/etc/sysconfig/network-scripts"
    elif [ -d /etc/sysconfig/network ]; then
        NETWORK_CONF_DIR="/etc/sysconfig/network"
    fi
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

    /sbin/ifup ${i} >/dev/null 2>&1 &

    local IFCFG_FILE="${NETWORK_CONF_DIR}/ifcfg-${i}"
    # W/A for conf files created with nmcli
    if [ ! -e "$IFCFG_FILE" ]; then
        IFCFG_FILE=$(grep -E "=\s*\"*${i}\"*\s*\$" ${NETWORK_CONF_DIR}/* 2>/dev/null | head -1 | cut -d":" -f"1")
    fi

    if [[ -e ${IFCFG_FILE} ]]; then
        . ${IFCFG_FILE}
    fi

    # Take CM mode settings from ifcfg file if set,
    # otherwise, take it from openib.conf
    SET_CONNECTED_MODE=${CONNECTED_MODE:-$SET_IPOIB_CM}

    # relevant for IPoIB interfaces only
    if (/sbin/ethtool -i ${i} 2>/dev/null | grep -q ib_ipoib); then
        if [ "X${SET_CONNECTED_MODE}" == "Xyes" ]; then
            set_ipoib_cm ${i} ${MTU}
        elif [ "X${SET_CONNECTED_MODE}" == "Xauto" ]; then
            handle_specific_mlx_intf ${i} ${MTU}
        fi
    fi

    local RC=$?

    if [ "X$MASTER" != "X" ]; then
        log_msg "$i - briging up bond master: $MASTER ..."
        local is_up=`/sbin/ip link show $MASTER | grep -w UP`
        if [ -z "$is_up" ]; then
            /sbin/ifup $MASTER >dev/null 2>&1
            if [ $? -ne 0 ]; then
                log_msg "$i - briging up bond master $MASTER: PASSED"
            else
                log_msg "$i - briging up bond master $MASTER: FAILED"
            fi
        else
                log_msg "$i - bond master $MASTER is already up"
        fi
    fi

    # bring up the relevant bridge interface
    if [ "X$BRIDGE" != "X" ]; then
        log_msg "$i - briging up bridge interface: $BRIDGE ..."
        /sbin/ifup $BRIDGE >dev/null 2>&1
        if [ $? -ne 0 ]; then
            log_msg "$i - briging up bridge interface $BRIDGE: PASSED"
        else
            log_msg "$i - briging up bridge interface $BRIDGE: FAILED"
        fi
    fi

    unset IPADDR NETMASK BROADCAST MASTER

    return $RC
}

# main
{
log_msg "Setting up Mellanox network interface: $i"

# bring up the interface
bring_up $i
RC=$?


# W/A for conf files created with nmcli
if [[ ! -e ${NETWORK_CONF_DIR}/ifcfg-${i} ]] &&
      !(grep -Eq "=\s*\"*${i}\"*\s*\$" ${NETWORK_CONF_DIR}/* 2>/dev/null); then
    log_msg "No configuration found for ${i}"
else
    if [ $RC -eq 0 ]; then
        log_msg "Bringing up interface $i: PASSED"
    else
        log_msg "Bringing up interface $i: FAILED"
    fi
fi

############################ IPoIB (Pkeys) ####################################
# get list of conf child interfaces conf files
CHILD_CONFS=$(/bin/ls -1 ${NETWORK_CONF_DIR}/ifcfg-${i}.???? 2> /dev/null)
# W/A for conf files created with nmcli
for ff in $(grep -E "=\s*\"*${i}\.[0-9][0-9][0-9][0-9]\"*\s*\$" ${NETWORK_CONF_DIR}/* 2>/dev/null | cut -d":" -f"1")
do
    if $(echo ${CHILD_CONFS} 2>/dev/null | grep -q ${ff}); then
        continue
    fi
    CHILD_CONFS="${CHILD_CONFS} ${ff}"
done

# Bring up child interfaces if configured.
for child_conf in ${CHILD_CONFS}
do
    ch_i=${child_conf##*-}
    # Skip saved interfaces rpmsave and rpmnew
    if (echo $ch_i | grep rpm > /dev/null 2>&1); then
        continue
    fi

    if [ ! -f /sys/class/net/${i}/create_child ]; then
        continue
    fi

    pkey=0x${ch_i##*.}

    if [ ! -e /sys/class/net/${i}.${ch_i##*.} ] ; then
        {
        local retry_cnt=0
        echo $pkey > /sys/class/net/${i}/create_child
        while [[ $? -ne 0 && $retry_cnt -lt 10 ]]; do
            sleep 1
            let retry_cnt++
            echo $pkey > /sys/class/net/${i}/create_child
        done
        } > /dev/null 2>&1
    fi

    bring_up $ch_i
    RC=$?
    if [ $RC -eq 0 ]; then
            log_msg "Bringing up interface $ch_i: PASSED"
    else
            log_msg "Bringing up interface $ch_i: FAILED"
    fi
done

########################### Ethernet  (Vlans) #################################
# get list of conf child interfaces conf files
CHILD_CONFS=$(/bin/ls -1 ${NETWORK_CONF_DIR}/ifcfg-${i}.[0-9]* 2> /dev/null)
# W/A for conf files created with nmcli
for ff in $(grep -E "=\s*\"*${i}\.[0-9]*\"*\s*\$" ${NETWORK_CONF_DIR}/* 2>/dev/null | cut -d":" -f"1")
do
    if $(echo ${CHILD_CONFS} 2>/dev/null | grep -q ${ff}); then
        continue
    fi
    CHILD_CONFS="${CHILD_CONFS} ${ff}"
done

# Bring up child interfaces if configured.
for child_conf in ${CHILD_CONFS}
do
    ch_i=${child_conf##*-}
    # Skip saved interfaces rpmsave and rpmnew
    if (echo $ch_i | grep rpm > /dev/null 2>&1); then
        continue
    fi

    bring_up $ch_i
    RC=$?
    if [ $RC -eq 0 ]; then
            log_msg "Bringing up interface $ch_i: PASSED"
    else
            log_msg "Bringing up interface $ch_i: FAILED"
    fi
done
}&

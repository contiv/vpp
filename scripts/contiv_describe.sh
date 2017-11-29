#!/bin/bash

# Print out current network and policy configuration of all pods and hosts
# as deployed by the Contiv network plugin.
#
# Usage: ./contiv-describe.sh

# Execute a VPP CTL command.
function vppctl {
    IP=$1
    shift
    echo -e "\n$@\n" | netcat -q 1 $IP 5002
}

# Print a multi-line delimiter to separate output from different pods.
function output_delim {
    echo
    echo "=================================="
    echo
}

# Get logs from the vswitch to learn full app namespace names
VSWITCH_POD=`kubectl get pods --all-namespaces | grep vswitch | awk '{print $2}'`
VSWITCH_LOG=`kubectl logs --namespace=kube-system $VSWITCH_POD contiv-vswitch`

# Get list of all pods outside of the kube-system namespace.
PODS=`kubectl get pods --all-namespaces | grep -v kube-system | grep Running`
HOSTS=''

IFS='
'
for POD in $PODS ; do
    # Metadata
    PODNS=`echo $POD | awk '{print $1}'`
    PODNAME=`echo $POD | awk '{print $2}'`
    PODINFO=`kubectl describe pod $PODNAME`

    # IP addresses
    PODIP=`echo -e "$PODINFO" | grep 'IP:' | awk '{print $2}'`
    HOSTIP=`echo -e "$PODINFO" | grep 'Node:' | cut -f2 -d '/'`

    # Is VPP accessible?
    nc -z $HOSTIP 5002
    if [ ! $? -eq 0 ]; then
        "Cannot describe Pod ${PODNAME}, VPP ${HOSTIP} is not responsive"
        output_delim
        continue
    fi

    # Loopback interface
    LOOPBACK=`vppctl $HOSTIP sh int addr | grep -B1 $PODIP | head -n1 | cut -f1 -d ' '`
    LOOPBACK_IDX=`vppctl $HOSTIP sh int $LOOPBACK | grep ^$LOOPBACK | awk '{print $2}'`

    # VPP shows truncated app namespace name :(
    TRUNC_APPNS=`vppctl $HOSTIP sh app ns | awk -v idx="$LOOPBACK_IDX" '$3==idx {print $4}' | tr -d "\r"`
    APPNS=`echo -e "$VSWITCH_LOG" | sed -n "s/.*K8S_POD_INFRA_CONTAINER_ID=\($TRUNC_APPNS\w*\)\}.*/\1/p"`

    # AF Packet interface
    HOST_SUFFIX=`echo ${TRUNC_APPNS} | cut -c1-15`
    HOSTIF_INFO=`vppctl $HOSTIP sh int | grep $HOST_SUFFIX`
    HOSTIF=`echo "$HOSTIF_INFO" | awk '{print $1}'`
    HOSTIF_IDX=`echo "$HOSTIF_INFO" | awk '{print $2}'`

    # ACLs
    ACL_INGRESS=`vppctl $HOSTIP sh acl-plugin acl | grep -B4 "applied inbound.*[^[:digit:]]${HOSTIF_IDX}[^[:digit:]]"`
    ACL_EGRESS=`vppctl $HOSTIP sh acl-plugin acl | grep -B5 "applied outbound.*[^[:digit:]]${HOSTIF_IDX}[^[:digit:]]"`

    # Local tables
    LOCAL_TABLE_TCP=`vppctl $HOSTIP sh session rules tcp scope local appns $APPNS | tail -n +3 | head -n -2`
    LOCAL_TABLE_UDP=`vppctl $HOSTIP sh session rules udp scope local appns $APPNS | tail -n +3 | head -n -2`
    LISTENER_TABLE=`vppctl $HOSTIP sh app ns table $APPNS | tail -n +3 | head -n -2`

    # Add host IP into the set of known hosts.
    echo -e "$HOSTS" | grep --quiet $HOSTIP
    if [ ! $? -eq 0 ]; then
        HOSTS="$HOSTS
$HOSTIP"
    fi

    # Print pod details.
    echo "POD: $PODNS/$PODNAME"
    echo "  IP: $PODIP"
    echo "  Host IP: $HOSTIP"
    echo "  Loopback: $LOOPBACK (Idx:$LOOPBACK_IDX)"
    echo "  Host Interface: $HOSTIF (Idx:$HOSTIF_IDX)"
    echo "  App NS: $APPNS"
    echo
    for LINE in $LOCAL_TABLE_TCP; do
        echo "  $LINE"
    done
    echo
    for LINE in $LOCAL_TABLE_UDP; do
        echo "  $LINE"
    done
    echo
    for LINE in $LISTENER_TABLE; do
        echo "  $LINE"
    done
    echo
    echo "  ACL Ingress"
    for LINE in $ACL_INGRESS; do
        echo "    $LINE"
    done
    echo
    echo "  ACL Egress"
    for LINE in $ACL_EGRESS; do
        echo "    $LINE"
    done
    output_delim
done

for HOST in $HOSTS ; do
    # Global tables.
    SERVERS=`vppctl $HOSTIP sh app server verbose | tail -n +3 | head -n -2`
    GLOBAL_TABLE_TCP=`vppctl $HOSTIP sh session rules tcp | tail -n +3 | head -n -2`
    GLOBAL_TABLE_UDP=`vppctl $HOSTIP sh session rules udp | tail -n +3 | head -n -2`

    # Print host details.
    echo "HOST: $HOST"
    for LINE in $SERVERS; do
        echo "  $LINE"
    done
    echo
    for LINE in $GLOBAL_TABLE_TCP; do
        echo "  $LINE"
    done
    echo
    for LINE in $GLOBAL_TABLE_UDP; do
        echo "  $LINE"
    done
    output_delim
done

#!/bin/bash

# Use collected bug report data to show contiv network connectivity.

set -euo pipefail

usage() {
    echo "Usage: $0 [OPTION]..."
    echo
    echo "Available options:"
    echo
}

trim() {
    echo -e "$1" | tr -d '[:space:])'
}

max_string_length() {
    m=0
    for x in "$@"
    do
       # echo "$x" >&2
       if [ "${#x}" -gt "$m" ]
       then
          m="${#x}"
       fi
    done
    echo "$m"
}

check_name() {
    NAME="${1}"

    for n in "${IF_NAMES[@]}"
    do
        if [ $( trim "$NAME" ) == $( trim "$n" ) ]
        then
            return 1
        fi
    done
    return 0
}

# Constants
# K8s file names
NODES_FILE="k8s-nodes.txt"
PODS_FILE="K8s-pods.txt"
# VPP file name
VPP_IP_ADDR_FILE="vpp-interface-address.log"
VPP_MAC_ADDR_FILE="vpp-hardware-info.log"
VPP_VXLAN_FILE="vpp-vxlan-tunnels.log"
VPP_L2FIB_FILE="vpp-l2-fib.log"

VERBOSE=0


while getopts "d:hv" opt
do
    case "$opt" in
    d)  REPORT_DIR=$OPTARG
        ;;
    h)
        usage
        exit 0
        ;;
    v)  VERBOSE=1
        ;;
    *)
        # getopts will have already displayed a "illegal option" error.
        echo
        usage
        exit 1
        ;;
    esac
done

declare -A NODE_HOST_IP
declare -A IF_IP
declare -A IF_MAC

declare -A MAC_LOOP_NODE
declare -A MAC_LOOP_IP

NODE_NAMES=()
PRINT_POD_LINES=()

# echo "$REPORT_DIR"
pushd "$REPORT_DIR"

# Get all the nodes in the cluster and their host IP addresses
NODES=$(cat "$NODES_FILE" | grep -v "NAME")
readarray -t NODE_LINES <<< "$NODES"

for l in "${NODE_LINES[@]}"
do
    IFS=' ' read -ra NODE_FIELDS <<< "$l"
    NODE_NAMES+=("${NODE_FIELDS[0]}")
    NODE_HOST_IP["${NODE_FIELDS[0]}"]="${NODE_FIELDS[5]}"
done

if [ "$VERBOSE" == "1" ]
then
    PODS=$(cat "$PODS_FILE" | grep -v "NAME")
    readarray -t POD_LINES <<< "$PODS"
fi


# Print header
NODE_NAME_LEN=$(max_string_length "${NODE_NAMES[@]}")
HOST_IP_LEN=$(max_string_length "${NODE_HOST_IP[@]}")
FORMAT_STRING=$( echo %-"$NODE_NAME_LEN""s  %""$HOST_IP_LEN"s   %18s %18s   %18s %18s\\n )
TOTAL_LEN=$(( $NODE_NAME_LEN + $HOST_IP_LEN + 79 ))

echo
printf "$FORMAT_STRING" "NODE NAME:" "HOST IP:" \
       "GIGE IP ADDR:" "GIGE MAC ADDR:" "BVI IP ADDR:" "BVI MAC ADDR:"
printf '%0.s-' $( seq 1 "$TOTAL_LEN" )
echo

# Show Pod connectivity
for nn in "${NODE_NAMES[@]}"
do
    IF_NAMES=()

    # Get IP addresses for all interfaces that have an IP address
    VPP_IP_ADDR=$(cat "$nn"/"$VPP_IP_ADDR_FILE")
    readarray -t VPP_IF_IP <<< "$VPP_IP_ADDR"
    for l in "${VPP_IF_IP[@]}"
    do
        if echo "$l" | grep -q "(up)"
        then
            IFS=' ' read -ra IF_NAME_STATUS <<< "$l"
            IF_NAME=$( trim "${IF_NAME_STATUS[0]}" )
            IF_NAMES+=("$IF_NAME")
        elif echo "$l" | grep -qoE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"
        then
            IF_IP["$IF_NAME"]=$( trim "$l" )
        fi
    done

    # Get MAC addresses for all interfaces that have an IP address
    VPP_MAC_ADDR=$(cat "$nn"/"$VPP_MAC_ADDR_FILE" | grep -v "Name" )
    readarray -t VPP_IF_MAC <<< "$VPP_MAC_ADDR"
    for l in "${VPP_IF_MAC[@]}"
    do
        IFS=' ' read -ra MAC_FIELDS <<< "$l"
        F0=$( trim "${MAC_FIELDS[0]}" )
        if [ "${#MAC_FIELDS[@]}" -eq 4 ]  && \
           [ "$F0" == $( trim "${MAC_FIELDS[3]}" ) ] && \
           [ $( trim "${MAC_FIELDS[2]}" ) == "up" ]
        then
            IF_NAME=$( trim "${MAC_FIELDS[0]}" )
            if check_name "$IF_NAME"
            then
                IF_NAMES+=("$IF_NAME")
            fi
        elif [ "$F0" == "Ethernet" ]
        then
            IF_MAC["$IF_NAME"]=$( trim "${MAC_FIELDS[2]}" )
        fi
    done

    # Print Host IP and GigE/Loop interface data
    for n in "${IF_NAMES[@]}"
    do
        if echo "$n" | grep -q "Ethernet"
        then
            GIGE_IF_NAME="$n"
        elif echo "$n" | grep -q "loop"
        then
            LOOP_IF_NAME="$n"
        fi
    done

    LOOP_IP="${IF_IP[$LOOP_IF_NAME]}"
    LOOP_MAC="${IF_MAC[$LOOP_IF_NAME]}"

    printf "$FORMAT_STRING" "$nn" "${NODE_HOST_IP[$nn]}" \
           "${IF_IP[$GIGE_IF_NAME]}" "${IF_MAC[$GIGE_IF_NAME]}" "$LOOP_IP" "$LOOP_MAC"

    MAC_LOOP_IP["$LOOP_MAC"]="$LOOP_IP"
    MAC_LOOP_NODE["$LOOP_MAC"]="$nn"

    if [ "$VERBOSE" == "1" ]
    then
       # Collect all pod data lines into an array for later printing
        PRINT_POD_LINES+=($( printf "\n%s:\n" "$nn" ))
        PRINT_POD_LINES+=($( printf '%0.s-' $( seq 1 $(( ${#nn} + 1 )) ) ))

        for l in "${POD_LINES[@]}"
        do
            if echo "$l" | grep -q "$nn"
            then
                PRINT_LINE=$( echo "$l" | sed -e "s/  $nn//g" )
                POD_IP=$( echo "$PRINT_LINE" | awk '{print $7}' )

                # Add tap interface data if pod is connected to VPP
                if [ "$POD_IP" != "${NODE_HOST_IP[$nn]}" ]
                then
                    for n in "${IF_NAMES[@]}"
                    do
                        if echo "$n" | grep -q "tap"
                        then
                            # Compare just the 3rd digit of the IP address for now;
                            # Assumes /16 PodSubnetCIDR and /24 PodIfIPCIDR
                            POD_ID=$( echo "$POD_IP" | awk -F. '{print $4}' )
                            TAP_ID=$( echo "${IF_IP[$n]}" | awk -F/ '{print $1}' |awk -F. '{print $4}' )
                            if [ "$POD_ID" == "$TAP_ID" ]
                            then
                                PRINT_LINE=$( printf "%s  %-5s  %-13s  %18s" \
                                                     "$PRINT_LINE" "$n" "${IF_IP[$n]}" "${IF_MAC[$n]}" )
                            fi
                        fi
                    done
                fi
                PRINT_POD_LINES+=("$PRINT_LINE")
            fi
        done
    fi
done

if [ "$VERBOSE" == "1" ]
then
    for pl in "${PRINT_POD_LINES[@]}"
    do
        echo "$pl"
    done
fi

# Validate remote node connectivity: L2FIB entries and VXLAN tunnels
FORMAT_STRING=$( echo %-"$NODE_NAME_LEN""s  %-18s  %-18s  %-14s" )
for nn in "${NODE_NAMES[@]}"
do
    VXLANS=$( cat "$nn/$VPP_VXLAN_FILE" )
    readarray -t VXLAN_LINES <<< "$VXLANS"

    unset VXLAN_MAP
    declare -A VXLAN_MAP
    for l in "${VXLAN_LINES[@]}"
    do
        IF_IDX=$( echo "$l" | awk '{print $9}')
        VXLAN_MAP["$IF_IDX"]="$l"
    done

    L2FIB=$( cat "$nn/$VPP_L2FIB_FILE" | grep -v "Mac-Address" | grep -v "L2FIB" )
    readarray -t L2FIB_LINES <<< "$L2FIB"

    ERROR_LINES=()

    # Print node header
    printf "\n%s:\n" "$nn"
    printf '%0.s-' $( seq 1 $(( ${#nn} + 1 )) )
    echo
    HDR_FORMAT_STRING=$( echo "$FORMAT_STRING""  %-18s"  "%-18s\n" )
    printf "$HDR_FORMAT_STRING" "REMOTE NODE" "REMOTE IP" "REMOTE MAC" "IF NAME" "TUNNEL SRC IP" "TUNNEL DST IP"

    REMOTE_NODES=("${NODE_NAMES[@]}")

    for lfl in "${L2FIB_LINES[@]}"
    do
        IFS=' ' read -ra L2FIB_FIELDS <<< "$lfl"
        MAC_ADDR="${L2FIB_FIELDS[0]}"

        if [ ! "${MAC_LOOP_NODE[$MAC_ADDR]+_}" ]
        then
            ERROR_LINE=$( echo "Invalid L2FIB entry $MAC_ADDR - no remote node with this address " )
            ERROR_LINES+=("$ERROR_LINE")
            continue
        fi
        REMOTE_NODE="${MAC_LOOP_NODE[$MAC_ADDR]}"
        # Mark remote node as processed
        DELETE=("$REMOTE_NODE")
        REMOTE_NODES=("${REMOTE_NODES[@]/$DELETE}")

        REMOTE_IP="${MAC_LOOP_IP[$MAC_ADDR]}"

        IF_NAME="${L2FIB_FIELDS[8]}"

        PRINT_LINE=$( printf "$FORMAT_STRING" "$REMOTE_NODE" "$REMOTE_IP" "$MAC_ADDR" "$IF_NAME" )

        # If the L2FIB entry does not point to the local loop interface, get its VXLAN tunnel
        if echo "${L2FIB_FIELDS[8]}" | grep -q "vxlan_tunnel"
        then
            IF_INDEX="${L2FIB_FIELDS[2]}"
            if [ ! "${VXLAN_MAP[$IF_INDEX]+_}" ]
            then
                ERROR_LINE=$( echo "No VXLAN tunnel for address $MAC_ADDR" )
                ERROR_LINES+=("$ERROR_LINE")
                printf "\x1b[31m%s  ERROR: Missing VXLAN tunnel\x1b[0m\n" "$REMOTE_NODE"
                continue
            fi
            TUNNEL_LINE="${VXLAN_MAP[$IF_INDEX]}"
            VXLAN_MAP["$IF_INDEX"]=""

            IFS=' ' read -ra TL_FIELDS <<< "$TUNNEL_LINE"
            PRINT_LINE=$( printf "%s  %-18s  %-18s" "$PRINT_LINE" "${TL_FIELDS[2]}" "${TL_FIELDS[4]}" )
        fi
        echo "$PRINT_LINE"
    done

    # Each unmarked remote node means a missing L2FIB entry for the node
    for MISSING_NODE in "${REMOTE_NODES[@]}"
    do
        if [ -n "$MISSING_NODE" ]
        then
            printf "\x1b[31m%s  ERROR: Missing L2FIB entry\x1b[0m\n" "$MISSING_NODE"
        fi
    done

    for K in "${!VXLAN_MAP[@]}"
    do
        ENTRY=${VXLAN_MAP[$K]}
        if [ "$ENTRY" != "" ]
        then
            ERROR_LINE=$( printf "No L2FIB entry for VXLAN, sw_if_index=%s" $K )
            ERROR_LINES+=("$ERROR_LINE")
        fi
    done


    if [ "${#ERROR_LINES[@]}" -gt "0" ]
    then
        echo
        echo  "ERRORS:"
        for el in "${ERROR_LINES[@]}"
        do
            echo "- $el"
        done
    fi
done
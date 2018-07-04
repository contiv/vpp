#!/bin/bash

# Contiv network connectivity report v1.2
# This version works with Contiv-VPP 1.2+ and Kubernetes 1.10.5+

set -euo pipefail

usage() {
    echo "Usage: $0 [OPTION]..."
    echo
    echo "If no options are specified, IP and MAC addresses are shown for:"
    echo " - Host GigE interface"
    echo " - VPP GigE interface"
    echo " - VPP BD1 BVI interface"
    echo
    echo "Available options:"
    echo
    echo "-a               Show and validate ARP tables."
    echo
    echo "-d <report-dir>  Directory with the unzipped bug report collected by the "
    echo "                 'cont-vpp-bug-report.sh' script."
    echo
    echo "-h               Show this help message."
    echo
    echo "-n               Show network connectivity. Correlates entries from the VPP"
    echo "                 L2FIB and VXLAN tables and performs basic connectivity"
    echo
    echo "-p               Show pod connectivity - show which Pods are connected to"
    echo "                 which VPP interfaces, by node."
    echo
}

trim() {
    echo -e "$1" | tr -d '[:space:])'
}

max_string_length() {
    m=0
    for x in "$@"
    do
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
        if [ "$( trim "$NAME" )" == "$( trim "$n" )" ]
        then
            return 1
        fi
    done
    return 0
}

print_node_header() (
    node_name="$1"
    printf "%s:\\n" "$node_name"
    printf '%0.s-' $( seq 1 $(( ${#node_name} + 1 )) )
    echo
)

# K8s file names
NODES_FILE="k8s-nodes.txt"
PODS_FILE="k8s-pods.txt"
NODE_ADDR_FILE="k8s-node-addresses.txt"

# VPP file names
VPP_IP_ADDR_FILE="vpp-interface-address.log"
VPP_MAC_ADDR_FILE="vpp-hardware-info.log"
VPP_VXLAN_FILE="vpp-vxlan-tunnels.log"
VPP_L2FIB_FILE="vpp-l2-fib.log"
VPP_IP_ARP_FILE="vpp-ip-arp.log"
LOOP_MAC_PATTERN="1a:2b:3c:4d:5e"

SHOW_PODS=0
SHOW_NETWORK=0
SHOW_ARP=0

NODE_NAMES=()
PRINT_POD_LINES=()

declare -A IF_IP
declare -A IF_MAC
declare -A NODE_HOST_IP
declare -A NODE_GIGE_IP     # Map <node-name>:<vpp-gige-ip> used to validate VXLAN tunnels
declare -A NODE_LOOP_MAC
declare -A MAC_LOOP_NODE    # Map <mac-addr>:<node-name> used for L2FIB validation
declare -A MAC_LOOP_IP

while getopts "ad:hnps" opt
do
    case "$opt" in
    a)  SHOW_ARP=1
        ;;
    d)  REPORT_DIR=$OPTARG
        ;;
    h)
        usage
        exit 0
        ;;
    n)  SHOW_NETWORK=1
        ;;
    p)  SHOW_PODS=1
        ;;
    *)
        # getopts will have already displayed a "illegal option" error.
        echo
        usage
        exit 1
        ;;
    esac
done

pushd "$REPORT_DIR" > /dev/null

# Get all nodes in the cluster and their host IP addresses
NODES=$( grep < "$NODES_FILE" -v "NAME" ) || true
if [ -z "$NODES" ]
then
    echo "Missing or empty node log: '$NODES_FILE'"
    exit 1
fi

readarray -t NODE_LINES <<< "$NODES"
for l in "${NODE_LINES[@]}"
do
    IFS=' ' read -ra NODE_FIELDS <<< "$l"
    NODE_NAMES+=("${NODE_FIELDS[0]}")
    NODE_HOST_IP["${NODE_FIELDS[0]}"]="${NODE_FIELDS[5]}"
done

# Get node internal IP addresses
NODE_ADDRS=$( cat "$NODE_ADDR_FILE" 2> /dev/null ) || true
if [ -z "$NODE_ADDRS" ]
then
    echo "Missing or empty node address log: '$NODE_ADDR_FILE'"
else
    readarray -t NODE_ADDR_LINES <<< "$NODE_ADDRS"
    for l in "${NODE_ADDR_LINES[@]}"
    do
        IFS=' ' read -ra NODE_ADDR_FIELDS <<< "$l"
        IFS=',' read -ra NODE_ADDRESSES <<< "${NODE_ADDR_FIELDS[1]}"
        NODE_HOST_IP["${NODE_ADDR_FIELDS[0]}"]="${NODE_ADDRESSES[0]}"
    done
fi

if [ "$SHOW_PODS" == "1" ]
then
    PODS=$( cat "$PODS_FILE" ) || true
    if [ -z "$PODS" ]
    then
        echo "Missing or empty pods log: $PODS'"
        exit 1
    fi

    readarray -t POD_LINES <<< "$PODS"

    HDR=$( echo "${POD_LINES[0]}" | sed -e "s/IP    /POD-IP/g" | sed -e "s/NODE/VPP-IF/g" )
    HDR=$( printf "%s  %-13s  %-18s" "$HDR" "VPP-IP" "VPP-MAC" )
fi

# Create header formatting strings
NODE_NAME_LEN=$( max_string_length "${NODE_NAMES[@]}" )
HOST_IP_LEN=$( max_string_length "${NODE_HOST_IP[@]}" )
FORMAT_STRING=$( printf "%%-%ds   %%-%ds  %%-18s %%-18s  %%-18s %%-18s" "$NODE_NAME_LEN" "$HOST_IP_LEN" )
NODE_ERR_FORMAT=$( printf "\\x1b[31m%%-%ds   ERROR: %%s\\x1b[0m" "$NODE_NAME_LEN" )

TOTAL_LEN=$(( NODE_NAME_LEN + HOST_IP_LEN + 80 ))

echo
printf "$FORMAT_STRING\\n" "NODE NAME:" "HOST IP:" \
       "GIGE IP ADDR:" "GIGE MAC ADDR:" "BVI IP ADDR:" "BVI MAC ADDR:"
printf '%0.s-' $( seq 1 "$TOTAL_LEN" )
echo

# Print node addressing map (IP and MAC addresses for host, VPP GigE and BD BVI)
# Collect per-node Pod connectivity data
for nn in "${NODE_NAMES[@]}"
do
    IF_NAMES=()

    # Get IP addresses for all interfaces that have an IP address
    VPP_IP_ADDR=$( cat "$nn"/"$VPP_IP_ADDR_FILE" 2> /dev/null ) || true
    if [ -z "$VPP_IP_ADDR" ]
    then
        printf "$NODE_ERR_FORMAT\\n" "$nn" "Missing IP address log file ($REPORT_DIR/$nn/$VPP_MAC_ADDR_FILE)"
        continue
    fi

    readarray -t VPP_IF_IP <<< "$VPP_IP_ADDR"
    for l in "${VPP_IF_IP[@]}"
    do
        IFS=' ' read -ra IF_NAME_STATUS <<< "$l"
        if echo "${IF_NAME_STATUS[1]}" | grep -q "(up):"
        then
            IF_NAME=$( trim "${IF_NAME_STATUS[0]}" )
            IF_NAMES+=("$IF_NAME")
        elif [ "$( trim "${IF_NAME_STATUS[0]}" )" == "L3" ]
        then
            IF_IP["$IF_NAME"]=$( trim "${IF_NAME_STATUS[1]}" )
        fi
    done

    # Get MAC addresses for all interfaces that have an IP address
    VPP_MAC_ADDR=$( grep < "$nn"/"$VPP_MAC_ADDR_FILE" -v "Name" ) || true
    if [ -z "$VPP_IP_ADDR" ]
    then
        printf "$NODE_ERR_FORMAT" "$MISSING_NODE" ""
        echo "Missing or empty hardware address log: \\'""$nn""/$VPP_MAC_ADDR_FILE\\'"
        exit 1
    fi
    readarray -t VPP_IF_MAC <<< "$VPP_MAC_ADDR"
    for l in "${VPP_IF_MAC[@]}"
    do
        IFS=' ' read -ra MAC_FIELDS <<< "$l"
        F0=$( trim "${MAC_FIELDS[0]}" )
        if [ "${#MAC_FIELDS[@]}" -eq 4 ]  && \
           [ "$F0" == "$( trim "${MAC_FIELDS[3]}" )" ] && \
           [ "$( trim "${MAC_FIELDS[2]}" )" == "up" ]
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

    # Handle cases where IP or MAC address was not present in the vpp log
    for ifn in "${IF_NAMES[@]}"
    do
        if [ ! ${IF_IP[$ifn]+_} ]
        then
            IF_IP[$ifn]="<none>"
        fi
        if [ ! ${IF_MAC[$ifn]+_} ]
        then
            IF_MAC[$ifn]="<none>"
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

    printf "$FORMAT_STRING\\n" "$nn" "${NODE_HOST_IP[$nn]}" \
           "${IF_IP[$GIGE_IF_NAME]}" "${IF_MAC[$GIGE_IF_NAME]}" "$LOOP_IP" "$LOOP_MAC"

    MAC_LOOP_IP["$LOOP_MAC"]="$LOOP_IP"
    MAC_LOOP_NODE["$LOOP_MAC"]="$nn"
    NODE_GIGE_IP["$nn"]="${IF_IP[$GIGE_IF_NAME]}"
    NODE_LOOP_MAC["$nn"]="$LOOP_MAC"

    if [ "$SHOW_PODS" == "1" ]
    then
       # Collect all pod data lines into an array for later printing
        PRINT_POD_LINES+=( "$( printf "\\n%s:\\n" "$nn" )" )
        PRINT_POD_LINES+=( "$( printf '%0.s-' $( seq 1 $(( ${#nn} + 1 )) ) )" )
        PRINT_POD_LINES+=("$HDR")

        for l in "${POD_LINES[@]}"
        do
            if echo "$l" | grep -q "$nn"
            then
                PRINT_LINE="${l//  $nn/}"
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
                                PRINT_LINE=$( printf "%s  %-6s  %-13s  %-18s" \
                                                     "$PRINT_LINE" "$n" "${IF_IP[$n]}" "${IF_MAC[$n]}" )
                            fi
                        fi
                    done
                fi
                PRINT_POD_LINES+=("$PRINT_LINE")
            fi
        done
        PRINT_POD_LINES+=("")
    fi
done
echo

# Print per-node Pod connectivity data
if [ "$SHOW_PODS" == "1" ]
then
    echo "================="
    echo "POD CONNECTIVITY:"
    echo "================="
    for pl in "${PRINT_POD_LINES[@]}"
    do
        echo "$pl"
    done
fi

if [ "$SHOW_NETWORK" == "1" ]
then
    echo "========================="
    echo "VXLAN/L2FIB CONNECTIVITY:"
    echo "========================="
    # Validate remote node connectivity: L2FIB entries and VXLAN tunnels
    FORMAT_STRING=$( printf "%%-%ss  %%-18s  %%-18s  %%-14s" "$NODE_NAME_LEN" )
    for nn in "${NODE_NAMES[@]}"
    do
        ERROR_LINES=()

        VXLANS=$( cat "$nn/$VPP_VXLAN_FILE" 2> /dev/null ) || true
        if [ -z "$VXLANS" ]
        then
            print_node_header "$nn"
            NODE_ERR_FORMAT="\\x1b[31m%-""$NODE_NAME_LEN""s   ERROR: %s\\x1b[0m\\n"
            printf "\\x1b[31mError: Missing or empty vxlan tunnel log %s\\x1b[0m\\n" "'$nn/$VPP_VXLAN_FILE'"
            echo "No VXLAN/L2FIB connectivity checking for this node."
            echo
            continue
        fi

        readarray -t VXLAN_LINES <<< "$VXLANS"

        unset VXLAN_MAP
        declare -A VXLAN_MAP
        for l in "${VXLAN_LINES[@]}"
        do
            IF_IDX=$( echo "$l" | grep -v "No vxlan tunnels" | awk '{print $13}') || true
            if [ -z "$IF_IDX" ]
            then
                ERROR_LINE="No VXLANs configured for the node"
                ERROR_LINES+=("$ERROR_LINE")
            else
                VXLAN_MAP["$IF_IDX"]="$l"
            fi
        done

        L2FIB=$( grep < "$nn/$VPP_L2FIB_FILE" -v "Mac-Address" | grep -v "L2FIB" ) || true
        if [ -z "$L2FIB" ]
        then
            print_node_header "$nn"
            printf "\\x1b[31mError: Missing or empty L2FIB table log %s\\x1b[0m\\n" "'$nn/$VPP_L2FIB_FILE'"
            echo "No VXLAN/L2FIB connectivity checking for this node."
            echo
            continue
        fi

        readarray -t L2FIB_LINES <<< "$L2FIB"

        print_node_header "$nn"
        HDR_FORMAT_STRING="$FORMAT_STRING  %-18s  %-18s\\n"
        printf "$HDR_FORMAT_STRING" "REMOTE NODE" "REMOTE IP" "REMOTE MAC" "IF NAME" "TUNNEL SRC IP" "TUNNEL DST IP"

        REMOTE_NODES=("${NODE_NAMES[@]}")

        for lfl in "${L2FIB_LINES[@]}"
        do
            IFS=' ' read -ra L2FIB_FIELDS <<< "$lfl"
            MAC_ADDR="${L2FIB_FIELDS[0]}"

            if [ ! "${MAC_LOOP_NODE[$MAC_ADDR]+_}" ]
            then
                ERROR_LINE=$( printf "Invalid L2FIB entry, address='%s'; no remote node with this address" "$MAC_ADDR" )
                ERROR_LINES+=("$ERROR_LINE")
                continue
            fi
            REMOTE_NODE="${MAC_LOOP_NODE[$MAC_ADDR]}"
            # Mark remote node as processed
            for i in "${!REMOTE_NODES[@]}"
            do
                if [ "${REMOTE_NODES[$i]}" == "$REMOTE_NODE" ]
                then
                    REMOTE_NODES["$i"]=""
                fi
            done

            REMOTE_IP="${MAC_LOOP_IP[$MAC_ADDR]}"

            IF_NAME="${L2FIB_FIELDS[8]}"

            PRINT_LINE=$( printf "$FORMAT_STRING" "$REMOTE_NODE" "$REMOTE_IP" "$MAC_ADDR" "$IF_NAME" )

            # If the L2FIB entry points to a vxlan tunnel, validate and print the tunnel info
            if echo "${L2FIB_FIELDS[8]}" | grep -q "vxlan_tunnel"
            then
                IF_INDEX="${L2FIB_FIELDS[2]}"
                if [ ! "${VXLAN_MAP[$IF_INDEX]+_}" ]
                then
                    ERROR_LINE=$( printf "Invalid L2FIB entry, address='%s'; missing VXLAN tunnel" "$MAC_ADDR" )
                    ERROR_LINES+=("$ERROR_LINE")
                    printf "\\x1b[31m%s  ERROR: Missing VXLAN tunnel\\x1b[0m\\n" "$REMOTE_NODE"
                    continue
                fi

                TUNNEL_LINE="${VXLAN_MAP[$IF_INDEX]}"
                IFS=' ' read -ra TL_FIELDS <<< "$TUNNEL_LINE"

                TUNNEL_SRC_IP="${TL_FIELDS[4]}"
                TUNNEL_DST_IP="${TL_FIELDS[6]}"
                PRINT_LINE=$( printf "%s  %-18s  %-18s" "$PRINT_LINE" "$TUNNEL_SRC_IP" "$TUNNEL_DST_IP" )

                LOCAL_GIGE_IP=$( echo "${NODE_GIGE_IP[$nn]}" | awk -F/ '{print $1}' )
                if [ "$TUNNEL_SRC_IP" != "$LOCAL_GIGE_IP" ]
                then
                    ERROR_LINE=$( printf "Invalid VXLAN Tunnel, sw_if_index=%s; bad SRC address '%s' (should be '%s')" \
                                  "${TL_FIELDS[8]}" "$TUNNEL_SRC_IP" "$LOCAL_GIGE_IP" )
                    ERROR_LINES+=("$ERROR_LINE")
                fi

                REMOTE_GIGE_IP=$( echo "${NODE_GIGE_IP[$REMOTE_NODE]}" |  awk -F/ '{print $1}' )
                if [ "$TUNNEL_DST_IP" != "$REMOTE_GIGE_IP" ]
                then
                    ERROR_LINE=$( printf "Invalid VXLAN Tunnel, sw_if_index=%s; bad DST address '%s' (should be '%s')" \
                                  "${TL_FIELDS[8]}" "$TUNNEL_DST_IP" "$REMOTE_GIGE_IP" )
                    ERROR_LINES+=("$ERROR_LINE")
                fi

                VXLAN_MAP["$IF_INDEX"]=""
            fi
            echo "$PRINT_LINE"
        done

        # Each unmarked remote node means a missing L2FIB entry for the node
        for MISSING_NODE in "${REMOTE_NODES[@]}"
        do
            if [ "$MISSING_NODE" != "" ]
            then
                printf "\\x1b[31m%s  ERROR: Missing L2FIB entry (and possibly VXLAN tunnel)\\x1b[0m\\n" "$MISSING_NODE"
                ERROR_LINE=$( printf "Missing L2FIB entry (and possibly VXLAN tunnel), node='%s'", "$MISSING_NODE")
                ERROR_LINES+=("$ERROR_LINE")
            fi
        done

        for K in "${!VXLAN_MAP[@]}"
        do
            ENTRY=${VXLAN_MAP[$K]}
            if [ "$ENTRY" != "" ]
            then
                ERROR_LINE=$( printf "Invalid VXLAN tunnel, sw_if_index=%s; missing L2FIB entry" $K )
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
        echo
    done
fi

if [ "$SHOW_ARP" == "1" ]
then
    echo "======================================="
    echo "VALIDATING STATIC ARP TABLE ENTRIES IN:"
    echo "======================================="

    for nn in "${NODE_NAMES[@]}"
    do
        print_node_header "$nn"

        REMOTE_NODES=("${NODE_NAMES[@]}")
        ERRORS=false

        ARP_TABLE=$( cat "$nn/$VPP_IP_ARP_FILE" 2>/dev/null ) || true
        if [ -z "$ARP_TABLE" ]
        then
            echo "Missing or empty ARP table log: '$nn"/"$VPP_IP_ARP_FILE'"
            echo
            continue
        fi

        readarray -t ARP_LINES <<< "$ARP_TABLE"
        for l in "${ARP_LINES[@]}"
        do
            if echo "$l" | grep -q "$LOOP_MAC_PATTERN"
            then
                IFS=' ' read -ra ARP_FIELDS <<< "$l"
                ARP_MAC="${ARP_FIELDS[3]}"
                ARP_IP="${ARP_FIELDS[1]}"
                if [ ${MAC_LOOP_NODE[$ARP_MAC]+_} ]
                then
                    REMOTE_NODE="${MAC_LOOP_NODE[$ARP_MAC]}"

                    # Mark node as having an entry in the ARP table
                    for i in "${!REMOTE_NODES[@]}"
                    do
                        if [ "${REMOTE_NODES[$i]}" == "$REMOTE_NODE" ]
                        then
                            REMOTE_NODES["$i"]=""
                        fi
                    done

                    REMOTE_IP="${MAC_LOOP_IP[$ARP_MAC]}"

                    if [ "$ARP_MAC" != "${NODE_LOOP_MAC[$REMOTE_NODE]}" ]
                    then
                        echo "- ERROR: Invalid MAC ADDRESS for \\'$ARP_IP\\':" \
                             "\\'${NODE_LOOP_MAC[$REMOTE_NODE]}\\', should be \\'$ARP_MAC\\'"
                        ERRORS=true
                    fi
                else
                    echo "- ERROR: No node for MAC address '""$ARP_MAC""'"
                    ERRORS=true
                fi
            fi
        done
        # Each unmarked remote node means a missing L2FIB entry for the node
        for MISSING_NODE in "${REMOTE_NODES[@]}"
        do
            if [ "$MISSING_NODE" != "" ] && [ "$MISSING_NODE" != "$nn" ]
            then
                echo "- ERROR: Missing ARP entry for node '$MISSING_NODE'"
                ERRORS=true
            fi
        done
        if [ "$ERRORS" == false ]
        then
            echo No errors found.
        fi
        echo
    done
fi
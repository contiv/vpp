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

# Constants
NODES_FILE="k8s-nodes.txt"
VPP_IP_ADDR_FILE="vpp-interface-address.log"
VPP_MAC_ADDR_FILE="vpp-hardware-info.log"
VERBOSE=0


declare -A NODE_HOST_IP
declare -A IF_IP
declare -A IF_MAC
NODE_NAMES=()

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
        if [ "${#MAC_FIELDS[@]}" -eq 4 ]  && [ "$F0" == $( trim "${MAC_FIELDS[3]}" ) ] && [ $( trim "${MAC_FIELDS[2]}" ) == "up" ]
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

    # Print results
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

    printf "$FORMAT_STRING" "$nn" "${NODE_HOST_IP[$nn]}" \
            "${IF_IP[$GIGE_IF_NAME]}" "${IF_MAC[$GIGE_IF_NAME]}" "${IF_IP[$LOOP_IF_NAME]}" "${IF_MAC[$LOOP_IF_NAME]}"
done
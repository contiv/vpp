#!/bin/bash

#########################################################################
# This script deletes dynamic NAT44 mappings for a given src/dst
# IP address pair and protocol type (tcp or udp).
#
# Example Usage:
# del-nat-sessions.sh <SRC-IP-ADDRESS> -s <DST-IP-ADDRESS> -p <PROTOCOL>
# <SRC-IP-ADDRESS>: Source IP address for the mapping
# <DST-IP-ADDRESS>: External host IP address for the mapping
# <PROTO>:          Protocol type (tcp or udp)
#
# All cli parameters are mandatory.
#########################################################################

set -euo pipefail

while getopts "h?s:d:p:" opt; do
    case "$opt" in
    h|\?)
        echo Usage: "$0 -s <SRC-IP-ADDRESS> -s <DST-IP-ADDRESS> -p <PROTOCOL>"
        exit 0
        ;;
    s)  SRC_IP_ADDR=$OPTARG
        ;;
    d)  DST_IP_ADDR=$OPTARG
        ;;
    p)  PROTO=$OPTARG
        ;;
    esac
done

NAT44_OUTPUT=$(echo "sh nat44 sessions detail" | sudo nc -U /run/vpp/cli.sock)

EL=0
DO_DELETE=false

while read -r line; do
    case "$EL" in
    0)
        ll=$(echo "$line" | grep "i2o $SRC_IP_ADDR proto $PROTO") || true
        if [ "$ll" != "" ]
        then
            EL=1
            PORT=$(echo "$line" | grep "i2o $SRC_IP_ADDR proto $PROTO" | awk '{ print $6 }')
        fi
        ;;
    1 | 3 | 4)
        EL=$((EL + 1))
        ;;
    2)
        ll=$(echo "$line" | grep "external host $DST_IP_ADDR") || true
        if [ "$ll" != "" ]
        then
            DO_DELETE=true
        fi
        EL=3
        ;;
    5)
        ll=$(echo "$line" | grep "dynamic translation") || true
        if [ "$ll" != "" ] && "$DO_DELETE"
        then
           echo Deleting entry "$SRC_IP_ADDR":"$PORT"
           echo "nat44 del session in $SRC_IP_ADDR:$PORT $PROTO" | sudo nc -U /run/vpp/cli.sock 1>/dev/null
           DO_DELETE=false
        fi
        EL=0
        ;;
    *)
        EL=0
        ;;
    esac
done <<< "$NAT44_OUTPUT"

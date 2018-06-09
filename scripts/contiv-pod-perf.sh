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
    echo -e "$1" | tr -d '[:space:]'
}

declare -A RX
declare -A TX
declare -A DROPS

INTERFACES=()
VERBOSE=0
STATS_FILE="-"

while getopts "e:f:hs:v" opt
do
    case "$opt" in
    e)  END_TIME=$OPTARG
        ;;
    f)  STATS_FILE=$OPTARG
        ;;
    h)
        usage
        exit 0
        ;;
    s)  START_TIME=$OPTARG
        ;;
    v)
        VERBOSE=1
        ;;
    *)
        # getopts will have already displayed a "illegal option" error.
        echo
        usage
        exit 1
        ;;
    esac
done

IF_DATA=$(cat "$STATS_FILE" | grep -v "Name" | grep -v "down")
while read -r line
do
    IFS=' ' read -ra FIELDS <<< "$line"
    case "${FIELDS[0]}" in
        "rx" )
            if [ "${FIELDS[1]}" == "bytes" ]
            then
                RX["$IF_NAME",0]=$(trim "${FIELDS[2]}")
            elif [ "${FIELDS[1]}" == "packets" ]
            then
                RX["$IF_NAME",1]=$(trim "${FIELDS[2]}")
            fi
            ;;
        "tx" )
            if [ "${FIELDS[1]}" == "bytes" ]
            then
                TX["$IF_NAME",0]=$(trim "${FIELDS[2]}")
            elif [ "${FIELDS[1]}" == "packets" ]
            then
                TX["$IF_NAME",1]=$(trim "${FIELDS[2]}")
            fi
            ;;
        "drops" )
            DROPS["$IF_NAME"]=$(trim "${FIELDS[1]}")
            ;;
        "ip4"|"ip6"|"punts" )
            ;;
        * )
            IF_NAME="${FIELDS[0]}"
            RX["$IF_NAME",1]=$(trim "${FIELDS[5]}")
            INTERFACES+=("$IF_NAME")
            ;;
    esac
done <<< "$IF_DATA"

TAP_RX_BYTES=0
TAP_RX_PKTS=0
TAP_TX_BYTES=0
TAP_TX_PKTS=0
TAP_DROPS=0

for K in "${!INTERFACES[@]}"
do
    IF_NAME="${INTERFACES[$K]}"
    if echo "$IF_NAME" | grep -q "tap"
    then
        let "TAP_RX_BYTES = $TAP_RX_BYTES + ${RX[$IF_NAME,0]}"
        let "TAP_TX_BYTES = $TAP_TX_BYTES + ${TX[$IF_NAME,0]}"
        let "TAP_RX_PKTS = $TAP_RX_PKTS + ${RX[$IF_NAME,1]}"
        let "TAP_TX_PKTS = $TAP_TX_PKTS + ${TX[$IF_NAME,1]}"
        let "TAP_DROPS = $TAP_DROPS + ${DROPS[$IF_NAME]}"
    fi
done

START_EPOCH=$(date -d "$START_TIME" +%s)
END_EPOCH=$(date -d "$END_TIME" +%s)
let "DELTA = $END_EPOCH - $START_EPOCH"

let "TX_ACTUAL_PKT_RATE = $TAP_TX_PKTS / $DELTA"
let "TX_OFFERD_PKT_RATE = ($TAP_TX_PKTS + $TAP_DROPS) / $DELTA"
let "RX_PKT_RATE = $TAP_RX_PKTS / $DELTA"

let "TX_BYTE_RATE = $TAP_TX_BYTES / $DELTA"
let "RX_BYTE_RATE = $TAP_RX_BYTES / $DELTA"

echo
printf "+-----------++-----------------------------------------------++-------------------------------+\n"
printf "|           ||                   PACKETS/s                   ||            BYTES/s            |\n"
printf "|           ||---------------+---------------+---------------++---------------+---------------+\n"
printf "|           ||      Rx:      |   Tx-Actual:  |  Tx-Attempts: ||      Rx:      |       Tx:     |\n"
printf "|===========++===============+===============+===============++===============+===============+\n"
printf "| AGGREGATE || %12d  | %12d  | %12d  || %12d  | %12d  |\n"\
        "$RX_PKT_RATE" "$TX_ACTUAL_PKT_RATE" "$TX_OFFERD_PKT_RATE" "$RX_BYTE_RATE" "$TX_BYTE_RATE"

if [ $VERBOSE == "1" ]
then
    printf "|===========++===============+===============+===============++===============+===============+\n"
    for K in "${!INTERFACES[@]}"
    do
        IF_NAME="${INTERFACES[$K]}"
        if echo "$IF_NAME" | grep -q "tap"
        then
            let "TX_ACTUAL_PKT_RATE = ${TX[$IF_NAME,1]} / $DELTA"
            let "TX_OFFERD_PKT_RATE = (${TX[$IF_NAME,1]} + ${DROPS[$IF_NAME]}) / $DELTA"
            let "RX_PKT_RATE = ${RX[$IF_NAME,1]} / $DELTA"

            let "TX_BYTE_RATE = ${TX[$IF_NAME,0]} / $DELTA"
            let "RX_BYTE_RATE = ${RX[$IF_NAME,0]} / $DELTA"
            printf "| %-9s || %12d  | %12d  | %12d  || %12d  | %12d  |\n"\
                "$IF_NAME" "$RX_PKT_RATE" "$TX_ACTUAL_PKT_RATE" "$TX_OFFERD_PKT_RATE" "$RX_BYTE_RATE" "$TX_BYTE_RATE"
        fi
    done
fi

printf "+-----------++-----------------------------------------------++-------------------------------+\n"
echo

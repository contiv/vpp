#!/bin/bash

# Use the output from the VPP 'show interface' command to compute aggregate
# and individual throughputs to pods attached to the vswitch in Contiv-VPP.

set -euo pipefail

usage() {
    echo "Usage: $0 [OPTION]..."
    echo
    echo "Available options:"
    echo
    echo "-e <end-time>    End of the measurement interval. Any valid output from the"
    echo "                 'date' command is accepted. For example:"
    echo "                 $0 -f <stats-file> -s '2012-03-22 22:01:05 EDT' -e \"\`date\`\""
    echo "                 If either the start or the end of the measurement interval"
    echo "                 is not specified, it is set to a default value of 1 second."
    echo
    echo "-f <stats-file>  Path to a file containing the out put from the vppctl command"
    echo "                 'show interfaces'. If the stats file is not specified, output"
    echo "                 from 'vpp ctl show interfaces' can be piped into this script on"
    echo "                 stdin. For example:"
    echo "                 vppctl sh int | $0 -s '2012-03-22 22:01:05 EDT' -e \"\`date\`\""
    echo
    echo "-h               Display this help message."
    echo
    echo "-s <start-time>  Start of the measurement interval. Any valid output from the"
    echo "                 'date' command is accepted. For example:"
    echo "                 $0 -f <stats-file> -s '2012-03-22 22:01:05 EDT' -e \"\`date\`\""
    echo "                 For throughput calculations it is assumed that stats counters"
    echo "                 are cleared at <start-time>. If either the start or the end"
    echo "                 of the measurement interval is not specified, it is set to a"
    echo "                 default value of 1 second."
    echo
    echo "-v               Verbose, in addition to the aggregate throughput for all pods,"
    echo "                 print throughput for each pod."
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
START_TIME=
END_TIME=
DELTA=1

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

echo

if [ -n "$START_TIME" ] && [ -n "$END_TIME" ]
then
    START_EPOCH=$(date -d "$START_TIME" +%s)
    END_EPOCH=$(date -d "$END_TIME" +%s)
    let "DELTA = $END_EPOCH - $START_EPOCH"
else
    echo "Start or End time not specified. Using 1 second as measurement interval"
fi


let "TX_ACTUAL_PKT_RATE = $TAP_TX_PKTS / $DELTA"
let "TX_OFFERD_PKT_RATE = ($TAP_TX_PKTS + $TAP_DROPS) / $DELTA"
let "RX_PKT_RATE = $TAP_RX_PKTS / $DELTA"

let "TX_BYTE_RATE = $TAP_TX_BYTES / $DELTA"
let "RX_BYTE_RATE = $TAP_RX_BYTES / $DELTA"

echo Measurement time interval: "$DELTA" seconds
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

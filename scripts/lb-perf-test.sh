#!/usr/bin/env bash

set -euo pipefail

usage() {
    echo "Usage: $0 [OPTION]..."
    echo
    echo "Available options:"
    echo
    echo "-a <address>     Address of the service-under-test."
    echo
    echo "-h               Show this help message."
    echo
    echo "-i <iterations>  Number of iterations in the test."
    echo
}

while getopts "a:hi:nps:" opt
do
    case "$opt" in
    a)  ADDRESS=$OPTARG
        ;;
    h)
        usage
        exit 0
        ;;
    i)  ITERATIONS=$OPTARG
        ;;
    *)
        # getopts will have already displayed a "illegal option" error.
        echo
        usage
        exit 1
        ;;
    esac
done

if [[ -z ${ITERATIONS+x} ]]
then
    echo Number of iterations is not specified
    usage
    exit 1
fi

if [[ -z ${ADDRESS+x} ]]
then
    echo Service address is not specified
    usage
    exit 1
fi

START_TIME=$(( $(date +%s%N)/1000000 ))

COUNTER=0
while [[ "$COUNTER" -lt "$ITERATIONS" ]]
do
    # echo Iteration "$COUNTER"
    wget -O - "$ADDRESS"  > /dev/null 2>&1
    let COUNTER=COUNTER+1
done


END_TIME=$(( $(date +%s%N)/1000000 ))
DURATION=`expr "$END_TIME" - "$START_TIME"`

echo "$ITERATIONS" iterations took "$DURATION" milliseconds
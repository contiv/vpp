#!/usr/bin/env bash

set -euo pipefail

usage() {
    echo "Usage: $0 [OPTION]..."
    echo
    echo "Available options:"
    echo
    echo "-a <address>     Mandatory, address of the service-under-test."
    echo
    echo "-h               Show this help message."
    echo
    echo "-i <iterations>  Mandatory, the number of iterations in the test."
    echo
    echo "-r <replicas>    Mandatory, number of lb-perf-test instances to"
    echo "                 run in parallel"
    echo "                 at the same time."
    echo
}

LABEL=""

while getopts "a:hi:r:" opt
do
    case "$opt" in
    a)  ADDRESS=$OPTARG
        ;;
    h)  usage
        exit 0
        ;;
    i)  ITERATIONS=$OPTARG
        ;;
    r)  REPLICAS=$OPTARG
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

if [[ -z ${REPLICAS+x} ]]
then
    echo The number of replicas is not specified
    usage
    exit 1
fi

COUNTER=0
while [[ "$COUNTER" -lt "$REPLICAS" ]]
do
    # echo Iteration "$COUNTER"
    ./lb-perf-test.sh -i "$ITERATIONS" -a "$ADDRESS" -l TEST-"$COUNTER" &
    let COUNTER=COUNTER+1
done

echo Done

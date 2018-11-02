#!/bin/bash

# Run a system test for a specified number of iterations, either locally on
# a master node or remotely via ssh. If number of failed tests is over
# treshold, iterations are stopped

set -euo pipefail

usage() {
  echo ""
  echo "usage: $0 -i <iterations> -f <inventory-file> -u <user> -m <master-node> -F <ssh-config-file> -t <failed-tests-treshold>"
}

LOCAL=false
MASTER=""
USER=""
ITERATIONS=1
TRESHOLD=5

cmd() {
    if [ "$LOCAL" == true ]
    then
        echo "cmd: $1"
        sh -c "$1"
    else
        echo "cmd: $1"
        ssh "$USER"@"$MASTER" -F "$SSH_CONFIG_FILE" $1
    fi
}


while getopts "h?f:F:i:m:u:t:" opt
do
    case "$opt" in
    h|\?)
        usage
        exit 0
        ;;
    f)  INVENTORY_FILE=$OPTARG
        ;;
    F)  SSH_CONFIG_FILE=$OPTARG
        ;;
    i)  ITERATIONS=$OPTARG
        ;;
    m)  MASTER=$OPTARG
        ;;
    u)  USER=$OPTARG
        ;;
    t)  TRESHOLD=$OPTARG
        ;;
    esac
done

if [ -z "${INVENTORY_FILE+x}" ]
then
    echo The test inventory file must be specified.
    usage
    exit 1
fi

if [ "$MASTER" == "" ] && [ "$USER" == "" ]
then
    LOCAL=true
elif [ "$MASTER" == "" ] || [ "$USER" == "" ]
then
    echo "For remote access, both <user> and <master-node> must be specified"
    usage
    exit 1
fi

set +o pipefail
echo "Using treshold: $TRESHOLD"
for (( c=1; c<="$ITERATIONS"; c++ ))
do
    echo "*************** Iteration "$c" out of "$ITERATIONS" ****************"
    .venv/bin/pytest --inventory "$INVENTORY_FILE" -v  k8s_tests/ | tee pytest_output_n$c
    cmd "kubectl get po -n kube-system -o wide"
    cmd free
    cmd "free -m"
    cmd "df -h"
    cmd "ps aux --sort -rss | head -10"
    cmd "lsof | awk '{ print \$2 \" \" \$1; }' | uniq -c | sort -rn | head -20"
    cmd date
    echo ""
    status=`cat pytest_output_n$c | grep ==== | grep second | grep failed | cut -d " " -f 2`
    echo "Failed tests: $status"
    if (( status > TRESHOLD )); then
        echo "Too many failed tests, ending..."
        exit $status
    fi
done

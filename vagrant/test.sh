#!/bin/bash

# Run a system test for a specified number of iterations, either locally on
# a master node or remotely via ssh.

set -euo pipefail

usage() {
  echo ""
  echo "usage: $0 -i <iterations> -f <inventory-file> -u <user> -m <master-node> -F <ssh-config-file>"
}

LOCAL=false
MASTER=""
USER=""
ITERATIONS=1

cmd() {
    if [ "$LOCAL" == true ]
    then
        $1
    else
        ssh "$USER"@"$MASTER" -F "$SSH_CONFIG_FILE" $1
    fi
}


while getopts "h?f:F:i:m:u:" opt
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

for (( c=1; c<="$ITERATIONS"; c++ ))
do
    echo "*************** Iteration "$c" out of "$ITERATIONS" ****************"
    .venv/bin/pytest --inventory "$INVENTORY_FILE" -v  k8s_tests/ || true
     cmd "kubectl get po -n kube-system -o wide"
     cmd free
     cmd "free -m"
     cmd date
     echo ""
done
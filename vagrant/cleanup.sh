#!/usr/bin/env bash

# Cleans up deployments, services, daemonsets, stateful sets and pods in
# default namespace that may have been left over on a cluster after an
# aborted test.

set -euo pipefail

usage() {
  echo ""
  echo "usage: $0 -u <user> -m <master-node> -F <ssh-config-file>"
  echo ""
  echo "Cleans up deployments, services, daemonsets, stateful sets and pods in"
  echo "default namespace that may have been left over on a cluster after an"
  echo "aborted test. Can be run locally on the cluster's master node, or"
  echo "on a remote client where passwordless login into the master node (or"
  echo "an ssh config file) is required".
  echo ""
}

LOCAL=false
MASTER=""
USER=""

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
    F)  SSH_CONFIG_FILE=$OPTARG
        ;;
    m)  MASTER=$OPTARG
        ;;
    u)  USER=$OPTARG
        ;;
    esac
done

if [ "$MASTER" == "" ] && [ "$USER" == "" ]
then
    LOCAL=true
elif [ "$MASTER" == "" ] || [ "$USER" == "" ]
then
    echo "For remote access, both <user> and <master-node> must be specified"
    usage
    exit 1
fi

echo Deleting deployments...
cmd "kubectl delete deployment --all"
echo Deleting services...
cmd "kubectl delete service --all"
echo Deleting daemonsets...
cmd "kubectl delete daemonset --all"
echo Deleting statefulsets...
cmd "kubectl delete statefulset --all"
echo Deleting pods...
cmd "kubectl delete pods --all"

#!/usr/bin/env bash

usage() {
  echo "Randomly reboots nodes in a kubernetes cluster."
  echo
  echo "Usage: $0 -u <user> -m <master-node> -F <ssh-config-file> -i <iterations>"
  echo "       -t <time-between-reboots> -M <reboot-master-only> -w <reboot-workers-only>"
  echo
  echo "Available options:"
  echo
  echo "-F <ssh-config-file>  Path to optional ssh configuration file. The ssh"
  echo "                      configuration file must be specified when logging into"
  echo "                      vagrant nodes."
  echo
  echo "-h                    Display this help message."
  echo
  echo "-m <k8s-master-node>  IP address or name of the k8s master node."
  echo
  echo "-M                    Only reboot the master node. Must not be specified together"
  echo "                      with the -w option."
  echo
  echo "-r <reboots>          The total number of reboots to perform (over all nodes"
  echo "                      in the cluster)."
  echo
  echo "-t                    Time between reboots (in seconds). The time until the next"
  echo "                      reboot is a random number from the interval <t-10% - t+10%>."
  echo
  echo "-u <user>             Username to login into the k8s nodes. If not specified,"
  echo "                      the current user will be used. The user must be able to"
  echo "                      login to all node without a password, and be able to"
  echo "                      run run sudo without a password. If logging into a node"
  echo "                      created by vagrant, specify the username 'vagrant'."
  echo
  echo "-w                    Only reboot worker nodes. Must not be specified together"
  echo "                      with the -M option."
  echo
}

MASTER=""
SSH_USER=""
SSH_OPTS=(-o LogLevel=error -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no)
WORKERS_ONLY=false
MASTER_ONLY=false
SSH_USER=$LOGNAME
TIME=600

cmd() {
    ssh "$SSH_USER"@"$1" "${SSH_OPTS[@]}" "$2"
}

while getopts "h?f:F:r:m:Mt:u:w" opt
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
    M)  MASTER_ONLY=true
        ;;
    r)  REBOOTS=$OPTARG
        ;;
    t)  TIME=$OPTARG
        ;;
    u)  SSH_USER=$OPTARG
        ;;
    w)  WORKERS_ONLY=true
        ;;
    esac
done

if [ "$MASTER" == "" ] || [ "$SSH_USER" == "" ]
then
    echo "Both <user> and <master-node> must be specified"
    usage
    exit 1
fi

if [ -n "$SSH_CONFIG_FILE" ]
then
    SSH_OPTS=("${SSH_OPTS[@]}" -F "$SSH_CONFIG_FILE")
    FORMAT="-o 'custom-columns=A:.metadata.name'"
else
    FORMAT="-o 'custom-columns=A:.status.addresses[0].address'"
fi

KUBE_CMD="kubectl get nodes --no-headers"

# Get the selector for nodes (all nodes, master-only, workers-only)
SELECTOR=""
if [ "$WORKERS_ONLY" = true ]
then
    SELECTOR="-l 'node-role.kubernetes.io/master !='"
elif [ "$MASTER_ONLY" = true ]
then
    SELECTOR="-l 'node-role.kubernetes.io/master'"
fi

NODES=()
while read -r line; do
    NODES+=("$line")
done <<< $(cmd "$MASTER" "$KUBE_CMD $SELECTOR $FORMAT")

if [ -z "${REBOOTS+x}" ]
then
    REBOOTS=${#NODES[@]}
fi

let VARIANCE="$TIME / 10"
if [ "$VARIANCE" -eq 0 ]
then
    VARIANCE=1
fi

echo Starting at $(date +"%T")
for (( c=1; c<="$REBOOTS"; c++ ))
do
    let idx="$((RANDOM * ("${#NODES[@]}") / 32768))"
    NODE="${NODES["$idx"]}"

    RND_TIME=$RANDOM
    let "RND_TIME %= $VARIANCE * 2"
    let "SLEEP_TIME=$TIME - $VARIANCE + $RND_TIME"
    while [ "$SLEEP_TIME" -gt 0 ]
    do
        dot=2
        t=$(($SLEEP_TIME<$dot?$SLEEP_TIME:$dot))
        echo -ne "                                              "
        echo -ne "\rRebooting '$NODE' in $SLEEP_TIME seconds"
        sleep "$t"s
        let SLEEP_TIME="$SLEEP_TIME - $dot"
    done

    echo -ne "                                              "
    echo -ne "\r- Rebooted '$NODE' at $(date +"%T")"
    cmd "$NODE" "sudo reboot now" 2> /dev/null
    echo

done
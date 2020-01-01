#!/bin/bash

# Collect debug information to diagnose Contiv-VPP problems.

set -euo pipefail

usage() {
    echo "Usage: $0 [OPTION]..."
    echo
    echo "Available options:"
    echo
    echo "-a                     Do not archive the report into a tar file, keep the"
    echo "                       contents in the report directory."
    echo
    echo "-f <ssh-config-file>   Path to optional ssh configuration file. The ssh"
    echo "                       configuration file must be specified when logging into"
    echo "                       vagrant nodes."
    echo
    echo "-h                     Display this help message."
    echo
    echo "-i <ssh-key-file>      Path to optional path ssh private key file."
    echo
    echo "-m <k8s-master-node>   IP address or name of the k8s master node from which to"
    echo "                       ssh to retrieve the debug data. If not specified, it is"
    echo "                       assumed that this script is being ran from the master."
    echo
    echo "-r <report-directory>  Generate report in this directory, instead of"
    echo "                       generating one ourselves."
    echo
    echo "-s                     Only gather data which can be obtained without calling"
    echo "                       ssh to another host."
    echo
    echo "-u <user>              Username to login into the k8s nodes. If not specified,"
    echo "                       the current user will be used. The user must be able to"
    echo "                       login to the at least the k8s master node without a"
    echo "                       password, and be able to run sudo without a password."
    echo "                       If the user can login to the other nodes, additional"
    echo "                       information will be gathered via ssh, unless -l is"
    echo "                       used. If logging into a node created by vagrant, specify"
    echo "                       the username 'vagrant'."
    echo
    echo "-w                     Do not print script usage warnings."

}

# Put args in single quotes, escaping existing single and double quotes, to allow us to safely pass strings through a
# shell.
shell_quote() {
    for arg in "$@"
    do
        echo -n "'${arg//\'/\'\"\'\"\'}' "
    done
    echo
}

master_kubectl() {
    # Any log we pull might fail, so by default we don't kill the script.
    if [ -n "$MASTER" ]
    then
        # The first set of quotes on the kubectl command get us past this shell, and shell_quote is used to properly
        # escape us through the remote shell.
        ssh "$SSH_USER@$MASTER" "${SSH_OPTS[@]}" "$(shell_quote kubectl "$@")" || true
    else
        kubectl "$@" || true
    fi
}

get_vpp_data_k8s() {
    log="$1"
    shift
    echo " - vppctl $*"
    # We need to call out /usr/bin/vppctl because /usr/local/bin/vppctl is a wrapper script that doesn't work inside the
    # container.
    master_kubectl exec "$POD_NAME" -n kube-system -c contiv-vswitch /usr/bin/vppctl "$@" > "$log"
}

get_vpp_data_local() {
    log="$1"
    shift
    echo " - vppctl $*"
    # Some versions of the vppctl wrapper script check if stdin is a terminal to setup a pseudo tty with docker.
    # Since we don't want that, make sure stdin isn't.
    sudo vppctl "$@" > "$log" </dev/null || true
}

get_shell_data_k8s() {
    log="$1"
    shift
    echo " - $*"
    master_kubectl exec "$POD_NAME" -n kube-system -- sh -c "$@" > "$log"
}

get_shell_data_local() {
    log="$1"
    shift
    echo " - $*"
    # We pass this to another shell so shell expressions (like variable assignments and tests) work properly.
    sh -c "$@" > "$log" || true
}

get_shell_data_ssh() {
    log="$1"
    shift
    echo " - $*"
    ssh "$SSH_USER@$NODE_NAME" "${SSH_OPTS[@]}" "$@" > "$log" || true
}

read_shell_data_local() {
    # We pass this to another shell so shell expressions (like variable assignments and tests) work properly.
    sh -c "$@" || true
}

read_shell_data_ssh() {
    ssh "$SSH_USER@$NODE_NAME" "${SSH_OPTS[@]}" "$@" || true
}

read_node_shell_data() {
    if [ "$USE_SSH" = "1" ]
    then
        read_shell_data_ssh "$@"
    else
        read_shell_data_local "$@"
    fi
}

get_k8s_data() {
    log="$1"
    shift
    echo " - kubectl $*"
    master_kubectl "$@"> "$log"
}

save_container_nw_report() {
    # generates Docker container network report for the $NODE_NAME into the $CONTAINER_NW_REPORT_FILE
    # for each docker container, prints out its interfaces, routing table and ARP table
    echo " - ${CONTAINER_NW_REPORT_FILE}"

    # get ID, name and image of each container except from the pause containers
    containers_txt=$(read_node_shell_data "sudo docker ps --format '{{.ID}} {{.Names}} {{.Image}}' | grep -vE ' [^ ]+/pause-[^ ]+$'")

    # return in case of no container data (e.g. issues with executing sudo)
    if [ -z "$containers_txt" ]
    then
        return
    fi

    containers=()
    while read -r line
    do
        containers+=( "$line" )
    done <<< "$containers_txt"

    for container_data in "${containers[@]}"
    do
        # split $container_data to an array with container ID, name and image
        IFS=' ' read -ra cinfo <<< "$container_data"

        echo >> "$CONTAINER_NW_REPORT_FILE"
        echo "Container ${cinfo[1]}" >> "$CONTAINER_NW_REPORT_FILE"

        pid=$(read_node_shell_data "sudo docker inspect --format '{{.State.Pid}}' \"${cinfo[0]}\"")
        addr=$(read_node_shell_data "sudo nsenter -t \"$pid\" -n ip addr")

        if [[ "$addr" = *"vpp1:"* ]]
        then
            echo "Host networking" >> "$CONTAINER_NW_REPORT_FILE"
        else
            echo "$addr" >> "$CONTAINER_NW_REPORT_FILE"
            read_node_shell_data "sudo nsenter -t \"$pid\" -n ip route" >> "$CONTAINER_NW_REPORT_FILE"
            read_node_shell_data "sudo nsenter -t \"$pid\" -n arp -na" >> "$CONTAINER_NW_REPORT_FILE"
        fi
    done
}

# We need associative arrays, introduced back in 2009 with bash 4.x.
if ! declare -A TEST_ARRAY >/dev/null 2>&1
then
    echo "Error: Your /bin/bash is too old. This script needs at least bash 4.x." >&2
    echo "If you have a newer bash installed elsewhere, you can use it manually:" >&2
    echo "/path/to/new/bash $0" >&2
    exit 1
fi

# Using an array allows proper handling of paths with whitespace.
SSH_OPTS=(-o LogLevel=error -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no)
HAVE_K8S_CONNECTIVITY=1
MASTER=
# Use whoami instead of POSIX variables LOGNAME or USER, for compatibility with bash for windows.
SSH_USER=$(whoami)
SSH_CONFIG_FILE=
SSH_KEY_FILE=
USE_SSH=1
ARCHIVE=1
WARNINGS=1
TIMESTAMP="$(date '+%Y-%m-%d-%H-%M')"
REPORT_DIR="contiv-vpp-bug-report-$TIMESTAMP"
STDERR_LOGFILE="script-stderr.log"
CONTAINER_NW_REPORT_FILE="container-nw-report.txt"

# What we want to collect is defined globally in arrays, because sometimes we need to use multiple methods of
# collection.  The array key is the name of the log file for the given command.

declare -A VPP_COMMANDS
VPP_COMMANDS["vpp-interface.log"]="sh int"
VPP_COMMANDS["vpp-interface-address.log"]="sh int addr"
VPP_COMMANDS["vpp-ip-fib.log"]="sh ip fib"
VPP_COMMANDS["vpp-l2-fib.log"]="sh l2fib verbose"
VPP_COMMANDS["vpp-ip-arp.log"]="sh ip arp"
VPP_COMMANDS["vpp-vxlan-tunnels.log"]="sh vxlan tunnel raw"
VPP_COMMANDS["vpp-nat44-interfaces.log"]="sh nat44 interfaces"
VPP_COMMANDS["vpp-nat44-static-mappings.log"]="sh nat44 static mappings"
VPP_COMMANDS["vpp-nat44-addresses.log"]="sh nat44 addresses"
VPP_COMMANDS["vpp-nat44-deterministic-mappings.log"]="sh nat44 deterministic mappings"
VPP_COMMANDS["vpp-nat44-deterministic-sessions.log"]="sh nat44 deterministic sessions"
VPP_COMMANDS["vpp-nat44-deterministic-timeouts.log"]="sh nat44 deterministic timeouts"
VPP_COMMANDS["vpp-nat44-hash-tables.log"]="sh nat44 hash tables detail"
VPP_COMMANDS["vpp-nat44-sessions.log"]="sh nat44 sessions"
VPP_COMMANDS["vpp-nat44-sessions-detail.log"]="sh nat44 sessions detail"
VPP_COMMANDS["vpp-acls.log"]="sh acl-plugin acl"
VPP_COMMANDS["vpp-hardware-info.log"]="sh hardware-interfaces"
VPP_COMMANDS["vpp-errors.log"]="sh errors"
VPP_COMMANDS["vpp-logs.log"]="sh logging"

declare -A LOCAL_COMMANDS
LOCAL_COMMANDS["linux-ip-route.log"]="ip route"
LOCAL_COMMANDS["contiv-stn.log"]='CONTAINER=$(sudo docker ps --filter name=contiv-stn --format "{{.ID}}") && [ -n "$CONTAINER" ] && sudo docker logs "$CONTAINER"'
LOCAL_COMMANDS["vswitch-version.log"]="curl -m 2 localhost:9999/liveness"
LOCAL_COMMANDS["docker-ps.log"]="sudo docker ps"
LOCAL_COMMANDS["core-dump.tar.xz"]="sudo test -d /var/contiv/dumps && sudo tar -Jc -C /var/contiv dumps"
LOCAL_COMMANDS["tmp-logs.tar.xz"]="sudo tar -Jc -C /tmp contiv-vswitch"
LOCAL_COMMANDS["cni.log"]="sudo cat /var/run/contiv/cni.log"
LOCAL_COMMANDS["vpp.conf"]="cat /etc/vpp/contiv-vswitch.conf"
LOCAL_COMMANDS["syslog.log"]="sudo cat /var/log/syslog"
LOCAL_COMMANDS["machine-status.log"]="free -h && df -h && lsof | awk '{ print \$2 \" \" \$1; }' | uniq -c | sort -rn | head -20"

declare -A ETCD_COMMANDS
ETCD_COMMANDS["etcd-tree.log"]="export ETCDCTL_API=3 && etcdctl --endpoints=127.0.0.1:32379 get / --prefix=true"

declare -A K8S_COMMANDS
K8S_COMMANDS["k8s-vpp-config-maps.yaml"]="describe configmaps -n kube-system contiv-agent-cfg"
K8S_COMMANDS["k8s-nodes.txt"]="get nodes -o wide"
K8S_COMMANDS["k8s-nodes-describe.txt"]="describe nodes"
K8S_COMMANDS["k8s-node-addresses.txt"]="get nodes --no-headers -o=custom-columns=A:.spec.externalID,B:.status.addresses[*].address"
K8S_COMMANDS["k8s-pods.txt"]="get pods -o wide --all-namespaces"
K8S_COMMANDS["k8s-pods-describe.txt"]="describe pods --all-namespaces"
K8S_COMMANDS["k8s-services.txt"]="get services -o wide --all-namespaces"
K8S_COMMANDS["k8s-networkpolicy.txt"]="get networkpolicy -o wide --all-namespaces"
K8S_COMMANDS["k8s-statefulsets.txt"]="get statefulsets -o wide --all-namespaces"
K8S_COMMANDS["k8s-daemonsets.txt"]="get daemonsets -o wide --all-namespaces"
K8S_COMMANDS["k8s-crd-telemetry-report.yaml"]="get telemetryreports.telemetry.contiv.vpp -o yaml"
K8S_COMMANDS["k8s-crd-nodeconfig.yaml"]="get nodeconfigs.nodeconfig.contiv.vpp -o yaml"

while getopts "af:hi:m:r:su:w" opt
do
    case "$opt" in
    a)  ARCHIVE=0
        ;;
    f)  SSH_CONFIG_FILE=$(realpath "$OPTARG")
        ;;
    h)
        usage
        exit 0
        ;;
    i)  SSH_KEY_FILE=$OPTARG
        ;;
    m)  MASTER=$OPTARG
        ;;
    r)  REPORT_DIR=$OPTARG
        ;;
    s)  USE_SSH=0
        ;;
    u)  SSH_USER=$OPTARG
        ;;
    w)  WARNINGS=0
        ;;
    *)
        # getopts will have already displayed a "illegal option" error.
        echo
        usage
        exit 1
        ;;
    esac
done

if [ -n "$MASTER" -a "$USE_SSH" = "0" ]
then
    echo "Error: Conflicting options -m and -s, choose only one." >&2
    exit 1
fi

if [ -z "$MASTER" ] && ! kubectl version >/dev/null 2>&1
then
    HAVE_K8S_CONNECTIVITY=0
    if [ "$WARNINGS" = "1" ]
    then
        echo >&2
        echo "WARNING: Cannot contact kubernetes using kubectl. Only minimal local data" >&2
        echo "will be collected. Did you mean to specify a master with -m?" >&2
        echo >&2
    fi
fi

if [ "$SSH_USER" == "vagrant" -a -z "$SSH_CONFIG_FILE" -a "$WARNINGS" = "1" ]
then
    echo >&2
    echo "WARNING: You specified a remote user of 'vagrant', but did not specify a" >&2
    echo "ssh configuration file with the -f option.  There's a good chance this" >&2
    echo "won't work." >&2
    echo >&2
fi

if [ -n "$SSH_CONFIG_FILE" ]
then
    SSH_OPTS=("${SSH_OPTS[@]}" -F "$SSH_CONFIG_FILE")
fi
if [ -n "$SSH_KEY_FILE" ]
then
    SSH_OPTS=("${SSH_OPTS[@]}" -i "$SSH_KEY_FILE")
fi

mkdir -p "$REPORT_DIR"
pushd "$REPORT_DIR" >/dev/null

# Users running this script won't know what to do with any errors, so assemble anything on stderr into a log for us
# to be able to examine.
exec 2> "$STDERR_LOGFILE"
# To help figure out what has failed, do a trace for this script (which will only get sent to the above log file).
set -x

if [ "$HAVE_K8S_CONNECTIVITY" = "1" ]
then
    echo "Collecting global Kubernetes data:"
    for CMD_INDEX in "${!K8S_COMMANDS[@]}"
    do
        # Intentional word split on command, because bash doesn't support arrays of arrays.
        get_k8s_data "$CMD_INDEX" ${K8S_COMMANDS[$CMD_INDEX]}
    done
    echo

    master_kubectl get po -n kube-system --no-headers -o \
        'custom-columns=A:.spec.nodeName,B:.metadata.name,C:.spec.containers[*].name,D:.spec.initContainers[*].name' \
        | sed -e 's|<none>$||g' | while
        read NODE_NAME POD_NAME CONTAINERS
    do
        if ! grep -q '^contiv-' <<< "$POD_NAME"
        then
            continue
        fi

        echo "Collecting Kubernetes data for pod $POD_NAME on node $NODE_NAME:"
        mkdir -p "$NODE_NAME"
        pushd "$NODE_NAME" >/dev/null

        for CONTAINER in ${CONTAINERS//,/ }
        do
            get_k8s_data "$POD_NAME-$CONTAINER.log" logs "$POD_NAME" -n kube-system -c "$CONTAINER" </dev/null
            get_k8s_data "$POD_NAME-$CONTAINER-previous.log" logs "$POD_NAME" -n kube-system -c "$CONTAINER" -p </dev/null
            # No need to create empty previous logs, it just clutters things up.
            if [ ! -s "$POD_NAME-$CONTAINER-previous.log" ]
            then
                rm -f "$POD_NAME-$CONTAINER-previous.log"
            fi
        done

        if grep -q '^contiv-vswitch' <<< "$POD_NAME"
        then
            # copy vswitch POD /tmp content
            master_kubectl cp kube-system/"$POD_NAME":/tmp ./tmp/ </dev/null

            for CMD_INDEX in "${!VPP_COMMANDS[@]}"
            do
                get_vpp_data_k8s "$CMD_INDEX" "${VPP_COMMANDS[$CMD_INDEX]}" </dev/null
            done
            get_vpp_data_k8s "vpp-api-trace-save.log" "api trace save trace.api" </dev/null
            get_vpp_data_k8s "vpp-api-trace-dump.log" "api trace custom-dump /tmp/trace.api" </dev/null
        fi

        if grep -q '^contiv-etcd' <<< "$POD_NAME"
        then
            for CMD_INDEX in "${!ETCD_COMMANDS[@]}"
            do
                get_shell_data_k8s "$CMD_INDEX" "${ETCD_COMMANDS[$CMD_INDEX]}" </dev/null
            done
        fi

        echo
        popd >/dev/null
    done

    if [ "$USE_SSH" = "1" ]
    then
        master_kubectl get nodes --no-headers -o 'custom-columns=A:.metadata.name,B:.status.addresses[0].address' \
            | sed -e 's|<none>$||g' | while
            read NODE_NAME NODE_IP
        do
            echo "Collecting local data for node $NODE_NAME:"
            mkdir -p "$NODE_NAME"
            pushd "$NODE_NAME" >/dev/null
            # When we don't have a ssh config file, use the IP instead of the name to handle the case where the machine running
            # this script cannot resolve the cluster hostnames.
            if [ -z "${SSH_CONFIG_FILE-}" ]
            then
                NODE_NAME="$NODE_IP"
            fi

            for CMD_INDEX in "${!LOCAL_COMMANDS[@]}"
            do
                # The command is quoted so shell expressions (like variable assignments and tests) work properly.
                get_shell_data_ssh "$CMD_INDEX" "${LOCAL_COMMANDS[$CMD_INDEX]}" </dev/null
            done

            save_container_nw_report </dev/null

            echo
            popd >/dev/null
        done
    elif [ -z "$MASTER" ]
    then
        mkdir -p localhost
        pushd localhost >/dev/null

        echo "Running local commands for this host only:"
        for CMD_INDEX in "${!LOCAL_COMMANDS[@]}"
        do
            # The command is quoted so shell expressions (like variable assignments and tests) work properly.
            get_shell_data_local "$CMD_INDEX" "${LOCAL_COMMANDS[$CMD_INDEX]}"
        done

        save_container_nw_report

        echo
        popd >/dev/null
    fi
fi

if [ "$HAVE_K8S_CONNECTIVITY" = "0" ]
then
    mkdir -p localhost
    pushd localhost >/dev/null

    echo "Collecting VPP data for this host only:"
    for CMD_INDEX in "${!VPP_COMMANDS[@]}"
    do
        get_vpp_data_local "$CMD_INDEX" "${VPP_COMMANDS[$CMD_INDEX]}"
    done
    get_vpp_data_local "vpp-api-trace-save.log" "api trace save trace.api" </dev/null
    get_vpp_data_local "vpp-api-trace-dump.log" "api trace custom-dump /tmp/trace.api" </dev/null
    echo

    echo "Running local commands for this host only:"
    for CMD_INDEX in "${!LOCAL_COMMANDS[@]}"
    do
        # The command is quoted so shell expressions (like variable assignments and tests) work properly.
        get_shell_data_local "$CMD_INDEX" "${LOCAL_COMMANDS[$CMD_INDEX]}"
    done

    echo
    popd >/dev/null
fi

# Since we are redirecting stderr during data collection, the user won't see SSH errors.  Give them a clue if we have
# failures.
SSH_ERROR=0
for MSG in 'Permission denied (publickey)' 'ssh: Could not resolve hostname'
do
    # We need to match from the beginning of the line, otherwise we'll match the grep command itself.
    if grep -q "^$MSG" "$STDERR_LOGFILE"
    then
        SSH_ERROR=1
        # Can't print this error to stderr since we are redirecting stderr to the log file.
        echo "Warning: At least one '$MSG' error found in $REPORT_DIR/$STDERR_LOGFILE."
    fi
done
if [ "$SSH_ERROR" = "1" ]
then
    echo "Are you sure your arguments are correct?"
    echo
fi

popd >/dev/null
if [ "$ARCHIVE" = "1" ]
then
    echo "Creating tar file $REPORT_DIR.tar.xz..."
    tar -Jcf "$REPORT_DIR.tar.xz" "$REPORT_DIR"
    if [ "$SSH_ERROR" = "0" ]
    then
        rm -rf "$REPORT_DIR"
    else
        echo "Warning: Disabling automatic deletion of $REPORT_DIR directory due to above warning."
    fi
    echo "Report finished.  Output is in the file $REPORT_DIR.tgz."
else
    echo "Report finished.  Output is in the directory $REPORT_DIR."
fi

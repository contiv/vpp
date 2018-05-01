#!/bin/bash

#################################################################
# Example Usage
# contiv-vpp-bug-report.sh <cluster-master-node> [<user-id>]
# <cluster-master-node>: IP address of K8s master node
# <user-id>:             User id used to login to the k8s master
#################################################################

set -euo pipefail

master_kubectl() {
    # Any log we pull might fail, so by default we don't kill the script.
    ssh "$SSH_USER@$MASTER" "${SSH_OPTS[@]}" kubectl "$@" || true
}

get_vpp_data() {
    echo " - vppctl '$1'"
    # We need to call out /usr/bin/vppctl because /usr/local/bin/vppctl is a wrapper script that doesn't work inside the
    # container.
    master_kubectl exec "$POD_NAME" -n kube-system -c contiv-vswitch /usr/bin/vppctl "$1" > "$2.log"
}

usage() {
    echo ""
    echo "usage: $0 -m <k8s-master-node> [-u <user>] "
    echo "        [-f <ssh-config-file>] [-i <ssh-key-file>]"
    echo ""
    echo "<k8s-master-node>: IP address or name of the k8s master node from"
    echo "        which to retrieve the debug data."
    echo "<user>: optional username to login into the k8s master node. If"
    echo "        no username is specified, the current user will be used."
    echo "        The user must have passwordless access to the k8s master"
    echo "        node, and must be able to execute passwordless sudo. If"
    echo "        logging into a node created by vagrant, specify username"
    echo "        vagrant'."
    echo "<ssh-config-file>: optional path to ssh configuration file. The ssh"
    echo "        configuration file must be specified when logging into"
    echo "        vagrant nodes."
    echo "<ssh-key-file>: optional path to ssh private key file."
}


while getopts "h?f:i:m:u:" opt; do
    case "$opt" in
    h|\?)
        usage
        exit 0
        ;;
    f)  SSH_CONFIG_FILE=$(realpath "$OPTARG")
        ;;
    i)  SSH_KEY_FILE=$OPTARG
        ;;
    u)  SSH_USER=$OPTARG
        ;;
    m)  MASTER=$OPTARG
        ;;
    esac
done

if [ -z "${MASTER:-}" ] ; then
    echo "Error - Master node must be specified"
    usage
    exit 1
fi

if [ -z "${SSH_USER:-}" ] ; then
    SSH_USER=$(whoami)
elif [ "$SSH_USER" == "vagrant" -a -z "${SSH_CONFIG_FILE:-}" ] ; then
    echo "Error - ssh configuration file must be specified when using vagrant"
    usage
    exit 1
fi

# Using an array allows proper handling of paths with whitespace.
SSH_OPTS=(-o LogLevel=error -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no)
if [ -n "${SSH_CONFIG_FILE-}" ]; then
    SSH_OPTS=("${SSH_OPTS[@]}" -F "$SSH_CONFIG_FILE")
fi
if [ -n "${SSH_KEY_FILE-}" ]; then
    SSH_OPTS=("${SSH_OPTS[@]}" -i "$SSH_KEY_FILE")
fi

STAMP="$(date "+%Y-%m-%d-%H-%M")"
REPORT_DIR=${REPORT_DIR:-"contiv-vpp-bugreport-$STAMP"}
mkdir -p "$REPORT_DIR"
pushd "$REPORT_DIR" >/dev/null

# In general, unexpected stderr messages are not muted so problems collecting logs can be shown.

echo "Collecting global Kubernetes data:"
echo " - configmaps"
master_kubectl describe configmaps -n kube-system contiv-agent-cfg > vpp.yaml
echo " - nodes"
master_kubectl get nodes -o wide > k8s-nodes.txt
echo " - pods"
master_kubectl get pods -o wide --all-namespaces > k8s-pods.txt
echo " - services"
master_kubectl get services -o wide --all-namespaces > k8s-services.txt
echo " - networkpolicy"
# Don't show 'No resources found.' error on stderr.
master_kubectl get networkpolicy -o wide --all-namespaces > k8s-policies.txt 2>/dev/null
echo

PODS="$(master_kubectl get po -n kube-system -l k8s-app=contiv-vswitch -o "'go-template={{range .items}}{{printf \"%s,%s \" (index .metadata).name (index .spec).nodeName}}{{end}}'")"
for POD in $PODS; do
    IFS=',' read -r POD_NAME NODE_NAME <<< "$POD"
    echo "Collecting Kubernetes data for pod $POD_NAME on node $NODE_NAME:"
    mkdir -p "$NODE_NAME"
    pushd "$NODE_NAME" >/dev/null
    echo " - vswitch log"
    master_kubectl logs "$POD_NAME" -n kube-system -c contiv-vswitch > "$POD_NAME.log"
    # The previous log might not exist, so don't print the error when trying to get it.
    master_kubectl logs "$POD_NAME" -n kube-system -c contiv-vswitch -p > "$POD_NAME-previous.log" 2>/dev/null
    get_vpp_data "sh int" interface
    get_vpp_data "sh int addr" interface-address
    get_vpp_data "sh ip fib" ip-fib
    get_vpp_data "sh l2fib verbose" l2-fib
    get_vpp_data "sh ip arp" ip-arp
    get_vpp_data "sh vxlan tunnel" vxlan-tunnels
    get_vpp_data "sh nat44 interfaces" nat44-interfaces
    get_vpp_data "sh nat44 static mappings" nat44-static-mappings
    get_vpp_data "sh nat44 sessions detail" nat44-sessions
    get_vpp_data "sh acl-plugin acl" acls
    get_vpp_data "sh hardware-interfaces" hardware-info
    get_vpp_data "sh errors" errors
#     get_vpp_data "api trace save trace.api" api-trace-save
#     get_vpp_data "api trace custom-dump /tmp/trace.api" api-trace-dump
    echo
    popd >/dev/null

done

NODES="$(master_kubectl get nodes -o "'go-template={{range .items}}{{printf \"%s,%s \" (index .metadata).name (index .status.addresses 0).address}}{{end}}'")"
for NODE in $NODES; do
    IFS=',' read -r NODE_NAME NODE_IP <<< "$NODE"
    echo "Collecting non-Kubernetes data for node $NODE_NAME:"
    mkdir -p "$NODE_NAME"
    pushd "$NODE_NAME" >/dev/null
    # When we don't have a ssh config file, use the IP instead of the name to handle the case where the machine running
    # this script cannot resolve the cluster hostnames.
    if [ -z "${SSH_CONFIG_FILE-}" ]
    then
        NODE_NAME="$NODE_IP"
    fi
    echo " - Linux IP routes"
    ssh "$SSH_USER@$NODE_NAME" "${SSH_OPTS[@]}" 'ip route' > linux-ip-route.log 2>&1 || true
    echo " - contiv-stn logs"
    ssh "$SSH_USER@$NODE_NAME" "${SSH_OPTS[@]}" 'CONTAINER=$(sudo docker ps --filter name=contiv-stn --format "{{.ID}}") && [ -n "$CONTAINER" ] && sudo docker logs "$CONTAINER"' > contiv-stn.log 2>&1 || true
    echo
    popd >/dev/null
done

popd >/dev/null
if [ "${ARCHIVE_BUGREPORT:-yes}" = "yes" ]
then
    echo "Creating tar file $REPORT_DIR.tgz..."
    tar -zcf "$REPORT_DIR.tgz" "$REPORT_DIR"
    rm -rf "$REPORT_DIR"
fi
echo "Done."

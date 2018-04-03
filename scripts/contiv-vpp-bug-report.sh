#!/bin/bash

#################################################################
# Example Usage
# contiv-vpp-bug-report.sh <cluster-master-node> [<user-id>]
# <cluster-master-node>: IP address of K8s master node 
# <user-id>:             User id used to login to the k8s master
#################################################################

set -euo pipefail

get_vpp_data() {
  echo "    . $2"
  ssh -t $SSH_OPTS "$SSH_USER"@"$NODE" echo $1 \| sudo nc -U /run/vpp/cli.sock \> /tmp/$REPORT_DIR/vpp-$2.txt 2>/dev/null
}

usage() {
  echo ""
  echo "usage: $0 -m <k8s-master-node> [-u <user>] "
  echo "        [-f <ssh-config-file>]"
  echo ""
  echo "<k8s-master-node>: IP address or name of the k8s master node from"
  echo "        which to retrieve the debug data."
  echo "<user>: optional username to login into the k8s master node. If"
  echo "        no username is specified, the current user will be used."
  echo "        The user must have passwordless access to the k8s master"
  echo "        node, and must be able to execute passwordless sudo. If"
  echo "        logging into a node created by vagrant, specify username"
  echo "        vagrant'."
  echo "ssh-config-file: optional path to ssh configuration file. The ssh"
  echo "        configuration file must be specified when logging into"
  echo "        vagrant nodes."
}

num_args=$#


while getopts "h?f:m:u:" opt; do
    case "$opt" in
    h|\?)
        usage
        exit 0
        ;;
    f)  SSH_CONFIG_FILE=$OPTARG
        ;;
    u)  SSH_USER=$OPTARG
        ;;
    m)  MASTER=$OPTARG
        ;;
    esac
done

if [ -z "${MASTER+xxx}" ] ; then
    echo "Error - Master node must be specified"
    exit 1
fi

if [ -z "${SSH_USER+xxx}" ] ; then
    SSH_USER=$(whoami)
elif [ "$SSH_USER" == "vagrant" ] ; then
        if [ -z "${SSH_CONFIG_FILE+xxx}" ] ; then
        echo "Error - ssh configuration file must be specified when using vagrant"
    fi
fi

if [ -z "${SSH_CONFIG_FILE+xxx}" ]; then
    SSH_OPTS=""
else
    SSH_OPTS="-F $SSH_CONFIG_FILE"
fi

echo "$SSH_OPTS"


STAMP="$(date "+%Y-%m-%d-%H-%M")"
REPORT_DIR="contiv-vpp-bugreport-$STAMP"
mkdir -p "$REPORT_DIR"

vswitch_pods="$(ssh "$SSH_USER"@"$MASTER" $SSH_OPTS kubectl get po -n kube-system -l k8s-app=contiv-vswitch -o go-template=\'{{range .items}}{{printf \"%s,%s \" \(index .metadata\).name \(index .spec\).nodeName}}{{end}}\')"
echo vswitch_pods $vswitch_pods

for p in $vswitch_pods; do
  IFS=',' read -r -a fields <<< "$p"
  echo "Collecting logs for vswitch" \'"${fields[0]}"\'  "on node" \'"${fields[1]}"\'
  mkdir "$REPORT_DIR"/"${fields[1]}"
  ssh "$SSH_USER"@"$MASTER" $SSH_OPTS kubectl logs "${fields[0]}" -n kube-system -c contiv-vswitch > "$REPORT_DIR"/"${fields[1]}"/"${fields[0]}".log
  set +e
  ssh "$SSH_USER"@"$MASTER" $SSH_OPTS kubectl logs "${fields[0]}" -n kube-system -c contiv-vswitch -p > "$REPORT_DIR"/"${fields[1]}"/"${fields[0]}"-previous.log 2>/dev/null
  if [ $? -ne 0 ]; then
    rm "$REPORT_DIR"/"${fields[1]}"/"${fields[0]}"-previous.log
  fi
  set -e
done

echo ""

echo "Getting Kubernetes data:"
echo " - configmaps"
ssh "$SSH_USER"@"$MASTER" $SSH_OPTS kubectl describe configmaps -n kube-system contiv-agent-cfg > "$REPORT_DIR"/vpp.yaml 2>/dev/null
echo " - nodes"
ssh "$SSH_USER"@"$MASTER" $SSH_OPTS kubectl get nodes -o wide >  "$REPORT_DIR"/k8s-nodes.txt 2>/dev/null
echo " - pods"
ssh "$SSH_USER"@"$MASTER" $SSH_OPTS kubectl get pods -o wide --all-namespaces > "$REPORT_DIR"/k8s-pods.txt 2>/dev/null
echo " - services"
ssh "$SSH_USER"@"$MASTER" $SSH_OPTS kubectl get services -o wide --all-namespaces > "$REPORT_DIR"/k8s-services.txt 2>/dev/null
echo " - networkpolicy"
ssh "$SSH_USER"@"$MASTER" $SSH_OPTS kubectl get networkpolicy -o wide --all-namespaces > "$REPORT_DIR"/k8s-policies.txt 2>/dev/null
echo ""

nodes="$(ssh "$SSH_USER"@"$MASTER" $SSH_OPTS kubectl get nodes -o go-template=\'{{range .items}}{{printf \"%s,%s \" \(index .status.addresses 0\).address \(index .metadata\).name}}{{end}}\')"
for n in $nodes; do
  IFS=',' read -r -a fields <<< "$n"
    if [ $SSH_USER == "vagrant" ] ; then
    NODE="${fields[1]}"
  else
    NODE="${fields[0]}"
  fi

  echo Getting data from \'"${fields[1]}"\':
  ssh "$SSH_USER"@"$NODE" $SSH_OPTS mkdir /tmp/"$REPORT_DIR"

  echo " - VPP:"
  # get_vpp_data <target-vpp-command> <file-name-string> <console-message-string>
  get_vpp_data "sh int" interface
  get_vpp_data "sh int addr" interface-address
  get_vpp_data "sh ip fib" ip-fib
  get_vpp_data "sh ip arp" ip-arp
  get_vpp_data "sh vxlan tunnel" vxlan-tunnels
  get_vpp_data "sh nat44 interfaces" nat44-interfaces
  get_vpp_data "sh nat44 static mappings" nat44-static-mappings
  get_vpp_data "sh nat44 sessions" nat44-sessions
  get_vpp_data "sh acl-plugin acl" acls
  get_vpp_data "sh hardware-interfaces" hardware-info
  get_vpp_data "sh errors" errors

  echo " - Logs for contiv-stn"
  ssh -t $SSH_OPTS "$SSH_USER@$NODE" 'sudo docker logs $(sudo docker ps --filter name=contiv-stn --format "{{.ID}}")' \> /tmp/$REPORT_DIR/contiv-stn.log 2>/dev/null || true


  ssh "$SSH_USER"@"$NODE" $SSH_OPTS tar -cC /tmp/"$REPORT_DIR"/ . | tar -xC "$REPORT_DIR"/${fields[1]} 2>/dev/null

  echo ""
done

echo "Creating tar file"
tar -z -cvf "$REPORT_DIR".tgz "$REPORT_DIR" >/dev/null
rm -rf "$REPORT_DIR"
echo "Done."

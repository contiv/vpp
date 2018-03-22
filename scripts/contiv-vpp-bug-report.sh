#!/bin/bash

#################################################################
# Example Usage
# contiv-vpp-bug-report.sh <cluster-master-node> [<user-id>]
# <cluster-master-node>: IP address of K8s master node 
# <user-id>:             User id used to login to the k8s master
#################################################################

get_vpp_data() {
  echo " . $2"
  ssh -t "$user"@"${fields[0]}" echo $1 \| sudo nc -U /run/vpp/cli.sock \> /tmp/$report_dir/vpp-$2.txt 2>/dev/null
}

set -euo pipefail

num_args=$#

if [ "$num_args" -lt 1 -o  "$num_args" -gt 2 ] ; then
  echo "Usage: $0 <k8s-master-IP-address> [<username>]"
  echo ""
  echo "k8s-master-IP-address: IP address of k8s master node from which to get"
  echo "          the debug data"
  echo "username: optional username to login into the k8s master node. If no user"
  echo "          name is specified, the current user will be used. The user must"
  echo "          have passwordless access to the k8s master node and must be able"
  echo "          to execute passwordless sudo."
  echo ""
  exit 1
fi

master=$1
if [ "$num_args" -eq 2 ] ; then
  user=$2
else
  user=$(whoami)
fi

stamp="$(date "+%Y-%m-%d-%H-%M")"
report_dir="contiv-vpp-bugreport-$stamp"
mkdir -p "$report_dir"

vswitch_pods="$(ssh "$user"@"$master" kubectl get po -n kube-system -l k8s-app=contiv-vswitch -o go-template=\'{{range .items}}{{printf \"%s,%s \" \(index .metadata\).name \(index .spec\).nodeName}}{{end}}\')"
for p in $vswitch_pods; do
  IFS=',' read -r -a fields <<< "$p"
  echo "Collecting logs for vswitch" \'"${fields[0]}"\'  "on node" \'"${fields[1]}"\'
  mkdir "$report_dir"/"${fields[1]}"
  ssh "$user"@"$master" kubectl logs "${fields[0]}" -n kube-system -c contiv-vswitch > "$report_dir"/"${fields[1]}"/"${fields[0]}".log
  set +e
  ssh "$user"@"$master" kubectl logs "${fields[0]}" -n kube-system -c contiv-vswitch -p > "$report_dir"/"${fields[1]}"/"${fields[0]}"-previous.log 2>/dev/null
  if [ $? -ne 0 ]; then
    rm "$report_dir"/"${fields[1]}"/"${fields[0]}"-previous.log
  fi
  set -e
done

echo ""

echo "Getting Kubernetes data:"
echo " . configmaps"
ssh "$user"@"$master" kubectl describe configmaps -n kube-system contiv-agent-cfg > "$report_dir"/vpp.yaml 2>/dev/null
echo " . nodes"
ssh "$user"@"$master" kubectl get nodes -o wide >  "$report_dir"/k8s-nodes.txt 2>/dev/null
echo " . pods"
ssh "$user"@"$master" kubectl get pods -o wide --all-namespaces > "$report_dir"/k8s-pods.txt 2>/dev/null
echo " . services"
ssh "$user"@"$master" kubectl get services -o wide --all-namespaces > "$report_dir"/k8s-services.txt 2>/dev/null
echo " . networkpolicy"
ssh "$user"@"$master" kubectl get networkpolicy -o wide --all-namespaces > "$report_dir"/k8s-policies.txt 2>/dev/null
echo ""

nodes="$(ssh "$user"@"$master" kubectl get nodes -o go-template=\'{{range .items}}{{printf \"%s,%s \" \(index .status.addresses 0\).address \(index .metadata\).name}}{{end}}\')"
for n in $nodes; do
  IFS=',' read -r -a fields <<< "$n"
  echo Getting VPP information from \'"${fields[1]}"\':
  ssh "$user"@"${fields[0]}" mkdir /tmp/"$report_dir"

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

  ssh $user@${fields[0]} tar -cC /tmp/$report_dir/ . | tar -xC $report_dir/${fields[1]} 2>/dev/null

  echo ""
done

echo "Creating tar file"
tar -z -cvf $report_dir.tgz $report_dir >/dev/null
# rm -rf $report_dir
echo "Done."

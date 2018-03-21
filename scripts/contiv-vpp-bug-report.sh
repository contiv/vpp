#!/bin/bash

#######################################################
# Example Usage
# contiv-vpp-bug-report.sh 1.2.3.4  # Address of master
#######################################################

set -euo pipefail

num_args=$#

if [ $num_args -lt 1 -o  $num_args -gt 2 ] ; then
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
if [ $num_args -eq 2 ] ; then
  user=$2
else
  user=$(whoami)
fi

stamp="$(date "+%Y-%m-%d-%H-%M")"
report_dir="contiv-vpp-bugreport-$stamp"
mkdir -p $report_dir

vswitch_pods="$(ssh $user@$master kubectl get po -n kube-system -l k8s-app=contiv-vswitch -o go-template=\'{{range .items}}{{printf \"%s,%s \" \(index .metadata\).name \(index .spec\).nodeName}}{{end}}\')"
for p in $vswitch_pods; do
  IFS=',' read -r -a fields <<< "$p"
  echo "Collecting logs for vswitch" \'${fields[0]}\'  "on node" \'${fields[1]}\'...
  mkdir $report_dir/${fields[1]}
  ssh $user@$master kubectl logs ${fields[0]} -n kube-system -c contiv-vswitch > $report_dir/${fields[1]}/${fields[0]}.log
done

ssh $user@$master kubectl describe configmaps -n kube-system contiv-agent-cfg > $report_dir/vpp.yaml
ssh $user@$master kubectl get nodes -o wide >  $report_dir/k8s-nodes.txt
ssh $user@$master kubectl get pods -o wide --all-namespaces > $report_dir/k8s-pods.txt
ssh $user@$master kubectl get services -o wide --all-namespaces > $report_dir/k8s-services.txt
ssh $user@$master kubectl get networkpolicy -o wide --all-namespaces > $report_dir/k8s-policies.txt

nodes="$(ssh $user@$master kubectl get nodes -o go-template=\'{{range .items}}{{printf \"%s,%s \" \(index .status.addresses 0\).address \(index .status.addresses 1\).address}}{{end}}\')"
for n in $nodes; do
  IFS=',' read -r -a fields <<< "$n"
  echo Getting VPP information from \'${fields[1]}\':
  ssh $user@${fields[0]} mkdir /tmp/$report_dir
  echo "   Getting interface status..."
  ssh -t $user@${fields[0]} echo sh int \| sudo nc -U /run/vpp/cli.sock \> /tmp/$report_dir/vpp-interface-status.txt 2>/dev/null
  echo "   Getting interface addresses..."
  ssh -t $user@${fields[0]} echo sh int addr \| sudo nc -U /run/vpp/cli.sock \> /tmp/$report_dir/vpp-interface-address.txt 2>/dev/null
  echo "   Getting ip fib table..."
  ssh -t $user@${fields[0]} echo sh ip fib \| sudo nc -U /run/vpp/cli.sock \> /tmp/$report_dir/vpp-ip-fib.txt 2>/dev/null
  echo "   Getting ip arp table..."
  ssh -t $user@${fields[0]} echo sh ip arp \| sudo nc -U /run/vpp/cli.sock \> /tmp/$report_dir/vpp-ip-arp.txt 2>/dev/null
  echo "   Getting vxlan tunnel..."
  ssh -t $user@${fields[0]} echo sh vxlan tunnel \| sudo nc -U /run/vpp/cli.sock \> /tmp/$report_dir/vpp-vxlan-tunnel.txt 2>/dev/null
  echo "   Getting NAT44 interfaces..."
  ssh -t $user@${fields[0]} echo sh nat44 interfaces \| sudo nc -U /run/vpp/cli.sock \> /tmp/$report_dir/vpp-nat44-interfaces.txt 2>/dev/null
  echo "   Getting NAT44 static mappings..."
  ssh -t $user@${fields[0]} echo sh nat44 static mappings \| sudo nc -U /run/vpp/cli.sock \> /tmp/$report_dir/vpp-nat44-static-mappings.txt 2>/dev/null
  echo "   Getting NAT44 sessions..."
  ssh -t $user@${fields[0]} echo sh nat44 sessions \| sudo nc -U /run/vpp/cli.sock \> /tmp/$report_dir/vpp-nat44-sessions.txt 2>/dev/null
  echo "   Getting ACLs..."
  ssh -t $user@${fields[0]} echo sh acl-plugin acl \| sudo nc -U /run/vpp/cli.sock \> /tmp/$report_dir/vpp-acl.txt 2>/dev/null
  echo "   Getting interface hardware info..."
  ssh -t $user@${fields[0]} echo sh hardware-interfaces \| sudo nc -U /run/vpp/cli.sock \> /tmp/$report_dir/vpp-hardware-info.txt 2>/dev/null
  echo "   Getting errors info..."
  ssh -t $user@${fields[0]} echo sh errors \| sudo nc -U /run/vpp/cli.sock \> /tmp/$report_dir/vpp-errors.txt 2>/dev/null
  ssh $user@${fields[0]} tar -cC /tmp/$report_dir/ . | tar -xC $report_dir/${fields[1]} 2>/dev/null
done

echo "Creating tar file..."
tar -z -cvf $report_dir.tgz $report_dir >/dev/null
# rm -rf $report_dir
echo "Done."

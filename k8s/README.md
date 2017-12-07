## Contiv-VPP Kubernetes Deployment Files

This folder contains a set of files that can be used to deploy Contiv-VPP
network plugin on Kubernetes.

#### contiv-vpp.yaml
The main deployment file that can be used to deploy Contiv-VPP network plugin using `kubeadm`:
```
# deploy
kubectl apply -f contiv-vpp.yaml

# undeploy
kubectl delete -f contiv-vpp.yaml
```
Optionaly you can edit `contiv-vpp.yaml` to deploy the dev-contiv-vswitch image, built
in local environment with `../docker/build-all.sh`.
```
sed -i "s@image: contivvpp/vswitch@image: dev-contiv-vswitch:<your image version>@g" ./contiv-vpp.yaml
```

To use the development image for testing with specific version of VPP, see
[DEVIMAGE.md](../docker/DEVIMAGE.md).

**contiv.yaml**

  Configuration file for Contiv agent is deployed via the Config map `contiv-agent-cfg`
  into the location `/etc/agent/contiv.yaml` of vSwitch. It includes several options
  allowing to customize the network connectivity between pods, such as the configuration
  of interfaces and allocation of IP addresses.

  * Pod-to-VPP connectivity (top-level options)
    - `TCPstackDisabled`: if the flag is set to `true`, neither VPP TCP stack nor STN is configured
      and only VETHs or TAPs are used to connect Pods with VPP;
    - `TCPChecksumOffloadDisabled`: disable checksum offloading for eth0 of every deployed pod;
    - `UseTAPInterfaces`: use TAP interfaces instead of VETHs for Pod-to-VPP interconnection
      (VETH is still used to connect VPP with the host stack);
    - `TAPInterfaceVersion`: select `1` to use the standard VPP TAP interface (default) or `2`
      for a faster, virtio-based, VPP TAPv2 interface (experimental);
    - `TAPv2RxRingSize`: number of entries to allocate for TAPv2 Rx ring (default is 256);
    - `TAPv2TxRingSize`: number of entries to allocate for TAPv2 Tx ring (default is 256).

  * IPAM (section `IPAMConfig`)
    - `PodSubnetCIDR`: subnet used for all pods across all nodes;
    - `PodNetworkPrefixLen`: subnet prefix length used for all pods of 1 k8s node
      (pod network = pod subnet for one k8s node);
    - `VSwitchSubnetCIDR`: subnet used in each node for vSwitch-to-host connectivity;
    - `VSwitchNetworkPrefixLen`: prefix length of the subnet used for vswitch-to-host connectivity
      on 1 k8s node (vSwitch network = vSwitch subnet for one k8s node);
    - `HostNodeSubnetCidr`: subnet used for main interfaces of all nodes.

  * Node configuration (section `NodeConfig`; one entry for each node)
    - `NodeName`: name of a Kubernetes node;
    - `MainVppInterfaceName`: name of the interface to be used for node-to-node connectivity
      (IP address is allocated from `HostNodeSubnetCidr` defined in the IPAM section);
    - `OtherVPPInterfaces` (other configured interfaces only get IP address assigned in VPP)
      - `InterfaceName`: name of the interface;
      - `IP`: IP address to be attached to the interface.

#### cri-install.sh
Contiv-VPP CRI Shim installer / uninstaller, that can be used as follows:
```
# install
./cri-install.sh

# uninstall
./cri-install.sh --uninstall
```

#### proxy-install.sh
Pre-installs custom version of Kube-Proxy that works with the Contiv-VPP. Needs to be done
on each node, before initializing the cluster with `kubeadm init` or joining the cluster with `kubeadm join`.
```
./proxy-install.sh
```

#### pull-images.sh
This script can be used to pull the newest version of the `:latest` tag of all Docker images
that Contiv-VPP plugin uses. This may be needed in case that you have already used Contiv-VPP plugin
on the host before and have the old (outdated) versions of docker images stored locally.

#### setup-node.sh
This script simplifies the setup of multi-node cluster - installs DPDK kernel module, pull the images, interactively creates startup config for vpp,... It has to be
executed on each node of the cluster.
```
./setup-node.sh
#########################################
#   Contiv - VPP                        #
#########################################
Do you want to setup multinode cluster? [Y/n] y
PCI UIO driver is not loaded
Do you want to load PCI UIO driver? [Y/n] y
[sudo] password for lukas:
Do you want the PCI UIO driver to be loaded on boot up? [Y/n] y
Module uio_pci_generic was added into /etc/modules
The following network devices were found
1) eth0 0000:00:03.0
2) eth1 0000:00:08.0
3) eth2 0000:00:09.0
Select interface for node interconnect [1-3]:3
Device 'eth2' must be shutdown, do you want to proceed? [Y/n] y

unix {
   nodaemon
   cli-listen 0.0.0.0:5002
   cli-no-pager
}
dpdk {
   dev 0000:00:09.0
}

File /etc/vpp/contiv-vswitch.conf will be modified, do you want to proceed? [Y/n] y
Configuration of the node finished successfully.

```
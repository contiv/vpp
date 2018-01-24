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
    - `UseL2Interconnect`: use pure L2 node interconnect instead of VXLANs;
    - `UseTAPInterfaces`: use TAP interfaces instead of VETHs for Pod-to-VPP interconnection
      (VETH is still used to connect VPP with the host stack);
    - `TAPInterfaceVersion`: select `1` to use the standard VPP TAP interface or `2`
      for a faster, virtio-based, VPP TAPv2 interface (default);
    - `TAPv2RxRingSize`: number of entries to allocate for TAPv2 Rx ring (default is 256);
    - `TAPv2TxRingSize`: number of entries to allocate for TAPv2 Tx ring (default is 256).

  * IPAM (section `IPAMConfig`)
    - `PodSubnetCIDR`: subnet used for all pods across all nodes;
    - `PodNetworkPrefixLen`: subnet prefix length used for all pods of 1 k8s node
      (pod network = pod subnet for one k8s node);
    - `VPPHostSubnetCIDR`: subnet used in each node for VPP-to-host connectivity;
    - `VPPHostNetworkPrefixLen`: prefix length of the subnet used for VPP-to-host connectivity
      on 1 k8s node (VPPHost network = VPPHost subnet for one k8s node);
    - `NodeInterconnectCIDR`: subnet used for main interfaces of all nodes;
    - `VxlanCIDR`: subnet used for VXLAN addressing providing node-interconnect overlay.
    - `ServiceCIDR`: subnet used for allocation of Cluster IPs for services. Default value
    is the default kubernetes service range `10.96.0.0/12`.

  * Node configuration (section `NodeConfig`; one entry for each node)
    - `NodeName`: name of a Kubernetes node;
    - `MainVppInterface`: name of the interface to be used for node-to-node connectivity.
       IP address is allocated from `HostNodeSubnetCidr` defined in the IPAM section OR can be specified manually:
      - `InterfaceName`: name of the main interface;
      - `IP`: IP address to be attached to the main interface;
      - `UseDHCP`: acquire IP address using DHCP
              (beware: the change of IP address is not supported)
    - `OtherVPPInterfaces` (other configured interfaces only get IP address assigned in VPP)
      - `InterfaceName`: name of the interface;
      - `IP`: IP address to be attached to the interface;
    - `Gateway`: IP address of the default gateway for external traffic, if it needs to be configured.

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
PCI UIO driver is loaded
The following network devices were found
1) eth0 0000:00:03.0
2) eth1 0000:00:08.0
3) eth2 0000:00:09.0
Select interface for node interconnect [1-3]:3
Device 'eth2' must be shutdown, do you want to proceed? [Y/n] y

unix {
   nodaemon
   cli-listen /run/vpp/cli.sock
   cli-no-pager
}
dpdk {
   dev 0000:00:09.0
}

File /etc/vpp/contiv-vswitch.conf will be modified, do you want to proceed? [Y/n] y
Do you want to pull the latest images? [Y/n] y
latest: Pulling from contivvpp/vswitch
Digest: sha256:51d875236ae4e59d03805900875b002f539fec8ab68b94156ba47cad3fef8630
Status: Image is up to date for contivvpp/vswitch:latest
latest: Pulling from contivvpp/cri
Digest: sha256:e7c34140d4bfdecb7f37022da8a1e57c5377cc77af776acbb2f7b1aeff577365
Status: Image is up to date for contivvpp/cri:latest
latest: Pulling from contivvpp/ksr
Digest: sha256:abf120fd901af3c8e265c5ddab9f918823999f5cd934ea8b7538c2e0b30411c2
Status: Image is up to date for contivvpp/ksr:latest
latest: Pulling from contivvpp/cni
Digest: sha256:7330227f9d7c717f6c0ecf1e214488af8e419123eca9332889712fd81a78be50
Status: Image is up to date for contivvpp/cni:latest
In order to use Kubernetes services custom Kube-proxy is required, do you want to install it? [Y/n] y
v1.8.0: Pulling from contivvpp/kube-proxy
Digest: sha256:eabddcb0c3cf8be21d1254547601dbfebd4a4a20472acf3b993467e55aaa4eeb
Status: Image is up to date for contivvpp/kube-proxy:v1.8.0
v1.8.1: Pulling from contivvpp/kube-proxy
Digest: sha256:32b436584115ef9da70b721b43285893c10eacec7e56e4b2111f193733847ee1
Status: Image is up to date for contivvpp/kube-proxy:v1.8.1
v1.8.2: Pulling from contivvpp/kube-proxy
Digest: sha256:11f9ee588accf7d05a98d415426f7e9dc0aedc604eba24073adfacae864cbc9b
Status: Image is up to date for contivvpp/kube-proxy:v1.8.2
v1.8.3: Pulling from contivvpp/kube-proxy
Digest: sha256:12c5936c2428fcdce182a41f8f7982540d7d3f8498aff263e4433506e07f8ce3
Status: Image is up to date for contivvpp/kube-proxy:v1.8.3
v1.8.4: Pulling from contivvpp/kube-proxy
Digest: sha256:50bf7bfc1d4b6732b41a234f9697b0e7db30d310f4c94c288eb43c3070d91073
Status: Image is up to date for contivvpp/kube-proxy:v1.8.4
Cri-shim is already running
Do you want to restart cri-shim? [Y/n] n
Configuration of the node finished successfully.
```

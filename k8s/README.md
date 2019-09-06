## Contiv-VPP Kubernetes Deployment Files

This folder contains a set of files and subfolders that can be used to deploy Contiv-VPP
network plugin on Kubernetes:

* [contiv-vpp.yaml](#contiv-vppyaml) + [contiv-vpp folder](contiv-vpp/README.md) for deployment
  of Contiv-VPP CNI plugin
* [contiv-vpp-ui](contiv-vpp-ui/README.md) for deployment of Contiv-VPP user interface
* [pull-images.sh](#pull-imagessh) for pulling the latest images
* [stn-install.sh](#stn-installsh) for Steal-The-Nic daemon installation
* [setup-node.sh](#setup-nodesh) for interactive DPDK setup on individual nodes


#### contiv-vpp.yaml
The main deployment file that can be used to deploy Contiv-VPP network plugin using `kubeadm`:
```bash
# deploy
kubectl apply -f contiv-vpp.yaml

# undeploy
kubectl delete -f contiv-vpp.yaml
```

This manifest can be re-generated from the [contiv-vpp](contiv-vpp/README.md) helm chart:
```bash
# from the contiv-vpp repo root
make generate-manifest
```

And optionally, a new manifest can be generated with different configuration values than the 
defaults in [`contiv-vpp/values.yaml`](contiv-vpp/values.yaml). E.g. to generate YAML with
a specific vswitch image version:
```
helm template --name contiv-vpp contiv-vpp \
  --set vswitch.image.repository=contivvpp/dev-vswitch \
  --set vswitch.image.tag=<your image version> > dev-contiv-vpp.yaml
```

To use the development image for testing with specific version of VPP, see
[DEVIMAGE.md](../docker/DEVIMAGE.md).

The deployment YAML starts with a config map which can be tweaked either 
manually or using the [helm options](contiv-vpp/README.md#configuration):

##### contiv.conf

  Configuration file for Contiv agent is deployed via the Config map `contiv-agent-cfg`
  into the location `/etc/contiv/contiv.conf` of vSwitch. It includes several options
  allowing to customize the network connectivity between pods, such as the configuration
  of interfaces and allocation of IP addresses.

  * Pod-to-VPP connectivity (top-level options)
    - `nodeToNodeTransport`: transportation used for node-to-node communication. Possible values:
      1. `vxlan`: VXLAN overlay encapsulates/decapsulates traffic between nodes using VXLAN.
      2. `srv6`: SRv6 overlay encapsulates/decapsulates traffic between nodes using SRv6 (segment routing based on IPv6).
      SRv6's steering and policy will be on ingress node and SRv6's localsid on egress node. This transportation expects
      ipv6 to be enabled (SRv6 packets=IPv6 packets using SR header extension).
      3. `nooverlay`: Using none of the previous mentioned overlays and route traffic using routing tables/etc., e.g. if the nodes are on the same L2 network.
    - `useSRv6ForServices`: use SRv6(IPv6) for k8s service (this handles only packet from service client to backend, but 
    in case of response packet, other networking settings handle it because it is normal pod/host-to-pod/host connectivity)
    - `useDX6ForSrv6NodetoNodeTransport`: enable usage of DX6 instead of DT6 for node-to-node communication (only for pod-to-pod case with full IPv6 environment), default is false
    - `useSRv6ForServiceFunctionChaining`: use SRv6(IPv6) for Service Function Chaining in k8s service
    - `useTAPInterfaces`: use TAP interfaces instead of VETHs for Pod-to-VPP and VPP-to-Host interconnection
    - `tAPInterfaceVersion`: select `1` to use the standard VPP TAP interface or `2`
      for a faster, virtio-based, VPP TAPv2 interface (default);
    - `stealInterface`: enable Steal The NIC feature on the specified interface on each node;``
    - `stealFirstNIC`: enable Steal The NIC feature on the first interface on each node;
    - `tapv2RxRingSize`: number of entries to allocate for TAPv2 Rx ring (default is 256)
    - `tapv2TxRingSize`: number of entries to allocate for TAPv2 Tx ring (default is 256)
    - `natExternalTraffic`: if enabled, traffic with cluster-outside destination is S-NATed
                            with the node IP before being sent out from the node (applies for all nodes)
    - `mtuSize`: maximum transmission unit (MTU) size (default is 1500)
    - `serviceLocalEndpointWeight`: how much more likely a service local endpoint is to receive
      connection over a remotely deployed one (default is `1`, i.e. equal distribution)

  * IPAM (section `ipamConfig`)
    - `podSubnetCIDR`: subnet used for all pods across all nodes
    - `podSubnetOneNodePrefixLen`: subnet prefix length used for all pods of 1 k8s node
      (pod network = pod subnet for one k8s node);
    - `vppHostSubnetCIDR`: subnet used in each node for VPP-to-host connectivity;
    - `vppHostSubnetOneNodePrefixLen`: prefix length of the subnet used for VPP-to-host connectivity
      on 1 k8s node (VPPHost network = VPPHost subnet for one k8s node)
    - `nodeInterconnectCIDR`: subnet used for main interfaces of all nodes
    - `nodeInterconnectDHCP`: use DHCP to acquire IP for all nodes by default
    - `vxlanCIDR`: subnet used for VXLAN addressing providing node-interconnect overlay
    - `serviceCIDR`: subnet used for allocation of Cluster IPs for services. Default value
    is the default kubernetes service range `10.96.0.0/12`
    * SRv6 (section `srv6`)
      - `servicePolicyBSIDSubnetCIDR`: subnet applied to lowest k8s service IP to get unique (per service,per node) binding sid for SRv6 policy
      - `servicePodLocalSIDSubnetCIDR`: subnet applied to k8s service local pod backend IP to get unique sid for SRv6 Localsid referring to local pod beckend using DX6 end function
      - `serviceHostLocalSIDSubnetCIDR`: subnet applied to k8s service host pod backend IP to get unique sid for SRv6 Localsid referring to local host beckend using DX6 end function
      - `serviceNodeLocalSIDSubnetCIDR`: subnet applied to node IP to get unique sid for SRv6 Localsid that is intermediate segment routing to other nodes in Srv6 segment list (used in k8s services)
      - `nodeToNodePodLocalSIDSubnetCIDR`: subnet applied to node IP to get unique sid for SRv6 Localsid that is the only segment in node-to-node Srv6 tunnel. Traffic from tunnel continues routing by looking into pod VRF table (DT6 end function of localsid)
      - `nodeToNodeHostLocalSIDSubnetCIDR`: subnet applied to node IP to get unique sid for SRv6 Localsid that is the only segment in node-to-node Srv6 tunnel. Traffic from tunnel continues routing by looking into main VRF table (DT6 end function of localsid)
      - `nodeToNodePodPolicySIDSubnetCIDR`: subnet applied to node IP to get unique bsid for SRv6 policy that defines path in node-to-node Srv6 tunnel as mentioned in `srv6NodeToNodePodLocalSIDSubnetCIDR`
      - `nodeToNodeHostPolicySIDSubnetCIDR`: subnet applied to node IP to get unique bsid for SRv6 policy that defines path in node-to-node Srv6 tunnel as mentioned in `srv6NodeToNodeHostLocalSIDSubnetCIDR`.
      - `sfcPolicyBSIDSubnetCIDR`: subnet applied to SFC ID(trimmed hash of SFC name) to get unique binding sid for SRv6 policy used in SFC
      - `sfcServiceFunctionSIDSubnetCIDR`: subnet applied to combination of SFC ID(trimmed hash of SFC name) and service function pod IP address to get unique sid for SRv6 Localsid referring to SFC service function
      - `sfcEndLocalSIDSubnetCIDR`: subnet applied to the IP address of last link of SFC to get unique sid for last localsid in the segment routing path representing SFC chain
      - `sfcIDLengthUsedInSidForServiceFunction`: length(in bits) of SFC ID(trimmed hash of SFC name) that should be used by computing SFC ServiceFunction localsid SID. A hash is computed from SFC name, trimmed by length (this setting) and used in computation of SFC ServiceFunction localsid SID (SID=prefix from sfcServiceFunctionSIDSubnetCIDR + trimmed hash of SFC name + service function pod IP address).

      Default config values for SRv6 SID/BSID subnets follow these rules to gain more clarity in debugging/maintaining/adding new functionality(adding new sids/bsids):
       - 8fff::/16 = service policy
       - 8eee::/16 = sfc policy
       - 8\<XYZ\>::/16 = policy for node-to-node communication ending in locasid with SID 9\<XYZ\>::/16
       - 9000::/16 = localsid with end function End
       - 9100::/16 = localsid with end function End.DX2 (crossconnect target could be found out from non-prefix part of SID (target interface leads to target pod/node and sid is created from IP of that pod/node))
       - 9200::/16 = localsid with end function End.DX4 (crossconnect target is known as in DX2 case)
       - 9300::/16 = localsid with end function End.DX6 (crossconnect target is known as in DX2 case), no SFC usage
       - 9310::/16 = localsid with end function End.DX6 (crossconnect target is known as in DX2 case), SFC usage
       - 94\<YZ\>::/16 = localsid with end function End.DT4 (\<YZ\> is id of target ipv4 VRF table)
       - 95\<YZ\>::/16 = localsid with end function End.DT6 (\<YZ\> is id of target ipv6 VRF table)
       - 9600::/16 = localsid with end function End.AD (crossconnect target is known as in DX2 case)

  * Node configuration (section `nodeConfig`; one entry for each node)
    - `nodeName`: name of a Kubernetes node;
    - `mainVPPInterface`: name of the interface to be used for node-to-node connectivity.
       IP address is allocated from `vppHostSubnetCIDR` defined in the IPAM section OR can be specified manually:
      - `interfaceName`: name of the main interface;
      - `ip`: IP address to be attached to the main interface;
      - `useDHCP`: acquire IP address using DHCP
              (beware: the change of IP address is not supported)
    - `stealInterface`: name of the interface in the Linux host stack, that should be "stolen" and used by VPP;
    - `otherVPPInterfaces` (other configured interfaces only get IP address assigned in VPP)
      - `interfaceName`: name of the interface;
      - `ip`: IP address to be attached to the interface;
    - `gateway`: IP address of the default gateway for external traffic, if it needs to be configured;
    - `natExternalTraffic`: if enabled, traffic with cluster-outside destination is S-NATed
                            with the node IP before being sent out from the node.


#### pull-images.sh
This script can be used to pull the newest version of the `:latest` tag of all Docker images
that Contiv-VPP plugin uses. This may be needed in case that you have already used Contiv-VPP plugin
on the host before and have the old (outdated) versions of docker images stored locally.


#### stn-install.sh
Contiv-VPP STN daemon installer / uninstaller, that can be used as follows:
```
# install
./stn-install.sh

# uninstall
./stn-install.sh --uninstall
```


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
   poll-sleep-usec 100
}
nat {
   endpoint-dependent
   translation hash buckets 1048576
   translation hash memory 268435456
   user hash buckets 1024
   max translations per user 10000
}
acl-plugin {
    use tuple merge 0
}
dpdk {
   dev 0000:00:09.0
}
socksvr {
   default
}
statseg {
   default
}

File /etc/vpp/contiv-vswitch.conf will be modified, do you want to proceed? [Y/n] y
Do you want to pull the latest images? [Y/n] y
latest: Pulling from contivvpp/vswitch
Digest: sha256:51d875236ae4e59d03805900875b002f539fec8ab68b94156ba47cad3fef8630
Status: Image is up to date for contivvpp/vswitch:latest
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
Configuration of the node finished successfully.
```

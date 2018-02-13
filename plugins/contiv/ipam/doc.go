// Package ipam provides node-local IPAM calculations: POD IP addresses, VPP-host interconnect and node interconnect IP addresses.
//
// The IP assignment is driven by unique node ID (uint32), that is passed to the IPAM module upon its initialization,
// together with IPAM configuration (can be specified as IPAMConfig in contiv-agent-cfg ConfigMap
// in ../../k8s/contiv-vpp.yaml). The contiv-agent on each node in the k8s cluster therefore does its node-local IPAM
// calculation and assignment itself, the cluster IPAM is therefore distributed between all nodes.
//
// The package calculates and assigns the following IP addresses:
// 		- node-local POD network and individual POD IPs (based on PodSubnetCIDR, PodNetworkPrefixLen and node ID)
//		- IP subnet for the VPP-to-host Linux stack interconnect (based on VPPHostSubnetCIDR, VPPHostNetworkPrefixLen and node ID)
//		- IP address of the physical interface used for node interconnect (based on NodeInterconnectCIDR and node ID)
//
// Example:
//
//	    IPAMConfig:
//		  PodSubnetCIDR: "10.1.0.0/16"
//		  PodNetworkPrefixLen: 24
//		  VPPHostSubnetCIDR: "172.30.0.0/16"
//		  VPPHostNetworkPrefixLen: 24
//		  NodeInterconnectCIDR: "192.168.16.0/24"
//
//		Assigned node ID: 5
//
//		Calculated POD IPs: 10.1.5.2 - 10.1.5.254 (/24)
//		Calculated VPP-host interconnect IPs: 172.30.5.1, 172.30.5.2 (/24)
//  	Calculated Node Interconnect IP:  192.168.16.5 (/24)
package ipam

// Package ipam provides node-local IPAM calculations: POD IP addresses,
// VPP-host interconnect and node interconnect IP addresses.
//
// The configuration for IPAM is retrieved from the ContivConf plugin.
//
// Single IPAM instance is responsible for all node-local allocations.
// Between nodes, however, IPAMs do not communicate with each other, instead,
// the unique node ID (uint32), retrieved from the nodesync plugin upon the first
// resync, is used to avoid inter-node collisions.
//
// The plugin calculates and assigns the following IP addresses:
// 		- node-local POD network and individual POD IPs (based on podSubnetCIDR,
//        podSubnetOneNodePrefixLen and node ID)
//		- IP subnet for the VPP-to-host Linux stack interconnect
//        (based on vppHostSubnetCIDR, vppHostSubnetOneNodePrefixLen
//        and node ID)
//		- IP address of the physical interface used for node interconnect
//        (based on nodeInterconnectCIDR and node ID)
//
// Example (configuration from contiv.conf processed by ContivConf plugin):
//
//	    ipamConfig:
//		  podSubnetCIDR: "10.1.0.0/16"
//		  podSubnetOneNodePrefixLen: 24
//		  vppHostSubnetCIDR: "172.30.0.0/16"
//		  vppHostSubnetOneNodePrefixLen: 24
//		  nodeInterconnectCIDR: "192.168.16.0/24"
//
//		Assigned node ID: 5
//
//		Calculated POD IPs: 10.1.5.2 - 10.1.5.254 (/24)
//		Calculated VPP-host interconnect IPs: 172.30.5.1, 172.30.5.2 (/24)
//  	Calculated Node Interconnect IP:  192.168.16.5 (/24)
package ipam

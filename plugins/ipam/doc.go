// Package ipam provides node-local IPAM calculations: POD IP addresses,
// VPP-host interconnect and node interconnect IP addresses.
//
// The configuration for IPAM is loaded from the config file ipam.conf.
//
// Single IPAM instance is responsible for all node-local allocations.
// Between nodes, however, IPAMs do not communicate with each other, instead,
// the unique node ID (uint32), retrieved from the nodesync plugin upon the first
// resync, is used to avoid inter-node collisions.
//
// The plugin calculates and assigns the following IP addresses:
// 		- node-local POD network and individual POD IPs (based on pod-subnet-cidr,
//        pod-subnet-one-node-prefix-len and node ID)
//		- IP subnet for the VPP-to-host Linux stack interconnect
//        (based on vpp-host-subnet-cidr, vpp-host-subnet-one-node-prefix-len
//        and node ID)
//		- IP address of the physical interface used for node interconnect
//        (based on node-interconnect-cidr and node ID)
//
// Example:
//
//	    ipam.conf:
//		  pod-subnet-cidr: "10.1.0.0/16"
//		  pod-subnet-one-node-prefix-len: 24
//		  vpp-host-subnet-cidr: "172.30.0.0/16"
//		  vpp-host-subnet-one-node-prefix-len: 24
//		  node-interconnect-cidr: "192.168.16.0/24"
//
//		Assigned node ID: 5
//
//		Calculated POD IPs: 10.1.5.2 - 10.1.5.254 (/24)
//		Calculated VPP-host interconnect IPs: 172.30.5.1, 172.30.5.2 (/24)
//  	Calculated Node Interconnect IP:  192.168.16.5 (/24)
//
// Additionally, the package provides REST endpoint for getting some of the IPAM
// information for the node on the URL:
// GET /contiv/v1/ipam.
//
// Example:
//
//      $ curl localhost:9999/contiv/v1/ipam
//      {
//        "nodeId": 1,
//        "nodeName": "vagrant-arch.vagrantup.com",
//        "nodeIP": "192.168.16.1",
//        "podSubnetThisNode": "10.1.1.0/24",
//        "vppHostNetwork": "172.30.1.0/24"
//      }
package ipam

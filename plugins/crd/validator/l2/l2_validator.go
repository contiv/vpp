// Copyright (c) 2018 Cisco and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package l2

import (
	"fmt"

	"github.com/ligato/cn-infra/logging"

	"github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"
	
	"github.com/contiv/vpp/plugins/crd/api"
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/contiv/vpp/plugins/crd/datastore"
	"github.com/contiv/vpp/plugins/crd/validator/utils"
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"	
)

// Validator is the implementation of the ContivTelemetryProcessor interface.
type Validator struct {
	Log logging.Logger

	VppCache api.VppCache
	K8sCache api.K8sCache
	Report   api.Report
}

type tapMap map[string]map[uint32]telemetrymodel.NodeInterface

// Validate performs the validation of L2 telemetry data collected from a
// Contiv cluster.
func (v *Validator) Validate() {
	v.ValidateArpTables()
	v.ValidateBridgeDomains()
	v.ValidateL2FibEntries()
	v.ValidateK8sNodeInfo()
	v.ValidatePodInfo()
}

// ValidateArpTables validates statically configured entries in the ARP table
// for both the local BVI interface as well as BVI interfaces on remote nodes.
// The routine checks that each entry points to a valid interface. The routine
// also detects stale entries in the ARP table (i.e. entries that do not point
// to any active nodes in the cluster).
func (v *Validator) ValidateArpTables() {
	errCnt := 0
	v.Report.SetPrefix("IP-ARP")
	nodeList := v.VppCache.RetrieveAllNodes()

	for _, node := range nodeList {

		if node.NodeIPArp == nil {
			v.Report.AppendToNodeReport(node.Name, "validation skipped - no IP-ARP data available")
			continue
		}

		loopNodeMap := make(map[string]bool)
		for _, n := range nodeList {
			if n.Name != node.Name {
				loopNodeMap[n.Name] = true
			}
		}

		for _, arpTableEntry := range node.NodeIPArp {
			if !arpTableEntry.Ae.Static {
				continue
			}

			arpIf, ok := node.NodeInterfaces[arpTableEntry.AeMeta.IfIndex]
			if !ok {
				errString := fmt.Sprintf("invalid ARP entry <'%s'-'%s'>: bad ifIndex %d",
					arpTableEntry.Ae.PhysAddress, arpTableEntry.Ae.IPAddress, arpTableEntry.AeMeta.IfIndex)
				v.Report.AppendToNodeReport(node.Name, errString)
				errCnt++
				continue
			}

			// skip over ARP entries for all interfaces other than Vxlan BVI
			if arpIf.Value.Type != interfaces.Interface_SOFTWARE_LOOPBACK || arpIf.Value.Name != "vxlanBVI" {
				continue
			}

			addressNotFound := false
			macNode, err := v.VppCache.RetrieveNodeByLoopMacAddr(arpTableEntry.Ae.PhysAddress)
			if err != nil {
				errString := fmt.Sprintf("invalid ARP entry <'%s'-'%s'>: bad MAC Addess",
					arpTableEntry.Ae.PhysAddress, arpTableEntry.Ae.IPAddress)
				v.Report.AppendToNodeReport(node.Name, errString)
				addressNotFound = true
				errCnt++
			}

			ipNode, err := v.VppCache.RetrieveNodeByLoopIPAddr(arpTableEntry.Ae.IPAddress + "/24")
			if err != nil {
				errString := fmt.Sprintf("invalid ARP entry <'%s'-'%s'>: bad IP Addess",
					arpTableEntry.Ae.PhysAddress, arpTableEntry.Ae.IPAddress)
				v.Report.AppendToNodeReport(node.Name, errString)
				addressNotFound = true
				errCnt++
			}

			if addressNotFound {
				continue
			}

			if macNode.Name != ipNode.Name {
				errString := fmt.Sprintf("invalid ARP entry <'%s'-'%s'>: MAC -> node %s, IP -> node %s",
					arpTableEntry.Ae.PhysAddress, arpTableEntry.Ae.IPAddress, macNode.Name, ipNode.Name)
				v.Report.AppendToNodeReport(node.Name, errString)
				errCnt++
			}

			delete(loopNodeMap, ipNode.Name)
		}

		for nodeName := range loopNodeMap {
			errCnt++
			errString := fmt.Sprintf("missing ARP entry for node %s", nodeName)
			v.Report.AppendToNodeReport(node.Name, errString)
		}
	}

	v.addSummary(errCnt)
}

// ValidateBridgeDomains makes sure that each node in the cache has the right
// number of vxlan_tunnels for the number of nodes as well as checking that
// each vxlan_tunnel points to a node that has a corresponding but opposite
// tunnel itself.
func (v *Validator) ValidateBridgeDomains() {
	errCnt := 0
	v.Report.SetPrefix("VXLAN-BD")
	nodeList := v.VppCache.RetrieveAllNodes()

validateNodeBD:
	for _, node := range nodeList {
		if node.NodeBridgeDomains == nil {
			v.Report.AppendToNodeReport(node.Name, "validation skipped - no VXLAN-BD data available")
			continue
		}

		nodeVxlanMap := make(map[string]bool)
		for _, n := range nodeList {
			nodeVxlanMap[n.Name] = true
		}

		// Validate that there is exactly one bridge domain with the name vxlanBD
		var vxLanBD *telemetrymodel.NodeBridgeDomain

		for _, bdomain := range node.NodeBridgeDomains {
			if bdomain.Bd.Name == "vxlanBD" {
				if vxLanBD != nil {
					errString := fmt.Sprintf("multiple VXLAN BDs - skipped BD validation")
					errCnt++
					v.Report.AppendToNodeReport(node.Name, errString)
					continue validateNodeBD
				}
				vxLanBD = &bdomain
			}
		}

		if vxLanBD == nil {
			errCnt++
			errString := fmt.Sprintf("no VXLAN BD - skipped L2 validation")
			v.Report.AppendToNodeReport(node.Name, errString)
			continue
		}

		validInterfaces := 0
		bdName2Id := make(map[string]uint32)
		for id, name := range vxLanBD.BdMeta.BdID2Name {
			bdName2Id[name] = id
		}

		// Validate interfaces listed in the BD
		hasBviIfc := false
		for _, bdIfc := range vxLanBD.Bd.Interfaces {
			ifIndex := bdName2Id[bdIfc.Name]

			//check if one of the indices point to the loop interface
			//if it does, increment a counter and set a boolean to true
			nodeIfc, ok := node.NodeInterfaces[ifIndex]
			if !ok {
				errCnt++
				errString := fmt.Sprintf("invalid interface in VXLAN BD; ifIndex %d, ifName %s", ifIndex, bdIfc.Name)
				v.Report.AppendToNodeReport(node.Name, errString)
				continue
			}

			if bdIfc.BVI {
				// check for duplicate BVIs (there must be only one BVI per BD)
				if hasBviIfc {
					errCnt++
					errString := fmt.Sprintf("duplicate BVI, type %+v, BVI %s (ifIndex %d, ifName %s)",
						nodeIfc.Value.Type, bdIfc.Name, ifIndex, nodeIfc.Value.Name)
					v.Report.AppendToNodeReport(node.Name, errString)
				}

				// BVI must be a software loopback interface
				if nodeIfc.Value.Type != interfaces.Interface_SOFTWARE_LOOPBACK {
					errCnt++
					errString := fmt.Sprintf("invalid BVI type %+v, BVI %s (ifIndex %d, ifName %s)",
						nodeIfc.Value.Type, bdIfc.Name, ifIndex, nodeIfc.Value.Name)
					v.Report.AppendToNodeReport(node.Name, errString)
					continue
				}

				hasBviIfc = true
				validInterfaces++

				if n, err := v.VppCache.RetrieveNodeByLoopMacAddr(nodeIfc.Value.PhysAddress); err != nil {
					errCnt++
					errString := fmt.Sprintf("validator internal error: bad MAC Addr index, "+
						"MAC Addr %s, BVI %s (ifIndex %d, ifName %s)",
						nodeIfc.Value.PhysAddress, bdIfc.Name, ifIndex, nodeIfc.Value.Name)
					v.Report.AppendToNodeReport(node.Name, errString)
					continue
				} else {
					delete(nodeVxlanMap, n.Name)
				}
			} else {
				// Make sure that the type of a regular BD interface is VXLAN_tunnel interface
				if nodeIfc.Value.Type != interfaces.Interface_VXLAN_TUNNEL {
					errCnt++
					errString := fmt.Sprintf("invalid BD interface type %+v, BVI %s (ifIndex %d, ifName %s)",
						nodeIfc.Value.Type, bdIfc.Name, ifIndex, nodeIfc.Value.Name)
					v.Report.AppendToNodeReport(node.Name, errString)
					continue
				}

				// Make sure the VXLAN tunnel's VNI is correct (value '10')
				if nodeIfc.Value.GetVxlan().Vni != api.VppVNI {
					errCnt++
					errString := fmt.Sprintf("invalid VNI for %s: got %d, expected %d",
						node.NodeInterfaces[ifIndex].Value.Name,
						node.NodeInterfaces[ifIndex].Value.GetVxlan().Vni,
						api.VppVNI)
					v.Report.AppendToNodeReport(node.Name, errString)
				}

				// Make sure the VXLAN's tunnel source IP address points to the current node.
				srcIPNode, err := v.VppCache.RetrieveNodeByGigEIPAddr(nodeIfc.Value.GetVxlan().SrcAddress)
				if err != nil {
					errCnt++
					errString := fmt.Sprintf("invalid VXLAN tunnel %s; node with src IP %s not found",
						nodeIfc.Value.Name, nodeIfc.Value.GetVxlan().SrcAddress)
					v.Report.AppendToNodeReport(node.Name, errString)
					continue
				}

				if srcIPNode.Name != node.Name {
					errCnt++
					errString := fmt.Sprintf("invalid VXLAN tunnel %s; source ip %s points "+
						"to a node different than %s.", nodeIfc.Value.Name, nodeIfc.Value.GetVxlan().SrcAddress, node.Name)
					v.Report.AppendToNodeReport(node.Name, errString)
					continue
				}

				// For the vxlan interface (i.e. the interface to a remote node),
				// try to find the node with its GigE interface IP Address equal
				// to the dst ip address in vxlan tunnel (i.e. find the node to
				// which the tunnel is pointing). Then, ensure that on this remote
				// node there is a a vxlan_tunnel that is points to our current
				// node.
				dstipNode, err := v.VppCache.RetrieveNodeByGigEIPAddr(nodeIfc.Value.GetVxlan().DstAddress)
				if err != nil {
					errCnt++
					errString := fmt.Sprintf("invalid VXLAN tunnel %s; node with dst ip %s not found",
						nodeIfc.Value.Name, nodeIfc.Value.GetVxlan().DstAddress)
					v.Report.AppendToNodeReport(node.Name, errString)
					continue
				}

				matchingTunnelFound := false
				for _, dstIntf := range dstipNode.NodeInterfaces {
					if dstIntf.Value.Type == nodeIfc.Value.Type {
						if dstIntf.Value.GetVxlan().DstAddress == nodeIfc.Value.GetVxlan().SrcAddress {
							matchingTunnelFound = true
						}
					}
				}

				if !matchingTunnelFound {
					errCnt++
					errString := fmt.Sprintf("VXLAN %s: missing reverse VXLAN tunnel on remote node %s",
						nodeIfc.Value.Name, dstipNode.Name)
					v.Report.AppendToNodeReport(node.Name, errString)
				}
				validInterfaces++

				// Try to mark the interface as seen
				dstAddr := node.NodeInterfaces[ifIndex].Value.GetVxlan().DstAddress
				if n1, err := v.VppCache.RetrieveNodeByGigEIPAddr(dstAddr); err == nil {
					delete(nodeVxlanMap, n1.Name)
				} else {
					errCnt++
					v.Report.AppendToNodeReport(n1.Name,
						fmt.Sprintf("validator internal error: inconsistent GigE Address index, dest addr %s",
							dstAddr))
				}
			}
		}

		// Ensure that there is exactly one valid interface in the BD for
		// each node in the cluster
		if validInterfaces != len(nodeList) {
			errCnt++
			errString := fmt.Sprintf("bad number of valid BD interfaces: have %d, expecting %d",
				validInterfaces, len(nodeList))
			v.Report.AppendToNodeReport(node.Name, errString)
		}

		// Ensure that there is exactly one BVI interface in the BD
		if !hasBviIfc {
			errCnt++
			errString := fmt.Sprintf("missing/invalid BVI interface in VXLAN BD")
			v.Report.AppendToNodeReport(node.Name, errString)
			continue
		}

		// List all the nodes for which we haven't found a valid interface
		// in the BD
		if len(nodeVxlanMap) > 0 {
			for n := range nodeVxlanMap {
				errCnt++
				errString := fmt.Sprintf("missing/invalid VXLAN interface in VXLAN BD for node %s", n)
				v.Report.AppendToNodeReport(node.Name, errString)
			}
			continue
		}
	}

	v.addSummary(errCnt)
}

// ValidateL2FibEntries validates statically configured L2 FIB entries for
// remote nodes. It checks that each remote node has a statically configured
// entry n the L2 FIB and that the entry points to a valid interface on the
// remote node. It also detect dangling L2FIB entries (i.e. entries that do
// not point to active remote nodes).
func (v *Validator) ValidateL2FibEntries() {
	errCnt := 0
	v.Report.SetPrefix("L2-FIB")
	nodeList := v.VppCache.RetrieveAllNodes()

	for _, node := range nodeList {
		if node.NodeL2Fibs == nil {
			v.Report.AppendToNodeReport(node.Name, "validation skipped - no L2-FIB data available")
			continue
		}

		fibHasLoopIF := false
		vxLanBD, err := getVxlanBD(node)
		if err != nil {
			errCnt++
			errString := fmt.Sprintf("%s - skipped L2Fib validation for node %s", err.Error(), node.Name)
			v.Report.AppendToNodeReport(node.Name, errString)
			continue
		}

		// Used to mark all nodes for which there exists an L2Fib entry
		nodeFibMap := make(map[string]bool)
		for _, n := range nodeList {
			nodeFibMap[n.Name] = true
		}

		// Used to mark all L2Fib entries for which there exists a node
		fibNodeMap := make(map[string]bool)
		for feKey, feVal := range node.NodeL2Fibs {
			if int(feVal.FeMeta.BridgeDomainID) != vxLanBD {
				// Skip over entries in other BDs
				continue
			}
			if !feVal.Fe.StaticConfig {
				// Skip over dynamic (not statically programmed) entries
				continue
			}
			fibNodeMap[feKey] = true
		}

		for feKey, feVal := range node.NodeL2Fibs {
			if int(feVal.FeMeta.BridgeDomainID) != vxLanBD {
				// Skip over entries in other BDs
				continue
			}

			// Skip over dynamic (not statically programmed) entries
			if !feVal.Fe.StaticConfig {
				continue
			}

			if feVal.Fe.BridgedVirtualInterface {
				// Validate local loop0 (BVI) L2FIB entry

				// Lookup the local BVI (loopback) interface in the local node
				if loopIf, err := datastore.GetNodeLoopIFInfo(node); err != nil {
					errCnt++
					errString := fmt.Sprintf("invalid L2Fib BVI entry '%s': loop interface not found on node %s",
						feKey, node.Name)
					v.Report.AppendToNodeReport(node.Name, errString)
				} else {
					// check if the L2Fib entry's MAC address is the same as
					// in the BVI interface on the local node
					if feVal.Fe.PhysAddress != loopIf.Value.PhysAddress {
						errCnt++
						errString := fmt.Sprintf("invalid L2Fib BVI entry '%s'; bad MAC address - "+
							"have '%s', expecting '%s'", feKey, feVal.Fe.PhysAddress, loopIf.Value.PhysAddress)
						v.Report.AppendToNodeReport(node.Name, errString)
					}
				}

				// Do a consistency check of internal databases and report
				// an error if out of whack
				if _, err := v.VppCache.RetrieveNodeByLoopMacAddr(feVal.Fe.PhysAddress); err == nil {
					fibHasLoopIF = true
				} else {
					errCnt++
					errString := fmt.Sprintf("L2Fib validator internal error: "+
						"inconsistent MAC Address index, MAC %s", feVal.Fe.PhysAddress)
					v.Report.AppendToNodeReport(node.Name, errString)
				}

				delete(fibNodeMap, feKey)
				delete(nodeFibMap, node.Name)
			} else {
				// Validate remote node (VXLAN) L2FIB entry

				// Make sure the outgoing interface in the L2FIB entry exists
				intf, ok := node.NodeInterfaces[feVal.FeMeta.OutgoingIfIndex]
				if !ok {
					errCnt++
					errString := fmt.Sprintf("invalid L2Fib entry '%s': outgoing interface %s / ifIndex %d "+
						"not found ", feVal.Fe.PhysAddress, feVal.Fe.OutgoingIfName, feVal.FeMeta.OutgoingIfIndex)
					v.Report.AppendToNodeReport(node.Name, errString)
					continue
				}

				// Lookup the remote node by the destination address in the VXLAN interface
				macNode, err := v.VppCache.RetrieveNodeByGigEIPAddr(intf.Value.GetVxlan().DstAddress)
				if err != nil {
					errCnt++
					errString := fmt.Sprintf("invalid L2Fib entry '%s': "+
						"remote node for VXLAN DstIP '%s' not found", feKey, intf.Value.GetVxlan().DstAddress)
					v.Report.AppendToNodeReport(node.Name, errString)
					continue
				}

				// Lookup the Vxlan BD's BVI (loopback) interface in the remote node
				remoteLoopIF, err := datastore.GetNodeLoopIFInfo(macNode)
				if err != nil {
					delete(fibNodeMap, feKey)
					delete(nodeFibMap, macNode.Name)
					errCnt++
					errString := fmt.Sprintf("invalid L2Fib entry '%s': missing loop interface on remote node %s",
						feVal.Fe.PhysAddress, macNode.Name)
					v.Report.AppendToNodeReport(node.Name, errString)
					continue
				}

				// Make sure that the L2Fib entry's MAC address is the same as
				// in the BVI interface on the remote node
				if remoteLoopIF.Value.PhysAddress != feVal.Fe.PhysAddress {
					errCnt++
					errString := fmt.Sprintf("invalid L2Fib entry '%s': have MAC Address '%s', expecting %s",
						feKey, feVal.Fe.PhysAddress, remoteLoopIF.Value.PhysAddress)
					v.Report.AppendToNodeReport(node.Name, errString)
				}

				// Do a consistency check of internal databases and report
				// an error if out of whack
				if _, err := v.VppCache.RetrieveNodeByLoopMacAddr(feVal.Fe.PhysAddress); err != nil {
					errCnt++
					errString := fmt.Sprintf("L2Fib validator internal error: "+
						"inconsistent MAC Address index, MAC %s", feVal.Fe.PhysAddress)
					v.Report.AppendToNodeReport(node.Name, errString)
				}

				delete(fibNodeMap, feKey)
				delete(nodeFibMap, macNode.Name)
			}
		}

		if !fibHasLoopIF {
			errCnt++
			errString := fmt.Sprintf("L2Fib entry for interface 'loop0' not found")
			v.Report.AppendToNodeReport(node.Name, errString)
		}

		// Show all nodes for which there is no L2FIB entry
		for remoteNodeName := range nodeFibMap {
			errCnt++
			errString := fmt.Sprintf("missing L2Fib entry for node %s", remoteNodeName)
			v.Report.AppendToNodeReport(node.Name, errString)
		}

		// Show all L2Fib entrie for which there is no node
		for fibEntry := range fibNodeMap {
			errCnt++
			errString := fmt.Sprintf("dangling L2Fib entry %s - no node for entry found", fibEntry)
			v.Report.AppendToNodeReport(node.Name, errString)
		}
	}

	v.addSummary(errCnt)
}

// ValidateK8sNodeInfo will make sure that K8s's view of nodes in the cluster
// is consistent with Contiv's view of nodes in the cluster. Each node in K8s
// database must have a counterpart node in the Contiv database and vice versa.
func (v *Validator) ValidateK8sNodeInfo() {
	errCnt := 0
	v.Report.SetPrefix("K8S-NODE")
	nodeList := v.VppCache.RetrieveAllNodes()

	nodeMap := make(map[string]bool)
	for _, node := range nodeList {
		nodeMap[node.Name] = true
	}

	k8sNodeMap := make(map[string]bool)
	for _, k8sNode := range v.K8sCache.RetrieveAllK8sNodes() {
		k8sNodeMap[k8sNode.Name] = true
	}

	for _, node := range nodeList {
		k8sNode, err := v.K8sCache.RetrieveK8sNode(node.Name)
		if err != nil {
			errCnt++
			errString := fmt.Sprintf("VPP node with name %s not present in the k8s node map", node.Name)
			v.Report.AppendToNodeReport(node.Name, errString)
			continue
		}

		if node.Name == k8sNode.Name {
			delete(nodeMap, node.Name)
			delete(k8sNodeMap, k8sNode.Name)
		}
	}

	if len(k8sNodeMap) > 0 {
		errCnt++
		for k8sNode := range k8sNodeMap {
			v.Report.AppendToNodeReport(k8sNode, fmt.Sprintf("VPP node missing for K8s node %s", k8sNode))
		}
	}

	if len(nodeMap) > 0 {
		errCnt++
		for contivNode := range nodeMap {
			v.Report.AppendToNodeReport(contivNode, fmt.Sprintf("K8s node missing for VPP node %s", contivNode))
		}
	}

	v.addSummary(errCnt)
}

// ValidatePodInfo will check that each pod has a valid host ip address node
// and that the information correctly correlates between the nodes and the pods.
func (v *Validator) ValidatePodInfo() {
	// Prepare the mark-and-sweep database for detection of dangling pod-facing
	// tap interfaces
	tapMap := v.createTapMarkAndSweepDB()

	// Prepare the mark-and-sweep database for detection of dangling pods
	podMap := make(map[string]string)

	errCnt := 0
	v.Report.SetPrefix("K8S-POD")
	podList := v.K8sCache.RetrieveAllPods()

	for _, pod := range podList {
		// Check if we have a vppNode with the Host IP address that K8s specifies
		// for the Pod
		vppNode, err := v.VppCache.RetrieveNodeByHostIPAddr(pod.HostIPAddress)
		if err != nil {
			errCnt++
			errString := fmt.Sprintf("pod '%s': vppNode for pod not found - skipping Pod validation (%v)",
				pod.Name, pod.HostIPAddress)
			v.Report.AppendToNodeReport(api.GlobalMsg, errString)
			continue
		}

		// A pod must be present in its node's pod database
		podPtr, ok := vppNode.PodMap[pod.Name]
		if !ok {
			errCnt++
			v.Report.AppendToNodeReport(vppNode.Name, fmt.Sprintf("pod '%s': IP address (%s) points to node %s, "+
				"but pod is not present in node's podMap", pod.Name, pod.HostIPAddress, vppNode.Name))
			continue
		}

		if pod != podPtr {
			// There is a different pod under this pod's name in node's database...
			errCnt++
			errString := fmt.Sprintf("pod %s in node's podMap (%+v) is not the same as "+
				"the pod in k8s cache (%+v)", podPtr.Name, podPtr, pod)
			v.Report.AppendToNodeReport(vppNode.Name, errString)
			continue
		}

		k8sNode, err := v.K8sCache.RetrieveK8sNode(vppNode.Name)
		if err != nil {
			// K8s does not know about the node where Contiv thinks that the
			// pod is hosted
			errCnt++
			errString := fmt.Sprintf("pods'%s': vppNode '%s' hosting the pod not in K8s database",
				pod.Name, vppNode.Name)
			v.Report.AppendToNodeReport(vppNode.Name, errString)
			continue
		}

		// Make sure that K8s view of the Pod's host IP address and host name
		// are consistent with Contiv's view
		for _, adr := range k8sNode.Addresses {
			switch adr.Type {
			case nodemodel.NodeAddress_NodeInternalIP:
				if adr.Address != pod.HostIPAddress {
					errCnt++
					errString := fmt.Sprintf("pod '%s:' Host IP Addr '%s' does not match NodeInternalIP "+
						"'%s' in K8s database", pod.Name, pod.HostIPAddress, adr.Address)
					v.Report.AppendToNodeReport(vppNode.Name, errString)
				}
			case nodemodel.NodeAddress_NodeHostName:
				if adr.Address != vppNode.Name {
					errCnt++
					errString := fmt.Sprintf("pod '%s': Node name %s does not match NodeHostName %s"+
						"in K8s database", pod.Name, vppNode.Name, adr.Address)
					v.Report.AppendToNodeReport(vppNode.Name, errString)
				}
			default:
				errCnt++
				errString := fmt.Sprintf("pod '%s:' unknown address type %+v", pod.Name, adr)
				v.Report.AppendToNodeReport(vppNode.Name, errString)
			}
		}

		// Skip over host-network pods
		if pod.IPAddress == pod.HostIPAddress {
			continue
		}

		// Get Contiv's view of the VPP's pod-facing tap interface subnet CIDR
		// on this node (PodVPPSubnetCIDR)
		if vppNode.NodeIPam == nil {
			errCnt++
			v.Log.Infof("No IPAM data for node %s", vppNode.Name)
			errString := fmt.Sprintf("pod %s not validated - no IPAM data available for node", pod.Name)
			v.Report.AppendToNodeReport(vppNode.Name, errString)
			continue
		}

		podIfIPAddr, podIfIPMask, err := utils.Ipv4CidrToAddressAndMask(vppNode.NodeIPam.Config.PodVPPSubnetCIDR)
		if err != nil {
			errCnt++
			errString := fmt.Sprintf("pod '%s': invalid IPAM PodVPPSubnetCIDR %s",
				pod.Name, vppNode.NodeIPam.Config.PodVPPSubnetCIDR)
			v.Report.AppendToNodeReport(k8sNode.Name, errString)
			continue
		}
		podIfIPPrefix := podIfIPAddr &^ podIfIPMask

		// Populate Pod's VPP interface data (IP addresses, interface name and
		// ifIndex)
		podMap[pod.Name] = vppNode.Name
		podAddr, err := utils.Ipv4ToUint32(pod.IPAddress)
		if err != nil {
			errCnt++
			errString := fmt.Sprintf("pod'%s': invalid pod IP address '%s'",
				pod.Name, pod.IPAddress)
			v.Report.AppendToNodeReport(k8sNode.Name, errString)
			continue
		}
		podAddrSuffix := podAddr & podIfIPMask

		// Find the VPP tap interface for the pod. The interface must be on
		// the PodVPPSubnetCIDR subnet and the bottom part of its address must be
		// the same as the bottom part of the pod's IP address.
		for _, intf := range vppNode.NodeInterfaces {
			if intf.Value.Type == interfaces.Interface_TAP {
				for _, ip := range intf.Value.IpAddresses {
					ifIPAddr, iffIPMask, err := utils.Ipv4CidrToAddressAndMask(ip)
					if err != nil {
						errCnt++
						errString := fmt.Sprintf("bad IP address %s on pod-facing tap interface %s",
							ip, intf.Value.Name)
						v.Report.AppendToNodeReport(k8sNode.Name, errString)
						continue
					}

					if iffIPMask != 0 {
						continue
					}

					ifIPAdrPrefix := ifIPAddr &^ podIfIPMask
					ifIPAdrSuffix := ifIPAddr & podIfIPMask
					if (podIfIPPrefix == ifIPAdrPrefix) && (ifIPAdrSuffix == podAddrSuffix) {
						pod.VppIfIPAddr = ip
						pod.VppIfName = intf.Value.Name
						pod.VppSwIfIdx = intf.Metadata.SwIfIndex

						// Mark both the pod and the tap interface as valid
						delete(podMap, pod.Name)
						delete(tapMap[vppNode.Name], intf.Metadata.SwIfIndex)
					}
				}
			}
		}

		if len(k8sNode.Pod_CIDR) > 0 {
			// Get K8s's view of the Pod's CIDR on this node
			_, k8sMask, err := utils.Ipv4CidrToAddressAndMask(k8sNode.Pod_CIDR)
			if err != nil {
				errCnt++
				errString := fmt.Sprintf("pod '%s': invalid Pod_CIDR %s", pod.Name, k8sNode.Pod_CIDR)
				v.Report.AppendToNodeReport(k8sNode.Name, errString)
				continue
			}

			// Make sure the VPP-side CIDR mask and K8s-side CIDR mask are the same
			if k8sMask != podIfIPMask {
				errCnt++
				errString := fmt.Sprintf("pod '%s': CIDR mask mismatch: K8s Pod CIDR: %s, Contiv PodVPPSubnetCIDR %s",
					pod.Name, k8sNode.Pod_CIDR, vppNode.NodeIPam.Config.PodVPPSubnetCIDR)
				v.Report.AppendToNodeReport(k8sNode.Name, errString)
				continue
			}
		}
	}

	for podName, nodeName := range podMap {
		errCnt++
		errString := fmt.Sprintf("pod '%s': no valid VPP tap interface found for the pod", podName)
		v.Report.AppendToNodeReport(nodeName, errString)
	}

	for _, node := range v.VppCache.RetrieveAllNodes() {
		for ifIdx, intf := range tapMap[node.Name] {
			errCnt++
			errString := fmt.Sprintf("dangling pod-facing tap interface '%s' (ifIndex %d)",
				intf.Value.Name, ifIdx)
			v.Report.AppendToNodeReport(node.Name, errString)
		}
	}

	v.addSummary(errCnt)
}

// createTapMarkAndSweepDB creates a database (db) used to detect dangling
// pod-facing tap interfaces. It contains a per-node set of pod-facing tap
// interfaces. Only interfaces with at least one address in the PodVPPSubnetCIDR
// subnet are placed in this DB. The validation algorithm will remove each
// valid tap interface from this DB, only leaving those for which a valid
// pod could not be found
func (v *Validator) createTapMarkAndSweepDB() map[string]map[uint32]telemetrymodel.NodeInterface {
	tapMap := make(map[string]map[uint32]telemetrymodel.NodeInterface, 0)

	for _, node := range v.VppCache.RetrieveAllNodes() {
		tapMap[node.Name] = make(map[uint32]telemetrymodel.NodeInterface, 0)

		if node.NodeIPam == nil {
			v.Log.Infof("No IPAM data for node %s", node.Name)
			v.Report.AppendToNodeReport(node.Name, "no IPAM data available")
			continue
		}

		podIfIPAddress, podIfIPMask, err := utils.Ipv4CidrToAddressAndMask(node.NodeIPam.Config.PodVPPSubnetCIDR)
		if err != nil {
			errString := fmt.Sprintf("invalid PodVPPSubnetCIDR - %s", node.NodeIPam.Config.PodVPPSubnetCIDR)
			v.Report.AppendToNodeReport(node.Name, errString)
			continue
		}
		podIfIPPrefix := podIfIPAddress &^ podIfIPMask

		for _, intf := range node.NodeInterfaces {
			if intf.Value.Type == interfaces.Interface_TAP {
				for _, ip := range intf.Value.IpAddresses {
					ifIPAddr, ifIPMask, err := utils.Ipv4CidrToAddressAndMask(ip)
					if (err != nil) || (ifIPMask != 0) {
						continue
					}

					if podIfIPPrefix == (ifIPAddr &^ podIfIPMask) {
						tapMap[node.Name][intf.Metadata.SwIfIndex] = intf
					}
				}
			}
		}
	}

	return tapMap
}

func (v *Validator) addSummary(errCnt int) {
	if errCnt == 0 {
		v.Report.AppendToNodeReport(api.GlobalMsg, fmt.Sprintf("validation OK"))
	} else {
		v.Report.AppendToNodeReport(api.GlobalMsg,
			fmt.Sprintf("%d error%s found", errCnt, printS(errCnt)))
	}
}

func printS(errCnt int) string {
	if errCnt > 0 {
		return "s"
	}
	return ""
}

func getVxlanBD(node *telemetrymodel.Node) (int, error) {
	for bdomainIdx, bdomain := range node.NodeBridgeDomains {
		if bdomain.Bd.Name == "vxlanBD" {
			return bdomainIdx, nil
		}
	}
	return 0, fmt.Errorf("vxlanBD not found")
}

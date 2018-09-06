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
	"github.com/contiv/vpp/plugins/crd/api"
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/contiv/vpp/plugins/crd/datastore"
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/vpp-agent/plugins/vpp/model/interfaces"
	"strconv"
	"strings"
)

// Validator is the implementation of the ContivTelemetryProcessor interface.
type Validator struct {
	Log logging.Logger

	VppCache api.VppCache
	K8sCache api.K8sCache
	Report   api.Report
}

// Validate performes the validation of L2 telemetry data collected from a
// Contiv cluster.
func (v *Validator) Validate() {
	v.ValidateArpTables()
	v.ValidateBridgeDomains()
	v.ValidateL2FibEntries()
	v.ValidateK8sNodeInfo()
	v.ValidatePodInfo()
}

// ValidateArpTables validates the the entries of node ARP tables to
// make sure that the number of entries is correct as well as making sure
// that each entry's ip address and mac address correspond to the correct
// node in the network.
func (v *Validator) ValidateArpTables() {
	errCnt := 0
	nodeList := v.VppCache.RetrieveAllNodes()

	for _, node := range nodeList {

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

			arpIf, ok := node.NodeInterfaces[int(arpTableEntry.AeMeta.IfIndex)]
			if !ok {
				errString := fmt.Sprintf("invalid ARP entry <'%s'-'%s'>: bad ifIndex %d",
					arpTableEntry.Ae.PhysAddress, arpTableEntry.Ae.IPAddress, arpTableEntry.AeMeta.IfIndex)
				v.Report.AppendToNodeReport(node.Name, errString)
				errCnt++
				continue
			}

			// skip over ARP entries for all interfaces other than Vxlan BVI
			if arpIf.If.IfType != interfaces.InterfaceType_SOFTWARE_LOOPBACK || arpIf.If.Name != "vxlanBVI" {
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

	v.addSummary(errCnt, "IP ARP")
}

//ValidateBridgeDomains makes sure that each node in the cache has the right
// number of vxlan_tunnels for the number of nodes as well as checking that
// each vxlan_tunnel points to a node that has a corresponding but opposite
// tunnel itself.
func (v *Validator) ValidateBridgeDomains() {
	errCnt := 0
	nodeList := v.VppCache.RetrieveAllNodes()

	nodeMap := make(map[string]bool)
	for _, node := range nodeList {
		nodeMap[node.Name] = true
	}

validateNodeBD:
	for _, node := range nodeList {
		nodeVxlanMap := make(map[string]bool)
		for _, n := range nodeList {
			nodeVxlanMap[n.Name] = true
		}

		// Validate that there is exactly one bridge domain with the name vxlanBD
		var vxLanBD *telemetrymodel.NodeBridgeDomain

		for _, bdomain := range node.NodeBridgeDomains {
			if bdomain.Bd.Name == "vxlanBD" {
				if vxLanBD != nil {
					errString := fmt.Sprintf("multiple vxlanBD bridge domains - skipping L2 validation")
					errCnt++
					v.Report.AppendToNodeReport(node.Name, errString)
					continue validateNodeBD
				}
				vxLanBD = &bdomain
			}
		}

		if vxLanBD == nil {
			errCnt++
			errString := fmt.Sprintf("no vxlan BD - skipping L2 validation")
			v.Report.AppendToNodeReport(node.Name, errString)
			continue
		}

		i := 0
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
			nodeIfc, ok := node.NodeInterfaces[int(ifIndex)]
			if !ok {
				errCnt++
				errString := fmt.Sprintf("ifIndex %d invalid for BD interface %s", ifIndex, bdIfc.Name)
				v.Report.AppendToNodeReport(node.Name, errString)
				continue
			}

			if bdIfc.BVI {
				// check for duplicate BVIs (there must be only one BVI per BD)
				if hasBviIfc {
					errCnt++
					errString := fmt.Sprintf("duplicate BVI, type %+v, BVI %s (ifIndex %d, ifName %s)",
						nodeIfc.If.IfType, bdIfc.Name, ifIndex, nodeIfc.If.Name)
					v.Report.AppendToNodeReport(node.Name, errString)
				}

				// BVI must be a software loopback interface
				if nodeIfc.If.IfType != interfaces.InterfaceType_SOFTWARE_LOOPBACK {
					errCnt++
					errString := fmt.Sprintf("invalid BVI type %+v, BVI %s (ifIndex %d, ifName %s)",
						nodeIfc.If.IfType, bdIfc.Name, ifIndex, nodeIfc.If.Name)
					v.Report.AppendToNodeReport(node.Name, errString)
					continue
				}

				hasBviIfc = true
				i++

				if n, err := v.VppCache.RetrieveNodeByLoopMacAddr(nodeIfc.If.PhysAddress); err != nil {
					errCnt++
					errString := fmt.Sprintf("validator internal error: bad MAC Addr index, "+
						"MAC Addr %s, BVI %s (ifIndex %d, ifName %s)",
						nodeIfc.If.PhysAddress, bdIfc.Name, ifIndex, nodeIfc.If.Name)
					v.Report.AppendToNodeReport(node.Name, errString)
					continue
				} else {
					delete(nodeVxlanMap, n.Name)
				}
			} else {
				// Make sure that the type of a regular BD interface is VXLAN_tunnel interface
				if nodeIfc.If.IfType != interfaces.InterfaceType_VXLAN_TUNNEL {
					errCnt++
					errString := fmt.Sprintf("invalid BD interface type %+v, BVI %s (ifIndex %d, ifName %s)",
						nodeIfc.If.IfType, bdIfc.Name, ifIndex, nodeIfc.If.Name)
					v.Report.AppendToNodeReport(node.Name, errString)
					continue
				}

				// Make sure the VXLAN tunnel's VNI is correct (value '10')
				if nodeIfc.If.Vxlan.Vni != api.VppVNI {
					errCnt++
					errString := fmt.Sprintf("bad VNI for %s (%s): got %d, expected %d",
						node.NodeInterfaces[int(ifIndex)].If.Name,
						node.NodeInterfaces[int(ifIndex)].IfMeta.VppInternalName,
						node.NodeInterfaces[int(ifIndex)].If.Vxlan.Vni,
						api.VppVNI)
					v.Report.AppendToNodeReport(node.Name, errString)
				}

				// Make sure the VXLAN's tunnel source IP address points to the current node.
				srcIPNode, err := v.VppCache.RetrieveNodeByGigEIPAddr(nodeIfc.If.Vxlan.SrcAddress)
				if err != nil {
					errCnt++
					errString := fmt.Sprintf("error finding node with src IP %s",
						nodeIfc.If.Vxlan.SrcAddress)
					v.Report.AppendToNodeReport(node.Name, errString)
					continue
				}

				if srcIPNode.Name != node.Name {
					errCnt++
					errString := fmt.Sprintf("vxlan_tunnel %s has source ip %s which points "+
						"to a different node than %s.",
						nodeIfc.If.Name, nodeIfc.If.Vxlan.SrcAddress, node.Name)
					v.Report.AppendToNodeReport(node.Name, errString)
					continue
				}

				// Try to find node with dst ip address in tunnel and validate
				// it has a vxlan_tunnel that is the opposite of the current
				// vxlan_tunnel and increment the counter if it does.
				dstipNode, err := v.VppCache.RetrieveNodeByGigEIPAddr(nodeIfc.If.Vxlan.DstAddress)
				if err != nil {
					errCnt++
					errString := fmt.Sprintf("node with dst ip %s in vxlan_tunnel %s not found",
						nodeIfc.If.Vxlan.DstAddress, nodeIfc.If.Name)
					v.Report.AppendToNodeReport(node.Name, errString)
					continue
				}

				matchingTunnelFound := false
				for _, dstIntf := range dstipNode.NodeInterfaces {
					if dstIntf.If.IfType == nodeIfc.If.IfType {
						if dstIntf.If.Vxlan.DstAddress == nodeIfc.If.Vxlan.SrcAddress {
							matchingTunnelFound = true
						}
					}
				}

				if !matchingTunnelFound {
					errCnt++
					errString := fmt.Sprintf("no matching vxlan_tunnel found on remote node %s for vxlan %s",
						dstipNode.Name, nodeIfc.If.Name)
					v.Report.AppendToNodeReport(node.Name, errString)
				}
				i++

				dstAddr := node.NodeInterfaces[int(ifIndex)].If.Vxlan.DstAddress
				if n1, err := v.VppCache.RetrieveNodeByGigEIPAddr(dstAddr); err == nil {
					delete(nodeVxlanMap, n1.Name)
				} else {
					errCnt++
					v.Report.LogErrAndAppendToNodeReport(n1.Name,
						fmt.Sprintf("validator internal error: inconsistent GigE Address index, dest addr %s",
							dstAddr))
				}
			}
		}

		//checks if there are an unequal amount vxlan tunnels for the current node versus the total number of nodes
		if i != len(nodeList) {
			errCnt++
			errString := fmt.Sprintf("the number of valid BD interfaces does not match the number of nodes "+
				"in cluster: got %d, expected %d", i, len(nodeList))
			v.Report.AppendToNodeReport(node.Name, errString)
		}

		if !hasBviIfc {
			errCnt++
			errString := fmt.Sprintf("BVI in the Contiv cluster Vxlan BD is invalid or missing")
			v.Report.AppendToNodeReport(node.Name, errString)
			continue
		}
		if len(nodeVxlanMap) > 0 {
			for n := range nodeVxlanMap {
				errCnt++
				errString := fmt.Sprintf("BD interface missing or invalid for node %s", n)
				v.Report.AppendToNodeReport(node.Name, errString)
			}
			continue
		}

		delete(nodeMap, node.Name)
	}

	//make sure that each node has been successfully validated
	if len(nodeMap) > 0 {
		for nodeName := range nodeMap {
			v.Report.AppendToNodeReport(nodeName, fmt.Sprintf("failed to validate the Contiv cluster Vxlan BD"))
		}
	}

	v.addSummary(errCnt, "BD")
}

// ValidateL2FibEntries will validate that each nodes fib entries ip address
// point to the right loop interface and the mac addresses match
func (v *Validator) ValidateL2FibEntries() {
	errCnt := 0
	nodeList := v.VppCache.RetrieveAllNodes()

	for _, node := range nodeList {
		fibHasLoopIF := false
		vxLanBD, err := getVxlanBD(node)
		if err != nil {
			errCnt++
			errString := fmt.Sprintf("%s - skipping L2Fib validation for node %s", err.Error(), node.Name)
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
					if feVal.Fe.PhysAddress != loopIf.If.PhysAddress {
						errCnt++
						errString := fmt.Sprintf("L2Fib BVI entry '%s' invalid - bad MAC address; "+
							"have '%s', expecting '%s'", feKey, feVal.Fe.PhysAddress, loopIf.If.PhysAddress)
						v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
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
					v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
				}

				delete(fibNodeMap, feKey)
				delete(nodeFibMap, node.Name)
			} else {
				// Validate remote node (VXLAN) L2FIB entry

				// Make sure the outgoing interface in the L2FIB entry exists
				intf, ok := node.NodeInterfaces[int(feVal.FeMeta.OutgoingIfIndex)]
				if !ok {
					errCnt++
					errString := fmt.Sprintf("outgoing interface for L2Fib entry '%s' not found ifName %s, "+
						"ifIndex %d", feVal.Fe.PhysAddress, feVal.Fe.OutgoingIfName, feVal.FeMeta.OutgoingIfIndex)
					v.Report.AppendToNodeReport(node.Name, errString)
					continue
				}

				// Lookup the remote node by the destination address in the VXLAN interface
				macNode, err := v.VppCache.RetrieveNodeByGigEIPAddr(intf.If.Vxlan.DstAddress)
				if err != nil {
					errCnt++
					errString := fmt.Sprintf("invalid L2Fib entry '%s': "+
						"remote node for VXLAN DstIP '%s' not found", feKey, intf.If.Vxlan.DstAddress)
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
				if remoteLoopIF.If.PhysAddress != feVal.Fe.PhysAddress {
					errCnt++
					errString := fmt.Sprintf("invalid L2Fib entry '%s': have MAC Address '%s', expecting %s",
						feKey, feVal.Fe.PhysAddress, remoteLoopIF.If.PhysAddress)
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
			errString := fmt.Sprintf("L2Fib entry for the 'loop0' interface not found")
			v.Report.AppendToNodeReport(node.Name, errString)
		}

		// Show all nodes for which there is no L2FIB entry
		for remoteNodeName := range nodeFibMap {
			errCnt++
			errString := fmt.Sprintf("missing L2Fib entry for node %s", remoteNodeName)
			v.Report.LogErrAndAppendToNodeReport(node.Name, errString)
		}

		// Show all L2Fib entrie for which there is no node
		for fibEntry := range fibNodeMap {
			errCnt++
			errString := fmt.Sprintf("dangling L2Fib entry %s - no node for entry found", fibEntry)
			v.Report.AppendToNodeReport(node.Name, errString)
		}
	}

	v.addSummary(errCnt, "L2Fib")
}

// ValidateK8sNodeInfo will make sure that K8s's view of nodes in the cluster
// is consistent with Contiv's view of nodes in the cluster. Each node in K8s
// database must have a counterpart node in the Contiv database and vice versa.
func (v *Validator) ValidateK8sNodeInfo() {
	errCnt := 0
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
			errString := fmt.Sprintf("node with name %s not present in the k8s node map", node.Name)
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
			v.Report.AppendToNodeReport(k8sNode, fmt.Sprintf("Contiv node missing for K8s node %s", k8sNode))
		}
	}

	if len(nodeMap) > 0 {
		errCnt++
		for contivNode := range nodeMap {
			v.Report.AppendToNodeReport(contivNode, fmt.Sprintf("K8s node missing for Contiv node %s", contivNode))
		}
	}

	v.addSummary(errCnt, "K8sNode")
}

// ValidatePodInfo will check  that each pod has a valid host ip address node
// and that the information correctly correlates between the nodes and the pods.
func (v *Validator) ValidatePodInfo() {
	errCnt := 0
	podList := v.K8sCache.RetrieveAllPods()
	podMap := make(map[string]string)

	for _, pod := range podList {
		// Check if we have a vppNode with the Host IP address that K8s specifies
		// for the Pod
		vppNode, err := v.VppCache.RetrieveNodeByHostIPAddr(pod.HostIPAddress)
		if err != nil {
			errCnt++
			errString := fmt.Sprintf("vppNode not found for Pod %s with Host IP %s - skipping Pod validation",
				pod.Name, pod.HostIPAddress)
			v.Report.AppendToNodeReport(api.GlobalMsg, errString)
			continue
		}

		podPtr, ok := vppNode.PodMap[pod.Name]
		if !ok {
			errCnt++
			v.Report.AppendToNodeReport(vppNode.Name, fmt.Sprintf("pod %s's IP address (%s) points to node %s, "+
				"but pod is not present in node's podMap", pod.Name, pod.HostIPAddress, vppNode.Name))
			continue
		}

		if pod != podPtr {
			errCnt++
			errString := fmt.Sprintf("pod %s in node's podMap (%+v) is not the same as "+
				"the pod in k8s cache (%+v)", podPtr.Name, podPtr, pod)
			v.Report.AppendToNodeReport(vppNode.Name, errString)
			continue
		}

		k8sNode, err := v.K8sCache.RetrieveK8sNode(vppNode.Name)
		if err != nil {
			errCnt++
			errString := fmt.Sprintf("vppNode '%s' hosting pod '%s' not in K8s database",
				vppNode.Name, pod.Name)
			v.Report.LogErrAndAppendToNodeReport(vppNode.Name, errString)
			continue
		}

		// Make sure that K8s view of the Pod's host IP address and host name
		// are consistent with Contiv's view
		for _, adr := range k8sNode.Addresses {
			switch adr.Type {
			case nodemodel.NodeAddress_NodeInternalIP:
				if adr.Address != pod.HostIPAddress {
					errCnt++
					errString := fmt.Sprintf("pod %s: Host IP Addr '%s' does not match NodeInternalIP "+
						"'%s' in K8s database", pod.Name, pod.HostIPAddress, adr.Address)
					v.Report.AppendToNodeReport(vppNode.Name, errString)
				}
			case nodemodel.NodeAddress_NodeHostName:
				if adr.Address != vppNode.Name {
					errCnt++
					errString := fmt.Sprintf("pod %s: Node name %s does not match NodeHostName %s"+
						"in K8s database", pod.Name, vppNode.Name, adr.Address)
					v.Report.AppendToNodeReport(vppNode.Name, errString)
				}
			default:
				errCnt++
				errString := fmt.Sprintf("pod %s: unknown address type %+v", pod.Name, adr)
				v.Report.AppendToNodeReport(vppNode.Name, errString)
			}
		}

		// Skip over host-network pods
		if pod.IPAddress == pod.HostIPAddress {
			continue
		}

		str := strings.Split(k8sNode.Pod_CIDR, "/")
		mask := str[1]
		i, err := strconv.Atoi(mask)
		if err != nil {
			errCnt++
			errString := fmt.Sprintf("invalid Pod_CIDR %s", k8sNode.Pod_CIDR)
			v.Report.AppendToNodeReport(k8sNode.Name, errString)
		}

		bitmask := MaskLength2Mask(i)

		// Populate Pod's VPP interface data (IP addresses, interface name and
		// ifIndex)
		podMap[pod.Name] = vppNode.Name
		for _, intf := range vppNode.NodeInterfaces {
			if strings.Contains(intf.IfMeta.VppInternalName, "tap") {
				for _, ip := range intf.If.IPAddresses {
					ipAddr := strings.Split(ip, "/")
					podIP := ip2uint32(pod.IPAddress)
					tapIP := ip2uint32(ipAddr[0])
					if (podIP & bitmask) == (tapIP & bitmask) {
						pod.VppIfIPAddr = ip
						pod.VppIfInternalName = intf.IfMeta.VppInternalName
						pod.VppIfName = intf.If.Name
						pod.VppSwIfIdx = intf.IfMeta.SwIfIndex
						delete(podMap, pod.Name)
					}
				}
			}
		}
	}

	for podName, nodeName := range podMap {
		errCnt++
		errString := fmt.Sprintf("no valid VPP tap interface found for pod %s", podName)
		v.Report.AppendToNodeReport(nodeName, errString)
	}

	v.addSummary(errCnt, "K8sPod")
}

func (v *Validator) addSummary(errCnt int, kind string) {
	if errCnt == 0 {
		v.Report.AppendToNodeReport(api.GlobalMsg, fmt.Sprintf("%s validation: OK", kind))
	} else {
		v.Report.AppendToNodeReport(api.GlobalMsg,
			fmt.Sprintf("%s validation: %d error%s found", kind, errCnt, printS(errCnt)))
	}
}

func getVxlanBD(node *telemetrymodel.Node) (int, error) {
	for bdomainIdx, bdomain := range node.NodeBridgeDomains {
		if bdomain.Bd.Name == "vxlanBD" {
			return bdomainIdx, nil
		}
	}
	return 0, fmt.Errorf("vxlanBD not found")
}

//Mask Length will tank in an int and return the bit mask for the number given
func MaskLength2Mask(ml int) uint32 {
	var mask uint32
	for i := 0; i < 32-ml; i++ {
		mask = mask << 1
		mask++
	}
	return mask
}

func ip2uint32(ipAddress string) uint32 {
	var ipu uint32
	parts := strings.Split(ipAddress, ".")
	for _, p := range parts {
		// num, _ := strconv.ParseUint(p, 10, 32)
		num, _ := strconv.Atoi(p)
		ipu = (ipu << 8) + uint32(num)
		//fmt.Printf("%d: num: 0x%x, ipu: 0x%x\n", i, num, ipu)
	}
	return ipu
}

func printS(errCnt int) string {
	if errCnt > 1 {
		return "s"
	}
	return ""
}

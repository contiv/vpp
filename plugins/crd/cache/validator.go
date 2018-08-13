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

package cache

import (
	"fmt"
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/ligato/vpp-agent/plugins/vpp/model/interfaces"
	"github.com/pkg/errors"
	"strconv"
	"strings"
)

const (
	globalMsg = "global"
)

type Processor interface {
	Validate()
}

type Validator struct {
	Deps

	VppCache VppCache
	K8sCache K8sCache
	Report   Report
}

func (v *Validator) Validate() {
	v.ValidateArpTables()
	v.ValidateL2Connectivity()
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
			if !arpTableEntry.Static {
				continue
			}

			arpIf, ok := node.NodeInterfaces[int(arpTableEntry.Interface)]
			if !ok {
				errString := fmt.Sprintf("ARP Table entry %+v: interface with ifIndex not found", arpTableEntry)
				v.Report.appendToNodeReport(node.Name, errString)
				errCnt++
				continue
			}

			if arpIf.IfType != interfaces.InterfaceType_SOFTWARE_LOOPBACK || arpIf.Name != "vxlanBVI" {
				continue
			}

			addressNotFound := false
			macNode, err := v.VppCache.RetrieveNodeByLoopMacAddr(arpTableEntry.MacAddress)
			if err != nil {
				errString := fmt.Sprintf("ARP Table entry %+v: no remote node for MAC Address", arpTableEntry)
				v.Report.appendToNodeReport(node.Name, errString)
				addressNotFound = true
				errCnt++
			}
			ipNode, err := v.VppCache.RetrieveNodeByLoopIPAddr(arpTableEntry.IPAddress + "/24")

			if err != nil {
				errString := fmt.Sprintf("ARP Table entry %+v: no remote node for IP Address", arpTableEntry)
				v.Report.appendToNodeReport(node.Name, errString)
				addressNotFound = true
				errCnt++
			}

			if addressNotFound {
				continue
			}

			if macNode.Name != ipNode.Name {
				errString := fmt.Sprintf("ARP Table entry %+v: MAC -> node %s, IP -> nodes %s",
					arpTableEntry, macNode.Name, ipNode.Name)
				v.Report.appendToNodeReport(node.Name, errString)
				errCnt++
			}

			delete(loopNodeMap, ipNode.Name)
		}

		for nodeName := range loopNodeMap {
			v.Report.appendToNodeReport(nodeName, fmt.Sprintf("ARP Table: No MAC entry  for node %s", node.Name))
			errCnt++
		}
	}
	if errCnt == 0 {
		v.Report.appendToNodeReport(globalMsg, fmt.Sprintf("ARP Table Validation: OK"))
	} else {
		v.Report.appendToNodeReport(globalMsg, fmt.Sprintf("ARP Table Validation: %d errors found", errCnt))
	}
}

//ValidateL2Connectivity makes sure that each node in the cache has the right
// number of vxlan_tunnels for the number of nodes as well as checking that
// each vxlan_tunnel points to a node that has a corresponding but opposite
// tunnel itself.
func (v *Validator) ValidateL2Connectivity() {
	nodeList := v.VppCache.RetrieveAllNodes()

	nodeMap := make(map[string]bool)
	for _, node := range nodeList {
		nodeMap[node.Name] = true
	}

	for _, node := range nodeList {
		nodeVxlanMap := make(map[string]bool)
		for _, n := range nodeList {
			nodeVxlanMap[n.Name] = true
		}

		bdHasLoopIF := false
		hasVXLanBD := false
		var vxLanBD telemetrymodel.NodeBridgeDomain
		//Make sure there is a bridge domain with the name vxlanBD
		vxlanBDCount := 0
		for _, bdomain := range node.NodeBridgeDomains {
			if bdomain.Name == "vxlanBD" {
				vxLanBD = bdomain
				hasVXLanBD = true
				vxlanBDCount++
			}
		}
		if vxlanBDCount > 1 {
			errString := fmt.Sprintf("Node %+v has multiple vxlanBD bridge domains", node.Name)
			v.Report.appendToNodeReport(node.Name, errString)
			continue
		}
		//if there is not then Report an error and move on.
		if !hasVXLanBD {
			errString := fmt.Sprintf("Node %+v does not have a vxlan BD", node.Name)
			v.Report.appendToNodeReport(node.Name, errString)
			continue
		}
		//Create a list with each of the indices of the xvlanBD.
		bDomainIdxs := make([]uint32, 0)
		for _, intf := range vxLanBD.Interfaces {
			bDomainIdxs = append(bDomainIdxs, intf.SwIfIndex)
		}

		i := 0
		//for each index in the vxlanBD
		for _, intfidx := range bDomainIdxs {
			//check if one of the indices point to the loop interface
			//if it does, increment a counter and set a boolean to true
			intfidxInterface, ok := node.NodeInterfaces[int(intfidx)]
			if !ok {
				errString := fmt.Sprintf("BD index %d for node %s does not point to a valid interface",
					intfidx, node.Name)
				v.Report.appendToNodeReport(node.Name, errString)
				continue

			}

			// Check if we have a lopp0 interface - there must be exactly one
			if intfidxInterface.IfType == interfaces.InterfaceType_SOFTWARE_LOOPBACK {
				bdHasLoopIF = true
				i++
				macAddr := node.NodeInterfaces[int(intfidx)].PhysAddress
				if n, err := v.VppCache.RetrieveNodeByLoopMacAddr(macAddr); err == nil {
					delete(nodeVxlanMap, n.Name)
				} else {
					v.Report.appendToNodeReport(node.Name,
						fmt.Sprintf("validator internal error: inconsistent MadAddress index, MAC %s",
							macAddr))
				}
				continue
			}

			// Check if one of the indices points to a vxlan_tunnel interface
			if intfidxInterface.IfType == interfaces.InterfaceType_VXLAN_TUNNEL {
				if node.NodeInterfaces[int(intfidx)].Vxlan.Vni != vppVNI {
					errString := fmt.Sprintf("unexpected VNI for node %+v: got %+v expected %+v",
						node.Name, node.NodeInterfaces[int(intfidx)].Vxlan.Vni, vppVNI)
					v.Report.appendToNodeReport(node.Name, errString)
					continue
				}

				vxlantun := node.NodeInterfaces[int(intfidx)]
				srcipNode, err := v.VppCache.RetrieveNodeByGigEIPAddr(vxlantun.Vxlan.SrcAddress + subnetmask)

				// Try to find node with src ip address of the tunnel and make
				// sure it is the same as the current node.
				if err != nil {
					errString := fmt.Sprintf("Error finding node with src IP %s",
						vxlantun.Vxlan.SrcAddress)
					v.Report.appendToNodeReport(node.Name, errString)
					continue
				}

				if srcipNode.Name != node.Name {
					errString := fmt.Sprintf("vxlan_tunnel %s has source ip %s which points "+
						"to a different node than %s.",
						vxlantun.Name, vxlantun.Vxlan.SrcAddress, node.Name)
					v.Report.appendToNodeReport(node.Name, errString)
					continue
				}

				// Try to find node with dst ip address in tunnel and validate
				// it has a vxlan_tunnel that is the opposite of the current
				// vxlan_tunnel and increment the counter if it does.
				dstipNode, err := v.VppCache.RetrieveNodeByGigEIPAddr(vxlantun.Vxlan.DstAddress + subnetmask)
				if err != nil {
					errString := fmt.Sprintf("Node with dst ip %s in vxlan_tunnel %s not found",
						vxlantun.Vxlan.DstAddress, vxlantun.Name)
					v.Report.appendToNodeReport(node.Name, errString)
					continue
				}

				matchingTunnelFound := false
				for _, dstIntf := range dstipNode.NodeInterfaces {
					if dstIntf.IfType == vxlantun.IfType {
						if dstIntf.Vxlan.DstAddress == vxlantun.Vxlan.SrcAddress {
							matchingTunnelFound = true
						}
					}
				}

				if !matchingTunnelFound {
					errString := fmt.Sprintf("no matching vxlan_tunnel found for vxlan %s", vxlantun.Name)
					v.Report.appendToNodeReport(node.Name, errString)
					continue
				}
				i++

				dstAddr := node.NodeInterfaces[int(intfidx)].Vxlan.DstAddress
				if n1, err := v.VppCache.RetrieveNodeByGigEIPAddr(dstAddr + subnetmask); err == nil {
					delete(nodeVxlanMap, n1.Name)
				} else {
					v.Report.logErrAndAppendToNodeReport(n1.Name,
						fmt.Sprintf("validator internal error: inconsistent GigE Address index, dest addr %s",
							dstAddr))
				}
			}
		}

		//checks if there are an unequal amount vxlan tunnels for the current node versus the total number of nodes
		if i != len(nodeList) {
			errString := fmt.Sprintf("number of valid vxlan tunnels for node %+v does "+
				"not match number of nodes on network: got %+v, expected %+v", node.Name, i, len(nodeList))
			v.Report.appendToNodeReport(node.Name, errString)
		}

		if !bdHasLoopIF {
			errString := fmt.Sprintf("bridge domain %+v has no loop interface",
				node.NodeBridgeDomains)
			v.Report.appendToNodeReport(node.Name, errString)
			continue
		}
		if len(nodeVxlanMap) > 0 {
			for node := range nodeVxlanMap {
				v.Report.appendToNodeReport(node,
					fmt.Sprintf("vxlan entry missing for node %s", node))
			}
			continue
		}

		delete(nodeMap, node.Name)
	}

	//make sure that each node has been successfully validated
	if len(nodeMap) > 0 {
		for nodeName := range nodeMap {
			v.Report.appendToNodeReport(nodeName, fmt.Sprintf("failed to validate BD info"))
		}
	} else {
		v.Report.appendToNodeReport(globalMsg, "Success validating L2 connectivity")
	}
}

// ValidateL2FibEntries will validate that each nodes fib entries ip address
// point to the right loop interface and the mac addresses match
func (v *Validator) ValidateL2FibEntries() {
	nodeList := v.VppCache.RetrieveAllNodes()

	nodemap := make(map[string]bool)
	for _, node := range nodeList {
		nodemap[node.Name] = true
	}

	for _, node := range nodeList {
		nodeFibMap := make(map[string]bool)
		for _, n := range nodeList {
			nodeFibMap[n.Name] = true
		}

		fibHasLoopIF := false
		if len(node.NodeL2Fibs) != len(nodeList) {
			errString := fmt.Sprintf("Incorrect number of L2 fib entries: %d for node %+v: expecting %d",
				len(node.NodeL2Fibs), node.Name, len(nodeList))
			v.Report.appendToNodeReport(node.Name, errString)
			continue
		}
		loopIf, err := GetNodeLoopIFInfo(node)
		if err != nil {
			v.Report.appendToNodeReport(node.Name, err.Error())
			continue
		}

		fibEntryCount := 0
		var vxLanBD int
		for bdomainIdx, bdomain := range node.NodeBridgeDomains {
			if bdomain.Name == "vxlanBD" {
				vxLanBD = bdomainIdx
				break
			}
		}

		for _, fib := range node.NodeL2Fibs {
			if int(fib.BridgeDomainIdx) != vxLanBD {
				continue
			}

			if fib.PhysAddress == loopIf.PhysAddress {
				fibHasLoopIF = true
				fibEntryCount++
				if n, err := v.VppCache.RetrieveNodeByLoopMacAddr(fib.PhysAddress); err == nil {
					delete(nodeFibMap, n.Name)
				} else {
					v.Report.logErrAndAppendToNodeReport(node.Name,
						fmt.Sprintf("validator internal error: inconsistent MadAddress index, MAC %s",
							fib.PhysAddress))
				}
				continue
			}

			intf := node.NodeInterfaces[int(fib.OutgoingInterfaceSwIfIdx)]
			macNode, err := v.VppCache.RetrieveNodeByGigEIPAddr(intf.Vxlan.DstAddress + subnetmask)
			if err != nil {
				errString := fmt.Sprintf("GigE IP address %s does not exist in gigEIPMap",
					intf.Vxlan.DstAddress)
				v.Report.appendToNodeReport(node.Name, errString)
				continue
			}

			remoteLoopIF, err := GetNodeLoopIFInfo(macNode)
			if err != nil {
				v.Report.appendToNodeReport(node.Name, err.Error())
				continue
			}

			if remoteLoopIF.PhysAddress == fib.PhysAddress {
				if n, err := v.VppCache.RetrieveNodeByLoopMacAddr(fib.PhysAddress); err == nil {
					delete(nodeFibMap, n.Name)
					fibEntryCount++
				} else {
					v.Report.appendToNodeReport(node.Name,
						fmt.Sprintf("validator internal error: inconsistent MAC Address index, MAC %s",
							fib.PhysAddress))
				}
				continue
			} else {
				errString := fmt.Sprintf("Fib MAC %+v is different than actual MAC "+
					"%+v", fib.PhysAddress, remoteLoopIF.PhysAddress)
				v.Report.appendToNodeReport(node.Name, errString)
			}

			if len(nodeFibMap) > 0 {
				errString := fmt.Sprintf("Missing Fib entries for node %+v", node.Name)
				v.Report.logErrAndAppendToNodeReport(node.Name, errString)
				for node := range nodeFibMap {
					v.Report.appendToNodeReport(node, node)
				}
			}
		}

		if !fibHasLoopIF {
			errString := fmt.Sprintf("Fib for node %+v loop interface missing",
				node.Name)
			v.Report.appendToNodeReport(node.Name, errString)
			continue
		}

		if fibEntryCount != len(nodeList) {
			errString := fmt.Sprintf("Unequal amount of fib entries for node %+v",
				node.Name)
			v.Report.appendToNodeReport(node.Name, errString)
		}
		delete(nodemap, node.Name)
	}

	if len(nodemap) > 0 {
		for node := range nodemap {
			errString := fmt.Sprintf("Error processing fib for node %s", node)
			v.Report.appendToNodeReport(node, errString)
		}

	} else {
		v.Report.appendToNodeReport(globalMsg, "Success validating Fib entries")
	}

}

//ValidateK8sNodeInfo will make sure that the cache has the same amount of k8s and etcd nodes and that each node has an
//equal opposite node.
func (v *Validator) ValidateK8sNodeInfo() {
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
			errString := fmt.Sprintf("node with name %s not present in the k8s node map", node.Name)
			v.Report.appendToNodeReport(node.Name, errString)
			continue
		}

		if node.Name == k8sNode.Name {
			delete(nodeMap, node.Name)
			delete(k8sNodeMap, k8sNode.Name)
		}
	}

	if len(k8sNodeMap) > 0 {
		for k8sNode := range k8sNodeMap {
			v.Report.appendToNodeReport(k8sNode, fmt.Sprintf("Contiv node missing for K8s node %s", k8sNode))
		}
	}

	if len(nodeMap) > 0 {
		for contivNode := range nodeMap {
			v.Report.appendToNodeReport(contivNode, fmt.Sprintf("K8s node missing for Contiv node %s", contivNode))
		}
	}
}

//ValidatePodInfo will check to see that each pod has a valid host ip address node and that the information correctly
//correlates between the nodes and the pods.
func (v *Validator) ValidatePodInfo() {

	podList := v.K8sCache.RetrieveAllPods()
	podMap := make(map[string]bool)
	for _, pod := range podList {
		podMap[pod.Name] = true
	}
	for _, pod := range podList {
		node, err := v.VppCache.RetrieveNodeByHostIPAddr(pod.HostIPAddress)
		if err != nil {
			v.Report.appendToNodeReport(globalMsg, fmt.Sprintf("Error finding node for Pod %s with host ip %s",
				pod.Name, pod.HostIPAddress))
			continue
		}

		podPtr, ok := node.PodMap[pod.Name]
		if !ok {
			v.Report.appendToNodeReport(node.Name, fmt.Sprintf("pod %s in node %s podMap not found",
				pod.Name, node.Name))
			continue
		}

		if pod != podPtr {
			errString := fmt.Sprintf("node podmap pod %+v is not the same as cache podmap pod %+v",
				podPtr.Name, pod.Name)
			v.Report.appendToNodeReport(node.Name, errString)
			continue
		}

		k8snode, err := v.K8sCache.RetrieveK8sNode(node.Name)
		if err != nil {
			errString := fmt.Sprintf("cannot find k8snode in k8sNodeMap for node with name %+v",
				node.Name)
			v.Report.logErrAndAppendToNodeReport(node.Name, errString)
			continue
		}

		i := 0
		for _, adr := range k8snode.Addresses {
			if adr.Type == 3 {
				if adr.Address != pod.HostIPAddress {
					errString := fmt.Sprintf("pod host ip %s does not match with k8snode ip %s",
						pod.HostIPAddress, adr.Address)
					v.Report.appendToNodeReport(node.Name, errString)
					continue
				}
				i++
			}
			if adr.Type == 1 {
				if adr.Address != node.Name {
					errString := fmt.Sprintf("pod host name %s does not match node name %s",
						adr.Address, node.Name)
					v.Report.appendToNodeReport(node.Name, errString)
					continue
				}
				i++
			}
		}
		if i != 2 {
			continue
		}
		delete(podMap, pod.Name)
	}

	if len(podMap) > 0 {
		for p := range podMap {
			v.Report.appendToNodeReport(globalMsg, fmt.Sprintf("error processing pod %+v", p))
		}

	} else {
		v.Report.appendToNodeReport(globalMsg, "Success validating pod info.")
	}
}

//ValidateTapToPod will find the appropriate tap interface for each pod and cache that information in the pod.
func (v *Validator) ValidateTapToPod() {
	podList := v.K8sCache.RetrieveAllPods()

	podMap := make(map[string]bool)
	for _, pod := range podList {
		podMap[pod.Name] = true
	}
	for _, pod := range podList {
		vppNode, err := v.VppCache.RetrieveNodeByHostIPAddr(pod.HostIPAddress)
		if err != nil {
			v.Report.logErrAndAppendToNodeReport(globalMsg,
				fmt.Sprintf("validator internal error: inconsistent Host IP Address index, IP %s",
					pod.HostIPAddress))
			continue
		}

		k8sNode, err := v.K8sCache.RetrieveK8sNode(vppNode.Name)
		if err != nil {
			v.Report.logErrAndAppendToNodeReport(vppNode.Name,
				fmt.Sprintf("validator internal error: inconsistent K8s node index, host name %s",
					vppNode.Name))
			continue
		}

		str := strings.Split(k8sNode.Pod_CIDR, "/")
		mask := str[1]
		i, err := strconv.Atoi(mask)
		if err != nil {
			v.Report.appendToNodeReport(k8sNode.Name, fmt.Sprintf("invalid Pod_CIDR %s", k8sNode.Pod_CIDR))
		}
		bitmask := maskLength2Mask(i)
		for _, intf := range vppNode.NodeInterfaces {
			if strings.Contains(intf.VppInternalName, "tap") {
				for _, ip := range intf.IPAddresses {
					podIP := ip2uint32(pod.IPAddress)
					tapIP := ip2uint32(ip)
					if (podIP & bitmask) == (tapIP & bitmask) {
						pod.VppIfIpAddr = ip
						pod.VppIfName = intf.VppInternalName
					}
				}
			}
		}
	}
}

func maskLength2Mask(ml int) uint32 {
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

func GetNodeLoopIFInfo(node *telemetrymodel.Node) (*telemetrymodel.NodeInterface, error) {
	for _, ifs := range node.NodeInterfaces {
		if ifs.VppInternalName == "loop0" {
			return &ifs, nil
		}
	}
	err := errors.Errorf("node %s does not have a loop interface", node.Name)
	return nil, err
}

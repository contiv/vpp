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

package cmdimpl

import (
	"encoding/json"
	"fmt"
	"github.com/contiv/vpp/plugins/contiv/model/node"
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/netctl/http"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/vpp-agent/plugins/vpp/model/interfaces"
	"os"
	"strings"
	"text/tabwriter"
)

type nodeData struct {
	ipam *telemetrymodel.IPamEntry
	ifcs telemetrymodel.NodeInterfaces
}
type nodeDataCache map[string]*nodeData

type podGetter struct {
	ndCache nodeDataCache
	db      *etcd.BytesConnectionEtcd
	pods    []*pod.Pod
}

// PrintAllPods will print out all of the non local pods in a network in
// a table format.
func PrintAllPods() {
	w := getWriter("HOST-NAME")
	pg := newPodGetter()
	pg.printAllPods(w)
	pg.db.Close()
	w.Flush()
}

//PrintPodsPerNode will print out all of the non-local pods for a certain
// pods along with their tap interface ip address
func PrintPodsPerNode(input string) {
	w := getWriter("")
	pg := newPodGetter()
	pg.printPodsPerNode(w, input, "")
	pg.db.Close()
	w.Flush()
}

func newPodGetter() *podGetter {
	pg := &podGetter{
		ndCache: make(nodeDataCache, 0),
		db:      getEtcdBroker(),
	}

	pg.pods = make([]*pod.Pod, 0)
	itr, err := pg.db.ListValues("/vnf-agent/contiv-ksr/k8s/pod/")
	if err != nil {
		fmt.Printf("Failed to get pods from etcd, error %s", err)
		os.Exit(2)
	}

	for {
		kv, stop := itr.GetNext()
		if stop {
			break
		}
		buf := kv.GetValue()
		podInfo := &pod.Pod{}
		if err = json.Unmarshal(buf, podInfo); err != nil {
			fmt.Printf("Failed to unmarshall pod, error %s", err)
			continue
		}
		pg.pods = append(pg.pods, podInfo)
	}

	return pg
}

func (pg *podGetter) printAllPods(w *tabwriter.Writer) {

	itr, err := pg.db.ListValues("/vnf-agent/contiv-ksr/allocatedIDs/")
	if err != nil {
		fmt.Printf("Error getting values")
		return
	}

	for {
		kv, stop := itr.GetNext()
		if stop {
			fmt.Println()
			break
		}
		buf := kv.GetValue()
		nodeInfo := &node.NodeInfo{}
		err = json.Unmarshal(buf, nodeInfo)
		nodeID := fmt.Sprintf("%s (%s):", nodeInfo.Name, nodeInfo.ManagementIpAddress)
		fmt.Fprintf(w, "%s\t\t\t\t\t\t\t\n", nodeID)
		fmt.Fprintf(w, "%s\t\t\t\t\t\t\t\n", strings.Repeat("-", len(nodeID)))

		pg.printPodsPerNode(w, nodeInfo.ManagementIpAddress, nodeInfo.Name)
		fmt.Fprintln(w, "\t\t\t\t\t\t\t\t")
	}
}

func (pg *podGetter) printPodsPerNode(w *tabwriter.Writer, nodeNameOrIP string, nodeName string) {
	hostIP := resolveNodeOrIP(nodeNameOrIP)

	fmt.Fprintf(w, "POD-NAME\tNAMESPACE\tPOD-IP\tVPP-IP\tIF-IDX\tIF-NAME\tINTERNAL-IF-NAME\n")

	for _, podInfo := range pg.pods {
		if podInfo.HostIpAddress != hostIP {
			continue
		} else if podInfo.IpAddress == hostIP {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				podInfo.Name,
				podInfo.Namespace,
				podInfo.IpAddress,
				"", "", "", "")
		} else {
			ipAddress, ifIndex, intName, name := pg.getTapInterfaceForPod(podInfo)
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
				podInfo.Name,
				podInfo.Namespace,
				podInfo.IpAddress,
				strings.Split(ipAddress, "/")[0],
				ifIndex,
				intName,
				name)
		}
	}
}

func (pg *podGetter) getTapInterfaceForPod(podInfo *pod.Pod) (string, uint32, string, string) {
	// when we see a pod from a given node for the first time, retrieve its
	// IPAM and interface info
	if pg.ndCache[podInfo.HostIpAddress] == nil {

		// Get ipam data for the node where the pod is hosted
		b, err := http.GetNodeInfo(podInfo.HostIpAddress, getIpamDataCmd)
		if err != nil {
			fmt.Printf("Host '%s', Pod '%s' - failed to get ipam, err %s\n",
				podInfo.HostIpAddress, podInfo.Name, err)
			return "N/A", 0, "N/A", "N/A"
		}

		ipam := &telemetrymodel.IPamEntry{}
		if err := json.Unmarshal(b, ipam); err != nil {
			fmt.Printf("Host '%s', Pod '%s' - failed to decode ipam, err %s\n",
				podInfo.HostIpAddress, podInfo.Name, err)
			return "N/A", 0, "N/A", "N/A"
		}

		// Get interfaces data for the node where the pod is hosted
		b, err = http.GetNodeInfo(podInfo.HostIpAddress, getInterfaceDataCmd)
		intfs := make(telemetrymodel.NodeInterfaces)
		if err := json.Unmarshal(b, &intfs); err != nil {
			fmt.Printf("Host '%s', Pod '%s' - failed to get pod's interface, err %s\n",
				podInfo.HostIpAddress, podInfo.Name, err)
			return "N/A", 0, "N/A", "N/A"
		}

		pg.ndCache[podInfo.HostIpAddress] = &nodeData{
			ipam: ipam,
			ifcs: intfs,
		}
	}

	// Determine the tap interface on VPP that connects the pod to the VPP
	podPfxLen := pg.ndCache[podInfo.HostIpAddress].ipam.Config.VppHostNetworkPrefixLen
	podMask := maskLength2Mask(int(podPfxLen))

	podIPSubnet, podIPMask, err := getIPAddressAndMask(pg.ndCache[podInfo.HostIpAddress].ipam.Config.PodSubnetCIDR)
	if err != nil {
		fmt.Printf("Host '%s', Pod '%s' - invalid PodSubnetCIDR address %s, err %s\n",
			podInfo.HostIpAddress, podInfo.Name, pg.ndCache[podInfo.HostIpAddress].ipam.Config.PodSubnetCIDR, err)
		// Do not return - we can still continue if this error happens
	}

	if podMask != podIPMask {
		fmt.Printf("Host '%s', Pod '%s' - vppHostNetworkPrefixLen mismatch: "+
			"PodSubnetCIDR '%s', podNetworkPrefixLen '%d'\n",
			podInfo.HostIpAddress, podInfo.Name,
			pg.ndCache[podInfo.HostIpAddress].ipam.Config.PodSubnetCIDR,
			pg.ndCache[podInfo.HostIpAddress].ipam.Config.PodNetworkPrefixLen)
		// Do not return - we can still continue if this error happens
	}

	podIfIPAddress, podIfIPMask, err := getIPAddressAndMask(pg.ndCache[podInfo.HostIpAddress].ipam.Config.PodIfIPCIDR)
	if err != nil {
		fmt.Printf("Host '%s', Pod '%s' - invalid PodIfIPCIDR address %s, err %s\n",
			podInfo.HostIpAddress, podInfo.Name, pg.ndCache[podInfo.HostIpAddress].ipam.Config.PodIfIPCIDR, err)
		return "N/A", 0, "N/A", "N/A"
	}

	if podMask != podIfIPMask {
		fmt.Printf("Host '%s', Pod '%s' - vppHostNetworkPrefixLen mismatch: "+
			"PodIfIPCIDR '%s', podNetworkPrefixLen '%d'\n",
			podInfo.HostIpAddress, podInfo.Name,
			pg.ndCache[podInfo.HostIpAddress].ipam.Config.PodIfIPCIDR,
			pg.ndCache[podInfo.HostIpAddress].ipam.Config.PodNetworkPrefixLen)
		// Do not return - we can still continue if this error happens
	}

	podIfIPPrefix := podIfIPAddress &^ podMask
	podAddr, err := ip2uint32(podInfo.IpAddress)
	if err != nil {
		fmt.Printf("Host '%s', Pod '%s' - invalid podInfo.IpAddress %s, err %s",
			podInfo.HostIpAddress, podInfo.Name, podInfo.IpAddress, err)
		return "N/A", 0, "N/A", "N/A"
	}

	podAddrSuffix := podAddr & podMask

	if podAddr&^podMask != podIPSubnet {
		fmt.Printf("Host '%s', Pod '%s' - pod IP address %s not from PodSubnetCIDR %s\n",
			podInfo.HostIpAddress, podInfo.Name, podInfo.IpAddress,
			pg.ndCache[podInfo.HostIpAddress].ipam.Config.PodSubnetCIDR)
		// Do not return - we can still continue if this error happens
	}

	for _, intf := range pg.ndCache[podInfo.HostIpAddress].ifcs {
		if intf.If.IfType == interfaces.InterfaceType_TAP_INTERFACE {
			for _, ip := range intf.If.IPAddresses {
				ifIPAddr, iffIPMask, err := getIPAddressAndMask(ip)
				if err != nil {
					continue
				}
				if iffIPMask != 0 {
					// TODO: do some error handling
					continue
				}

				ifIPAdrPrefix := ifIPAddr &^ podMask
				ifIPAdrSuffix := ifIPAddr & podMask
				if (podIfIPPrefix == ifIPAdrPrefix) && (ifIPAdrSuffix == podAddrSuffix) {
					return ip, intf.IfMeta.SwIfIndex, intf.IfMeta.VppInternalName, intf.If.Name
				}
			}
		}
	}

	return "N/A", 0, "N/A", "N/A"
}

func getWriter(hostName string) *tabwriter.Writer {
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	return w
}

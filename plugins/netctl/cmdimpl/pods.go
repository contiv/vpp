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
	"os"
	"strings"
	"text/tabwriter"

	"github.com/gogo/protobuf/jsonpb"

	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/servicelabel"

	vppifdescr "github.com/ligato/vpp-agent/plugins/vppv2/ifplugin/descriptor"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"

	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"github.com/contiv/vpp/plugins/ksr"
	"github.com/contiv/vpp/plugins/ksr/model/node"
	"github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/netctl/remote"
	"github.com/contiv/vpp/plugins/ipv4net"
)

type nodeData struct {
	ipam *ipv4net.IPAMData
	ifcs telemetrymodel.NodeInterfaces
}
type nodeDataCache map[string]*nodeData

type podGetter struct {
	ndCache nodeDataCache
	db      *etcd.BytesConnectionEtcd
	client  *remote.HTTPClient
	pods    []*pod.Pod
}

// PrintAllPods will print out all of the non local pods in a network in
// a table format.
func PrintAllPods(client *remote.HTTPClient, db *etcd.BytesConnectionEtcd) {
	w := getWriter("HOST-NAME")
	pg := newPodGetter(client, db)
	pg.printAllPods(w)
	pg.db.Close()
	w.Flush()
}

//PrintPodsPerNode will print out all of the non-local pods for a certain
// pods along with their tap interface ip address
func PrintPodsPerNode(client *remote.HTTPClient, db *etcd.BytesConnectionEtcd, input string) {
	w := getWriter("")
	pg := newPodGetter(client, db)
	pg.printPodsPerNode(w, input, "")
	pg.db.Close()
	w.Flush()
}

func newPodGetter(client *remote.HTTPClient, db *etcd.BytesConnectionEtcd) *podGetter {
	ksrPrefix := servicelabel.GetDifferentAgentPrefix(ksr.MicroserviceLabel)

	pg := &podGetter{
		ndCache: make(nodeDataCache, 0),
		db:      db,
		client:  client,
	}

	pg.pods = make([]*pod.Pod, 0)
	itr, err := pg.db.ListValues(ksrPrefix + pod.KeyPrefix())
	if err != nil {
		fmt.Printf("Failed to get pods from etcd, error %s\n", err)
		os.Exit(2)
	}

	for {
		kv, stop := itr.GetNext()
		if stop {
			break
		}
		buf := kv.GetValue()
		podInfo := &pod.Pod{}
		if err = jsonpb.UnmarshalString(string(buf), podInfo); err != nil {
			fmt.Printf("Failed to unmarshall pod, error %s\n", err)
			continue
		}
		pg.pods = append(pg.pods, podInfo)
	}

	return pg
}

func (pg *podGetter) printAllPods(w *tabwriter.Writer) {
	ksrPrefix := servicelabel.GetDifferentAgentPrefix(ksr.MicroserviceLabel)
	itr, err := pg.db.ListValues(ksrPrefix + node.KeyPrefix())
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
		nodeInfo := &node.Node{}
		err = jsonpb.UnmarshalString(string(buf), nodeInfo)
		var mgmtAddr string
		for _, address := range nodeInfo.Addresses {
			if address.Type == node.NodeAddress_NodeInternalIP ||
				address.Type == node.NodeAddress_NodeExternalIP {
				mgmtAddr = address.Address
				break
			}
		}
		nodeID := fmt.Sprintf("%s (%s):", nodeInfo.Name, mgmtAddr)
		fmt.Fprintf(w, "%s\t\t\t\t\t\t\t\n", nodeID)
		fmt.Fprintf(w, "%s\t\t\t\t\t\t\t\n", strings.Repeat("-", len(nodeID)))

		pg.printPodsPerNode(w, mgmtAddr, nodeInfo.Name)
		fmt.Fprintln(w, "\t\t\t\t\t\t\t\t")
	}
}

func (pg *podGetter) printPodsPerNode(w *tabwriter.Writer, nodeNameOrIP string, nodeName string) {
	hostIP := resolveNodeOrIP(pg.db, nodeNameOrIP)

	fmt.Fprintf(w, "POD-NAME\tNAMESPACE\tPOD-IP\tVPP-IP\tIF-IDX\tIF-NAME\n")

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
			ipAddress, ifIndex, name := pg.getTapInterfaceForPod(podInfo)
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
				podInfo.Name,
				podInfo.Namespace,
				podInfo.IpAddress,
				strings.Split(ipAddress, "/")[0],
				ifIndex,
				name)
		}
	}
}

func (pg *podGetter) getTapInterfaceForPod(podInfo *pod.Pod) (string, uint32, string) {
	// when we see a pod from a given node for the first time, retrieve its
	// IPAM and interface info
	if pg.ndCache[podInfo.HostIpAddress] == nil {

		// Get ipam data for the node where the pod is hosted
		b, err := getNodeInfo(pg.client, podInfo.HostIpAddress, getIpamDataCmd)
		if err != nil {
			fmt.Printf("Host '%s', Pod '%s' - failed to get ipam, err %s\n",
				podInfo.HostIpAddress, podInfo.Name, err)
			return "N/A", 0, "N/A"
		}

		ipam := &ipv4net.IPAMData{}
		if err := json.Unmarshal(b, ipam); err != nil {
			fmt.Printf("Host '%s', Pod '%s' - failed to decode ipam, err %s\n",
				podInfo.HostIpAddress, podInfo.Name, err)
			return "N/A", 0, "N/A"
		}

		// Get interfaces data for the node where the pod is hosted
		ifaceDumpCmd := vppDumpCommand(vppifdescr.InterfaceDescriptorName)
		b, err = getNodeInfo(pg.client, podInfo.HostIpAddress, ifaceDumpCmd)
		intfs := make(telemetrymodel.NodeInterfaces, 0)
		if err := json.Unmarshal(b, &intfs); err != nil {
			fmt.Printf("Host '%s', Pod '%s' - failed to get pod's interface, err %s\n",
				podInfo.HostIpAddress, podInfo.Name, err)
			return "N/A", 0, "N/A"
		}

		pg.ndCache[podInfo.HostIpAddress] = &nodeData{
			ipam: ipam,
			ifcs: intfs,
		}
	}

	// Determine the tap interface on VPP that connects the pod to the VPP
	podPfxLen := pg.ndCache[podInfo.HostIpAddress].ipam.Config.VPPHostSubnetOneNodePrefixLen
	podMask := maskLength2Mask(int(podPfxLen))

	podNetwork, podIPMask, err := getIPAddressAndMask(pg.ndCache[podInfo.HostIpAddress].ipam.PodSubnetThisNode)
	if err != nil {
		fmt.Printf("Host '%s', Pod '%s' - invalid PodSubnetThisNode address %s, err %s\n",
			podInfo.HostIpAddress, podInfo.Name, pg.ndCache[podInfo.HostIpAddress].ipam.PodSubnetThisNode, err)
		// Do not return - we can still continue if this error happens
	}

	if podMask != podIPMask {
		fmt.Printf("Host '%s', Pod '%s' - vppHostSubnetOneNodePrefixLen mismatch: "+
			"PodSubnetThisNode '%s', podSubnetOneNodePrefixLen '%d'\n",
			podInfo.HostIpAddress, podInfo.Name,
			pg.ndCache[podInfo.HostIpAddress].ipam.PodSubnetThisNode,
			pg.ndCache[podInfo.HostIpAddress].ipam.Config.PodSubnetOneNodePrefixLen)
		// Do not return - we can still continue if this error happens
	}

	podIfIPAddress, podIfIPMask, err := getIPAddressAndMask(pg.ndCache[podInfo.HostIpAddress].ipam.Config.PodVPPSubnetCIDR)
	if err != nil {
		fmt.Printf("Host '%s', Pod '%s' - invalid PodVPPSubnetCIDR address %s, err %s\n",
			podInfo.HostIpAddress, podInfo.Name, pg.ndCache[podInfo.HostIpAddress].ipam.Config.PodVPPSubnetCIDR, err)
		return "N/A", 0, "N/A"
	}

	if podMask != podIfIPMask {
		fmt.Printf("Host '%s', Pod '%s' - vppHostSubnetOneNodePrefixLen mismatch: "+
			"PodVPPSubnetCIDR '%s', podSubnetOneNodePrefixLen '%d'\n",
			podInfo.HostIpAddress, podInfo.Name,
			pg.ndCache[podInfo.HostIpAddress].ipam.Config.PodVPPSubnetCIDR,
			pg.ndCache[podInfo.HostIpAddress].ipam.Config.PodSubnetOneNodePrefixLen)
		// Do not return - we can still continue if this error happens
	}

	podIfIPPrefix := podIfIPAddress &^ podMask
	podAddr, err := ip2uint32(podInfo.IpAddress)
	if err != nil {
		fmt.Printf("Host '%s', Pod '%s' - invalid podInfo.IpAddress %s, err %s",
			podInfo.HostIpAddress, podInfo.Name, podInfo.IpAddress, err)
		return "N/A", 0, "N/A"
	}

	podAddrSuffix := podAddr & podMask

	if podAddr&^podMask != podNetwork {
		fmt.Printf("Host '%s', Pod '%s' - pod IP address %s not from PodSubnetThisNode subnet %s\n",
			podInfo.HostIpAddress, podInfo.Name, podInfo.IpAddress,
			pg.ndCache[podInfo.HostIpAddress].ipam.PodSubnetThisNode)
		// Do not return - we can still continue if this error happens
	}

	for _, intf := range pg.ndCache[podInfo.HostIpAddress].ifcs {
		if intf.Value.Type == interfaces.Interface_TAP {
			for _, ip := range intf.Value.IpAddresses {
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
					return ip, intf.Metadata.SwIfIndex, intf.Value.Name
				}
			}
		}
	}

	return "N/A", 0, "N/A"
}

func getWriter(hostName string) *tabwriter.Writer {
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	return w
}

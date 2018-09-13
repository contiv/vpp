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
	"github.com/coreos/etcd/clientv3"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/ligato/vpp-agent/plugins/vpp/model/interfaces"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

type nodeData struct {
	ipam *telemetrymodel.IPamEntry
	ifcs telemetrymodel.NodeInterfaces
}
type nodeDataCache map[string]*nodeData

type podGetter struct {
	etcdConfig *etcd.ClientConfig
	ndCache    nodeDataCache
	logger     logging.Logger
	db         *etcd.BytesConnectionEtcd
	pods       []*pod.Pod
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
		etcdConfig: &etcd.ClientConfig{
			Config: &clientv3.Config{
				Endpoints: []string{"127.0.0.1:32379"},
			},
			OpTimeout: 1 * time.Second,
		},
		ndCache: make(nodeDataCache, 0),
		logger:  logrus.DefaultLogger(),
	}

	pg.logger.SetLevel(logging.ErrorLevel)

	// Create connection to etcd.
	var err error
	if pg.db, err = etcd.NewEtcdConnectionWithBytes(*pg.etcdConfig, pg.logger); err != nil {
		fmt.Println(err)
		os.Exit(1)
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
		fmt.Fprintf(w, "%s:\t\t\t\t\t\t\t\t\n", nodeInfo.Name)
		fmt.Fprintf(w, "%s\t\t\t\t\t\t\t\t\n", strings.Repeat("-", len(nodeInfo.Name)+1))

		pg.printPodsPerNode(w, nodeInfo.ManagementIpAddress, nodeInfo.Name)
		fmt.Fprintln(w, "\t\t\t\t\t\t\t\t")
	}
}

func (pg *podGetter) printPodsPerNode(w *tabwriter.Writer, nodeNameOrIP string, nodeName string) {
	hostIP := resolveNodeOrIP(nodeNameOrIP)

	fmt.Fprintf(w, "POD-NAME\tNAMESPACE\tPOD-IP\tVPP-IP\tIF-IDX\tIF-NAME\tINTERNAL-IF-NAME\tHOST-IP\n")

	for _, podInfo := range pg.pods {
		if podInfo.HostIpAddress != hostIP || podInfo.IpAddress == hostIP {
			continue
		}

		if ipAddress, ifIndex, intName, name, err := pg.getTapInterfaces(podInfo); err == nil {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
				podInfo.Name,
				podInfo.Namespace,
				podInfo.IpAddress,
				strings.Split(ipAddress, "/")[0],
				ifIndex,
				intName,
				name,
				podInfo.HostIpAddress)

		} else {
			fmt.Printf("error %s\n", err)
		}
	}
}

func (pg *podGetter) getTapInterfaces(podInfo *pod.Pod) (string, uint32, string, string, error) {
	// If we haven't retrieved node info from the Agent yet, do it now
	if pg.ndCache[podInfo.HostIpAddress] == nil {
		// Get ipam data for the node where the pod is hosted
		cmd := "contiv/v1/ipam"
		b := http.GetNodeInfo(podInfo.HostIpAddress, cmd)
		ipam := &telemetrymodel.IPamEntry{}
		if err := json.Unmarshal(b, ipam); err != nil {
			return "", 0, "", "", fmt.Errorf("failed to get ipam for node %s, err %s",
				podInfo.HostIpAddress, err)
		}

		// Get interfaces data for the node where the pod is hosted
		cmd = "vpp/dump/v1/interfaces"
		b = http.GetNodeInfo(podInfo.HostIpAddress, cmd)
		intfs := make(telemetrymodel.NodeInterfaces)
		if err := json.Unmarshal(b, &intfs); err != nil {
			return "", 0, "", "", fmt.Errorf("failed to get pod's interface; pod %s, hostIPAddress %s, err %s",
				podInfo.Name, podInfo.HostIpAddress, err)
		}

		pg.ndCache[podInfo.HostIpAddress] = &nodeData{
			ipam: ipam,
			ifcs: intfs,
		}
	}

	// Determine the tap interface on VPP that connects the pod to the VPP
	podIfIPAddress, podIfIPMask, err := getIPAddressAndMask(pg.ndCache[podInfo.HostIpAddress].ipam.Config.PodIfIPCIDR)
	if err != nil {
		return "", 0, "", "", fmt.Errorf("invalid PodIfIPCIDR address %s, err %s",
			podInfo.HostIpAddress, err)
	}

	podIfIPPrefix := podIfIPAddress &^ podIfIPMask
	podAddr, err := ip2uint32(podInfo.IpAddress)
	if err != nil {
		return "", 0, "", "", fmt.Errorf("invalid podInfo.IpAddress %s, err %s",
			podInfo.HostIpAddress, err)
	}
	podAddrSuffix := podAddr & podIfIPMask

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

				ifIPAdrPrefix := ifIPAddr &^ podIfIPMask
				ifIPAdrSuffix := ifIPAddr & podIfIPMask
				if (podIfIPPrefix == ifIPAdrPrefix) && (ifIPAdrSuffix == podAddrSuffix) {
					return ip, intf.IfMeta.SwIfIndex, intf.IfMeta.VppInternalName, intf.If.Name, nil
				}
			}
		}
	}

	return "", 0, "", "", nil
}

func getWriter(hostName string) *tabwriter.Writer {
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	return w
}

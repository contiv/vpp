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
}

// PrintAllPods will print out all of the non local pods in a network in
// a table format.
func PrintAllPods() {
	pg := newPodGetter()
	pg.printAllPods()
	pg.db.Close()
}

//PrintPodsPerNode will print out all of the non-local pods for a certain
// pods along with their tap interface ip address
func PrintPodsPerNode(input string) {
	pg := newPodGetter()
	pg.printPodsPerNode(input)
	pg.db.Close()
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

	return pg
}

func (pg *podGetter) printPodsPerNode(input string) {
	hostIP := resolveNodeOrIP(input)

	w := tabwriter.NewWriter(os.Stdout, 0, 8, 0, '\t', 0)

	itr, err := pg.db.ListValues("/vnf-agent/contiv-ksr/k8s/pod/")
	if err != nil {
		fmt.Printf("Error getting values")
		return
	}
	fmt.Fprintf(w, "name\tip_address\thost_ip_addr\ttap_ip\toutgoing_idx\ttag\n")

	for {
		kv, stop := itr.GetNext()
		if stop {
			break
		}
		buf := kv.GetValue()
		podInfo := &pod.Pod{}
		err = json.Unmarshal(buf, podInfo)
		if podInfo.HostIpAddress != hostIP || podInfo.IpAddress == hostIP {
			continue
		}

		if ipAddress, ifIndex, tag, err := pg.getTapInterfaces(podInfo); err == nil {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
				podInfo.Name,
				podInfo.IpAddress,
				podInfo.HostIpAddress,
				ipAddress,
				ifIndex,
				tag)

		} else {
			fmt.Printf("error %s\n", err)
		}
	}
	w.Flush()
}

func (pg *podGetter) getTapInterfaces(podInfo *pod.Pod) (string, uint32, string, error) {
	// Get interface information
	if pg.ndCache[podInfo.HostIpAddress]== nil {
		// Get ipam data for the node where the pod is hosted
		cmd := "contiv/v1/ipam"
		b := http.GetNodeInfo(podInfo.HostIpAddress, cmd)
		ipam := &telemetrymodel.IPamEntry{}
		if err := json.Unmarshal(b, ipam); err != nil {
			return "", 0, "", fmt.Errorf("could not get ipam for host %s, err %s",
				podInfo.HostIpAddress, err)
		}

		// Get interfaces data for the node where the pod is hosted
		cmd = "vpp/dump/v1/interfaces"
		b = http.GetNodeInfo(podInfo.HostIpAddress, cmd)
		intfs := make(telemetrymodel.NodeInterfaces)
		if err := json.Unmarshal(b, &intfs); err != nil {
			return "", 0, "", fmt.Errorf("could not get pod's interface; pod %s, hostIPAddress %s, err %s",
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
		return "", 0, "", fmt.Errorf("invalid PodIfIPCIDR address %s, err %s",
			podInfo.HostIpAddress, err)
	}

	podIfIPPrefix := podIfIPAddress &^ podIfIPMask
	podAddr, err := ip2uint32(podInfo.IpAddress)
	if err != nil {
		return "", 0, "", fmt.Errorf("invalid podInfo.IpAddress %s, err %s",
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
					return ip, intf.IfMeta.SwIfIndex, intf.IfMeta.Tag, nil
				}
			}
		}
	}

	return "", 0, "", nil
}

func (pg *podGetter) printAllPods() {

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
		fmt.Println("\n" + nodeInfo.Name + ":")
		fmt.Println("--------------")

		pg.printPodsPerNode(nodeInfo.ManagementIpAddress)
	}
}

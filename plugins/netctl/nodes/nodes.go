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
//

package nodes

import (
	"encoding/json"
	"fmt"
	nodeinfomodel "github.com/contiv/vpp/plugins/contiv/model/node"

	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	k8snodeinfo "github.com/contiv/vpp/plugins/ksr/model/node"
	"github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/netctl/http"
	"github.com/coreos/etcd/clientv3"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/ligato/vpp-agent/plugins/vpp/model/interfaces"
	"os"
	"regexp"
	"text/tabwriter"
	"time"
)

//PrintNodes will print out all of the nodes in a network in a table format.
func PrintNodes() {
	cfg := &etcd.ClientConfig{
		Config: &clientv3.Config{
			Endpoints: []string{"127.0.0.1:32379"},
		},
		OpTimeout: 1 * time.Second,
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 4, '\t', 0)
	// Create connection to etcd.
	db, err := etcd.NewEtcdConnectionWithBytes(*cfg, logrus.DefaultLogger())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	itr, err := db.ListValues("/vnf-agent/contiv-ksr/allocatedIDs/")
	if err != nil {
		fmt.Printf("Error getting values")
		return
	}
	fmt.Fprintf(w, "id\tname\t\tip_address\t\tman_ip_addr\tbuild_date\t\t\tbuild_version\t\tstart_time\tstate\n")
	w.Flush()
	for {
		kv, stop := itr.GetNext()
		if stop {
			break
		}
		buf := kv.GetValue()
		nodeInfo := &nodeinfomodel.NodeInfo{}
		err = json.Unmarshal(buf, nodeInfo)
		//fmt.Printf("NodeInfo: %+v\n", nodeInfo)
		// Do whatever processing we need to do
		bytes := http.GetNodeInfo(nodeInfo.ManagementIpAddress, "liveness")
		var liveness telemetrymodel.NodeLiveness
		err = json.Unmarshal(bytes, &liveness)
		if err != nil {
			fmt.Println(err)
			liveness.BuildDate = "Not Available"
		}

		fmt.Fprintf(w, "%+v\t%s\t%s\t%s\t%s\t%s\t%d\t%d\n",
			nodeInfo.Id,
			nodeInfo.Name,
			nodeInfo.IpAddress,
			nodeInfo.ManagementIpAddress,
			liveness.BuildDate,
			liveness.BuildVersion,
			liveness.StartTime,
			liveness.State)

		w.Flush()
	}
	db.Close()
}

//FindIPForNodeName will find an ip address that corresponds to the passed in nodeName
func FindIPForNodeName(nodeName string) string {
	cfg := &etcd.ClientConfig{
		Config: &clientv3.Config{
			Endpoints: []string{"127.0.0.1:32379"},
		},
		OpTimeout: 1 * time.Second,
	}
	// Create connection to etcd.
	db, err := etcd.NewEtcdConnectionWithBytes(*cfg, logrus.DefaultLogger())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	itr, err := db.ListValues("/vnf-agent/contiv-ksr/allocatedIDs/")
	if err != nil {
		fmt.Printf("Error getting values")
		return ""
	}
	for {
		kv, stop := itr.GetNext()
		if stop {
			break
		}
		buf := kv.GetValue()
		//key := kv.GetKey()
		//fmt.Printf("Key: %s, value: %s\n", key, string(buf))
		nodeInfo := &nodeinfomodel.NodeInfo{}
		err = json.Unmarshal(buf, nodeInfo)
		if nodeInfo.Name == nodeName {
			return nodeInfo.ManagementIpAddress
		}
	}
	db.Close()
	return ""
}

//VppCliCmd will receive a nodeName and a vpp cli command and print it out to the console
func VppCliCmd(nodeName string, vppclicmd string) {

	fmt.Printf("vppcli %s %s\n", nodeName, vppclicmd)

	ipAdr := ResolveNodeOrIP(nodeName)
	cmd := fmt.Sprintf("vpp/command")
	body := fmt.Sprintf("{\"vppclicommand\":\"%s\"}", vppclicmd)
	err := http.SetNodeInfo(ipAdr, cmd, body)
	if err != nil {
		fmt.Println(err)
	}

}

//NodeIPamCMD prints out the ipam information of a specific node
func NodeIPamCmd(nodeName string) {
	fmt.Printf("nodeipam %s\n", nodeName)
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 4, '\t', 0)

	ip := ResolveNodeOrIP(nodeName)
	fmt.Fprintf(w, "id\tname\tip_address\tpod_network_ip\tvpp_host_network\n")
	b := http.GetNodeInfo(ip, "contiv/v1/ipam")
	ipam := telemetrymodel.IPamEntry{}
	err := json.Unmarshal(b, &ipam)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n",
		ipam.NodeID,
		ipam.NodeName,
		ipam.NodeIP,
		ipam.PodNetwork,
		ipam.VppHostNetwork)

	w.Flush()
}

//PrintPodsPerNode will print out all of the non-local pods for a certain pods along with their tap interface ip address
func PrintPodsPerNode(input string) {
	hostIP := ResolveNodeOrIP(input)
	cfg := &etcd.ClientConfig{
		Config: &clientv3.Config{
			Endpoints: []string{"127.0.0.1:32379"},
		},
		OpTimeout: 1 * time.Second,
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 6, '\t', 0)
	// Create connection to etcd.
	db, err := etcd.NewEtcdConnectionWithBytes(*cfg, logrus.DefaultLogger())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	itr, err := db.ListValues("/vnf-agent/contiv-ksr/k8s/pod/")
	if err != nil {
		fmt.Printf("Error getting values")
		return
	}
	fmt.Fprintf(w, "name\t\t\tip_address\t\thost_ip_addr\ttap_ip\n")

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
		ip := printTapInterfaces(podInfo)
		fmt.Fprintf(w, "%s\t\t\t%s\t\t%s\t%s\n",
			podInfo.Name, podInfo.IpAddress, podInfo.HostIpAddress, ip[0])
		for _, str := range ip[1:] {
			fmt.Fprintf(w, "\t\t\t\t\t\t%s\n", str)
		}

	}
	w.Flush()
	db.Close()
}

//ResolveNodeOrIP will take in an input string which is either a node name or string and return the ip for the nodename or
//simply return the ip
func ResolveNodeOrIP(input string) (ipAdr string) {
	re := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
	if re.MatchString(input) {
		return input
	}
	ip := FindIPForNodeName(input)
	return ipg
}

func printTapInterfaces(podInfo *pod.Pod) []string {
	var str []string
	cmd := fmt.Sprintf("vpp/dump/v1/interfaces")
	b := http.GetNodeInfo(podInfo.HostIpAddress, cmd)
	intfs := make(telemetrymodel.NodeInterfaces)
	json.Unmarshal(b, &intfs)
	for _, intf := range intfs {
		if intf.If.IfType == interfaces.InterfaceType_TAP_INTERFACE {
			for _, ip := range intf.If.IPAddresses {
				str = append(str, ip)
			}
		}

	}
	return str
}

func getK8sNode(nodeName string) *k8snodeinfo.Node {
	cfg := &etcd.ClientConfig{
		Config: &clientv3.Config{
			Endpoints: []string{"127.0.0.1:32379"},
		},
		OpTimeout: 1 * time.Second,
	}
	// Create connection to etcd.
	db, err := etcd.NewEtcdConnectionWithBytes(*cfg, logrus.DefaultLogger())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	b, found, _, err := db.GetValue("/vnf-agent/contiv-ksr/k8s/" + nodeName)
	if err != nil || !found {
		fmt.Printf("Error getting values")
		return nil
	}
	k8sInfo := &k8snodeinfo.Node{}
	json.Unmarshal(b, k8sInfo)
	return k8sInfo
}

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
	"github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/netctl/http"
	"github.com/coreos/etcd/clientv3"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/ligato/vpp-agent/plugins/vpp/model/interfaces"
	"os"
	"regexp"
	"strconv"
	"strings"
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
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.FatalLevel)
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 4, '\t', 0)
	// Create connection to etcd.
	db, err := etcd.NewEtcdConnectionWithBytes(*cfg, logger)
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

//NodeIPamCmd prints out the ipam information of a specific node
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
	logger := logrus.DefaultLogger()
	logger.SetLevel(logging.FatalLevel)
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 0, '\t', 0)
	// Create connection to etcd.
	db, err := etcd.NewEtcdConnectionWithBytes(*cfg, logger)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	itr, err := db.ListValues("/vnf-agent/contiv-ksr/k8s/pod/")
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
		if ipAddress, ifIndex, tag, err := printTapInterfaces(podInfo); err == nil {
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
	return ip
}

func printTapInterfaces(podInfo *pod.Pod) (string, uint32, string, error) {
	// Get interface information
	cmd := "vpp/dump/v1/interfaces"
	b := http.GetNodeInfo(podInfo.HostIpAddress, cmd)
	intfs := make(telemetrymodel.NodeInterfaces)
	if err := json.Unmarshal(b, &intfs); err != nil {

		return "", 0, "", fmt.Errorf("could not get pod's interface; pod %s, hostIPAddress %s, err %s",
			podInfo.Name, podInfo.HostIpAddress, err)
	}

	// Get ipam information
	cmd = "contiv/v1/ipam"
	b = http.GetNodeInfo(podInfo.HostIpAddress, cmd)
	ipam := telemetrymodel.IPamEntry{}
	if err := json.Unmarshal(b, &ipam); err != nil {
		return "", 0, "", fmt.Errorf("could not get ipam for host %s, err %s",
			podInfo.HostIpAddress, err)
	}

	podIfIPAddress, podIfIPMask, err := getIPAddressAndMask(ipam.Config.PodIfIPCIDR)
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

	for _, intf := range intfs {
		if intf.If.IfType == interfaces.InterfaceType_TAP_INTERFACE {
			for _, ip := range intf.If.IPAddresses {
				ifIPAddr, iffIPMask, err := getIPAddressAndMask(ip)
				if err != nil {
					continue
				}
				if iffIPMask != 0 {
					// TODO: do spme error handling
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

// maskLength2Mask will tank in an int and return the bit mask for the number given
func maskLength2Mask(ml int) uint32 {
	var mask uint32
	for i := 0; i < 32-ml; i++ {
		mask = mask << 1
		mask++
	}
	return mask
}

func ip2uint32(ipAddress string) (uint32, error) {
	var ipu uint32
	parts := strings.Split(ipAddress, ".")
	for _, p := range parts {
		// num, _ := strconv.ParseUint(p, 10, 32)
		num, _ := strconv.Atoi(p)
		ipu = (ipu << 8) + uint32(num)
		//fmt.Printf("%d: num: 0x%x, ipu: 0x%x\n", i, num, ipu)
	}
	return ipu, nil
}

func getIPAddressAndMask(ip string) (uint32, uint32, error) {
	addressParts := strings.Split(ip, "/")
	maskLen, err := strconv.Atoi(addressParts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid mask")
	}

	address, err := ip2uint32(addressParts[0])
	if err != nil {
		return 0, 0, err
	}
	mask := maskLength2Mask(maskLen)

	return address, mask, nil
}

//PrintAllPods will print out all of the non local pods in a network in a table format.
func PrintAllPods() {
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
		return
	}
	for {
		kv, stop := itr.GetNext()
		if stop {
			fmt.Println()
			break
		}
		buf := kv.GetValue()
		nodeInfo := &nodeinfomodel.NodeInfo{}
		err = json.Unmarshal(buf, nodeInfo)
		fmt.Println("\n" + nodeInfo.Name + ":")
		fmt.Println("--------------")

		PrintPodsPerNode(nodeInfo.ManagementIpAddress)
	}
	db.Close()
}

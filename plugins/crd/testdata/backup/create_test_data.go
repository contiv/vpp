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

package testdata

import (
	"encoding/json"
	"fmt"
	"github.com/contiv/vpp/plugins/crd/api"
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	vppnodemodel "github.com/contiv/vpp/plugins/nodesync/vppnode"
)

// createNodeTestData creates a test vector that roughly corresponds to a 3-node
// vagrant topology (1 master, 2 workers). The created topology is defect-free,
// i.e. defect must be injected into the topology individually for each test
// case.
func CreateNodeTestData(vppCache api.VppCache) error {
	rawData := getRawNodeTestData()

	for node, data := range rawData {
		vn := &vppnodemodel.VppNode{}
		if err := json.Unmarshal([]byte(data["vppnode"]), vn); err != nil {
			return fmt.Errorf("failed to unmarshall vpp node")
		}

		nl := &telemetrymodel.NodeLiveness{}
		if err := json.Unmarshal([]byte(data["liveness"]), nl); err != nil {
			return fmt.Errorf("failed to unmarshall node liveness, err %s", err)
		}

		nifc := make(telemetrymodel.NodeInterfaces, 0)
		if err := json.Unmarshal([]byte(data["interfaces"]), &nifc); err != nil {
			return fmt.Errorf("failed to unmarshall node interfaces, err %s", err)
		}

		nbd := make(telemetrymodel.NodeBridgeDomains, 0)
		if err := json.Unmarshal([]byte(data["bridgedomains"]), &nbd); err != nil {
			return fmt.Errorf("failed to unmarshall node interfaces, err %s", err)
		}

		nodel2fib := make(telemetrymodel.NodeL2FibTable, 0)
		if err := json.Unmarshal([]byte(data["l2fib"]), &nodel2fib); err != nil {
			return fmt.Errorf("failed to unmarshall node interfaces, err %s", err)
		}

		narp := make(telemetrymodel.NodeIPArpTable, 0)
		if err := json.Unmarshal([]byte(data["arps"]), &narp); err != nil {
			return fmt.Errorf("failed to unmarshall node interfaces, err %s", err)
		}

		nr := make(telemetrymodel.NodeStaticRoutes, 0)
		if err := json.Unmarshal([]byte(data["routes"]), &nr); err != nil {
			return fmt.Errorf("failed to unmarshall node interfaces, err %s", err)
		}

		nipe := telemetrymodel.IPamEntry{}
		if err := json.Unmarshal([]byte(data["ipam"]), &nipe); err != nil {
			return fmt.Errorf("failed to unmarshall node ipam, err %s", err)
		}

		if node != vn.Name {
			return fmt.Errorf("invalid data - TODO more precise error")
		}

		if err := vppCache.CreateNode(vn.Id, vn.Name, vn.IpAddress); err != nil {
			return fmt.Errorf("failed to create test data for node %s, err: %s", vn.Name, err)
		}

		if err := vppCache.SetNodeLiveness(vn.Name, nl); err != nil {
			return fmt.Errorf("failed to set liveness for node %s, err: %s", vn.Name, err)
		}

		if err := vppCache.SetNodeInterfaces(vn.Name, nifc); err != nil {
			return fmt.Errorf("failed to set interfaces for node %s, err: %s", vn.Name, err)
		}

		if err := vppCache.SetNodeBridgeDomain(vn.Name, nbd); err != nil {
			return fmt.Errorf("failed to set bridge domains for node %s, err: %s", vn.Name, err)
		}

		if err := vppCache.SetNodeL2Fibs(vn.Name, nodel2fib); err != nil {
			return fmt.Errorf("failed to set l2fib table for node %s, err: %s", vn.Name, err)
		}

		if err := vppCache.SetNodeIPARPs(vn.Name, narp); err != nil {
			return fmt.Errorf("failed to set arp table for node %s, err: %s", vn.Name, err)
		}

		if err := vppCache.SetNodeStaticRoutes(vn.Name, nr); err != nil {
			return fmt.Errorf("failed to set route table for node %s, err: %s", vn.Name, err)
		}

		if err := vppCache.SetNodeIPam(vn.Name, nipe); err != nil {
			return fmt.Errorf("failed to set ipam for node %s, err: %s", vn.Name, err)
		}
	}
	return nil
}

func CreateK8sPodTestData(k8sCache api.K8sCache) error {
	for _, rp := range getRawK8sPodTestData() {
		pod := &podmodel.Pod{
			Label:     []*podmodel.Pod_Label{},
			Container: []*podmodel.Pod_Container{},
		}

		if err := json.Unmarshal([]byte(rp), pod); err != nil {
			return fmt.Errorf("failed to unmarshall pod data, err %s", err)
		}

		if err := k8sCache.CreatePod(pod.Name, pod.Namespace, pod.Label,
			pod.IpAddress, pod.HostIpAddress, nil); err != nil {
			return fmt.Errorf("failed to create test data for pod %s, err: %s", pod.Name, err)
		}
	}
	return nil
}

func CreateK8sNodeTestData(k8sCache api.K8sCache, vppCache api.VppCache) error {
	for _, rp := range getRawK8sNodeTestData() {
		node := &nodemodel.Node{
			Addresses: []*nodemodel.NodeAddress{},
			NodeInfo:  &nodemodel.NodeSystemInfo{},
		}

		if err := json.Unmarshal([]byte(rp), node); err != nil {
			return fmt.Errorf("failed to unmarshall pod data, err %s", err)
		}

		if err := k8sCache.CreateK8sNode(node.Name, node.Pod_CIDR, node.Provider_ID,
			node.Addresses, node.NodeInfo); err != nil {
			return fmt.Errorf("failed to create test data for pod %s, err: %s", node.Name, err)
		}

		// correlate vppCache with k8sCache
		var manIPAddr string
		for _, addr := range node.Addresses {
			if addr.Type == nodemodel.NodeAddress_NodeInternalIP {
				manIPAddr = addr.Address
			}
		}
		vppNode, err := vppCache.RetrieveNode(node.Name)
		if err != nil {
			return err
		}
		vppNode.ManIPAddr = manIPAddr

	}
	return nil
}

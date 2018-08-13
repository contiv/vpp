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
	"encoding/json"
	"fmt"
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	node2 "github.com/contiv/vpp/plugins/ksr/model/node"

	"github.com/ligato/cn-infra/logging"
	"io/ioutil"
	"net/http"
	"time"
)

const subnetmask = "/24"
const vppVNI = 10

const (
	agentPort          = ":9999"
	livenessURL        = "/liveness"
	interfaceURL       = "/interfaces"
	bridgeDomainURL    = "/bridgedomains"
	l2FibsURL          = "/l2fibs"
	telemetryURL       = "/telemetry"
	arpURL             = "/arps"
	clientTimeout      = 10 // HTTP client timeout, in seconds
	collectionInterval = 1  // data collection interval, in minutes
)

// ContivTelemetryCache is used for a in-memory storage of K8s State data
// The cache processes K8s State data updates and RESYNC events through Update()
// and Resync() APIs, respectively.
// The cache allows to get notified about changes via convenient callbacks.
type ContivTelemetryCache struct {
	Deps

	Synced    bool
	VppCache  VppCache
	K8sCache  K8sCache
	Processor ContivTelemetryProcessor
	Report    *Report

	nodeResponseChannel  chan *NodeDTO
	networkInfoGetCh     chan bool
	dtoList              []*NodeDTO
	ticker               *time.Ticker
	collectionInterval   time.Duration
	httpClientTimeout    time.Duration
	agentPort            string
	validationInProgress bool
}

// Deps lists dependencies of PolicyCache.
type Deps struct {
	Log logging.Logger
}

// Report holds error/warning messages recorded during data collection /
// validation
type Report struct {
	Log  logging.Logger
	Data map[string][]string
}

// NodeDTO holds generic node information to be sent over a channel
// and associated with a name in the cache.
type NodeDTO struct {
	NodeName string
	NodeInfo interface{}
	err      error
}

// Init initializes policy cache.
func (ctc *ContivTelemetryCache) Init() error {
	ctc.init()

	// Start the processor
	go ctc.nodeEventProcessor()

	ctc.Log.Infof("ContivTelemetryCache init done")
	return nil
}

func (ctc *ContivTelemetryCache) init() {
	ctc.agentPort = agentPort
	ctc.collectionInterval = collectionInterval * time.Minute
	ctc.httpClientTimeout = clientTimeout * time.Second
	ctc.validationInProgress = false

	ctc.nodeResponseChannel = make(chan *NodeDTO)
	ctc.networkInfoGetCh = make(chan bool)
	ctc.dtoList = make([]*NodeDTO, 0)
	ctc.ticker = time.NewTicker(ctc.collectionInterval)
}

// retrieveNetworkInfo triggers the processor to retrieve vpp data from all
// agents in the cluster and validate it.
func (ctc *ContivTelemetryCache) retrieveNetworkInfo() {
	ctc.networkInfoGetCh <- true
}

// ClearCache with clear all Contiv Telemetry cache data except for the
// data discovered from etcd updates.
func (ctc *ContivTelemetryCache) ClearCache() {
	ctc.VppCache.ClearCache()
	// ctc.K8sCache.ClearCache()
	ctc.Report.clear()
}

// ReinitializeCache completely re-initializes the Contiv Telemetry cache,
// clearing all data, including discovered vpp and k8s nodes and discovered
// k8s pods.
func (ctc *ContivTelemetryCache) ReinitializeCache() {
	ctc.VppCache.ReinitializeCache()
	// ctc.K8sCache.ReinitializeCache()
	ctc.Report.clear()
}

func (ctc *ContivTelemetryCache) nodeEventProcessor() {
	for {
		select {
		case _, ok := <-ctc.ticker.C:
			ctc.Log.Info("Timer-triggered data collection & validation, status:", ok)
			if !ok {
				return
			}
			ctc.startNodeInfoCollection()

		case _, ok := <-ctc.networkInfoGetCh:
			ctc.Log.Info("Externally triggered data collection & validation, status: ", ok)
			if !ok {
				return
			}
			ctc.startNodeInfoCollection()

		case data, ok := <-ctc.nodeResponseChannel:
			ctc.Log.Info("Received DTO, status: ", ok)
			if !ok {
				return
			}
			ctc.processNodeResponse(data)
		}
	}
}

func (ctc *ContivTelemetryCache) startNodeInfoCollection() {
	if ctc.validationInProgress {
		ctc.Log.Info("Skipping data collection/validation - previous run still in progress")
		return
	}
	ctc.validationInProgress = true
	ctc.ClearCache()

	nodelist := ctc.VppCache.RetrieveAllNodes()
	for _, node := range nodelist {
		ctc.collectNodeInfo(node)
	}
}

// collectNodeInfo collects node data from all agents in the Contiv
// cluster and puts it in the cache
func (ctc *ContivTelemetryCache) collectNodeInfo(node *telemetrymodel.Node) {
	ctc.collectAgentInfo(node)
}

// validateNodeInfo checks the consistency of the node data in the cache. It
// checks the ARP tables, ... . Data inconsistencies may cause loss of
// connectivity between nodes or pods. All sata inconsistencies found during
// validation are reported to the CRD.
func (ctc *ContivTelemetryCache) validateNodeInfo() {

	nodelist := ctc.VppCache.RetrieveAllNodes()
	for _, node := range nodelist {
		ctc.populateNodeMaps(node)
	}
	ctc.Log.Info("Beginning validation of Node Data")
	ctc.Processor.Validate()

	for _, n := range nodelist {
		ctc.Report.appendToNodeReport(n.Name, "Report done.")
	}
	ctc.Report.printReport()
}

//Gathers a number of data points for every node in the Node List
func (ctc *ContivTelemetryCache) collectAgentInfo(node *telemetrymodel.Node) {
	client := http.Client{
		Transport:     nil,
		CheckRedirect: nil,
		Jar:           nil,
		Timeout:       ctc.httpClientTimeout,
	}

	go ctc.getNodeInfo(client, node, livenessURL, &telemetrymodel.NodeLiveness{})

	nodeInterfaces := make(telemetrymodel.NodeInterfaces, 0)
	go ctc.getNodeInfo(client, node, interfaceURL, &nodeInterfaces)

	nodeBridgeDomains := make(telemetrymodel.NodeBridgeDomains, 0)
	go ctc.getNodeInfo(client, node, bridgeDomainURL, &nodeBridgeDomains)

	nodel2fibs := make(telemetrymodel.NodeL2FibTable, 0)
	go ctc.getNodeInfo(client, node, l2FibsURL, &nodel2fibs)

	//TODO: Implement getTelemetry correctly.
	//Does not parse information correctly
	//nodetelemetry := make(map[string]NodeTelemetry)
	//go ctc.getNodeInfo(client, node, telemetryURL, &nodetelemetry)

	nodeiparpslice := make(telemetrymodel.NodeIPArpTable, 0)
	go ctc.getNodeInfo(client, node, arpURL, &nodeiparpslice)
}

/* Here are the several functions that run as goroutines to collect information
about a specific node using an http client. First, an http request is made to the
specific url and port of the desired information and the request received is read
and unmarshalled into a struct to contain that information. Then, a data transfer
object is created to hold the struct of information as well as the name and is sent
over the plugins node database channel to node_db_processor.go where it will be read,
processed, and added to the node database.
*/
func (ctc *ContivTelemetryCache) getNodeInfo(client http.Client, node *telemetrymodel.Node, url string,
	nodeInfo interface{}) {

	res, err := client.Get(ctc.getAgentURL(node.ManIPAdr, url))
	if err != nil {
		err := fmt.Errorf("getNodeInfo: url: %s cleintGet Error: %s", url, err.Error())
		ctc.Log.Error(err)
		ctc.nodeResponseChannel <- &NodeDTO{node.Name, nil, err}
		return
	} else if res.StatusCode < 200 || res.StatusCode > 299 {
		err := fmt.Errorf("getNodeInfo: url: %s HTTP res.Status: %s", url, res.Status)
		ctc.Log.Error(err)
		ctc.nodeResponseChannel <- &NodeDTO{node.Name, nil, err}
		return
	}

	b, _ := ioutil.ReadAll(res.Body)
	b = []byte(b)
	json.Unmarshal(b, nodeInfo)

	ctc.nodeResponseChannel <- &NodeDTO{node.Name, nodeInfo, nil}
}

// populateNodeMaps populates many of needed node maps for processing once
// all of the information has been retrieved. It also checks to make sure
// that there are no duplicate addresses within the map.
func (ctc *ContivTelemetryCache) populateNodeMaps(node *telemetrymodel.Node) {
	errReport := ctc.VppCache.SetSecondaryNodeIndices(node)
	for _, r := range errReport {
		ctc.Report.appendToNodeReport(node.Name, r)
	}

	k8snode, err := ctc.K8sCache.RetrieveK8sNode(node.Name)
	if err != nil {
		errString := fmt.Sprintf("node %s discovered in Contiv, but not present in K8s", node.Name)
		ctc.Report.appendToNodeReport(node.Name, errString)
	} else {
		for _, adr := range k8snode.Addresses {
			switch adr.Type {
			case node2.NodeAddress_NodeHostName:
				if adr.Address != node.Name {
					errString := fmt.Sprintf("Inconsistent K8s host name for node %s, host name:,%s",
						k8snode.Name, adr.Address)
					ctc.Report.appendToNodeReport(node.Name, errString)
				}
			case node2.NodeAddress_NodeInternalIP:
				if adr.Address != node.ManIPAdr {
					errString := fmt.Sprintf("Inconsistent Host IP Address for node %s: Contiv: %s, K8s %s",
						k8snode.Name, node.ManIPAdr, adr.Address)
					ctc.Report.appendToNodeReport(node.Name, errString)
				}
			}
		}
	}

	for _, pod := range ctc.K8sCache.RetrieveAllPods() {
		if pod.HostIPAddress == node.ManIPAdr {
			node.PodMap[pod.Name] = pod
		}
	}
}

// getAgentURL creates the URL for the data we're trying to retrieve
func (ctc *ContivTelemetryCache) getAgentURL(ipAddr string, url string) string {
	return "http://" + ipAddr + ctc.agentPort + url
}

// waitForValidationToFinish waits until the node cache has been cleared at
// the end of data validation
func (ctc *ContivTelemetryCache) waitForValidationToFinish() int {
	cycles := 0
	for {
		if !ctc.validationInProgress {
			return cycles
		}
		time.Sleep(1 * time.Millisecond)
		cycles++
	}
}

// nodeResponseProcessor will read the nodeDTO map and make sure that each
// node has enough DTOs to fully process information. It then clears the
// node DTO map after it is finished with it.
func (ctc *ContivTelemetryCache) processNodeResponse(data *NodeDTO) {
	nodelist := ctc.VppCache.RetrieveAllNodes()
	ctc.dtoList = append(ctc.dtoList, data)
	if len(ctc.dtoList) == numDTOs*len(nodelist) {
		ctc.setNodeData()
		ctc.validateNodeInfo()
		ctc.dtoList = ctc.dtoList[0:0]
		ctc.validationInProgress = false
	}
}

// setNodeData will iterate through the dtoList, read the type of dto, and
// assign the dto info to the name associated with the DTO.
func (ctc *ContivTelemetryCache) setNodeData() {
	for _, data := range ctc.dtoList {
		err := error(nil)

		if data.err != nil {
			err = fmt.Errorf("node %+v has nodeDTO %+v and http error %s", data.NodeName, data, data.err)
			ctc.Report.logErrAndAppendToNodeReport(data.NodeName, err.Error())
			continue
		}

		switch data.NodeInfo.(type) {
		case *telemetrymodel.NodeLiveness:
			nl := data.NodeInfo.(*telemetrymodel.NodeLiveness)
			err = ctc.VppCache.SetNodeLiveness(data.NodeName, nl)
		case *telemetrymodel.NodeInterfaces:
			niDto := data.NodeInfo.(*telemetrymodel.NodeInterfaces)
			err = ctc.VppCache.SetNodeInterfaces(data.NodeName, *niDto)
		case *telemetrymodel.NodeBridgeDomains:
			nbdDto := data.NodeInfo.(*telemetrymodel.NodeBridgeDomains)
			err = ctc.VppCache.SetNodeBridgeDomain(data.NodeName, *nbdDto)
		case *telemetrymodel.NodeL2FibTable:
			nl2fDto := data.NodeInfo.(*telemetrymodel.NodeL2FibTable)
			err = ctc.VppCache.SetNodeL2Fibs(data.NodeName, *nl2fDto)
		case *telemetrymodel.NodeTelemetries:
			ntDto := data.NodeInfo.(*telemetrymodel.NodeTelemetries)
			err = ctc.VppCache.SetNodeTelemetry(data.NodeName, *ntDto)
		case *telemetrymodel.NodeIPArpTable:
			nipaDto := data.NodeInfo.(*telemetrymodel.NodeIPArpTable)
			err = ctc.VppCache.SetNodeIPARPs(data.NodeName, *nipaDto)
		default:
			err = fmt.Errorf("node %+v has unknown data type: %+v", data.NodeName, data.NodeInfo)
		}
		if err != nil {
			ctc.Report.logErrAndAppendToNodeReport(data.NodeName, err.Error())
		}
	}
}

func (r *Report) logErrAndAppendToNodeReport(nodeName string, errString string) {
	r.appendToNodeReport(nodeName, errString)
	r.Log.Errorf(errString)
}

func (r *Report) appendToNodeReport(nodeName string, errString string) {
	if r.Data[nodeName] == nil {
		r.Data[nodeName] = make([]string, 0)
	}
	r.Data[nodeName] = append(r.Data[nodeName], errString)
}

func (r *Report) clear() {
	r.Data = make(map[string][]string)
}

func (r *Report) printReport() {
	fmt.Println("Error Report:")
	fmt.Println("=============")
	for k, rl := range r.Data {
		fmt.Printf("Key: %s\n", k)
		for i, line := range rl {
			fmt.Printf("  %d: %s\n", i, line)
		}
		fmt.Println()
	}
}

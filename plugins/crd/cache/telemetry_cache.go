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
	"github.com/contiv/vpp/plugins/crd/api"
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/logging"
	"io/ioutil"
	"net/http"
	"reflect"
	"time"
)

const (
	// here goes different cache types
	//Update this whenever a new DTO type is added.
	numDTOs            = 7
	agentPort          = ":9999"
	livenessURL        = "/liveness"
	interfaceURL       = "/vpp/dump/v1/interfaces"
	bridgeDomainURL    = "/vpp/dump/v1/bd"
	l2FibsURL          = "/vpp/dump/v1/fib"
	telemetryURL       = "/telemetry"
	ipamURL            = "/contiv/v1/ipam"
	arpURL             = "/vpp/dump/v1/arps"
	staticRouteURL     = "/vpp/dump/v1/routes"
	clientTimeout      = 10 // HTTP client timeout, in seconds
	collectionInterval = 1  // data collection interval, in minutes

)

// ContivTelemetryCache is used for a in-memory storage of K8s State data
// The cache processes K8s State data updates and RESYNC events through Update()
// and Resync() APIs, respectively.
// The cache allows to get notified about changes via convenient callbacks.
type ContivTelemetryCache struct {
	Deps

	Synced           bool
	VppCache         api.VppCache
	K8sCache         api.K8sCache
	Processor        api.ContivTelemetryProcessor
	Report           api.Report
	ControllerReport api.ContivTelemetryControllerReport

	nodeResponseChannel  chan *NodeDTO
	dsUpdateChannel      chan interface{}
	dtoList              []*NodeDTO
	ticker               *time.Ticker
	collectionInterval   time.Duration
	httpClientTimeout    time.Duration
	agentPort            string
	validationInProgress bool
	databaseVersion      uint32
}

// Deps lists dependencies of PolicyCache.
type Deps struct {
	Log logging.Logger
}

// NodeDTO is the Data Transfer Object (DTO) for sending data received from
// Contiv node Agent to the cache thread.
type NodeDTO struct {
	NodeName string
	NodeInfo interface{}
	err      error
	version  uint32
}

// Init initializes policy cache.
func (ctc *ContivTelemetryCache) Init() error {
	ctc.init()

	// Start the telemetryCache
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
	ctc.dsUpdateChannel = make(chan interface{})
	ctc.dtoList = make([]*NodeDTO, 0)
	ctc.ticker = time.NewTicker(ctc.collectionInterval)
	ctc.databaseVersion = 0
}

// ClearCache with clear all Contiv Telemetry cache data except for the
// data discovered from etcd updates.
func (ctc *ContivTelemetryCache) ClearCache() {
	ctc.VppCache.ClearCache()
	// ctc.K8sCache.ClearCache()
}

// ReinitializeCache completely re-initializes the Contiv Telemetry cache,
// clearing all data, including discovered vpp and k8s nodes and discovered
// k8s pods.
func (ctc *ContivTelemetryCache) ReinitializeCache() {
	ctc.VppCache.ReinitializeCache()
	ctc.K8sCache.ReinitializeCache()
	ctc.Report.Clear()
}

func (ctc *ContivTelemetryCache) nodeEventProcessor() {
	for {
		select {
		case _, ok := <-ctc.ticker.C:
			ctc.Log.Info("Timer-triggered data collection & validation, status:", ok)
			if !ok {
				return
			}
			ctc.Report.Clear()
			ctc.startNodeInfoCollection()

		case data, ok := <-ctc.nodeResponseChannel:
			ctc.Log.Info("Received node response DTO, status: ", ok)
			if !ok {
				return
			}
			ctc.processNodeResponse(data)

		case data, ok := <-ctc.dsUpdateChannel:
			ctc.Log.Info("Received dsUpdate DTO, status: ", ok)
			if !ok {
				return
			}
			ctc.databaseVersion++
			ctc.dtoList = ctc.dtoList[0:0]
			ctc.processDataStoreUpdate(data)
			ctc.startNodeInfoCollection()
		}
	}
}

func (ctc *ContivTelemetryCache) startNodeInfoCollection() {
	if ctc.validationInProgress {
		ctc.Log.Info("Skipping data collection/validation - previous run still in progress")
		return
	}
	nodelist := ctc.VppCache.RetrieveAllNodes()
	if len(nodelist) == 0 {
		return
	}

	ctc.ClearCache()
	ctc.validationInProgress = true
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
	ctc.Report.SetTimeStamp(time.Now())

	for _, n := range nodelist {
		ctc.Report.AppendToNodeReport(n.Name, "Report done.")
	}
	ctc.Report.Print()
	ctc.ControllerReport.GenerateCRDReport()
}

//Gathers a number of data points for every node in the Node List
func (ctc *ContivTelemetryCache) collectAgentInfo(node *telemetrymodel.Node) {
	client := http.Client{
		Transport:     nil,
		CheckRedirect: nil,
		Jar:           nil,
		Timeout:       ctc.httpClientTimeout,
	}

	go ctc.getNodeInfo(client, node, livenessURL, &telemetrymodel.NodeLiveness{}, ctc.databaseVersion)

	nodeInterfaces := make(telemetrymodel.NodeInterfaces, 0)
	go ctc.getNodeInfo(client, node, interfaceURL, &nodeInterfaces, ctc.databaseVersion)

	nodeBridgeDomains := make(telemetrymodel.NodeBridgeDomains, 0)
	go ctc.getNodeInfo(client, node, bridgeDomainURL, &nodeBridgeDomains, ctc.databaseVersion)

	nodel2fibs := make(telemetrymodel.NodeL2FibTable, 0)
	go ctc.getNodeInfo(client, node, l2FibsURL, &nodel2fibs, ctc.databaseVersion)

	//TODO: Implement getTelemetry correctly.
	//Does not parse information correctly
	//nodetelemetry := make(map[string]NodeTelemetry)
	//go ctc.getNodeInfo(client, node, telemetryURL, &nodetelemetry)

	nodeiparpslice := make(telemetrymodel.NodeIPArpTable, 0)
	go ctc.getNodeInfo(client, node, arpURL, &nodeiparpslice, ctc.databaseVersion)

	nodestaticroutes := make(telemetrymodel.NodeStaticRoutes, 0)
	go ctc.getNodeInfo(client, node, staticRouteURL, &nodestaticroutes, ctc.databaseVersion)

	nodeipam := telemetrymodel.IPamEntry{}
	go ctc.getNodeInfo(client, node, ipamURL, &nodeipam, ctc.databaseVersion)
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
	nodeInfo interface{}, version uint32) {

	res, err := client.Get(ctc.getAgentURL(node.ManIPAddr, url))
	if err != nil {
		err := fmt.Errorf("getNodeInfo: url: %s cleintGet Error: %s", url, err.Error())
		ctc.Log.Error(err)
		ctc.nodeResponseChannel <- &NodeDTO{node.Name, nil, err, version}
		return
	} else if res.StatusCode < 200 || res.StatusCode > 299 {
		err := fmt.Errorf("getNodeInfo: url: %s HTTP res.Status: %s", url, res.Status)
		ctc.Log.Error(err)
		ctc.nodeResponseChannel <- &NodeDTO{node.Name, nil, err, version}
		return
	}

	b, _ := ioutil.ReadAll(res.Body)
	b = []byte(b)
	err = json.Unmarshal(b, nodeInfo)
	if err != nil {
		errString := fmt.Sprintf("Error unmarshaling data for node %+v: %+v", node.Name, err)
		ctc.Report.AppendToNodeReport(node.Name, errString)
	}
	ctc.nodeResponseChannel <- &NodeDTO{node.Name, nodeInfo, err, version}
}

// populateNodeMaps populates many of needed node maps for processing once
// all of the information has been retrieved. It also checks to make sure
// that there are no duplicate addresses within the map.
func (ctc *ContivTelemetryCache) populateNodeMaps(node *telemetrymodel.Node) {
	errReport := ctc.VppCache.SetSecondaryNodeIndices(node)
	for _, r := range errReport {
		ctc.Report.AppendToNodeReport(node.Name, r)
	}

	k8snode, err := ctc.K8sCache.RetrieveK8sNode(node.Name)
	if err != nil {
		errString := fmt.Sprintf("node %s discovered in Contiv, but not present in K8s", node.Name)
		ctc.Report.AppendToNodeReport(node.Name, errString)
	} else {
		for _, adr := range k8snode.Addresses {
			switch adr.Type {
			case nodemodel.NodeAddress_NodeHostName:
				if adr.Address != node.Name {
					errString := fmt.Sprintf("Inconsistent K8s host name for node %s, host name:,%s",
						k8snode.Name, adr.Address)
					ctc.Report.AppendToNodeReport(node.Name, errString)
				}
			case nodemodel.NodeAddress_NodeInternalIP:
				if adr.Address != node.ManIPAddr {
					errString := fmt.Sprintf("Inconsistent Host IP Address for node %s: Contiv: %s, K8s %s",
						k8snode.Name, node.ManIPAddr, adr.Address)
					ctc.Report.AppendToNodeReport(node.Name, errString)
				}
			}
		}
	}

	for _, pod := range ctc.K8sCache.RetrieveAllPods() {
		if pod.HostIPAddress == node.ManIPAddr {
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
	if data.version >= ctc.databaseVersion {
		ctc.dtoList = append(ctc.dtoList, data)
	}
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
			ctc.Report.LogErrAndAppendToNodeReport(data.NodeName, err.Error())
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
		case *telemetrymodel.NodeStaticRoutes:
			nSrDto := data.NodeInfo.(*telemetrymodel.NodeStaticRoutes)
			err = ctc.VppCache.SetNodeStaticRoutes(data.NodeName, *nSrDto)
		case *telemetrymodel.IPamEntry:
			nipamDto := data.NodeInfo.(*telemetrymodel.IPamEntry)
			err = ctc.VppCache.SetNodeIPam(data.NodeName, *nipamDto)
		default:
			err = fmt.Errorf("node %+v has unknown data type: %+v", data.NodeName, data.NodeInfo)
		}
		if err != nil {
			ctc.Report.LogErrAndAppendToNodeReport(data.NodeName, err.Error())
		}
	}
}

func (ctc *ContivTelemetryCache) processDataStoreUpdate(data interface{}) {
	switch data.(type) {

	case datasync.ResyncEvent:
		resyncEv := data.(datasync.ResyncEvent)
		ctc.Report.Clear()
		ctc.resync(resyncEv)

	case datasync.ChangeEvent:
		dataChngEv := data.(datasync.ChangeEvent)
		if err := ctc.update(dataChngEv); err != nil {
			ctc.Log.Errorf("data update error, %s", err.Error())
			ctc.Synced = false
			// TODO: initiate resync at this point
		}

	default:
		ctc.Log.Errorf("unknown type received, %s", reflect.TypeOf(data))
	}
}

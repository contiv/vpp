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
	"github.com/contiv/vpp/plugins/crd/datastore"
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
	numDTOs   = 8
	agentPort = ":9999"

	livenessURL       = "/liveness"
	linuxInterfaceURL = "/linux/dump/v1/interfaces"
	ipamURL           = "/contiv/v1/ipam"
	telemetryURL      = "/telemetry"

	nodeInterfaceURL = "/vpp/dump/v1/interfaces"
	bridgeDomainURL  = "/vpp/dump/v1/bd"
	l2FibsURL        = "/vpp/dump/v1/fib"
	arpURL           = "/vpp/dump/v1/arps"
	staticRouteURL   = "/vpp/dump/v1/routes"

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
	Verbose          bool

	nodeResponseChannel  chan *NodeDTO
	dsUpdateChannel      chan interface{}
	dtoList              []*NodeDTO
	ticker               *time.Ticker
	collectionInterval   time.Duration
	httpClientTimeout    time.Duration
	agentPort            string
	validationInProgress bool
	databaseVersion      uint32
	dataChangeEvents     DcEventQueue

	nValidations uint32
	nUpdates     uint32
	nResyncs     uint32
	nnResponses  uint32
}

// Deps lists dependencies of PolicyCache.
type Deps struct {
	Log logging.Logger
}

// DcEventQueue defines the queue for data change events coming from Etcd.
type DcEventQueue []interface{}

// NodeDTO is the Data Transfer Object (DTO) for sending data received from
// Contiv node Agent to the cache thread.
type NodeDTO struct {
	NodeName string
	URL      string
	NodeInfo interface{}
	err      error
	version  uint32
}

// NewTelemetryCache returns a new instance of telemetry cache
func NewTelemetryCache(p logging.PluginLogger, verbose bool) *ContivTelemetryCache {
	return &ContivTelemetryCache{
		Deps: Deps{
			Log: p.NewLogger("-telemetryCache"),
		},
		Synced:   false,
		VppCache: datastore.NewVppDataStore(),
		K8sCache: datastore.NewK8sDataStore(),
		Report:   datastore.NewSimpleReport(p.NewLogger("-report")),
		Verbose:  verbose,

		agentPort:            agentPort,
		collectionInterval:   collectionInterval * time.Minute,
		httpClientTimeout:    clientTimeout * time.Second,
		validationInProgress: false,

		nodeResponseChannel: make(chan *NodeDTO),
		dsUpdateChannel:     make(chan interface{}),
		dtoList:             make([]*NodeDTO, 0),
		dataChangeEvents:    make(DcEventQueue, 0),
		ticker:              time.NewTicker(collectionInterval * time.Minute),
		databaseVersion:     0,
	}
}

// Init initializes policy cache.
func (ctc *ContivTelemetryCache) Init() error {
	go ctc.nodeEventProcessor()
	ctc.Log.Infof("ContivTelemetryCache init done")
	return nil
}

// ClearCache clears all Contiv Telemetry cache data except for the
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

// nodeEventProcessor is the main processing loop for the Telemetry Cache.
// It performs three tasks:
// - Listens to data change and resync events from EtcdEtcd . It queues incoming
//   events for further processing
// - Performs periodic validations of the cluster. The validations are
//   triggered by a timer. Upon receiving a validation trigger, the queued
//   data change and resync events are processed, the VPP and K8s config state
//   caches are updated and collection of real-time state from VPP Agents in
//   the cluster is started.
// - Collects all incoming real-time state from the cluster and starts the
//   validation of the cluster state
func (ctc *ContivTelemetryCache) nodeEventProcessor() {
	for {
		select {
		case /*_, _ok := */ <-ctc.ticker.C:
			// TODO: update CRD to reflect the refactored vpp-agent
			ctc.Log.Info("SKIPPING timer-triggered data collection & validation")
			return
			/*
				ctc.Log.Info("Timer-triggered data collection & validation, status:", ok)
				if !ok {
					return
				}
				ctc.Report.Clear()
				ctc.processQueuedDataStoreUpdates()
				ctc.startNodeInfoCollection()
			*/

		case data, ok := <-ctc.nodeResponseChannel:
			if !ok {
				ctc.Log.Error("error getting node response DTO")
				return
			}
			ctc.Log.Infof("Node response DTO from %s, url %s, DTOv: %d DBv: %d",
				data.NodeName, data.URL, data.version, ctc.databaseVersion)
			ctc.processNodeResponse(data)

		case data, ok := <-ctc.dsUpdateChannel:
			ctc.Log.Info("dsUpdate DTO, status: ", ok)
			if !ok {
				return
			}
			ctc.dataChangeEvents = append(ctc.dataChangeEvents, data)
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
		ctc.collectAgentInfo(node)
	}
}

// validateCluster checks the consistency of data in various contiv data stores.
// It correlates the configured (desired) cluster state from Etcd and with data
// retrieved from Contiv vswitches running in the cluster (actual state) and
// reports any errors that it finds.
func (ctc *ContivTelemetryCache) validateCluster() {

	nodelist := ctc.VppCache.RetrieveAllNodes()
	for _, node := range nodelist {
		ctc.populateNodeMaps(node)
	}
	ctc.Log.Info("Beginning validation of Node Data")
	ctc.Processor.Validate()
	ctc.Report.SetTimeStamp(time.Now())

	ctc.nValidations++
	ctc.Log.Infof("validations: %d, resyncs: %d, updates: %d, responses: %d\n",
		ctc.nValidations, ctc.nResyncs, ctc.nUpdates, ctc.nnResponses)
	if ctc.Verbose {
		ctc.Report.Print()
	}

	ctc.ControllerReport.GenerateCRDReport()
}

// Collect real-time node state (mainly VPP, but some Linux too) from the
// specified node's VPP Agent.
func (ctc *ContivTelemetryCache) collectAgentInfo(node *telemetrymodel.Node) {
	client := http.Client{
		Transport:     nil,
		CheckRedirect: nil,
		Jar:           nil,
		Timeout:       ctc.httpClientTimeout,
	}
	ctc.Report.SetPrefix("HTTP")

	go ctc.getNodeInfo(client, node, livenessURL, &telemetrymodel.NodeLiveness{}, ctc.databaseVersion)

	nodeInterfaces := make(telemetrymodel.NodeInterfaces, 0)
	go ctc.getNodeInfo(client, node, nodeInterfaceURL, &nodeInterfaces, ctc.databaseVersion)

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

	linuxInterfaces := make(telemetrymodel.LinuxInterfaces, 0)
	go ctc.getNodeInfo(client, node, linuxInterfaceURL, &linuxInterfaces, ctc.databaseVersion)

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
		ctc.nodeResponseChannel <- &NodeDTO{node.Name, url, nil, err, version}
		return
	} else if res.StatusCode < 200 || res.StatusCode > 299 {
		err := fmt.Errorf("HTTP Get error: url %s, Status: %s", url, res.Status)
		ctc.nodeResponseChannel <- &NodeDTO{node.Name, url, nil, err, version}
		return
	}

	b, _ := ioutil.ReadAll(res.Body)
	defer res.Body.Close()

	err = json.Unmarshal(b, nodeInfo)
	if err != nil {
		errString := fmt.Sprintf("failed to unmarshal data for node %s, error %s", node.Name, err)
		ctc.Report.AppendToNodeReport(node.Name, errString)
	}
	ctc.nodeResponseChannel <- &NodeDTO{node.Name, url, nodeInfo, err, version}
}

// populateNodeMaps populates many of needed node maps for processing once
// all of the information has been retrieved. It also checks to make sure
// that there are no duplicate addresses within the map.
func (ctc *ContivTelemetryCache) populateNodeMaps(node *telemetrymodel.Node) {
	ctc.Report.SetPrefix("NODE-MAP")
	errReport := ctc.VppCache.SetSecondaryNodeIndices(node)
	for _, r := range errReport {
		ctc.Report.AppendToNodeReport(node.Name, r)
	}

	k8snode, err := ctc.K8sCache.RetrieveK8sNode(node.Name)
	if err != nil {
		errString := fmt.Sprintf("VPP node %s present in Contiv, but not in K8s", node.Name)
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

	node.PodMap = make(map[string]*telemetrymodel.Pod, 0)
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

// waitForValidationToFinish waits until the the next hod validation finishes
func (ctc *ContivTelemetryCache) waitForValidationToFinish() int {
	cycles := 0
	current := ctc.nValidations + 1

	for {
		if current == ctc.nValidations {
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
	ctc.nnResponses++

	nodelist := ctc.VppCache.RetrieveAllNodes()
	if data.version >= ctc.databaseVersion {
		ctc.dtoList = append(ctc.dtoList, data)
	}

	if len(ctc.dtoList) == numDTOs*len(nodelist) {
		ctc.setNodeData()
		ctc.validateCluster()
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
			errString := fmt.Sprintf("node '%s', error '%s'", data.NodeName, data.err)
			ctc.Report.AppendToNodeReport(data.NodeName, errString)
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
		case *telemetrymodel.LinuxInterfaces:
			liDto := data.NodeInfo.(*telemetrymodel.LinuxInterfaces)
			err = ctc.VppCache.SetLinuxInterfaces(data.NodeName, *liDto)

		default:
			err = fmt.Errorf("node %+v has unknown data type: %+v", data.NodeName, data.NodeInfo)
		}
		if err != nil {
			ctc.Report.AppendToNodeReport(data.NodeName, err.Error())
		}
	}
}

// processQueuedDataStoreUpdates processes all Etcd resync and data change events that
// have been queued up since the last validation run. While collection of real-
// time data from VPP Agents and cluster validation is going on, incoming resync
// and data change events are queued up.
// We also increment the DB version here - DB version number is used to eliminate
// delayed responses from the network (i.e. responses to requests from previous
// validation runs).
func (ctc *ContivTelemetryCache) processQueuedDataStoreUpdates() {
	for _, data := range ctc.dataChangeEvents {
		switch data.(type) {

		case datasync.ResyncEvent:
			ctc.nResyncs++
			resyncEv := data.(datasync.ResyncEvent)
			ctc.Report.Clear()
			ctc.resync(resyncEv)

		case datasync.ChangeEvent:
			ctc.nUpdates++
			dataChngEv := data.(datasync.ChangeEvent)
			for _, dataChng := range dataChngEv.GetChanges() {
				if err := ctc.update(dataChng); err != nil {
					ctc.Log.Errorf("data update error, %s", err.Error())
					ctc.Synced = false
					// TODO: initiate resync at this point
				}
			}

		default:
			ctc.Log.Errorf("unknown event type received, %s", reflect.TypeOf(data))
			continue
		}
		ctc.dataChangeEvents = make(DcEventQueue, 0)
	}

	ctc.databaseVersion++
	ctc.dtoList = ctc.dtoList[0:0]
}

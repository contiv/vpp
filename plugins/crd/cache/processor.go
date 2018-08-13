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

package cache

import (
	"encoding/json"
	"fmt"
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"io/ioutil"
	"net/http"
	"time"
)

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

// NodeDTO holds generic node information to be sent over a channel and associated with a name in the cache.
type NodeDTO struct {
	NodeName string
	NodeInfo interface{}
	err      error
}

// ContivTelemetryProcessor defines the processor's data structures and dependencies
type ContivTelemetryProcessor struct {
	Deps
	nodeResponseChannel  chan *NodeDTO
	networkInfoGetCh     chan bool
	ContivTelemetryCache *ContivTelemetryCache
	dtoList              []*NodeDTO
	ticker               *time.Ticker
	collectionInterval   time.Duration
	httpClientTimeout    time.Duration
	agentPort            string
	validationInProgress bool
}

func (p *ContivTelemetryProcessor) init() {
	p.nodeResponseChannel = make(chan *NodeDTO)
	p.networkInfoGetCh = make(chan bool)
	p.dtoList = make([]*NodeDTO, 0)
	p.agentPort = agentPort
	p.collectionInterval = collectionInterval * time.Minute
	p.ticker = time.NewTicker(p.collectionInterval)
	p.httpClientTimeout = clientTimeout * time.Second
	p.validationInProgress = false
}

// Init initializes the processor.
func (p *ContivTelemetryProcessor) Init() error {
	// initialize structures, dependencies and attributes
	p.init()
	// Start the processor
	go p.nodeEventProcessor()
	return nil
}

// RetrieveNetworkInfo triggers the processor to retrieve vpp data from all
// agents in the cluster and validate it.
func (p *ContivTelemetryProcessor) RetrieveNetworkInfo() {
	p.networkInfoGetCh <- true
}

func (p *ContivTelemetryProcessor) nodeEventProcessor() {
	for {
		select {
		case _, ok := <-p.ticker.C:
			p.Log.Info("Timer-triggered data collection & validation, status:", ok)
			if !ok {
				return
			}
			p.startNodeInfoCollection()

		case _, ok := <-p.networkInfoGetCh:
			p.Log.Info("Externally triggered data collection & validation, status: ", ok)
			if !ok {
				return
			}
			p.startNodeInfoCollection()

		case data, ok := <-p.nodeResponseChannel:
			p.Log.Info("Received DTO, status: ", ok)
			if !ok {
				return
			}
			p.processNodeResponse(data)
		}
	}
}

func (p *ContivTelemetryProcessor) startNodeInfoCollection() {
	if p.validationInProgress {
		p.Log.Info("Skipping data collection/validation - previous run still in progress")
		return
	}
	p.validationInProgress = true
	p.ContivTelemetryCache.ClearCache()

	nodelist := p.ContivTelemetryCache.ListAllVppNodes()
	for _, node := range nodelist {
		p.collectNodeInfo(node)
	}
}

// collectNodeInfo collects node data from all agents in the Contiv
// cluster and puts it in the cache
func (p *ContivTelemetryProcessor) collectNodeInfo(node *telemetrymodel.Node) {
	p.collectAgentInfo(node)
}

// validateNodeInfo checks the consistency of the node data in the cache. It
// checks the ARP tables, ... . Data inconsistencies may cause loss of
// connectivity between nodes or pods. All sata inconsistencies found during
// validation are reported to the CRD.
func (p *ContivTelemetryProcessor) validateNodeInfo() {

	nodelist := p.ContivTelemetryCache.ListAllVppNodes()
	for _, node := range nodelist {
		p.ContivTelemetryCache.PopulateNodeMaps(node)
	}
	p.Log.Info("Beginning validation of Node Data")

	p.ContivTelemetryCache.ValidateArpTables()

	p.ContivTelemetryCache.ValidateL2Connectivity()

	p.ContivTelemetryCache.ValidateL2FibEntries()

	p.ContivTelemetryCache.ValidateK8sNodeInfo()

	p.ContivTelemetryCache.ValidatePodInfo()

	for _, n := range nodelist {
		p.ContivTelemetryCache.appendToNodeReport(n.Name, "Report done.")
	}
	p.ContivTelemetryCache.Report.printReport()
}

//Gathers a number of data points for every node in the Node List
func (p *ContivTelemetryProcessor) collectAgentInfo(node *telemetrymodel.Node) {
	client := http.Client{
		Transport:     nil,
		CheckRedirect: nil,
		Jar:           nil,
		Timeout:       p.httpClientTimeout,
	}

	go p.getNodeInfo(client, node, livenessURL, &telemetrymodel.NodeLiveness{})

	nodeInterfaces := make(telemetrymodel.NodeInterfaces, 0)
	go p.getNodeInfo(client, node, interfaceURL, &nodeInterfaces)

	nodeBridgeDomains := make(telemetrymodel.NodeBridgeDomains, 0)
	go p.getNodeInfo(client, node, bridgeDomainURL, &nodeBridgeDomains)

	nodel2fibs := make(telemetrymodel.NodeL2FibTable, 0)
	go p.getNodeInfo(client, node, l2FibsURL, &nodel2fibs)

	//TODO: Implement getTelemetry correctly.
	//Does not parse information correctly
	//nodetelemetry := make(map[string]NodeTelemetry)
	//go p.getNodeInfo(client, node, telemetryURL, &nodetelemetry)

	nodeiparpslice := make(telemetrymodel.NodeIPArpTable, 0)
	go p.getNodeInfo(client, node, arpURL, &nodeiparpslice)
}

/* Here are the several functions that run as goroutines to collect information
about a specific node using an http client. First, an http request is made to the
specific url and port of the desired information and the request received is read
and unmarshalled into a struct to contain that information. Then, a data transfer
object is created to hold the struct of information as well as the name and is sent
over the plugins node database channel to node_db_processor.go where it will be read,
processed, and added to the node database.
*/
func (p *ContivTelemetryProcessor) getNodeInfo(client http.Client, node *telemetrymodel.Node, url string,
	nodeInfo interface{}) {

	res, err := client.Get(p.getAgentURL(node.ManIPAdr, url))
	if err != nil {
		err := fmt.Errorf("getNodeInfo: url: %s cleintGet Error: %s", url, err.Error())
		p.Log.Error(err)
		p.nodeResponseChannel <- &NodeDTO{node.Name, nil, err}
		return
	} else if res.StatusCode < 200 || res.StatusCode > 299 {
		err := fmt.Errorf("getNodeInfo: url: %s HTTP res.Status: %s", url, res.Status)
		p.Log.Error(err)
		p.nodeResponseChannel <- &NodeDTO{node.Name, nil, err}
		return
	}

	b, _ := ioutil.ReadAll(res.Body)
	b = []byte(b)
	json.Unmarshal(b, nodeInfo)

	p.nodeResponseChannel <- &NodeDTO{node.Name, nodeInfo, nil}
}

// getAgentURL creates the URL for the data we're trying to retrieve
func (p *ContivTelemetryProcessor) getAgentURL(ipAddr string, url string) string {
	return "http://" + ipAddr + p.agentPort + url
}

// waitForValidationToFinish waits until the node cache has been cleared at
// the end of data validation
func (p *ContivTelemetryProcessor) waitForValidationToFinish() int {
	cycles := 0
	for {
		if !p.validationInProgress {
			return cycles
		}
		time.Sleep(1 * time.Millisecond)
		cycles++
	}
}

// nodeResponseProcessor will read the nodeDTO map and make sure that each
// node has enough DTOs to fully process information. It then clears the
// node DTO map after it is finished with it.
func (p *ContivTelemetryProcessor) processNodeResponse(data *NodeDTO) {
	nodelist := p.ContivTelemetryCache.ListAllVppNodes()
	p.dtoList = append(p.dtoList, data)
	if len(p.dtoList) == numDTOs*len(nodelist) {
		p.setNodeData()
		p.validateNodeInfo()
		p.dtoList = p.dtoList[0:0]
		p.validationInProgress = false
	}
}

// setNodeData will iterate through the dtoList, read the type of dto, and
// assign the dto info to the name associated with the DTO.
func (p *ContivTelemetryProcessor) setNodeData() {
	for _, data := range p.dtoList {
		err := error(nil)

		if data.err != nil {
			err = fmt.Errorf("node %+v has nodeDTO %+v and http error %s", data.NodeName, data, data.err)
			p.ContivTelemetryCache.logErrAndAppendToNodeReport(data.NodeName, err.Error())
			continue
		}

		switch data.NodeInfo.(type) {
		case *telemetrymodel.NodeLiveness:
			nl := data.NodeInfo.(*telemetrymodel.NodeLiveness)
			err = p.ContivTelemetryCache.VppCache.SetNodeLiveness(data.NodeName, nl)
		case *telemetrymodel.NodeInterfaces:
			niDto := data.NodeInfo.(*telemetrymodel.NodeInterfaces)
			err = p.ContivTelemetryCache.VppCache.SetNodeInterfaces(data.NodeName, *niDto)
		case *telemetrymodel.NodeBridgeDomains:
			nbdDto := data.NodeInfo.(*telemetrymodel.NodeBridgeDomains)
			err = p.ContivTelemetryCache.VppCache.SetNodeBridgeDomain(data.NodeName, *nbdDto)
		case *telemetrymodel.NodeL2FibTable:
			nl2fDto := data.NodeInfo.(*telemetrymodel.NodeL2FibTable)
			err = p.ContivTelemetryCache.VppCache.SetNodeL2Fibs(data.NodeName, *nl2fDto)
		case *telemetrymodel.NodeTelemetries:
			ntDto := data.NodeInfo.(*telemetrymodel.NodeTelemetries)
			err = p.ContivTelemetryCache.VppCache.SetNodeTelemetry(data.NodeName, *ntDto)
		case *telemetrymodel.NodeIPArpTable:
			nipaDto := data.NodeInfo.(*telemetrymodel.NodeIPArpTable)
			err = p.ContivTelemetryCache.VppCache.SetNodeIPARPs(data.NodeName, *nipaDto)
		default:
			err = fmt.Errorf("node %+v has unknown data type: %+v", data.NodeName, data.NodeInfo)
		}
		if err != nil {
			p.ContivTelemetryCache.logErrAndAppendToNodeReport(data.NodeName, err.Error())
		}
	}
}

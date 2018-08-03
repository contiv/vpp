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
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"time"
)

const (
	agentPort       = ":9999"
	livenessURL     = "/liveness"
	timeout         = 10
	interfaceURL    = "/interfaces"
	bridgeDomainURL = "/bridgedomains"
	l2FibsURL       = "/l2fibs"
	telemetryURL    = "/telemetry"
	arpURL          = "/arps"
)

// ContivTelemetryProcessor defines the processor's data structures and dependencies
type ContivTelemetryProcessor struct {
	Deps
	nodeResponseChannel  chan *NodeDTO
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
	p.dtoList = make([]*NodeDTO, 0)
	p.agentPort = agentPort
	p.collectionInterval = 1 * time.Minute
	p.ticker = time.NewTicker(p.collectionInterval)
	p.httpClientTimeout = timeout * time.Second
	p.validationInProgress = false
}

// Init initializes the processor.
func (p *ContivTelemetryProcessor) Init() error {
	// initialize structures, dependencies and attributes
	p.init()
	// Start goroutines
	go p.ProcessNodeResponses()
	go p.retrieveNetworkInfoOnTimerExpiry()
	return nil
}

// CollectNodeInfo collects node data from all agents in the Contiv
// cluster and puts it in the cache
func (p *ContivTelemetryProcessor) CollectNodeInfo(node *Node) {
	p.validationInProgress = true
	p.collectAgentInfo(node)
}

// ValidateNodeInfo checks the consistency of the node data in the cache. It
// checks the ARP tables, ... . Data inconsistencies may cause loss of
// connectivity between nodes or pods. All sata inconsistencies found during
// validation are reported to the CRD.
func (p *ContivTelemetryProcessor) ValidateNodeInfo() {

	nodelist := p.ContivTelemetryCache.Cache.GetAllNodes()
	for _, node := range nodelist {
		p.ContivTelemetryCache.Cache.PopulateNodeMaps(node)
	}
	p.Log.Info("Beginning validation of Node Data")

	p.ContivTelemetryCache.Cache.ValidateLoopIFAddresses()

	p.ContivTelemetryCache.Cache.ValidateL2Connections()

	p.ContivTelemetryCache.Cache.ValidateFibEntries()

	for _, entry := range p.ContivTelemetryCache.Cache.report {
		p.Log.Info(entry)
		for _, node := range p.ContivTelemetryCache.Cache.nMap {
			p.Log.Infof("Report for %+v", node.Name)
			p.Log.Info(node.report)
			node.report = node.report[0:0]
		}
	}

}

//Gathers a number of data points for every node in the Node List
func (p *ContivTelemetryProcessor) collectAgentInfo(node *Node) {
	client := http.Client{
		Transport:     nil,
		CheckRedirect: nil,
		Jar:           nil,
		Timeout:       p.httpClientTimeout,
	}

	go p.getNodeInfo(client, node, livenessURL, &NodeLiveness{})

	nodeInterfaces := make(nodeInterfacesMapType, 0)
	go p.getNodeInfo(client, node, interfaceURL, &nodeInterfaces)

	nodeBridgeDomains := make(nodeBridgeDomainMapTypes, 0)
	go p.getNodeInfo(client, node, bridgeDomainURL, &nodeBridgeDomains)

	nodel2fibs := make(nodeL2FibMapTypes, 0)
	go p.getNodeInfo(client, node, l2FibsURL, &nodel2fibs)

	//TODO: Implement getTelemetry correctly.
	//Does not parse information correctly
	//nodetelemetry := make(map[string]NodeTelemetry)
	//go p.getNodeInfo(client, node, telemetryURL, &nodetelemetry)

	nodeiparpslice := make(nodeIPARPMapTypes, 0)
	go p.getNodeInfo(client, node, arpURL, &nodeiparpslice)

}

func (p *ContivTelemetryProcessor) retrieveNetworkInfoOnTimerExpiry() {
	for range p.ticker.C {
		nodelist := p.ContivTelemetryCache.Cache.GetAllNodes()

		p.Log.Info("Timer has expired; Beginning gathering of information.")
		p.ContivTelemetryCache.ClearCache()
		for _, node := range nodelist {
			p.CollectNodeInfo(node)
		}
	}
}

/* Here are the several functions that run as goroutines to collect information
about a specific node using an http client. First, an http request is made to the
specific url and port of the desired information and the request received is read
and unmarshalled into a struct to contain that information. Then, a data transfer
object is created to hold the struct of information as well as the name and is sent
over the plugins node database channel to node_db_processor.go where it will be read,
processed, and added to the node database.
*/
func (p *ContivTelemetryProcessor) getNodeInfo(client http.Client, node *Node, url string, nodeInfo interface{}) {
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

//ProcessNodeResponses will read the nodeDTO map and make sure that each node has
//enough DTOS to fully process information. It then clears the node DTO map after it
//is finished with it.
func (p *ContivTelemetryProcessor) ProcessNodeResponses() {
	for data := range p.nodeResponseChannel {
		nodelist := p.ContivTelemetryCache.Cache.GetAllNodes()
		p.dtoList = append(p.dtoList, data)
		if len(p.dtoList) == numDTOs*len(nodelist) {
			p.SetNodeData()
			p.ValidateNodeInfo()
			p.dtoList = p.dtoList[0:0]
			p.validationInProgress = false
		}
	}
}

// SetNodeData will iterate through the dtoList, read the type of dto, and assign the dto info to the name
// associated with the DTO.
func (p *ContivTelemetryProcessor) SetNodeData() {
	for _, data := range p.dtoList {
		if data.err != nil {
			p.ContivTelemetryCache.Cache.report = append(p.ContivTelemetryCache.Cache.report, errors.Errorf(
				"Node %+v has nodeDTO %+v and http error %s", data.NodeName, data, data.err).Error())
			continue
		}
		switch data.NodeInfo.(type) {
		case *NodeLiveness:
			nl := data.NodeInfo.(*NodeLiveness)
			p.ContivTelemetryCache.Cache.SetNodeLiveness(data.NodeName, nl)
		case *nodeInterfacesMapType:
			niDto := data.NodeInfo.(*nodeInterfacesMapType)
			p.ContivTelemetryCache.Cache.SetNodeInterfaces(data.NodeName, *niDto)
		case *nodeBridgeDomainMapTypes:
			nbdDto := data.NodeInfo.(*nodeBridgeDomainMapTypes)
			p.ContivTelemetryCache.Cache.SetNodeBridgeDomain(data.NodeName, *nbdDto)
		case *nodeL2FibMapTypes:
			nl2fDto := data.NodeInfo.(*nodeL2FibMapTypes)
			p.ContivTelemetryCache.Cache.SetNodeL2Fibs(data.NodeName, *nl2fDto)
		case *nodeTelemetryMapTypes:
			ntDto := data.NodeInfo.(*nodeTelemetryMapTypes)
			p.ContivTelemetryCache.Cache.SetNodeTelemetry(data.NodeName, *ntDto)
		case *nodeIPARPMapTypes:
			nipaDto := data.NodeInfo.(*nodeIPARPMapTypes)
			p.ContivTelemetryCache.Cache.SetNodeIPARPs(data.NodeName, *nipaDto)
		default:
			p.Log.Errorf("Node %+v has unknown data type: %+v", data.NodeName, data.NodeInfo)
		}

	}

}

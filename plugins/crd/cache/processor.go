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
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"time"
)

const (
	agentPort       = ":9999"
	livenessURL     = "/liveness"
	timeout         = 100000000000
	interfaceURL    = "/interfaces"
	bridgeDomainURL = "/bridgedomains"
	l2FibsURL       = "/l2fibs"
	telemetryURL    = "/telemetry"
	arpURL          = "/arps"
)

// ContivTelemetryProcessor defines the processor's data structures and dependencies
type ContivTelemetryProcessor struct {
	Deps
	nodeResponseChannel  chan interface{}
	ContivTelemetryCache *ContivTelemetryCache
	dtoList              []interface{}
	ticker               *time.Ticker
	collectionInterval   time.Duration
	agentPort            string
}

// Init initializes the processor.
func (p *ContivTelemetryProcessor) Init() error {
	// initialize structures, dependencies and attributes
	p.nodeResponseChannel = make(chan interface{})
	p.dtoList = make([]interface{}, 0)
	p.agentPort = agentPort
	p.collectionInterval = 1 * time.Minute
	p.ticker = time.NewTicker(p.collectionInterval)

	// Start goroutines
	go p.ProcessNodeResponses()
	go p.retrieveNetworkInfoOnTimerExpiry()
	return nil
}

// CollectNodeInfo collects node data from all agents in the Contiv
// cluster and puts it in the cache
func (p *ContivTelemetryProcessor) CollectNodeInfo(node *Node) {
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
	}

}

//Gathers a number of data points for every node in the Node List
func (p *ContivTelemetryProcessor) collectAgentInfo(node *Node) {
	client := http.Client{
		Transport:     nil,
		CheckRedirect: nil,
		Jar:           nil,
		Timeout:       timeout,
	}

	go p.getLivenessInfo(client, node)

	go p.getInterfaceInfo(client, node)

	go p.getBridgeDomainInfo(client, node)

	go p.getL2FibInfo(client, node)

	//TODO: Implement getTelemetry correctly.
	//Does not parse information correctly
	//go p.getTelemetryInfo(client, node)

	go p.getIPArpInfo(client, node)

}

func (p *ContivTelemetryProcessor) retrieveNetworkInfoOnTimerExpiry() {

	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		nodelist := p.ContivTelemetryCache.Cache.GetAllNodes()

		p.Log.Info("Timer has expired; Beginning gathering of information.")
		p.ContivTelemetryCache.Cache.report = p.ContivTelemetryCache.Cache.report[0:0]
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
func (p *ContivTelemetryProcessor) getLivenessInfo(client http.Client, node *Node) {
	res, err := client.Get(p.getAgentURL(node.ManIPAdr, livenessURL))
	if err != nil {
		p.Log.Error(err)
		p.nodeResponseChannel <- NodeLivenessDTO{node.Name, nil, err}
		return
	} else if res.StatusCode < 200 || res.StatusCode > 299 {
		err := errors.Errorf("HTTP response is: %+v", res.Status)
		p.nodeResponseChannel <- NodeLivenessDTO{node.Name, nil, err}
	}
	b, _ := ioutil.ReadAll(res.Body)
	b = []byte(b)
	nodeInfo := &NodeLiveness{}
	json.Unmarshal(b, nodeInfo)
	p.nodeResponseChannel <- NodeLivenessDTO{node.Name, nodeInfo, nil}

}

func (p *ContivTelemetryProcessor) getInterfaceInfo(client http.Client, node *Node) {
	res, err := client.Get(p.getAgentURL(node.ManIPAdr, interfaceURL))
	if err != nil {
		p.Log.Error(err)
		p.nodeResponseChannel <- NodeInterfacesDTO{node.Name, nil, err}
		p.nodeResponseChannel <- node.Name
		return
	} else if res.StatusCode < 200 || res.StatusCode > 299 {
		err := errors.Errorf("HTTP response is: %+v", res.Status)
		p.nodeResponseChannel <- NodeInterfacesDTO{node.Name, nil, err}
	}
	b, _ := ioutil.ReadAll(res.Body)
	b = []byte(b)

	nodeInterfaces := make(map[int]NodeInterface, 0)
	json.Unmarshal(b, &nodeInterfaces)
	p.nodeResponseChannel <- NodeInterfacesDTO{node.Name, nodeInterfaces, nil}
}
func (p *ContivTelemetryProcessor) getBridgeDomainInfo(client http.Client, node *Node) {
	res, err := client.Get(p.getAgentURL(node.ManIPAdr, bridgeDomainURL))
	if err != nil {
		p.Log.Error(err)
		p.nodeResponseChannel <- NodeBridgeDomainsDTO{node.Name, nil, err}
		return
	} else if res.StatusCode < 200 || res.StatusCode > 299 {
		err := errors.Errorf("HTTP response is: %+v", res.Status)
		p.nodeResponseChannel <- NodeBridgeDomainsDTO{node.Name, nil, err}
	}
	b, _ := ioutil.ReadAll(res.Body)
	b = []byte(b)

	nodeBridgeDomains := make(map[int]NodeBridgeDomains)
	json.Unmarshal(b, &nodeBridgeDomains)
	p.nodeResponseChannel <- NodeBridgeDomainsDTO{node.Name, nodeBridgeDomains, nil}
}

func (p *ContivTelemetryProcessor) getL2FibInfo(client http.Client, node *Node) {
	res, err := client.Get(p.getAgentURL(node.ManIPAdr, l2FibsURL))
	if err != nil {
		p.Log.Error(err)
		p.nodeResponseChannel <- NodeL2FibsDTO{node.Name, nil, err}
		return
	} else if res.StatusCode < 200 || res.StatusCode > 299 {
		err := errors.Errorf("HTTP response is: %+v", res.Status)
		p.nodeResponseChannel <- NodeL2FibsDTO{node.Name, nil, err}
	}
	b, _ := ioutil.ReadAll(res.Body)
	b = []byte(b)
	nodel2fibs := make(map[string]NodeL2Fib)
	json.Unmarshal(b, &nodel2fibs)
	p.nodeResponseChannel <- NodeL2FibsDTO{node.Name, nodel2fibs, nil}
}

func (p *ContivTelemetryProcessor) getTelemetryInfo(client http.Client, node *Node) {
	res, err := client.Get(p.getAgentURL(node.ManIPAdr, telemetryURL))
	if err != nil {
		p.Log.Error(err)
		p.nodeResponseChannel <- NodeTelemetryDTO{node.Name, nil, err}
		return
	} else if res.StatusCode < 200 || res.StatusCode > 299 {
		err := errors.Errorf("HTTP response is: %+v", res.Status)
		p.nodeResponseChannel <- NodeTelemetryDTO{node.Name, nil, err}
	}
	b, _ := ioutil.ReadAll(res.Body)
	b = []byte(b)
	nodetelemetry := make(map[string]NodeTelemetry)
	json.Unmarshal(b, &nodetelemetry)
	p.nodeResponseChannel <- NodeTelemetryDTO{node.Name, nodetelemetry, nil}
}

func (p *ContivTelemetryProcessor) getIPArpInfo(client http.Client, node *Node) {
	res, err := client.Get(p.getAgentURL(node.ManIPAdr, arpURL))
	if err != nil {
		p.Log.Error(err)
		p.nodeResponseChannel <- NodeIPArpDTO{[]NodeIPArp{}, node.Name, err}
		return
	} else if res.StatusCode < 200 || res.StatusCode > 299 {
		err := errors.Errorf("HTTP response is: %+v", res.Status)
		p.nodeResponseChannel <- NodeIPArpDTO{nil, node.Name, err}
	}
	b, _ := ioutil.ReadAll(res.Body)

	b = []byte(b)
	nodeiparpslice := make([]NodeIPArp, 0)
	json.Unmarshal(b, &nodeiparpslice)
	p.nodeResponseChannel <- NodeIPArpDTO{nodeiparpslice, node.Name, nil}
}

// getAgentURL creates the URL for the data we're trying to retrieve
func (p *ContivTelemetryProcessor) getAgentURL(ipAddr string, url string) string {
	return "http://" + ipAddr + p.agentPort + url
}

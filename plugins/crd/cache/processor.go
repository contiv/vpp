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
	"net/http"
	"io/ioutil"
	"encoding/json"
)

const (
	livenessPort      = ":9999"
	livenessURL       = "/liveness"
	timeout           = 100000000000
	interfacePort     = ":9999"
	interfaceURL      = "/interfaces"
	bridgeDomainsPort = ":9999"
	bridgeDomainURL   = "/bridgedomains"
	l2FibsPort        = ":9999"
	l2FibsURL         = "/l2fibs"
	telemetryPort     = ":9999"
	telemetryURL      = "/telemetry"
	arpPort           = ":9999"
	arpURL            = "/arps"
)

// ContivTelemetryProcessor defines the processor's data structures and
// dependencies
type ContivTelemetryProcessor struct {
	Deps
	dbChannel chan interface{}
	Cache *Cache
	Processor *ContivTelemetryProcessor
}


// Init initializes the processor
func (p *ContivTelemetryProcessor) Init() error {
	p.dbChannel = make(chan interface{})
	return nil
}

// CollectNodeInfo collects node data from all agents in the Contiv
// cluster and puts it in the cache
func (p *ContivTelemetryProcessor) CollectNodeInfo(node *Node) {

	p.collectAgentInfo(node)

	p.ProcessNodeData()

	p.Cache.PopulateNodeMaps(node)

}

// ValidateNodeInfo checks the consistency of the node data in the cache. It
// checks the ARP tables, ... . Data inconsistencies may cause loss of
// connectivity between nodes or pods. All sata inconsistencies found during
// validation are reported to the CRD.
func (p *ContivTelemetryProcessor) ValidateNodeInfo(nodelist []*Node) {

	p.Cache.ValidateLoopIFAddresses(nodelist)

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

/* Here are the several functions that run as goroutines to collect information
about a specific node using an http client. First, an http request is made to the
specific url and port of the desired information and the request received is read
and unmarshalled into a struct to contain that information. Then, a data transfer
object is created to hold the struct of information as well as the name and is sent
over the plugins node database channel to node_db_processor.go where it will be read,
processed, and added to the node database.
*/

func (p *ContivTelemetryProcessor) getLivenessInfo(client http.Client, node *Node) {
	res, err := client.Get("http://" + node.ManIPAdr + livenessPort + livenessURL)
	if err != nil {
		p.Log.Error(err)
		p.dbChannel <- NodeLivenessDTO{node.Name, nil}
		return
	}
	b, _ := ioutil.ReadAll(res.Body)
	b = []byte(b)
	nodeInfo := &NodeLiveness{}
	json.Unmarshal(b, nodeInfo)
	p.dbChannel <- NodeLivenessDTO{node.Name, nodeInfo}

}

func (p *ContivTelemetryProcessor) getInterfaceInfo(client http.Client, node *Node) {
	res, err := client.Get("http://" + node.ManIPAdr + interfacePort + interfaceURL)
	if err != nil {
		p.Log.Error(err)
		p.dbChannel <- NodeInterfacesDTO{node.Name, nil}
		return
	}
	b, _ := ioutil.ReadAll(res.Body)
	b = []byte(b)

	nodeInterfaces := make(map[int]NodeInterface, 0)
	json.Unmarshal(b, &nodeInterfaces)
	p.dbChannel <- NodeInterfacesDTO{node.Name, nodeInterfaces}

}
func (p *ContivTelemetryProcessor) getBridgeDomainInfo(client http.Client, node *Node) {
	res, err := client.Get("http://" + node.ManIPAdr + bridgeDomainsPort + bridgeDomainURL)
	if err != nil {
		p.Log.Error(err)
		p.dbChannel <- NodeBridgeDomainsDTO{node.Name, nil}
		return
	}
	b, _ := ioutil.ReadAll(res.Body)
	b = []byte(b)

	nodeBridgeDomains := make(map[int]NodeBridgeDomains)
	json.Unmarshal(b, &nodeBridgeDomains)
	p.dbChannel <- NodeBridgeDomainsDTO{node.Name, nodeBridgeDomains}

}

func (p *ContivTelemetryProcessor) getL2FibInfo(client http.Client, node *Node) {
	res, err := client.Get("http://" + node.ManIPAdr + l2FibsPort + l2FibsURL)
	if err != nil {
		p.Log.Error(err)
		p.dbChannel <- NodeL2FibsDTO{node.Name, nil}
		return
	}
	b, _ := ioutil.ReadAll(res.Body)
	b = []byte(b)
	nodel2fibs := make(map[string]NodeL2Fib)
	json.Unmarshal(b, &nodel2fibs)
	p.dbChannel <- NodeL2FibsDTO{node.Name, nodel2fibs}

}

func (p *ContivTelemetryProcessor) getTelemetryInfo(client http.Client, node *Node) {
	res, err := client.Get("http://" + node.ManIPAdr + telemetryPort + telemetryURL)
	if err != nil {
		p.Log.Error(err)
		p.dbChannel <- NodeTelemetryDTO{node.Name, nil}
		return
	}
	b, _ := ioutil.ReadAll(res.Body)
	b = []byte(b)
	nodetelemetry := make(map[string]NodeTelemetry)
	json.Unmarshal(b, &nodetelemetry)
	p.dbChannel <- NodeTelemetryDTO{node.Name, nodetelemetry}
}

func (p *ContivTelemetryProcessor) getIPArpInfo(client http.Client, node *Node) {
	res, err := client.Get("http://" + node.ManIPAdr + arpPort + arpURL)
	if err != nil {
		p.Log.Error(err)
		p.dbChannel <- NodeIPArpDTO{[]NodeIPArp{}, ""}
		return
	}
	b, _ := ioutil.ReadAll(res.Body)

	b = []byte(b)
	nodeiparpslice := make([]NodeIPArp, 0)
	json.Unmarshal(b, &nodeiparpslice)
	p.dbChannel <- NodeIPArpDTO{nodeiparpslice, node.Name}
}


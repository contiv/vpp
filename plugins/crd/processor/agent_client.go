package processor

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"github.com/contiv/vpp/plugins/crd/cache"
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
	nodeHTTPCalls     = 5
)

//Gathers a number of data points for every node in the Node List

func (p *ContivTelemetryProcessor) collectAgentInfo(node *cache.Node) {
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

func (p *ContivTelemetryProcessor) getLivenessInfo(client http.Client, node *cache.Node) {
	res, err := client.Get("http://" + node.ManIPAdr + livenessPort + livenessURL)
	if err != nil {
		p.Log.Error(err)
		p.dbChannel <- cache.NodeLivenessDTO{node.Name,nil}
		return
	}
	b, _ := ioutil.ReadAll(res.Body)
	b = []byte(b)
	nodeInfo := &cache.NodeLiveness{}
	json.Unmarshal(b, nodeInfo)
	p.dbChannel <- cache.NodeLivenessDTO{ node.Name, nodeInfo}

}

func (p *ContivTelemetryProcessor) getInterfaceInfo(client http.Client, node *cache.Node) {
	res, err := client.Get("http://" + node.ManIPAdr + interfacePort + interfaceURL)
	if err != nil {
		p.Log.Error(err)
		p.dbChannel <- cache.NodeInterfacesDTO{ node.Name,  nil}
		return
	}
	b, _ := ioutil.ReadAll(res.Body)
	b = []byte(b)

	nodeInterfaces := make(map[int]cache.NodeInterface, 0)
	json.Unmarshal(b, &nodeInterfaces)
	p.dbChannel <- cache.NodeInterfacesDTO{ node.Name, nodeInterfaces}

}
func (p *ContivTelemetryProcessor) getBridgeDomainInfo(client http.Client, node *cache.Node) {
	res, err := client.Get("http://" + node.ManIPAdr + bridgeDomainsPort + bridgeDomainURL)
	if err != nil {
		p.Log.Error(err)
		p.dbChannel <- cache.NodeBridgeDomainsDTO{node.Name, nil}
		return
	}
	b, _ := ioutil.ReadAll(res.Body)
	b = []byte(b)

	nodeBridgeDomains := make(map[int]cache.NodeBridgeDomains)
	json.Unmarshal(b, &nodeBridgeDomains)
	p.dbChannel <- cache.NodeBridgeDomainsDTO{ node.Name,  nodeBridgeDomains}

}

func (p *ContivTelemetryProcessor) getL2FibInfo(client http.Client, node *cache.Node) {
	res, err := client.Get("http://" + node.ManIPAdr + l2FibsPort + l2FibsURL)
	if err != nil {
		p.Log.Error(err)
		p.dbChannel <- cache.NodeL2FibsDTO{node.Name,  nil}
		return
	}
	b, _ := ioutil.ReadAll(res.Body)
	b = []byte(b)
	nodel2fibs := make(map[string]cache.NodeL2Fib)
	json.Unmarshal(b, &nodel2fibs)
	p.dbChannel <- cache.NodeL2FibsDTO{ node.Name,  nodel2fibs}

}

func (p *ContivTelemetryProcessor) getTelemetryInfo(client http.Client, node *cache.Node) {
	res, err := client.Get("http://" + node.ManIPAdr + telemetryPort + telemetryURL)
	if err != nil {
		p.Log.Error(err)
		p.dbChannel <- cache.NodeTelemetryDTO{node.Name,  nil}
		return
	}
	b, _ := ioutil.ReadAll(res.Body)
	b = []byte(b)
	nodetelemetry := make(map[string]cache.NodeTelemetry)
	json.Unmarshal(b, &nodetelemetry)
	p.dbChannel <- cache.NodeTelemetryDTO{ node.Name,  nodetelemetry}
}

func (p *ContivTelemetryProcessor) getIPArpInfo(client http.Client, node *cache.Node) {
	res, err := client.Get("http://" + node.ManIPAdr + arpPort + arpURL)
	if err != nil {
		p.Log.Error(err)
		p.dbChannel <- cache.NodeIPArpDTO{[]cache.NodeIPArp{},  ""}
		return
	}
	b, _ := ioutil.ReadAll(res.Body)

	b = []byte(b)
	nodeiparpslice := make([]cache.NodeIPArp, 0)
	json.Unmarshal(b, &nodeiparpslice)
	p.dbChannel <- cache.NodeIPArpDTO{ nodeiparpslice,  node.Name}
}

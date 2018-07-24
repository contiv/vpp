package cache

import (
	"github.com/ligato/cn-infra/logging"
	"github.com/pkg/errors"
	"sort"
)

//Nodes defines functions to be implemented that that allow the interaction with the Node Cache.
type Nodes interface {
	AddNode(ID uint32, nodeName, IPAdr, ManIPAdr string) error
	DeleteNode(key string) error
	GetNode(key string) (*Node, error)
	GetAllNodes() []*Node
	SetNodeLiveness(name string, nL *NodeLiveness) error
	SetNodeInterfaces(name string, nInt map[int]NodeInterface) error
	SetNodeBridgeDomain(name string, nBridge map[int]NodeBridgeDomains) error
	SetNodeL2Fibs(name string, nL2f map[string]NodeL2Fib) error
	SetNodeTelemetry(name string, nTele map[string]NodeTelemetry) error
	SetNodeIPARPs(name string, nArps []NodeIPArp) error
	PopulateNodeMaps(node *Node)
	ValidateLoopIFAddresses(nodelist []*Node) bool
}

//NodesDB holds various maps which all take different keys but point to the same underlying value.
type NodesDB struct {
	nMap        map[string]*Node
	loopIPMap   map[string]*Node
	gigEIPMap   map[string]*Node
	loopMACMap  map[string]*Node
	errorReport map[string][]string
	logger      logging.Logger
}

//NewNodesDB returns a pointer to a new node Database
func NewNodesDB(logger logging.Logger) (n *NodesDB) {

	return &NodesDB{
		make(map[string]*Node),
		make(map[string]*Node),
		make(map[string]*Node),
		make(map[string]*Node),
		make(map[string][]string),
		logger}
}

//SetNodeLiveness is a simple function to set a nodes liveness given its name.
func (nDB *NodesDB) SetNodeLiveness(name string, nLive *NodeLiveness) error {
	node, err := nDB.GetNode(name)
	if err != nil {
		return err
	}
	node.NodeLiveness = nLive
	return nil
}

//SetNodeInterfaces is a simple function to set a nodes interface given its name.
func (nDB *NodesDB) SetNodeInterfaces(name string, nInt map[int]NodeInterface) error {
	node, err := nDB.GetNode(name)
	if err != nil {
		return err
	}
	node.NodeInterfaces = nInt
	return nil

}

//SetNodeBridgeDomain is a simple function to set a nodes bridge domain given its name.
func (nDB *NodesDB) SetNodeBridgeDomain(name string, nBridge map[int]NodeBridgeDomains) error {
	node, err := nDB.GetNode(name)
	if err != nil {
		return err
	}
	node.NodeBridgeDomains = nBridge
	return nil
}

//SetNodeL2Fibs is a simple function to set a nodes l2 fibs given its name.
func (nDB *NodesDB) SetNodeL2Fibs(name string, nL2F map[string]NodeL2Fib) error {
	node, err := nDB.GetNode(name)
	if err != nil {
		return err
	}
	node.NodeL2Fibs = nL2F
	return nil
}

//SetNodeTelemetry is a simple function to set a nodes telemetry data given its name.
func (nDB *NodesDB) SetNodeTelemetry(name string, nTele map[string]NodeTelemetry) error {
	node, err := nDB.GetNode(name)
	if err != nil {
		return err
	}
	node.NodeTelemetry = nTele
	return nil
}

//SetNodeIPARPs is a simple function to set a nodes ip arp table given its name.
func (nDB *NodesDB) SetNodeIPARPs(name string, nArps []NodeIPArp) error {
	node, err := nDB.GetNode(name)
	if err != nil {
		return err
	}
	node.NodeIPArp = nArps
	return nil

}

//GetNode returns a pointer to a node for the given key.
//Returns an error if that key is not found.
func (nDB *NodesDB) GetNode(key string) (n *Node, err error) {
	if node, ok := nDB.nMap[key]; ok {
		return node, nil
	}
	err = errors.Errorf("value with given key not found: %s", key)
	return nil, err
}

//DeleteNode deletes node with the given key.
//Returns an error if the key is not found.
func (nDB *NodesDB) DeleteNode(key string) error {
	_, err := nDB.GetNode(key)
	if err != nil {
		return err
	}
	delete(nDB.nMap, key)
	return nil
}

//AddNode adds a new node with the given information.
//Returns an error if the node is already in the database
func (nDB *NodesDB) AddNode(ID uint32, nodeName, IPAdr, ManIPAdr string) error {
	n := &Node{IPAdr: IPAdr, ManIPAdr: ManIPAdr, ID: ID, Name: nodeName}
	_, err := nDB.GetNode(nodeName)
	if err == nil {
		err = errors.Errorf("duplicate key found: %s", nodeName)
		return err
	}
	nDB.nMap[nodeName] = n
	nDB.gigEIPMap[IPAdr] = n
	return nil
}

//GetAllNodes returns an ordered slice of all nodes in a database organized by name.
func (nDB *NodesDB) GetAllNodes() []*Node {
	var str []string
	for k := range nDB.nMap {
		str = append(str, k)
	}
	var nList []*Node
	sort.Strings(str)
	for _, v := range str {
		n, _ := nDB.GetNode(v)
		nList = append(nList, n)
	}
	return nList
}

//PopulateNodeMaps populates two of the node maps: the ip and mac address map
//It also checks to make sure that there are no duplicate addresses within the map.
func (nDB *NodesDB) PopulateNodeMaps(node *Node) {

		loopIF, err := nDB.getNodeLoopIFInfo(node)
		if err != nil {
			nDB.logger.Error(err)
		}
		for i := range loopIF.IPAddresses {
			if ip, ok := nDB.loopIPMap[loopIF.IPAddresses[i]]; !ok && ip != nil {
				//TODO: Report an error back to the controller; store it somewhere, report it at the end of the function
				nDB.logger.Errorf("Duplicate IP found: %s", ip)
			} else {
				for i := range loopIF.IPAddresses {
					nDB.loopIPMap[loopIF.IPAddresses[i]] = node
				}
			}
		}
		if mac, ok := nDB.loopMACMap[loopIF.PhysAddress]; !ok && mac != nil {
			nDB.logger.Errorf("Duplicate MAC address found: %s", mac)
		} else {
			nDB.loopMACMap[loopIF.PhysAddress] = node
		}
}

//Small helper function that returns the loop interface of a node
func (nDB *NodesDB) getNodeLoopIFInfo(node *Node) (NodeInterface, error) {
	for _, ifs := range node.NodeInterfaces {
		if ifs.VppInternalName == "loop0" {
			return ifs, nil
		}
	}
	err := errors.Errorf("Node %s does not have a loop interface")
	return NodeInterface{}, err
}

/*ValidateLoopIFAddresses validates the the entries of node ARP tables to make sure that
the number of entries is correct as well as making sure that each entry's
ip address and mac address correspond to the correct node in the network.*/
func (nDB *NodesDB) ValidateLoopIFAddresses(nodelist []*Node) bool {
	nodemap := make(map[string]bool)
	for key := range nDB.nMap {
		nodemap[key] = true
	}
	for _, node := range nodelist {
		nLoopIF, err := nDB.getNodeLoopIFInfo(node)
		if err != nil {
			nDB.logger.Error(err)
			nDB.logger.Errorf("Cannot process node ARP Table because loop interface info is missing.")
			continue
		}
		for _, arp := range node.NodeIPArp {
			if node.NodeInterfaces[int(arp.Interface)].VppInternalName != "loop0" {
				continue
			}

			nLoopIFTwo, ok := node.NodeInterfaces[int(arp.Interface)]
			if !ok {
				nDB.logger.Errorf("Loop Interface in ARP Table not found: %d", arp.Interface)
			}
			if nLoopIF.VppInternalName != nLoopIFTwo.VppInternalName {
				continue
			}
			macNode, ok := nDB.loopMACMap[arp.MacAddress]
			addressNotFound := false
			if !ok {
				nDB.logger.Errorf("Node for MAC Address %s not found", arp.MacAddress)
				addressNotFound = true
			}
			ipNode, ok := nDB.loopIPMap[arp.IPAddress+"/24"]

			if !ok {
				nDB.logger.Errorf("Node %s could not find Node with IP Address %s", node.Name, arp.IPAddress)
				addressNotFound = true
			}
			if addressNotFound {
				continue
			}
			if macNode.Name != ipNode.Name {
				nDB.logger.Errorf("MAC and IP point to different nodes: %s and %s in ARP Table %+v",
					macNode.Name, ipNode.Name, arp)

			}
			delete(nodemap, node.Name)
		}
	}
	if len(nodemap) > 0 {
		for node := range nodemap {
			nDB.logger.Errorf("No MAC entry found for %+v", node)
			delete(nodemap, node)
		}
	}
	return true
}

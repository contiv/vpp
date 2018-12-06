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

package nodesync

import (
	"fmt"
	"net"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
)

// API defines methods provided by NodeSync for use by other plugins.
type API interface {
	// GetNodeID returns the integer ID allocated for this node.
	// The method is thread-safe, but should not be called before the startup resync.
	GetNodeID() uint32

	// PublishNodeIPs can be used to publish update about currently assigned
	// node IPs of the given IP version on the VPP-side.
	// The method is efficient enough that it can be called during every resync
	// - only if something has really changed an update will be sent.
	// The method should be called only from within the main event loop (not thread
	// safe) and not before the startup resync.
	PublishNodeIPs(addresses contivconf.IPsWithNetworks, version contivconf.IPVersion) error

	// GetAllNodes returns information about all nodes in the cluster.
	// The method should be called only from within the main event loop (not thread
	// safe) and not before the startup resync.
	GetAllNodes() Nodes // node name -> node info
}

// Node represents a single node in the cluster.
type Node struct {
	ID              uint32
	Name            string
	VppIPAddresses  contivconf.IPsWithNetworks
	MgmtIPAddresses []net.IP
}

// Nodes is a map of node-name -> Node info.
type Nodes map[string]*Node

// String returns a string representation of the node.
func (n *Node) String() string {
	if n == nil {
		return "<nil>"
	}
	return fmt.Sprintf("<ID: %d, Name: %s, VPP-IPs: %v, Mgmt-IPs: %v",
		n.ID, n.Name, n.VppIPAddresses.String(), n.MgmtIPAddresses)
}

// String returns a string representation of nodes.
func (ns Nodes) String() string {
	str := "{"
	first := true
	for nodeName, node := range ns {
		if !first {
			str += ", "
		}
		first = false
		str += fmt.Sprintf("%s: %s", nodeName, node.String())
	}
	str += "}"
	return str
}

// NodeUpdate is an Update event that represents change in the status of a K8s node.
// For other nodes, the event is triggered when:
//   - node joins the cluster
//   - node leaves the cluster
//   - VPP or management IP addresses of the node are updated
// For this node, the event is triggered only when:
//   - the management IP addresses are updated
// For update of this node VPP IP addresses, there is already resync event NodeIPv*Change.
type NodeUpdate struct {
	NodeName  string
	PrevState *Node // nil if the node joined the cluster
	NewState  *Node // nil if the node left the cluster
}

// GetName returns name of the NodeUpdate event.
func (ev *NodeUpdate) GetName() string {
	return "Node Update"
}

// String describes NodeUpdate event.
func (ev *NodeUpdate) String() string {
	return fmt.Sprintf("%s\n"+
		"* node: %s\n"+
		"* prev-state: %s\n"+
		"* new-state: %s", ev.GetName(), ev.NodeName,
		ev.PrevState.String(), ev.NewState.String())
}

// Method is Update.
func (ev *NodeUpdate) Method() controller.EventMethodType {
	return controller.Update
}

// TransactionType is BestEffort.
func (ev *NodeUpdate) TransactionType() controller.UpdateTransactionType {
	return controller.BestEffort
}

// Direction is Forward.
func (ev *NodeUpdate) Direction() controller.UpdateDirectionType {
	return controller.Forward
}

// IsBlocking returns false.
func (ev *NodeUpdate) IsBlocking() bool {
	return false
}

// Done is NOOP.
func (ev *NodeUpdate) Done(error) {
	return
}

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

	controller "github.com/contiv/vpp/plugins/controller/api"
)

// API defines methods provided by NodeSync for use by other plugins.
type API interface {
	// GetNodeID returns the integer ID allocated for this node.
	// The method should be called only from within the main event loop (not thread
	// safe) and not before the startup resync.
	GetNodeID() uint32

	// PublishNodeIPs can be used to publish update about currently assigned
	// node IPs of the given IP version on the VPP-side.
	// The method is efficient enough that it can be called during every resync
	// - only if something has really changed an update will be sent.
	// The method should be called only from within the main event loop (not thread
	// safe) and not before the startup resync.
	PublishNodeIPs(addresses []*IPWithNetwork, version IPVersion) error

	// GetAllNodes returns information about all nodes in the cluster.
	// The method should be called only from within the main event loop (not thread
	// safe) and not before the startup resync.
	GetAllNodes() map[string]*Node // node name -> node info
}

// Node represents a single node in the cluster.
type Node struct {
	ID              uint32
	Name            string
	VppIPAddresses  []*IPWithNetwork
	MgmtIPAddresses []net.IP
}

// IPWithNetwork encapsulates IP address with the network address.
type IPWithNetwork struct {
	address net.IP
	network *net.IPNet
}

// IPVersion is either v4 or v6.
type IPVersion int

const (
	// IPv4 represents IP version 4.
	IPv4 IPVersion = iota
	// IPv6 represents IP version 6.
	IPv6
)

// String returns a string representation of the node.
func (n *Node) String() string {
	if n == nil {
		return "<nil>"
	}
	return fmt.Sprintf("<ID: %d, Name: %s, VPP-IPs: %v, Mgmt-IPs: %v",
		n.ID, n.Name, n.VppIPAddresses, n.MgmtIPAddresses)
}

// OtherNodeUpdate is an Update event that represents change in the status
// of another node.
type OtherNodeUpdate struct {
	PrevState *Node // nil if the node joined the cluster
	NewState  *Node // nil if the node left the cluster
}

// GetName returns name of the OtherNodeUpdate event.
func (ev *OtherNodeUpdate) GetName() string {
	return "Other Node Update"
}

// String describes OtherNodeUpdate event.
func (ev *OtherNodeUpdate) String() string {
	return fmt.Sprintf("%s\n"+
		"* prev-state: %s\n"+
		"* new-state: %s", ev.GetName(), ev.PrevState.String(), ev.NewState.String())
}

// Method is Update.
func (ev *OtherNodeUpdate) Method() controller.EventMethodType {
	return controller.Update
}

// TransactionType is BestEffort.
func (ev *OtherNodeUpdate) TransactionType() controller.UpdateTransactionType {
	return controller.BestEffort
}

// Direction is Forward.
func (ev *OtherNodeUpdate) Direction() controller.UpdateDirectionType {
	return controller.Forward
}

// IsBlocking returns false.
func (ev *OtherNodeUpdate) IsBlocking() bool {
	return false
}

// Done is NOOP.
func (ev *OtherNodeUpdate) Done(error) {
	return
}

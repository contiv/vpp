// Copyright (c) 2017 Cisco and/or its affiliates.
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

package ipv4net

import (
	"fmt"
	"net"
	"sync"

	govpp "git.fd.io/govpp.git/api"

	"github.com/ligato/cn-infra/idxmap"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/rpc/rest"
	"github.com/ligato/cn-infra/servicelabel"
	"github.com/ligato/cn-infra/utils/safeclose"

	vpp_ifplugin "github.com/ligato/vpp-agent/plugins/vppv2/ifplugin"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ipam"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/podmanager"
	"github.com/ligato/cn-infra/logging"
)

const (
	// interface host name length limit in Linux
	linuxIfNameMaxLen = 15

	// logical interface logical name length limit in the vpp-agent/ifplugin
	logicalIfNameMaxLen = 63

	// any IPv4 address
	ipv4AddrAny = "0.0.0.0"
	ipv4NetAny  = ipv4AddrAny + "/0"
)

// IPv4Net plugin builds configuration to be applied by ligato/VPP-agent for VPP-based
// IPv4 network connectivity between Kubernetes pods and nodes.
type IPv4Net struct {
	Deps

	*externalState
	*internalState
}

// externalState groups attributes/callbacks used to access the state of the system
// outside of the plugin.
// The attributes are set in the plugin Init phase. In the unit tests it is possible
// to override the original Init method and inject mocks instead.
type externalState struct {
	// set to true when running unit tests
	test bool

	// GoVPP channel for direct binary API calls (not needed for UTs)
	govppCh govpp.Channel

	// VPP DHCP index map
	dhcpIndex idxmap.NamedMapping

	// dumping of host IPs
	hostLinkIPsDump HostLinkIPsDumpClb
}

// internalState groups attributes representing the internal state of the plugin.
// The attributes are refreshed by Resync and updated during Update events.
type internalState struct {
	// DHCP watching
	watchingDHCP bool // true if dhcpIndex is being watched
	useDHCP      bool // whether DHCP is disabled by the latest config (can be changed via CRD)

	// this node's main IP address
	nodeIP    net.IP
	nodeIPNet *net.IPNet

	// IP addresses of this node present in the host network namespace (Linux)
	hostIPs []net.IP

	// pod ID from interface name
	vppIfaceToPodMutex sync.RWMutex
	vppIfaceToPod      map[string]podmodel.ID
}

// Deps groups the dependencies of the plugin.
type Deps struct {
	infra.PluginDeps
	EventLoop    controller.EventLoop
	ServiceLabel servicelabel.ReaderAPI
	ContivConf   contivconf.API
	IPAM         ipam.API
	NodeSync     nodesync.API
	PodManager   podmanager.API
	VPPIfPlugin  vpp_ifplugin.API
	GoVPP        GoVPP
	HTTPHandlers rest.HTTPHandlers
}

// GoVPP is the interface of govppmux plugin replicated here to avoid direct
// dependency on vppapiclient.h for other plugins that import ipv4net just to
// read some constants etc.
type GoVPP interface {
	// NewAPIChannel returns a new API channel for communication with VPP via govpp.
	NewAPIChannel() (govpp.Channel, error)

	// NewAPIChannelBuffered returns a new API channel for communication with VPP via govpp.
	NewAPIChannelBuffered(reqChanBufSize, replyChanBufSize int) (govpp.Channel, error)
}

// HostLinkIPsDumpClb is callback for dumping all IP addresses assigned to interfaces
// in the host stack.
type HostLinkIPsDumpClb func() ([]net.IP, error)

/********************************** Plugin ************************************/

// Init initializes attributes/callbacks used to access the plugin-external state.
// Internal state is initialized later by the first resync.
func (n *IPv4Net) Init() error {
	n.internalState = &internalState{}
	n.externalState = &externalState{}

	// silence the microservice descriptor - debug logs are not very usefull
	var err error
	err = logging.DefaultRegistry.SetLevel("linux-nsplugin.ms-descriptor", "info")
	if err != nil {
		return err
	}

	// create GoVPP channel
	n.govppCh, err = n.GoVPP.NewAPIChannel()
	if err != nil {
		return err
	}

	// get reference to map with DHCP leases
	n.dhcpIndex = n.VPPIfPlugin.GetDHCPIndex()

	// setup callback used to access host interfaces (can be replaced in UTs with a mock)
	n.hostLinkIPsDump = n.getHostLinkIPs

	// register REST handlers
	n.registerRESTHandlers()
	return nil
}

// StateToString returns human-readable string representation of the ipv4net
// plugin internal state.
// The method cannot be called String(), otherwise it overloads the Stringer
// from PluginDeps.
func (s *internalState) StateToString() string {
	// pod ID by VPP interface name
	vppIfaceToPod := "{"
	first := true
	for vppIfName, podID := range s.vppIfaceToPod {
		if !first {
			vppIfaceToPod += ", "
		}
		first = false
		vppIfaceToPod += fmt.Sprintf("%s: %s", vppIfName, podID.String())
	}
	vppIfaceToPod += "}"

	return fmt.Sprintf("<useDHCP: %t, watchingDHCP: %t, "+
		"nodeIP: %s, nodeIPNet: %s, hostIPs: %v, vppIfaceToPod: %s",
		s.useDHCP, s.watchingDHCP,
		s.nodeIP.String(), ipNetToString(s.nodeIPNet), s.hostIPs,
		vppIfaceToPod)
}

// Close is called by the plugin infra upon agent cleanup.
// It cleans up the resources allocated by the plugin.
func (n *IPv4Net) Close() error {
	_, err := safeclose.CloseAll(n.govppCh)
	return err
}

/********************************** Events ************************************/

// HandlesEvent selects:
//   - any Resync event (extra action for NodeIPv4Change)
//   - AddPod and DeletePod
//   - NodeUpdate for other nodes
//   - Shutdown event
func (n *IPv4Net) HandlesEvent(event controller.Event) bool {
	if event.Method() != controller.Update {
		return true
	}
	if _, isAddPod := event.(*podmanager.AddPod); isAddPod {
		return true
	}
	if _, isDeletePod := event.(*podmanager.DeletePod); isDeletePod {
		return true
	}
	if nodeUpdate, isNodeUpdate := event.(*nodesync.NodeUpdate); isNodeUpdate {
		return nodeUpdate.NodeName != n.ServiceLabel.GetAgentLabel()
	}
	if _, isShutdown := event.(*controller.Shutdown); isShutdown {
		return true
	}

	// unhandled event
	return false
}

/**************************** IPv4Net plugin API ******************************/

// GetPodByIf looks up podName and podNamespace that is associated with logical interface name.
// The method can be called from outside of the main event loop.
func (n *IPv4Net) GetPodByIf(ifName string) (podNamespace string, podName string, exists bool) {
	n.vppIfaceToPodMutex.RLock()
	defer n.vppIfaceToPodMutex.RUnlock()

	podID, found := n.vppIfaceToPod[ifName]
	if !found {
		return "", "", false
	}
	return podID.Namespace, podID.Name, true
}

// GetIfName looks up logical interface name that corresponds to the interface associated with the given POD name.
func (n *IPv4Net) GetIfName(podNamespace string, podName string) (name string, exists bool) {
	// check that the pod is locally deployed
	podID := podmodel.ID{Name: podName, Namespace: podNamespace}
	pod, exists := n.PodManager.GetLocalPods()[podID]
	if !exists {
		return "", false
	}

	// check that the pod is attached to VPP network stack
	n.vppIfaceToPodMutex.RLock()
	defer n.vppIfaceToPodMutex.RUnlock()
	vppIfName, _ := n.podInterfaceName(pod)
	_, configured := n.vppIfaceToPod[vppIfName]
	if !configured {
		return "", false
	}

	return vppIfName, true
}

// GetNodeIP returns the IP address of this node.
func (n *IPv4Net) GetNodeIP() (ip net.IP, network *net.IPNet) {
	return n.nodeIP, n.nodeIPNet
}

// GetHostIPs returns all IP addresses of this node present in the host network namespace (Linux).
func (n *IPv4Net) GetHostIPs() []net.IP {
	return n.hostIPs
}

// GetHostInterconnectIfName returns the name of the TAP/AF_PACKET interface
// interconnecting VPP with the host stack.
func (n *IPv4Net) GetHostInterconnectIfName() string {
	return n.hostInterconnectVPPIfName()
}

// GetVxlanBVIIfName returns the name of an BVI interface facing towards VXLAN tunnels to other hosts.
// Returns an empty string if VXLAN is not used (in L2 interconnect mode).
func (n *IPv4Net) GetVxlanBVIIfName() string {
	if n.ContivConf.GetRoutingConfig().UseL2Interconnect {
		return ""
	}

	return VxlanBVIInterfaceName
}

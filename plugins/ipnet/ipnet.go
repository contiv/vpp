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

package ipnet

import (
	"fmt"
	"net"
	"sync"

	govpp "git.fd.io/govpp.git/api"

	"github.com/ligato/cn-infra/idxmap"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/rpc/rest"
	"github.com/ligato/cn-infra/servicelabel"
	"github.com/ligato/cn-infra/utils/safeclose"
	"github.com/pkg/errors"

	linux_nsplugin "github.com/ligato/vpp-agent/plugins/linux/nsplugin"
	vpp_ifplugin "github.com/ligato/vpp-agent/plugins/vpp/ifplugin"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	customnetmodel "github.com/contiv/vpp/plugins/crd/handler/customnetwork/model"
	extifmodel "github.com/contiv/vpp/plugins/crd/handler/externalinterface/model"
	"github.com/contiv/vpp/plugins/devicemanager"
	"github.com/contiv/vpp/plugins/idalloc"
	"github.com/contiv/vpp/plugins/idalloc/idallocation"
	"github.com/contiv/vpp/plugins/ipam"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/podmanager"
)

const (
	// interface host name length limit in Linux
	linuxIfNameMaxLen = 15

	// logical interface logical name length limit in the vpp-agent/ifplugin
	logicalIfNameMaxLen = 63
)

// IPNet plugin builds configuration to be applied by ligato/VPP-agent for VPP-based
// IP network connectivity between Kubernetes pods and nodes.
type IPNet struct {
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

	// custom interface information
	podCustomIf map[string]*podCustomIfInfo // key = pod.ID.String() + interface-name

	// cache of pods pending for AddPodCustomIfs event (waiting for metadata)
	pendingAddPodCustomIf map[podmodel.ID]bool

	// custom network information
	customNetworks map[string]*customNetworkInfo // custom network name to info map

	// configuration written to etcd for other ligato-based microservices to apply
	microserviceConfig map[string][]byte

	// VNI / VRF pool states
	vniPoolInitialized bool
	vrfPoolInitialized bool
}

// configEventType represents the type of an configuration event processed by the ipnet plugin
type configEventType int

const (
	// synchronization of the existing config vs demanded config
	configResync configEventType = iota
	// addition of new config
	configAdd
	// deletion of existing config
	configDelete
)

// Deps groups the dependencies of the plugin.
type Deps struct {
	infra.PluginDeps
	EventLoop     controller.EventLoop
	ServiceLabel  servicelabel.ReaderAPI
	ContivConf    contivconf.API
	IDAlloc       idalloc.API
	IPAM          ipam.API
	NodeSync      nodesync.API
	PodManager    podmanager.API
	DeviceManager devicemanager.API
	VPPIfPlugin   vpp_ifplugin.API
	LinuxNsPlugin linux_nsplugin.API
	GoVPP         GoVPP
	HTTPHandlers  rest.HTTPHandlers
	RemoteDB      nodesync.KVDBWithAtomic
}

// GoVPP is the interface of govppmux plugin replicated here to avoid direct
// dependency on vppapiclient.h for other plugins that import ipnet just to
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
func (n *IPNet) Init() error {
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

	// init internal maps
	n.podCustomIf = make(map[string]*podCustomIfInfo)
	n.pendingAddPodCustomIf = make(map[podmodel.ID]bool)
	n.customNetworks = make(map[string]*customNetworkInfo)
	n.microserviceConfig = make(map[string][]byte)

	return nil
}

// StateToString returns human-readable string representation of the ipnet
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

	// custom interface information
	podCustomIf := "{"
	first = true
	for podID, ifInfo := range s.podCustomIf {
		if !first {
			podCustomIf += ", "
		}
		first = false
		podCustomIf += fmt.Sprintf("%s: %s/%s/%s", podID,
			ifInfo.ifName, ifInfo.ifType, ifInfo.ifNet)
	}
	podCustomIf += "}"

	// pods pending for AddPodCustomIfs
	pendingCustomIf := "["
	first = true
	for podID := range s.pendingAddPodCustomIf {
		if !first {
			pendingCustomIf += ", "
		}
		first = false
		pendingCustomIf += podID.String()
	}
	pendingCustomIf += "]"

	// custom network information
	customNetworks := "{"
	first = true
	for nwName, nwInfo := range s.customNetworks {
		if !first {
			customNetworks += ", "
		}
		first = false
		customNetworks += fmt.Sprintf("%s: <config: %s, interfaces: %v>", nwName,
			nwInfo.config.String(), nwInfo.localInterfaces)
	}
	customNetworks += "}"

	// microserviceConfig not printed (too big and not so important)

	return fmt.Sprintf("<useDHCP: %t, watchingDHCP: %t, "+
		"nodeIP: %s, nodeIPNet: %s, hostIPs: %v, vppIfaceToPod: %s, "+
		"podCustomIf: %s, pendingAddPodCustomIf: %s, customNetworks: %s",
		s.useDHCP, s.watchingDHCP,
		s.nodeIP.String(), ipNetToString(s.nodeIPNet), s.hostIPs,
		vppIfaceToPod, podCustomIf, pendingCustomIf, customNetworks)
}

// DescribeInternalData describes the internal state of IPNet plugin.
// Used for Verification Resync.
func (n *IPNet) DescribeInternalData() string {
	return n.internalState.StateToString()
}

// Close is called by the plugin infra upon agent cleanup.
// It cleans up the resources allocated by the plugin.
func (n *IPNet) Close() error {
	_, err := safeclose.CloseAll(n.govppCh)
	return err
}

/********************************** Events ************************************/

// HandlesEvent selects:
//   - any Resync event (extra action for NodeIPv4Change)
//   - AddPod and DeletePod (CNI)
//   - POD k8s state changes
//   - POD custom interfaces update
//   - custom network update
//   - external interfaces update
//   - NodeUpdate for other nodes
//   - Shutdown event
func (n *IPNet) HandlesEvent(event controller.Event) bool {
	if event.Method() != controller.Update {
		return true
	}
	if _, isAddPod := event.(*podmanager.AddPod); isAddPod {
		return true
	}
	if _, isDeletePod := event.(*podmanager.DeletePod); isDeletePod {
		return true
	}
	if ksChange, isKSChange := event.(*controller.KubeStateChange); isKSChange {
		switch ksChange.Resource {
		case podmodel.PodKeyword:
			return true
		case customnetmodel.Keyword:
			return true
		case extifmodel.Keyword:
			return true
		default:
			// unhandled Kubernetes state change
			return false
		}
	}
	if _, isPodCustomIfUpdate := event.(*PodCustomIfUpdate); isPodCustomIfUpdate {
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

/**************************** IPNet plugin API ******************************/

// GetPodByIf looks up podName and podNamespace that is associated with logical interface name.
// The method can be called from outside of the main event loop.
func (n *IPNet) GetPodByIf(ifName string) (podNamespace string, podName string, exists bool) {
	n.vppIfaceToPodMutex.RLock()
	defer n.vppIfaceToPodMutex.RUnlock()

	podID, found := n.vppIfaceToPod[ifName]
	if !found {
		return "", "", false
	}
	return podID.Namespace, podID.Name, true
}

// GetPodIfNames looks up logical interface names that correspond to the interfaces
// associated with the given local pod name + namespace.
func (n *IPNet) GetPodIfNames(podNamespace string, podName string) (vppIfName, linuxIfName, loopIfName string,
	exists bool) {
	// check that the pod is locally deployed
	podID := podmodel.ID{Name: podName, Namespace: podNamespace}
	pod, exists := n.PodManager.GetLocalPods()[podID]
	if !exists {
		return "", "", "", false
	}

	// check that the pod is attached to VPP network stack
	n.vppIfaceToPodMutex.RLock()
	defer n.vppIfaceToPodMutex.RUnlock()
	vppIfName, linuxIfName, _ = n.podInterfaceName(pod, "", "")
	loopIfName = n.podLinuxLoopName(pod)
	_, configured := n.vppIfaceToPod[vppIfName]
	if !configured {
		return "", "", "", false
	}

	return vppIfName, linuxIfName, loopIfName, true
}

// GetPodCustomIfNames looks up logical interface name that corresponds to the custom interface
// with specified name and type associated with the given local pod name + namespace.
func (n *IPNet) GetPodCustomIfNames(podNamespace, podName, customIfName string) (ifName string, linuxIfName string,
	exists bool) {
	// check that the pod is locally deployed
	podID := podmodel.ID{Name: podName, Namespace: podNamespace}
	pod, exists := n.PodManager.GetLocalPods()[podID]
	if !exists {
		return "", "", false
	}

	customIf, exists := n.podCustomIf[pod.ID.String()+customIfName]
	if !exists {
		return "", "", false
	}

	ifName, linuxIfName, _ = n.podInterfaceName(pod, customIf.ifName, customIf.ifType)
	return ifName, linuxIfName, true
}

// GetExternalIfName returns logical name that corresponds to the specified external interface name and VLAN ID.
func (n *IPNet) GetExternalIfName(extIfName string, vlan uint32) (ifName string) {
	if vlan == 0 {
		return extIfName
	}
	return n.getSubInterfaceName(extIfName, vlan)
}

// GetNodeIP returns the IP address of this node.
func (n *IPNet) GetNodeIP() (ip net.IP, network *net.IPNet) {
	return n.nodeIP, n.nodeIPNet
}

// GetHostIPs returns all IP addresses of this node present in the host network namespace (Linux).
func (n *IPNet) GetHostIPs() []net.IP {
	return n.hostIPs
}

// GetHostInterconnectIfName returns the name of the TAP/AF_PACKET interface
// interconnecting VPP with the host stack.
func (n *IPNet) GetHostInterconnectIfName() string {
	return n.hostInterconnectVPPIfName()
}

// GetVxlanBVIIfName returns the name of an BVI interface facing towards VXLAN tunnels to other hosts.
// Returns an empty string if VXLAN is not used (in no overlay mode).
func (n *IPNet) GetVxlanBVIIfName() string {
	if n.ContivConf.GetRoutingConfig().NodeToNodeTransport != contivconf.VXLANTransport {
		return ""
	}
	return n.vxlanBVIInterfaceName(DefaultPodNetworkName)
}

// GetOrAllocateVxlanVNI returns the allocated VXLAN VNI number for the given network.
// Allocates a new VNI if not already allocated.
func (n *IPNet) GetOrAllocateVxlanVNI(networkName string) (vni uint32, err error) {

	// allocate the pool if needed
	if !n.vniPoolInitialized {
		err = n.IDAlloc.InitPool(VxlanVniPoolName, &idallocation.AllocationPool_Range{
			MinId: vxlanVNIPoolStart,
			MaxId: vxlanVNIPoolEnd,
		})
		if err != nil {
			n.Log.Errorf("VNI pool init failed: %v", err)
			return 0, err
		}
		n.vniPoolInitialized = true
	}

	// get / allocate a VNI
	vni, err = n.IDAlloc.GetOrAllocateID(VxlanVniPoolName, networkName)
	if err != nil {
		n.Log.Errorf("VNI retrieval/allocation failed: %v", err)
	}
	return vni, err
}

// ReleaseVxlanVNI releases the allocated VXLAN VNI number for the given network.
func (n *IPNet) ReleaseVxlanVNI(networkName string) (err error) {
	return n.IDAlloc.ReleaseID(VxlanVniPoolName, networkName)
}

// GetOrAllocateVrfID returns the allocated VRF ID number for the given network.
// Allocates a new VRF ID if not already allocated.
func (n *IPNet) GetOrAllocateVrfID(networkName string) (vrf uint32, err error) {
	// default pod network does not need any allocation
	if n.isDefaultPodNetwork(networkName) {
		return n.ContivConf.GetRoutingConfig().PodVRFID, nil
	}

	// allocate the pool if needed
	if !n.vrfPoolInitialized {
		err = n.IDAlloc.InitPool(vrfPoolName, &idallocation.AllocationPool_Range{
			MinId: vrfPoolStart,
			MaxId: vrfPoolEnd,
		})
		if err != nil {
			n.Log.Errorf("VRF pool init failed: %v", err)
			return 0, err
		}
		n.vrfPoolInitialized = true
	}

	// get / allocate a VRF
	vrf, err = n.IDAlloc.GetOrAllocateID(vrfPoolName, networkName)
	if err != nil {
		n.Log.Errorf("VRF retrieval/allocation failed: %v", err)
	}
	return vrf, err
}

// ReleaseVrfID releases the allocated VRF ID number for the given network.
func (n *IPNet) ReleaseVrfID(networkName string) (err error) {
	return n.IDAlloc.ReleaseID(vrfPoolName, networkName)
}

// GetPodCustomIfNetworkName returns the name of custom network which should contain given
// pod custom interface or error otherwise. This supports both type of pods, remote and local
func (n *IPNet) GetPodCustomIfNetworkName(podID podmodel.ID, ifName string) (string, error) {
	for name, info := range n.customNetworks {
		if pod, inPod := info.pods[podID.String()]; inPod {
			for _, intf := range info.interfaces[pod.ID.String()] {
				if ifName == intf {
					return name, nil // in local Pod && in local interface of given network
				}
			}
		}
	}
	return "", errors.Errorf("couldn't find any custom network that custom interface %v in pod %v "+
		"belongs to (Custom networks: %v)", ifName, podID, n.customNetworks)
}

// GetExternalIfNetworkName returns the name of custom network which should contain given
// external interface or error otherwise.
func (n *IPNet) GetExternalIfNetworkName(ifName string) (string, error) {
	for name, info := range n.customNetworks {
		if extIf, exists := info.extInterfaces[ifName]; exists {
			if ifName == extIf.Name { // match of external interface resource name
				return name, nil
			}
			for _, intf := range info.interfaces[extIf.Name] {
				if ifName == intf { // match of external interface vpp (DPDK) name
					return name, nil
				}
			}
		}
	}
	return "", errors.Errorf("couldn't find any custom network that external interface %v "+
		"belongs to (Custom networks: %v)", ifName, n.customNetworks)
}

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

package contiv

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"git.fd.io/govpp.git/api"
	"golang.org/x/net/context"
	"github.com/apparentlymart/go-cidr/cidr"
	"google.golang.org/grpc"

	"github.com/ligato/cn-infra/idxmap"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/rpc/rest"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/db/keyval"

	scheduler_api "github.com/ligato/vpp-agent/plugins/kvscheduler/api"
	"github.com/ligato/vpp-agent/plugins/vppv2/ifplugin/ifaceidx"
	vpp_intf "github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"
	vpp_l3 "github.com/ligato/vpp-agent/plugins/vppv2/model/l3"
	linux_l3 "github.com/ligato/vpp-agent/plugins/linuxv2/model/l3"
	intf_vppcalls "github.com/ligato/vpp-agent/plugins/vppv2/ifplugin/vppcalls"

	txn_api "github.com/contiv/vpp/plugins/controller/txn"
	"github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/contiv/ipam"
	"github.com/contiv/vpp/plugins/contiv/model/cni"
	"github.com/contiv/vpp/plugins/contiv/model/node"
	stn_grpc "github.com/contiv/vpp/cmd/contiv-stn/model/stn"
)

/* Global constants */
const (
	// defaultSTNSocketFile is the default socket file path where CNI GRPC server listens for incoming CNI requests.
	defaultSTNSocketFile = "/var/run/contiv/stn.sock"

	// interface host name length limit in Linux
	linuxIfNameMaxLen             = 15

	// logical interface logical name length limit in the vpp-agent/ifplugin
	logicalIfNameMaxLen           = 63

	// any IPv4 address
	ipv4NetAny = "0.0.0.0/0"
)

/* CNI requests */
const (
	// possible retvals for CNI request
	resultOk  uint32 = 0
	resultErr uint32 = 1

	// name of the argument that stores pod name within a CNI request
	podNameExtraArg = "K8S_POD_NAME"

	// name of the argument that stores pod namespace within a CNI request
	podNamespaceExtraArg = "K8S_POD_NAMESPACE"
)

/* Pod connectivity */
const (
	// interface host name as required by Kubernetes for every pod
	podInterfaceHostName = "eth0" // required by Kubernetes

	// prefix for logical name of AF-Packet interface (VPP) connecting a pod
	podAFPacketLogicalNamePrefix = "afpacket"

	// prefix for logical name of the VPP-TAP interface connecting a pod
	podVPPSideTAPLogicalNamePrefix = "vpp-tap-"

	// prefix for logical name of the Linux-TAP interface connecting a pod
	podLinuxSideTAPLogicalNamePrefix = "linux-tap-"
)

/* Main VPP interface */
const (
	// loopbackNICLogicalName is the logical name of the loopback interface configured instead of physical NICs.
	loopbackNICLogicalName = "loopbackNIC"
)

/* VRFs */
const (
	defaultMainVrfID = 0
	defaultPodVrfID  = 1
)

/* VPP - Host interconnect */
const (
	/* AF-PACKET + VETH */

	// logical & host names of the VETH interface connecting host stack with VPP.
	//  - the host stack side of the pipe
	hostInterconnectVETH1LogicalName = "veth-vpp1"
	hostInterconnectVETH1HostName    = "vpp1"

	// logical & host names of the VETH interface connecting host stack with VPP.
	//  - the VPP side of the pipe
	hostInterconnectVETH2LogicalName = "veth-vpp2"
	hostInterconnectVETH2HostName    = "vpp2"

	// logical name of the AF-packet interface attached to VETH2.
	hostInterconnectAFPacketLogicalName = "afpacket-vpp2"

	/* TAP */

	// HostInterconnectTAPinVPPLogicalName is the logical name of the TAP interface
	// connecting host stack with VPP
	//  - VPP side
	HostInterconnectTAPinVPPLogicalName = "tap-vpp2"

	// HostInterconnectTAPinLinuxLogicalName is the logical name of the TAP interface
	// connecting host stack with VPP
	//  - Linux side
	HostInterconnectTAPinLinuxLogicalName = "tap-vpp1"

	// HostInterconnectTAPinLinuxHostName is the physical name of the TAP interface
	// connecting host stack with VPP
	//  - the Linux side
	HostInterconnectTAPinLinuxHostName = "vpp1"
)

// prefix for the hardware address of host interconnects
var hostInterconnectHwAddrPrefix = []byte{0x34, 0x3c}


/* VXLANs */
const (
	// VXLAN Network Identifier (or VXLAN Segment ID)
	vxlanVNI = 10

	// as VXLAN tunnels are added to a BD, they must be configured with the same
	// and non-zero Split Horizon Group (SHG) number. Otherwise, flood packet may
	// loop among servers with the same VXLAN segment because VXLAN tunnels are fully
	// meshed among servers.
	vxlanSplitHorizonGroup = 1

	// name of the VXLAN BVI interface.
	vxlanBVIInterfaceName = "vxlanBVI" // name of the VXLAN BVI interface.

	// name of the VXLAN bridge domain
	vxlanBDName = "vxlanBD"

)

// prefix for the hardware address of VXLAN interfaces
var vxlanBVIHwAddrPrefix = []byte{0x12, 0x2b}

// remoteCNIserver represents the remote CNI server instance.
// It accepts the requests from the contiv-CNI (acting as a GRPC-client) and configures
// the networking between VPP and Kuernetes Pods.
type remoteCNIserver struct {
	logging.Logger
	sync.Mutex

	// transaction factory
	txnFactory func() txn_api.Transaction

	// GoVPP channel for direct binary API calls (if needed)
	govppChan api.Channel

	// VPP interface index map
	swIfIndex ifaceidx.IfaceMetadataIndex

	// VPP dhcp index map
	dhcpIndex idxmap.NamedMapping

	// IPAM module used by the CNI server
	ipam *ipam.IPAM

	// set to true when running unit tests
	test bool

	// agent microservice label
	agentLabel string

	// node IDs
	nodeID uint32 // this node ID
	otherNodes map[uint32]*node.NodeInfo // other node ID -> node info

	// this node's main IP address and the default gateway
	// - NOT reset by resync
	nodeIP string // TODO: net.IP
	defaultGw net.IP

	// IP addresses of this node present in the host network namespace (Linux)
	hostIPs []net.IP

	// nodeIPsubscribers is a slice of channels that are notified when nodeIP is changed
	nodeIPsubscribers []chan string

	// global config
	config *Config

	// podPreRemovalHooks is a slice of callbacks called before a pod removal
	podPreRemovalHooks []PodActionHook

	// podPostAddHooks is a slice of callbacks called once pod is added
	podPostAddHook []PodActionHook

	// node specific configuration
	nodeConfig *NodeConfig

	// pod run-time attributes
	podByID        map[pod.ID]*Pod
	podByVPPIfName map[string]*Pod

	// the variables ensures that add/del requests are processed only after the server
	// was first resynced
	inSync        bool
	inSyncCond    *sync.Cond
	resyncCounter int

	// name of the main physical interface
	mainPhysicalIf string

	// name of extra physical interfaces configured by the agent
	otherPhysicalIfs []string

	// IP address and gateway in the STN case
	stnIP string // TODO: net.IP
	stnGw string // TODO: net.IP

	// default gateway IP address

	ctx           context.Context
	ctxCancelFunc context.CancelFunc

	http rest.HTTPHandlers
}

/******* Constructor *******/

// newRemoteCNIServer initializes a new remote CNI server instance.
func newRemoteCNIServer(logger logging.Logger, txnFactory func() txn_api.Transaction,
	govppChan api.Channel, index ifaceidx.IfaceMetadataIndex, dhcpIndex idxmap.NamedMapping, agentLabel string,
	config *Config, nodeConfig *NodeConfig, nodeID uint32, nodeExcludeIPs []net.IP, broker keyval.ProtoBroker, http rest.HTTPHandlers) (*remoteCNIserver, error) {

	ipam, err := ipam.New(logger, nodeID, agentLabel, &config.IPAMConfig, nodeExcludeIPs, broker)
	if err != nil {
		return nil, err
	}

	server := &remoteCNIserver{
		Logger:     logger,
		txnFactory: txnFactory,
		govppChan:  govppChan,
		swIfIndex:  index,
		dhcpIndex:  dhcpIndex,
		agentLabel: agentLabel,
		nodeID:     nodeID,
		ipam:       ipam,
		nodeConfig: nodeConfig,
		config:     config,
		http:       http,
	}
	server.reset()
	server.inSyncCond = sync.NewCond(&server.Mutex)
	server.ctx, server.ctxCancelFunc = context.WithCancel(context.Background())
	if nodeConfig != nil && nodeConfig.Gateway != "" {
		server.defaultGw = net.ParseIP(nodeConfig.Gateway)
	}
	server.registerHandlers()
	return server, nil
}

// reset resets the CNI server to pre-resync state.
func (s *remoteCNIserver) reset() {
	s.mainPhysicalIf = ""
	s.hostIPs = []net.IP{}
	s.otherPhysicalIfs = []string{}
	s.stnIP = ""
	s.stnGw = ""
	s.otherNodes = make(map[uint32]*node.NodeInfo)
	s.podByID = make(map[pod.ID]*Pod)
	s.podByVPPIfName = make(map[string]*Pod)
	s.inSync = false
}

/******* Events *******/

// Resync re-synchronizes configuration based on Kubernetes state data.
func (s *remoteCNIserver) Resync(dataResyncEv datasync.ResyncEvent) error {
	s.Lock()
	defer s.Unlock()
	s.resyncCounter++

	s.reset()
	txn := s.txnFactory()

	// node <-> host, host -> pods
	var wasErr error
	err := s.configureVswitchConnectivity(txn)
	if err != nil {
		wasErr = err
		s.Logger.Error(err)
	}

	// node <-> node
	err = s.otherNodesResync(dataResyncEv, txn)
	if err != nil {
		wasErr = err
		s.Logger.Error(err)
	}

	// TODO pods <-> vswitch

	// commit resync transaction
	ctx := context.Background()
	ctx = scheduler_api.WithRetry(ctx, time.Second, true)
	ctx = scheduler_api.WithFullResync(ctx)
	ctx = scheduler_api.WithDescription(ctx, fmt.Sprintf("Remote CNI server resync no. %d", s.resyncCounter))
	err = txn.Commit(ctx)
	if err != nil {
		wasErr = fmt.Errorf("failed to resync vswitch configuration: %v ", err)
	}

	// set the state to configured and broadcast
	s.inSync = true
	s.inSyncCond.Broadcast()

	return wasErr
}

// Update updates configuration based on a change in the Kubernetes state data.
func (s *remoteCNIserver) Update(dataChng datasync.ProtoWatchResp) error {
	s.Lock()
	defer s.Unlock()

	return s.processOtherNodeChangeEvent(dataChng)
}

// Close is called by the plugin infra when the CNI server needs to be stopped.
func (s *remoteCNIserver) Close() {
	s.cleanupVswitchConnectivity()
	s.ctxCancelFunc()
}

// Add handles CNI Add request, connects a Pod container to the network.
func (s *remoteCNIserver) Add(ctx context.Context, request *cni.CNIRequest) (*cni.CNIReply, error) {
	s.Info("Add request received ", *request)

	// 0. Wait for the CNI server to be in-sync

	s.Lock()
	for !s.inSync {
		s.inSyncCond.Wait()
		// TODO: with controller, we may even refuse to configure pods until
		// DHCP granted node IP address, but it has its own risks
	}
	defer s.Unlock()

	// 1. Check if the pod has an obsolete container connected to vswitch to be removed first

	var err error
	extraArgs := parseCniExtraArgs(request.ExtraArguments)
	podID := pod.ID{
		Name:      extraArgs[podNameExtraArg],
		Namespace: extraArgs[podNamespaceExtraArg],
	}
	pod, found := s.podByID[podID]
	if found {
		s.Logger.WithFields(
			logging.Fields{
				"name":        pod.ID.Name,
				"namespace":   pod.ID.Namespace,
				"containerID": pod.ContainerID,
			}).Info("Removing obsolete pod container")

		err = s.DeletePod(pod, true)
		if err != nil {
			// treat error as warning
			s.Logger.Warnf("Error while removing obsolete pod container: %v", err)
			err = nil
		}
	}

	// 2. Collect parameters of the pod that is about to be added

	pod = &Pod{
		ID:               podID,
		ContainerID:      request.ContainerId,
		NetworkNamespace: request.NetworkNamespace,
		// VPPIfName & LinuxIfName are filled by podConnectivityConfig
	}

	// 3. Schedule revert for pod IP allocation in case of an error

	defer func() {
		if err != nil {
			if pod.IPAddress != nil {
				s.ipam.ReleasePodIP(pod.ContainerID)
			}
		}
	}()

	// 4. Assign an IP address for this POD

	pod.IPAddress, err = s.ipam.NextPodIP(pod.ContainerID)
	if err != nil {
		err = fmt.Errorf("failed to allocate new IP address for pod %v: %v", pod.ID, err)
		s.Logger.Error(err)
		return generateCniErrorReply(err)
	}

	// 5. Enable IPv6

	// This is necessary for the latest docker where ipv6 is disabled by default.
	// OS assigns automatically ipv6 addr to a newly created TAP. We
	// try to reassign all IPs once interfaces is moved to a namespace.
	// Without explicitly enabled ipv6,/ we receive an error while moving
	// interface to a namespace.
	if !s.test {
		err = s.enableIPv6(pod)
		if err != nil {
			err = fmt.Errorf("failed to enable ipv6 in the namespace for pod %v: %v", pod.ID, err)
			s.Logger.Error(err)
			return generateCniErrorReply(err)
		}
	}

	// 6. Configure VPP <-> Pod connectivity

	// build transaction
	txn := s.txnFactory()
	config := s.podConnectivityConfig(pod)
	txn_api.PutAll(txn, config)

	// execute the config transaction
	txnCtx := context.Background()
	txnCtx = scheduler_api.WithRetry(txnCtx, time.Second, true)
	txnCtx = scheduler_api.WithRevert(txnCtx)
	txnCtx = scheduler_api.WithDescription(txnCtx,
		fmt.Sprintf("Connect pod %v (container: %s)", pod.ID, pod.ContainerID))
	err = txn.Commit(txnCtx)
	if err != nil {
		s.Logger.Error(err)
		return generateCniErrorReply(err)
	}

	// 7. Store pod attributes for queries issued by other plugins.

	s.podByID[pod.ID] = pod
	s.podByVPPIfName[pod.VPPIfName] = pod

	// 8. Run all registered post add hooks in the unlocked state.

	s.Unlock() // must be run in unlocked state, single event loop will help to avoid this
	for _, hook := range s.podPostAddHook {
		err = hook(pod.ID.Namespace, pod.ID.Name)
		if err != nil {
			// treat error as warning
			s.Logger.WithField("err", err).Warn("Pod post add hook has failed")
			err = nil
		}
	}
	s.Lock()

	// 9. prepare and send reply for the CNI request

	reply := generateCniReply(request, pod.IPAddress, s.ipam.PodGatewayIP())
	return reply, err
}

// Delete handles CNI Delete request, disconnects a Pod container from the network.
func (s *remoteCNIserver) Delete(ctx context.Context, request *cni.CNIRequest) (*cni.CNIReply, error) {
	s.Info("Delete request received ", *request)

	// 0. Wait for the CNI server to be in-sync

	s.Lock()
	for !s.inSync {
		s.inSyncCond.Wait()
	}
	defer s.Unlock()

	// 1. Check that the pod was indeed configured and obtain the configuration

	extraArgs := parseCniExtraArgs(request.ExtraArguments)
	podID := pod.ID{
		Name:      extraArgs[podNameExtraArg],
		Namespace: extraArgs[podNamespaceExtraArg],
	}
	pod, found := s.podByID[podID]
	if !found {
		s.Logger.Warnf("Cannot find configuration for pod: %s\n", podID)
		reply := generateCniEmptyOKReply()
		return reply, nil
	}

	// 2. Continue with DeletePod in the locked state

	err := s.DeletePod(pod, false)
	if err != nil {
		s.Logger.Error(err)
		return generateCniErrorReply(err)
	}

	// 3. Prepare and send reply for the CNI request

	reply := generateCniEmptyOKReply()
	return reply, nil
}

// DeletePod disconnects a Pod container from the vswitch.
// The function assumes that the CNI server is already in the locked state.
func (s *remoteCNIserver) DeletePod(pod *Pod, obsoletePod bool) error {
	var err, wasErr error

	// 1. Run all registered pre-removal hooks

	s.Unlock() // must be run in unlocked state, single event loop will help to avoid this
	for _, hook := range s.podPreRemovalHooks {
		err := hook(pod.ID.Namespace, pod.ID.Name)
		if err != nil {
			// treat error as warning
			s.Logger.WithField("err", err).Warn("Pod pre-removal hook has failed")
			err = nil
		}
	}
	s.Lock()

	// 2. Un-configure VPP <-> Pod connectivity

	// build transaction
	txn := s.txnFactory()
	config := s.podConnectivityConfig(pod)
	txn_api.DeleteAll(txn, config)

	// execute the config transaction
	txnCtx := context.Background()
	txnCtx = scheduler_api.WithRetry(txnCtx, time.Second, true)
	txnCtx = scheduler_api.WithDescription(txnCtx,
		fmt.Sprintf("Disconnect pod %v (container: %s)", pod.ID, pod.ContainerID))
	err = txn.Commit(txnCtx)
	if err != nil {
		wasErr = err
		if !obsoletePod {
			return err
		}
	}

	// 3. Remove internally stored pod attributes

	delete(s.podByID, pod.ID)
	delete(s.podByVPPIfName, pod.VPPIfName)

	// 4. Release IP address of the POD

	err = s.ipam.ReleasePodIP(pod.ContainerID)
	if err != nil {
		wasErr = err
		if !obsoletePod {
			return err
		}
	}

	return wasErr
}

/******* Resync *******/

// configureVswitchConnectivity configures base vSwitch VPP connectivity.
// Namely, it configures:
//  - physical NIC interfaces
//  - connectivity to the host stack (Linux)
//  - one route in VPP for every host interface
//  - one route in the host stack to direct traffic destined to pods via VPP
//  - one route in the host stack to direct traffic destined to services via VPP
//  - inter-VRF routing
//  - IP neighbor scanning
func (s *remoteCNIserver) configureVswitchConnectivity(txn txn_api.ResyncOperations) error {
	s.Logger.Info("Applying base vSwitch config.")

	// configure physical NIC
	err := s.configureVswitchNICs(txn)
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	// configure vswitch to host connectivity
	s.configureVswitchHostConnectivity(txn)

	// configure inter-VRF routing
	s.configureVswitchVrfRoutes(txn)

	// enable IP neighbor scanning (to clean up old ARP entries)
	key, ipneigh := s.enabledIPNeighborScan()
	txn.Put(key, ipneigh)

	// subscribe to VnetFibCounters to get rid of the not wanted notifications and errors from GoVPP
	// TODO: this is just a workaround until non-subscribed notifications are properly ignored by GoVPP
	s.subscribeVnetFibCounters()

	// enable packet trace if requested (should be used for debugging only)
	if s.config.EnablePacketTrace {
		s.executeDebugCLI("trace add dpdk-input 100000")
		s.executeDebugCLI("trace add virtio-input 100000")
	}

	return err
}

// configureVswitchNICs configures vswitch NICs - main NIC for node interconnect
// and other NICs optionally specified in the contiv plugin YAML configuration.
func (s *remoteCNIserver) configureVswitchNICs(txn txn_api.ResyncOperations) error {
	s.Logger.Info("Existing interfaces: ", s.swIfIndex.ListAllInterfaces())

	// configure the main VPP NIC interface
	err := s.configureMainVPPInterface(txn)
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	// configure other interfaces that were configured in contiv plugin YAML configuration
	if s.nodeConfig != nil && len(s.nodeConfig.OtherVPPInterfaces) > 0 {
		s.Logger.Debug("Configuring VPP for additional interfaces")
		s.configureOtherVPPInterfaces(txn)
	}

	return nil
}

// configureMainVPPInterface configures the main NIC used for node interconnect on vswitch VPP.
func (s *remoteCNIserver) configureMainVPPInterface(txn txn_api.ResyncOperations) error {
	var err error

	// 1. Determine the name of the main VPP NIC interface

	nicName := ""
	if s.nodeConfig != nil {
		// use name as as specified in node config YAML
		nicName = s.nodeConfig.MainVPPInterface.InterfaceName
		s.Logger.Debugf("Physical NIC name taken from nodeConfig: %v ", nicName)
	}

	if nicName == "" {
		// name not specified in config, use heuristic - select first non-virtual interface
		ifHandler := intf_vppcalls.NewIfVppHandler(s.govppChan, s.Logger)
		nics, err := ifHandler.DumpInterfacesByType(vpp_intf.Interface_ETHERNET_CSMACD)
		if err != nil {
			s.Logger.Errorf("Failed to dump physical interfaces: %v", err)
			return err
		}
nextNIC:
		for _, nic := range nics {
			// exclude "other" (non-main) NICs
			for _, otherNIC := range s.nodeConfig.OtherVPPInterfaces {
				if otherNIC.InterfaceName == nic.Interface.Name {
					continue nextNIC
				}
			}

			// we have the main NIC
			nicName = nic.Interface.Name
			s.Logger.Debugf("Physical NIC not taken from nodeConfig, but heuristic was used: %v ", nicName)
			break
		}
	}

	// 2. Determine the node IP address, default gateway IP and whether to use DHCP

	// 2.1 Non-STN case, read the configuration
	nicIP := ""
	useDHCP := false
	if s.nodeConfig != nil && s.nodeConfig.MainVPPInterface.IP != "" {
		nicIP = s.nodeConfig.MainVPPInterface.IP
	} else if s.nodeConfig != nil && s.nodeConfig.MainVPPInterface.UseDHCP {
		useDHCP = true
	} else if s.ipam.NodeInterconnectDHCPEnabled() {
		// inherit DHCP from global setting
		useDHCP = true
	}

	// 2.2 STN case, IP address taken from the stolen interface
	if s.UseSTN() {
		// get IP address of the STN interface
		var gwIP string
		if s.nodeConfig != nil && s.nodeConfig.StealInterface != "" {
			s.Logger.Infof("STN of the host interface %s requested.", s.nodeConfig.StealInterface)
			nicIP, gwIP, err = s.getSTNInterfaceIP(s.nodeConfig.StealInterface)
		} else if s.config.StealInterface != "" {
			s.Logger.Infof("STN of the interface %s requested.", s.config.StealInterface)
			nicIP, gwIP, err = s.getSTNInterfaceIP(s.config.StealInterface)
		} else {
			s.Logger.Infof("STN of the first interface (%s) requested.", nicName)
			nicIP, gwIP, err = s.getSTNInterfaceIP("")
		}

		if err != nil || nicIP == "" {
			s.Logger.Errorf("Unable to get STN interface info: %v, disabling the interface.", err)
			return err
		}

		s.stnIP = nicIP
		s.stnGw = gwIP
	}

	// 2.3 Set node IP address
	if !s.UseSTN() && useDHCP {
		// ip address will be assigned by DHCP server, not known yet
		s.Logger.Infof("Configuring %v to use dhcp", nicName)
	} else if nicIP != "" {
		s.setNodeIP(nicIP)
		s.Logger.Infof("Configuring %v to use %v", nicName, nicIP)
	} else {
		nodeIP, err := s.ipam.NodeIPWithPrefix(s.ipam.NodeID())
		if err != nil {
			s.Logger.Error("Unable to generate node IP address.")
			return err
		}
		s.setNodeIP(nodeIP.String())
		s.Logger.Infof("Configuring %v to use %v", nicName, nodeIP.String())
	}

	// 3. Configure the main interface

	if nicName != "" {
		// configure the physical NIC
		s.Logger.Info("Configuring physical NIC ", nicName)

		nicKey, nic := s.physicalInterface(nicName, s.nodeIP)
		if useDHCP {
			// clear IP addresses
			nic.IpAddresses = []string{}
			nic.SetDhcpClient = true
			if s.resyncCounter == 1 {
				// start watching dhcp notif
				s.dhcpIndex.Watch("cniserver", s.handleDHCPNotification)
			}
			// do lookup to cover the case where dhcp was configured by resync
			// and ip address is already assigned
			dhcpData, exists := s.dhcpIndex.GetValue(nicName)
			if exists {
				dhcpLease := dhcpData.(*vpp_intf.DHCPLease)
				s.Logger.Infof("DHCP notification already received: %v", dhcpLease)
				s.applyDHCPLease(dhcpLease)
			} else {
				s.Logger.Debugf("Waiting for DHCP notification. Existing DHCP events: %v", s.dhcpIndex.ListAllNames())
			}
		}
		txn.Put(nicKey, nic)
		s.mainPhysicalIf = nicName
	} else {
		// configure loopback instead of the physical NIC
		s.Logger.Debug("Physical NIC not found, configuring loopback instead.")
		key, loopback := s.loopbackInterface(s.nodeIP)
		txn.Put(key, loopback)
	}

	// 4. Configure the default route

	if nicName != "" && s.nodeConfig != nil && s.nodeConfig.Gateway != "" {
		// configure the default gateway
		key, defaultRoute := s.defaultRoute(s.nodeConfig.Gateway, nicName)
		txn.Put(key, defaultRoute)
	}

	return nil
}

// configureOtherVPPInterfaces configure all physical interfaces defined in the config but the main one.
func (s *remoteCNIserver) configureOtherVPPInterfaces(txn txn_api.ResyncOperations) {

	// match existing interfaces and build configuration
	interfaces := make(map[string]*vpp_intf.Interface)
	for _, name := range s.swIfIndex.ListAllInterfaces() {
		for _, intIP := range s.nodeConfig.OtherVPPInterfaces {
			if intIP.InterfaceName == name {
				key, iface := s.physicalInterface(name, intIP.IP)
				interfaces[key] = iface
			}
		}
	}

	// configure the interfaces on VPP
	if len(interfaces) > 0 {
		for key, iface := range interfaces {
			txn.Put(key, iface)
			s.otherPhysicalIfs = append(s.otherPhysicalIfs, iface.Name)
		}
	}
}

// configureVswitchHostConnectivity configures vswitch VPP to Linux host interconnect.
func (s *remoteCNIserver) configureVswitchHostConnectivity(txn txn_api.ResyncOperations) {
	var key string

	// configure interfaces to between VPP and the host network stack
	if s.config.UseTAPInterfaces {
		// TAP interface
		key, vppTAP := s.interconnectTapVPP()
		txn.Put(key, vppTAP)
		key, hostVPP := s.interconnectTapHost()
		txn.Put(key, hostVPP)
	} else {
		// veth + AF_PACKET
		key, afpacket := s.interconnectAfpacket()
		txn.Put(key, afpacket)
		key, vethHost := s.interconnectVethHost()
		txn.Put(key, vethHost)
		key, vethVPP := s.interconnectVethVpp()
		txn.Put(key, vethVPP)
	}

	// configure the routes from VPP to host interfaces
	var routesToHost map[string]*vpp_l3.StaticRoute
	if !s.UseSTN() {
		routesToHost = s.routesToHost(s.ipam.VEthHostEndIP().String())
	} else {
		routesToHost = s.routesToHost(ipNetToAddress(s.stnIP))
	}
	for key, route := range routesToHost {
		s.Logger.Debug("Adding route to host IP: ", route)
		txn.Put(key, route)
	}

	// configure the route from the host to PODs
	var routeToPods *linux_l3.LinuxStaticRoute
	if s.stnGw == "" {
		key, routeToPods = s.routePODsFromHost(s.ipam.VEthVPPEndIP().String())
	} else {
		key, routeToPods = s.routePODsFromHost(s.stnGw)
	}
	txn.Put(key, routeToPods)

	// route from the host to k8s service range from the host
	var routeToServices *linux_l3.LinuxStaticRoute
	if s.stnGw == "" {
		key, routeToServices = s.routeServicesFromHost(s.ipam.VEthVPPEndIP().String())
	} else {
		key, routeToServices = s.routeServicesFromHost(s.stnGw)
	}
	txn.Put(key, routeToServices)
}

// configureVswitchVrfRoutes configures inter-VRF routing
func (s *remoteCNIserver) configureVswitchVrfRoutes(txn txn_api.ResyncOperations) {
	// routes from main towards POD VRF: PodSubnet + VPPHostSubnet
	routes := s.routesMainToPodVRF()
	for key, route := range routes {
		txn.Put(key, route)
	}

	// routes from POD towards main VRF: default route + VPPHostNetwork
	routes = s.routesPodToMainVRF()
	for key, route := range routes {
		txn.Put(key, route)
	}

	// add DROP routes into POD VRF to avoid loops: the same routes that point
	// from main VRF to POD VRF are installed into POD VRF as DROP, to not go back
	// into the main VRF via default route in case that PODs are not reachable
	routes = s.dropRoutesIntoPodVRF()
	for key, route := range routes {
		txn.Put(key, route)
	}
}

/******* Cleanup *******/

// cleanupVswitchConnectivity cleans up base vSwitch VPP connectivity
// configuration in the host IP stack.
func (s *remoteCNIserver) cleanupVswitchConnectivity() {
	// prepare the config transaction
	txn := s.txnFactory()

	// un-configure VPP-host interconnect interfaces
	if s.config.UseTAPInterfaces {
		key, _ := s.interconnectTapVPP()
		txn.Delete(key)
		key, _ = s.interconnectTapHost()
		txn.Delete(key)
	} else {
		key, _ := s.interconnectVethHost()
		txn.Delete(key)
		key, _ = s.interconnectVethVpp()
		txn.Delete(key)
	}

	// execute the config transaction
	ctx := context.Background()
	ctx = scheduler_api.WithDescription(ctx, "Remote CNI Server Cleanup")
	err := txn.Commit(ctx)
	if err != nil {
		s.Logger.Warn(err)
	}
}

/******* Main Interface IP Address *******/

// getSTNInterfaceIP returns IP address of the interface before stealing it from the host stack.
func (s *remoteCNIserver) getSTNInterfaceIP(ifName string) (ip string, gw string, err error) {
	s.Logger.Debugf("Getting STN info for interface %s", ifName)

	// connect to STN GRPC server
	if s.config.STNSocketFile == "" {
		s.config.STNSocketFile = defaultSTNSocketFile
	}
	conn, err := grpc.Dial(
		s.config.STNSocketFile,
		grpc.WithInsecure(),
		grpc.WithDialer(
			func(addr string, timeout time.Duration) (net.Conn, error) {
				return net.DialTimeout("unix", addr, timeout)
			}),
	)
	if err != nil {
		s.Logger.Errorf("Unable to connect to STN GRPC: %v", err)
		return
	}
	defer conn.Close()
	c := stn_grpc.NewSTNClient(conn)

	// request info about the stolen interface
	reply, err := c.StolenInterfaceInfo(context.Background(), &stn_grpc.STNRequest{
		InterfaceName: ifName,
	})
	if err != nil {
		s.Logger.Errorf("Error by executing STN GRPC: %v", err)
		return
	}

	s.Logger.Debugf("STN GRPC reply: %v", reply)

	// STN IP address
	if len(reply.IpAddresses) == 0 {
		return
	}
	ip = reply.IpAddresses[0]

	// try to find the default gateway in the list of routes
	for _, r := range reply.Routes {
		if r.DestinationSubnet == "" || strings.HasPrefix(r.DestinationSubnet, "0.0.0.0") {
			gw = r.NextHopIp
			s.defaultGw = net.ParseIP(gw)
		}
	}
	if gw == "" {
		// no default gateway in routes, calculate fake gateway address for route pointing to VPP
		_, ipNet, _ := net.ParseCIDR(ip)
		firstIP, lastIP := cidr.AddressRange(ipNet)
		if cidr.Inc(firstIP).String() != ip {
			gw = cidr.Inc(firstIP).String()
		} else {
			gw = cidr.Dec(lastIP).String()
		}
	}

	return
}

// handleDHCPNotifications handles DHCP state change notifications
func (s *remoteCNIserver) handleDHCPNotification(notif idxmap.NamedMappingGenericEvent) {
	s.Logger.Info("DHCP notification received")
	if notif.Del {
		return
	}
	if notif.Value == nil {
		s.Logger.Warn("DHCP notification metadata is empty")
		return
	}

	dhcpLease, isDHCPLease := notif.Value.(*vpp_intf.DHCPLease)
	if !isDHCPLease {
		s.Logger.Warn("received invalid DHCP notification")
		return
	}

	if dhcpLease.InterfaceName != s.mainPhysicalIf {
		s.Logger.Warn("DHCP notification for a non-main interface")
		return
	}

	s.Lock()
	s.applyDHCPLease(dhcpLease)
	s.Unlock()
}

// applyDHCPLease updates defaultGw and node IP based on received DHCP lease.
// The method must be called with acquired mutex guarding remoteCNI server.
func (s *remoteCNIserver) applyDHCPLease(lease *vpp_intf.DHCPLease) {
	s.Logger.Debug("Processing DHCP event", lease)

	var err error
	s.defaultGw, _, err = net.ParseCIDR(lease.RouterIpAddress)
	if err != nil {
		s.Logger.Errorf("failed to parse DHCP route IP address: %v", err)
	}

	if s.nodeIP != "" && s.nodeIP != lease.HostIpAddress {
		s.Logger.Error("Update of Node IP address is not supported")
	}

	s.setNodeIP(lease.HostIpAddress)
	s.Logger.Info("DHCP event processed", lease)
}

// setNodeIP updates nodeIP and propagate the change to subscribers.
// The method must be called with acquired mutex guarding remoteCNI server.
func (s *remoteCNIserver) setNodeIP(nodeIP string) error {

	s.nodeIP = nodeIP

	for _, sub := range s.nodeIPsubscribers {
		select {
		case sub <- nodeIP:
		default:
			// skip subscribers who are not ready to receive notification
		}
	}

	return nil
}

/******* Remote CNI Server API *******/

// GetMainPhysicalIfName returns name of the "main" interface - i.e. physical interface connecting
// the node with the rest of the cluster.
func (s *remoteCNIserver) GetMainPhysicalIfName() string {
	s.Lock()
	defer s.Unlock()

	return s.mainPhysicalIf
}

// GetOtherPhysicalIfNames returns a slice of names of all physical interfaces configured additionally
// to the main interface.
func (s *remoteCNIserver) GetOtherPhysicalIfNames() []string {
	s.Lock()
	defer s.Unlock()

	return s.otherPhysicalIfs
}

// GetVxlanBVIIfName returns the name of an BVI interface facing towards VXLAN tunnels to other hosts.
// Returns an empty string if VXLAN is not used (in L2 interconnect mode).
func (s *remoteCNIserver) GetVxlanBVIIfName() string {
	if s.config.UseL2Interconnect {
		return ""
	}

	return vxlanBVIInterfaceName
}

// GetHostInterconnectIfName returns the name of the TAP/AF_PACKET interface
// interconnecting VPP with the host stack.
func (s *remoteCNIserver) GetHostInterconnectIfName() string {
	return s.hostInterconnectIfName()
}

// GetNodeIP returns the IP address of this node.
func (s *remoteCNIserver) GetNodeIP() (ip net.IP, network *net.IPNet) {
	s.Lock()
	defer s.Unlock()

	if s.nodeIP == "" {
		return nil, nil
	}

	nodeIP, nodeNet, err := net.ParseCIDR(s.nodeIP)
	if err != nil {
		return nil, nil
	}

	return nodeIP, nodeNet
}

// GetHostIPs returns all IP addresses of this node present in the host network namespace (Linux).
func (s *remoteCNIserver) GetHostIPs() []net.IP {
	s.Lock()
	defer s.Unlock()

	return s.hostIPs
}

// GetPodByIf looks up podName and podNamespace that is associated with logical interface name.
func (s *remoteCNIserver) GetPodByIf(ifName string) (podNamespace string, podName string, exists bool) {
	s.Lock()
	defer s.Unlock()

	pod, found := s.podByVPPIfName[ifName]
	if !found {
		return "", "", false
	}
	return pod.ID.Namespace, pod.ID.Name, true
}

// GetIfName looks up logical interface name that corresponds to the interface associated with the given POD name.
func (s *remoteCNIserver) GetIfName(podNamespace string, podName string) (name string, exists bool) {
	s.Lock()
	defer s.Unlock()

	pod, found := s.podByID[pod.ID{Name: podName, Namespace: podNamespace}]
	if !found {
		return "", false
	}
	return pod.VPPIfName, true
}

// WatchNodeIP adds given channel to the list of subscribers that are notified upon change
// of nodeIP address. If the channel is not ready to receive notification, the notification is dropped.
func (s *remoteCNIserver) WatchNodeIP(subscriber chan string) {
	s.Lock()
	defer s.Unlock()

	s.nodeIPsubscribers = append(s.nodeIPsubscribers, subscriber)
}

// RegisterPodPreRemovalHook allows to register callback that will be run for each
// pod immediately before its removal.
func (s *remoteCNIserver) RegisterPodPreRemovalHook(hook PodActionHook) {
	s.Lock()
	defer s.Unlock()

	s.podPreRemovalHooks = append(s.podPreRemovalHooks, hook)
}

// RegisterPodPostAddHook allows to register callback that will be run for each
// pod once it is added and before the CNI reply is sent.
func (s *remoteCNIserver) RegisterPodPostAddHook(hook PodActionHook) {
	s.Lock()
	defer s.Unlock()

	s.podPostAddHook = append(s.podPostAddHook, hook)
}

// GetDefaultInterface returns the name and the IP address of the interface
// used by the default route to send packets out from VPP towards the default gateway.
// If the default GW is not configured, the function returns zero values.
func (s *remoteCNIserver) GetDefaultInterface() (ifName string, ifAddress net.IP) {
	s.Lock()
	defer s.Unlock()

	if s.defaultGw != nil {
		if s.mainPhysicalIf != "" {
			nodeIP, nodeNet, _ := net.ParseCIDR(s.nodeIP)
			if nodeNet != nil && nodeNet.Contains(s.defaultGw) {
				return s.mainPhysicalIf, nodeIP
			}
		}
		for _, physicalIf := range s.nodeConfig.OtherVPPInterfaces {
			intIP, intNet, _ := net.ParseCIDR(physicalIf.IP)
			if intNet != nil && intNet.Contains(s.defaultGw) {
				return physicalIf.InterfaceName, intIP
			}
		}
	}

	return "", nil
}

// UseSTN returns true if the cluster was configured to be deployed in the STN mode.
func (s *remoteCNIserver) UseSTN() bool {
	return s.config.StealFirstNIC || s.config.StealInterface != "" || (s.nodeConfig != nil && s.nodeConfig.StealInterface != "")
}

// GetMainVrfID returns the ID of the main network connectivity VRF.
func (s *remoteCNIserver) GetMainVrfID() uint32 {
	if s.config.MainVRFID != 0 && s.config.PodVRFID != 0 {
		return s.config.MainVRFID
	}
	return defaultMainVrfID
}

// GetPodVrfID returns the ID of the POD VRF.
func (s *remoteCNIserver) GetPodVrfID() uint32 {
	if s.config.MainVRFID != 0 && s.config.PodVRFID != 0 {
		return s.config.PodVRFID
	}
	return defaultPodVrfID
}

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
	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/fsouza/go-dockerclient"
	"golang.org/x/net/context"

	"github.com/ligato/cn-infra/idxmap"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/rpc/rest"

	scheduler_api "github.com/ligato/vpp-agent/plugins/kvscheduler/api"
	"github.com/ligato/vpp-agent/plugins/linuxv2/model/l3"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/l3"

	stn_grpc "github.com/contiv/vpp/cmd/contiv-stn/model/stn"
	"github.com/contiv/vpp/plugins/contiv/ipam"
	"github.com/contiv/vpp/plugins/contiv/model/cni"
	controller "github.com/contiv/vpp/plugins/controller/api"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/gogo/protobuf/proto"
)

/* Global constants */
const (
	// defaultSTNSocketFile is the default socket file path where CNI GRPC server listens for incoming CNI requests.
	defaultSTNSocketFile = "/var/run/contiv/stn.sock"

	// interface host name length limit in Linux
	linuxIfNameMaxLen = 15

	// logical interface logical name length limit in the vpp-agent/ifplugin
	logicalIfNameMaxLen = 63

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
	// label attached to the sandbox container of every pod
	k8sLabelForSandboxContainer = "io.kubernetes.docker.type=podsandbox"

	// labels attached to (not only sandbox) container to identify the pod it belongs to
	k8sLabelForPodName      = "io.kubernetes.pod.name"
	k8sLabelForPodNamespace = "io.kubernetes.pod.namespace"

	// interface host name as required by Kubernetes for every pod
	podInterfaceHostName = "eth0" // required by Kubernetes

	// prefix for logical name of AF-Packet interface (VPP) connecting a pod
	podAFPacketLogicalNamePrefix = "afpacket"

	// prefix for logical name of VETH1 interface (pod namespace) connecting a pod
	podVETH1LogicalNamePrefix = "veth1-"

	// prefix for logical name of VETH2 interface (vswitch namespace) connecting a pod
	podVETH2LogicalNamePrefix = "veth2-"

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
// the networking between VPP and Kubernetes Pods.
type remoteCNIserver struct {
	sync.Mutex

	// input arguments
	*remoteCNIserverArgs

	// DHCP watching
	watchingDHCP bool // true if dhcpIndex is being watched
	useDHCP      bool // whether DHCP is disabled by the latest config (can be changed via CRD)

	// IPAM module used by the CNI server
	ipam *ipam.IPAM

	// set to true when running unit tests
	test bool

	// this node's main IP address and the default gateway
	nodeIP    net.IP
	nodeIPNet *net.IPNet
	defaultGw net.IP

	// IP addresses of this node present in the host network namespace (Linux)
	hostIPs []net.IP

	// podPreRemovalHooks is a slice of callbacks called before a pod removal
	podPreRemovalHooks []PodActionHook

	// podPostAddHooks is a slice of callbacks called once pod is added
	podPostAddHook []PodActionHook

	// pod run-time attributes
	podByID        map[podmodel.ID]*Pod
	podByVPPIfName map[string]*Pod

	// name of the main physical interface
	mainPhysicalIf string

	// name of extra physical interfaces configured by the agent
	otherPhysicalIfs []string

	// routes going via stolen interface
	stnRoutes []*stn_grpc.STNReply_Route
}

// remoteCNIserverArgs groups input arguments of the Remote CNI Server.
type remoteCNIserverArgs struct {
	logging.Logger
	eventLoop controller.EventLoop

	// node synchronization
	nodeSync nodesync.API

	// transaction factory - TODO: remove once all events are implemented
	txnFactory func() controller.Transaction

	// dumping of physical interfaces
	physicalIfsDump PhysicalIfacesDumpClb

	// callback to receive information about a stolen interface
	getStolenInterfaceInfo StolenInterfaceInfoClb

	// dumping of host IPs
	hostLinkIPsDump HostLinkIPsDumpClb

	// docker client
	dockerClient DockerClient

	// GoVPP channel for direct binary API calls (not needed for UTs)
	govppChan api.Channel

	// VPP DHCP index map
	dhcpIndex idxmap.NamedMapping

	// agent microservice label
	agentLabel string

	// node specific configuration
	nodeConfig *NodeConfig

	// global config
	config *Config

	// a set of IP addresses from node CIDR to not use for allocation
	nodeInterconnectExcludedIPs []net.IP

	// REST interface (not needed for UTs)
	http rest.HTTPHandlers
}

// DockerClient requires API of a Docker client needed by the remote CNI server.
type DockerClient interface {
	// Ping pings the docker server.
	Ping() error
	// ListContainers returns a slice of containers matching the given criteria.
	ListContainers(opts docker.ListContainersOptions) ([]docker.APIContainers, error)
	// InspectContainer returns information about a container by its ID.
	InspectContainer(id string) (*docker.Container, error)
}

// PhysicalIfacesDumpClb is callback for dumping physical interfaces on VPP.
type PhysicalIfacesDumpClb func() (ifaces map[uint32]string, err error) // interface index -> interface name

// StolenInterfaceInfoClb is callback for receiving information about a stolen interface.
type StolenInterfaceInfoClb func(ifName string) (reply *stn_grpc.STNReply, err error)

// HostLinkIPsDumpClb is callback for dumping all IP addresses assigned to interfaces
// in the host stack.
type HostLinkIPsDumpClb func() ([]net.IP, error)

/********************************* Constructor *********************************/

// newRemoteCNIServer initializes a new remote CNI server instance.
func newRemoteCNIServer(args *remoteCNIserverArgs) (*remoteCNIserver, error) {
	ipam, err := ipam.New(args.Logger, args.nodeSync.GetNodeID(), &args.config.IPAMConfig, args.nodeInterconnectExcludedIPs)
	if err != nil {
		return nil, err
	}
	server := &remoteCNIserver{remoteCNIserverArgs: args, ipam: ipam}
	server.registerHandlers()
	return server, nil
}

/********************************** Stringer **********************************/

// String returns human-readable string representation of RemoteCNIServer state (not args).
func (s *remoteCNIserver) String() string {
	// pods by ID
	podsByID := "{"
	first := true
	for podID, pod := range s.podByID {
		if !first {
			podsByID += ", "
		}
		first = false
		podsByID += fmt.Sprintf("%s: %s", podID.String(), pod.String())
	}
	podsByID += "}"

	// pods by VPP interface name
	podByVPPIfName := "{"
	first = true
	for vppIfName, pod := range s.podByVPPIfName {
		if !first {
			podByVPPIfName += ", "
		}
		first = false
		podByVPPIfName += fmt.Sprintf("%s: %s", vppIfName, pod.String())
	}
	podByVPPIfName += "}"

	return fmt.Sprintf("<useDHCP: %t, watchingDHCP: %t, "+
		"mainPhysicalIf: %s, otherPhysicalIfs: %v, "+
		"nodeIP: %s, nodeIPNet: %s, defaultGw: %s, hostIPs: %v, "+
		"podByID: %s, podByVppIfName: %s, stnRoutes: %v",
		s.useDHCP, s.watchingDHCP,
		s.mainPhysicalIf, s.otherPhysicalIfs,
		s.nodeIP.String(), ipNetToString(s.nodeIPNet), s.defaultGw.String(), s.hostIPs,
		podsByID, podByVPPIfName, s.stnRoutes)
}

/********************************* Events **************************************/

// Resync re-synchronizes configuration based on Kubernetes state data.
func (s *remoteCNIserver) Resync(event controller.Event, kubeStateData controller.KubeStateData,
	resyncCount int, txn controller.ResyncOperations) error {

	var wasErr error
	s.Lock()
	defer s.Unlock()

	// ipam
	if resyncCount == 1 {
		// No need to run resync for IPAM in run-time - IP address will not be allocated
		// to a local pod without the agent knowing about it. Also there is a risk
		// of a race condition - resync triggered shortly after Add/DelPod may work
		// with K8s state data that do not yet reflect the freshly added/removed pod.
		err := s.ipam.Resync(kubeStateData)
		if err != nil {
			wasErr = err
			s.Logger.Error(err)
		}
	}

	// node <-> host, host -> pods
	err := s.configureVswitchConnectivity(event, txn)
	if err != nil {
		wasErr = err
		s.Logger.Error(err)
	}

	// node <-> node
	err = s.otherNodesResync(txn)
	if err != nil {
		wasErr = err
		s.Logger.Error(err)
	}

	// pods <-> vswitch
	if resyncCount == 1 {
		// No need to resync the state of running pods in run-time - local pod
		// will not be added/deleted without the agent knowing about it. Also there
		// is a risk of a race condition - resync triggered shortly after Add/DelPod
		// may work with K8s state data that do not yet reflect the freshly added/removed pod.
		err = s.podStateResync(kubeStateData)
		if err != nil {
			wasErr = err
			s.Logger.Error(err)
		}
	}
	for _, pod := range s.podByID {
		config := s.podConnectivityConfig(pod)
		controller.PutAll(txn, config)
	}

	s.Logger.Infof("Remote CNI Server state after RESYNC: %s", s.String())
	return wasErr
}

// Update reacts to NodeUpdate.
func (s *remoteCNIserver) Update(nodeUpdate *nodesync.NodeUpdate, txn controller.UpdateOperations) (change string, err error) {
	s.Lock()
	defer s.Unlock()

	return s.processNodeUpdateEvent(nodeUpdate, txn)
}

// Close is called by the plugin infra when the CNI server needs to be stopped.
func (s *remoteCNIserver) Close() {
	s.cleanupVswitchConnectivity()
}

// Add handles CNI Add request, connects a Pod container to the network.
func (s *remoteCNIserver) Add(ctx context.Context, request *cni.CNIRequest) (*cni.CNIReply, error) {
	s.Info("Add request received ", *request)
	s.Lock()
	defer s.Unlock()

	// 1. Check if the pod has an obsolete container connected to vswitch to be removed first

	var err error
	extraArgs := parseCniExtraArgs(request.ExtraArguments)
	podID := podmodel.ID{
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

	// 3. Schedule revert

	defer func() {
		if err != nil {
			if pod.IPAddress != nil {
				s.ipam.ReleasePodIP(podID)
			}
			delete(s.podByID, pod.ID)
			delete(s.podByVPPIfName, pod.VPPIfName)
		}
	}()

	// 4. Assign an IP address for this POD

	pod.IPAddress, err = s.ipam.AllocatePodIP(podID)
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

	// 6. Prepare configuration for VPP <-> Pod connectivity

	txn := s.txnFactory()
	config := s.podConnectivityConfig(pod)
	controller.PutAll(txn, config)

	// 7. Store pod attributes for queries issued by other plugins.

	s.podByID[pod.ID] = pod
	s.podByVPPIfName[pod.VPPIfName] = pod

	// 8. Run all registered post add hooks in the unlocked state.

	s.Unlock() // must be run in unlocked state, single event loop will help to avoid this
	for _, hook := range s.podPostAddHook {
		err = hook(pod.ID.Namespace, pod.ID.Name, txn)
		if err != nil {
			// treat error as warning
			s.Logger.WithField("err", err).Warn("Pod post add hook has failed")
			err = nil
		}
	}
	s.Lock()

	// 9. Execute the config transaction

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

	// 9. Prepare and send reply for the CNI request

	reply := generateCniReply(request, pod.IPAddress, s.ipam.PodGatewayIP())
	return reply, err
}

// Delete handles CNI Delete request, disconnects a Pod container from the network.
func (s *remoteCNIserver) Delete(ctx context.Context, request *cni.CNIRequest) (*cni.CNIReply, error) {
	s.Info("Delete request received ", *request)
	s.Lock()
	defer s.Unlock()

	// 1. Check that the pod was indeed configured and obtain the configuration

	extraArgs := parseCniExtraArgs(request.ExtraArguments)
	podID := podmodel.ID{
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
	txn := s.txnFactory()

	// 1. Run all registered pre-removal hooks
	s.Unlock() // must be run in unlocked state, single event loop will help to avoid this
	for _, hook := range s.podPreRemovalHooks {
		err := hook(pod.ID.Namespace, pod.ID.Name, txn)
		if err != nil {
			// treat error as warning
			s.Logger.WithField("err", err).Warn("Pod pre-removal hook has failed")
			err = nil
		}
	}
	s.Lock()

	// 2. Un-configure VPP <-> Pod connectivity

	// add configuration for pod connectivity into the transaction
	config := s.podConnectivityConfig(pod)
	controller.DeleteAll(txn, config)

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

	err = s.ipam.ReleasePodIP(pod.ID)
	if err != nil {
		wasErr = err
		if !obsoletePod {
			return err
		}
	}

	return wasErr
}

/********************************* Resync *************************************/

// configureVswitchConnectivity configures base vSwitch VPP connectivity.
// Namely, it configures:
//  - physical NIC interfaces
//  - connectivity to the host stack (Linux)
//  - one route in VPP for every host interface
//  - one route in the host stack to direct traffic destined to pods via VPP
//  - one route in the host stack to direct traffic destined to services via VPP
//  - inter-VRF routing
//  - IP neighbor scanning
func (s *remoteCNIserver) configureVswitchConnectivity(event controller.Event, txn controller.ResyncOperations) error {
	// configure physical NIC
	err := s.configureVswitchNICs(event, txn)
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	// configure vswitch to host connectivity
	err = s.configureVswitchHostConnectivity(txn)
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	if s.UseSTN() {
		// configure STN connectivity
		s.configureSTNConnectivity(txn)
	}

	// configure inter-VRF routing
	s.configureVswitchVrfRoutes(txn)

	// enable IP neighbor scanning (to clean up old ARP entries)
	key, ipneigh := s.enabledIPNeighborScan()
	txn.Put(key, ipneigh)

	// subscribe to VnetFibCounters to get rid of the not wanted notifications and errors from GoVPP
	// TODO: this is just a workaround until non-subscribed notifications are properly ignored by GoVPP
	if !s.test {
		s.subscribeVnetFibCounters()
	}

	// enable packet trace if requested (should be used for debugging only)
	if !s.test && s.config.EnablePacketTrace {
		s.executeDebugCLI("trace add dpdk-input 100000")
		s.executeDebugCLI("trace add virtio-input 100000")
	}

	return err
}

// configureVswitchNICs configures vswitch NICs - main NIC for node interconnect
// and other NICs optionally specified in the contiv plugin YAML configuration.
func (s *remoteCNIserver) configureVswitchNICs(event controller.Event, txn controller.ResyncOperations) error {
	// dump physical interfaces present on VPP
	nics, err := s.physicalIfsDump()
	if err != nil {
		s.Logger.Errorf("Failed to dump physical interfaces: %v", err)
		return err
	}
	s.Logger.Infof("Existing interfaces: %v", nics)

	// configure the main VPP NIC interface
	err = s.configureMainVPPInterface(event, nics, txn)
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	// configure other interfaces that were configured in contiv plugin YAML configuration
	if s.nodeConfig != nil && len(s.nodeConfig.OtherVPPInterfaces) > 0 {
		s.Logger.Debug("Configuring VPP for additional interfaces")
		err = s.configureOtherVPPInterfaces(nics, txn)
		if err != nil {
			s.Logger.Error(err)
			return err
		}
	}

	return nil
}

// configureMainVPPInterface configures the main NIC used for node interconnect on vswitch VPP.
func (s *remoteCNIserver) configureMainVPPInterface(event controller.Event, physicalIfaces map[uint32]string, txn controller.ResyncOperations) error {
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
	nextNIC:
		for _, physicalIface := range physicalIfaces {
			// exclude "other" (non-main) NICs
			if s.nodeConfig != nil {
				for _, otherNIC := range s.nodeConfig.OtherVPPInterfaces {
					if otherNIC.InterfaceName == physicalIface {
						continue nextNIC
					}
				}
			}

			// we have the main NIC
			nicName = physicalIface
			s.Logger.Debugf("Physical NIC not taken from nodeConfig, but heuristic was used: %v ", nicName)
			break
		}
	}

	if nicName != "" {
		s.Logger.Info("Configuring physical NIC ", nicName)
	}

	// 2. Determine the node IP address, default gateway IP and whether to use DHCP

	// 2.1 Read the configuration
	var nicStaticIPs []*nodesync.IPWithNetwork
	s.useDHCP = false
	if s.nodeConfig != nil && s.nodeConfig.MainVPPInterface.IP != "" {
		nicIP, nicIPNet, err := net.ParseCIDR(s.nodeConfig.MainVPPInterface.IP)
		if err != nil {
			s.Logger.Errorf("Failed to parse main interface IP address from the config: %v", err)
			return err
		}
		nicStaticIPs = append(nicStaticIPs,
			&nodesync.IPWithNetwork{Address: nicIP, Network: nicIPNet})
	} else if s.nodeConfig != nil && s.nodeConfig.MainVPPInterface.UseDHCP {
		s.useDHCP = true
	} else if s.ipam.NodeInterconnectDHCPEnabled() {
		// inherit DHCP from global setting
		s.useDHCP = true
	}

	// 2.2 STN case, IP address taken from the stolen interface
	if s.UseSTN() {
		// determine name of the stolen interface
		var stolenIface string
		if s.nodeConfig != nil && s.nodeConfig.StealInterface != "" {
			stolenIface = s.nodeConfig.StealInterface
		} else if s.config.StealInterface != "" {
			stolenIface = s.config.StealInterface
		} // else go with the first stolen interface

		// obtain STN interface configuration
		nicStaticIPs, s.defaultGw, s.stnRoutes, err = s.getStolenInterfaceConfig(stolenIface)
		if err != nil {
			s.Logger.Errorf("Unable to get STN interface info: %v, disabling the interface.", err)
			return err
		}
	}

	// 2.3 Set node IP address
	if s.useDHCP {
		// ip address is assigned by DHCP server
		s.Logger.Infof("Configuring %v to use DHCP", nicName)
		if nodeIPv4Change, isNodeIPv4Change := event.(*NodeIPv4Change); isNodeIPv4Change {
			// this resync event has been triggered to process DHCP event
			s.nodeIP = nodeIPv4Change.NodeIP
			s.nodeIPNet = nodeIPv4Change.NodeIPNet
			s.defaultGw = nodeIPv4Change.DefaultGw
		}
	} else if len(nicStaticIPs) > 0 {
		s.nodeIP = nicStaticIPs[0].Address
		s.nodeIPNet = nicStaticIPs[0].Network
		s.Logger.Infof("Configuring %v to use %v", nicName, s.nodeIP)
	} else {
		nodeIP, nodeIPNet, err := s.ipam.NodeIPAddress(s.nodeSync.GetNodeID())
		if err != nil {
			s.Logger.Error("Unable to generate node IP address.")
			return err
		}
		nicStaticIPs = append(nicStaticIPs,
			&nodesync.IPWithNetwork{Address: nodeIP, Network: nodeIPNet})
		s.nodeIP = nodeIP
		s.nodeIPNet = nodeIPNet
		s.Logger.Infof("Configuring %v to use %v", nicName, nodeIP.String())
	}
	// publish the node IP address to other nodes
	var nodeIPs []*nodesync.IPWithNetwork
	if len(s.nodeIP) > 0 {
		nodeIPs = append(nodeIPs, &nodesync.IPWithNetwork{Address: s.nodeIP, Network: s.nodeIPNet})
	}
	s.nodeSync.PublishNodeIPs(nodeIPs, nodesync.IPv4)

	// 3. Configure the main interface

	if nicName != "" {
		// configure the physical NIC
		nicKey, nic := s.physicalInterface(nicName, nicStaticIPs)
		if s.useDHCP {
			// clear IP addresses
			nic.IpAddresses = []string{}
			nic.SetDhcpClient = true
			if !s.watchingDHCP {
				// start watching of DHCP notifications
				s.dhcpIndex.Watch("cniserver", s.handleDHCPNotification)
				s.watchingDHCP = true
			}
		}
		txn.Put(nicKey, nic)
		s.mainPhysicalIf = nicName
	} else {
		// configure loopback instead of the physical NIC
		s.Logger.Debug("Physical NIC not found, configuring loopback instead.")
		key, loopback := s.loopbackInterface(nicStaticIPs)
		txn.Put(key, loopback)
		s.mainPhysicalIf = ""
	}

	// 4. For 2NICs non-DHCP case, configure the default route from the configuration

	if !s.UseSTN() && !s.useDHCP {
		if s.mainPhysicalIf != "" && s.nodeConfig != nil && s.nodeConfig.Gateway != "" {
			// configure default gateway from the config file
			s.defaultGw = net.ParseIP(s.nodeConfig.Gateway)
			if s.defaultGw == nil {
				err = fmt.Errorf("failed to parse gateway IP address from the config (%s)",
					s.nodeConfig.Gateway)
				return err
			}
			key, defaultRoute := s.defaultRoute(s.defaultGw, nicName)
			txn.Put(key, defaultRoute)
		}
	}

	return nil
}

// configureOtherVPPInterfaces configure all physical interfaces defined in the config but the main one.
func (s *remoteCNIserver) configureOtherVPPInterfaces(physicalIfaces map[uint32]string, txn controller.ResyncOperations) error {
	s.otherPhysicalIfs = []string{}

	// match existing interfaces and build configuration
	interfaces := make(map[string]*interfaces.Interface)
	for _, physicalIface := range physicalIfaces {
		for _, ifaceCfg := range s.nodeConfig.OtherVPPInterfaces {
			if ifaceCfg.InterfaceName == physicalIface {
				ipAddr, ipNet, err := net.ParseCIDR(ifaceCfg.IP)
				if err != nil {
					err := fmt.Errorf("failed to parse IP address configured for interface %s: %v",
						ifaceCfg.InterfaceName, err)
					return err
				}
				key, iface := s.physicalInterface(physicalIface, []*nodesync.IPWithNetwork{
					{Address: ipAddr, Network: ipNet},
				})
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

	return nil
}

// configureVswitchHostConnectivity configures vswitch VPP to Linux host interconnect.
func (s *remoteCNIserver) configureVswitchHostConnectivity(txn controller.ResyncOperations) (err error) {
	var key string

	// list all IPs assigned to host interfaces
	s.hostIPs, err = s.hostLinkIPsDump()
	if err != nil {
		return err
	}

	// configure interfaces between VPP and the host network stack
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

	// configure routes from VPP to the host
	var routesToHost map[string]*l3.StaticRoute
	if !s.UseSTN() {
		routesToHost = s.routesToHost(s.ipam.HostInterconnectIPInLinux())
	} else {
		routesToHost = s.routesToHost(s.nodeIP)
	}
	for key, route := range routesToHost {
		txn.Put(key, route)
	}

	// configure the route from the host to PODs
	var routeToPods *linux_l3.StaticRoute
	if !s.UseSTN() {
		key, routeToPods = s.routePODsFromHost(s.ipam.HostInterconnectIPInVPP())
	} else {
		key, routeToPods = s.routePODsFromHost(s.defaultGw)
	}
	txn.Put(key, routeToPods)

	// route from the host to k8s service range from the host
	var routeToServices *linux_l3.StaticRoute
	if !s.UseSTN() {
		key, routeToServices = s.routeServicesFromHost(s.ipam.HostInterconnectIPInVPP())
	} else {
		key, routeToServices = s.routeServicesFromHost(s.defaultGw)
	}
	txn.Put(key, routeToServices)

	return nil
}

// configureSTNConnectivity configures vswitch VPP to operate in the STN mode.
func (s *remoteCNIserver) configureSTNConnectivity(txn controller.ResyncOperations) {
	if len(s.nodeIP) > 0 {
		// STN rule
		key, stnrule := s.stnRule()
		txn.Put(key, stnrule)

		// proxy ARP for ARP requests from the host
		key, proxyarp := s.proxyArpForSTNGateway()
		txn.Put(key, proxyarp)
	}

	// STN routes
	stnRoutesVPP := s.stnRoutesForVPP()
	for key, route := range stnRoutesVPP {
		txn.Put(key, route)
	}
	stnRoutesHost := s.stnRoutesForHost()
	for key, route := range stnRoutesHost {
		txn.Put(key, route)
	}
}

// configureVswitchVrfRoutes configures inter-VRF routing
func (s *remoteCNIserver) configureVswitchVrfRoutes(txn controller.ResyncOperations) {
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

// podStateResync resynchronizes internal maps (s.podBy*) with the current
// state of locally deployed pods based on Kubernetes state data and information
// provided by Docker server.
func (s *remoteCNIserver) podStateResync(kubeStateData controller.KubeStateData) error {
	// use docker client to obtain the set of running pods
	runningPods, err := s.listRunningPods()
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	// reset internal maps with pods only after we have successfully obtained
	// information from the docker server
	s.podByID = make(map[podmodel.ID]*Pod)
	s.podByVPPIfName = make(map[string]*Pod)

	// iterate over state data of all locally deployed pods
	for _, podProto := range kubeStateData[podmodel.PodKeyword] {
		podData := podProto.(*podmodel.Pod)
		// ignore pods deployed on other nodes or without IP address
		podIPAddress := net.ParseIP(podData.IpAddress)
		if podIPAddress == nil || !s.ipam.PodSubnetThisNode().Contains(podIPAddress) {
			continue
		}

		// ignore pods which are not actually running
		podID := podmodel.ID{Name: podData.Name, Namespace: podData.Namespace}
		pod, isRunning := runningPods[podID]
		if !isRunning {
			s.Logger.Warnf("Pod %v is not in the RUNNING state, skipping.", podID)
			continue
		}

		// fill the pod parameters not provided by listRunningPods
		pod.VPPIfName, pod.LinuxIfName = s.podInterfaceName(pod)
		pod.IPAddress = podIPAddress

		// store pod configuration
		s.podByID[pod.ID] = pod
		s.podByVPPIfName[pod.VPPIfName] = pod
	}

	return nil
}

// listRunningPods uses Docker client to talk to the Docker server in order to list
// all locally running pods.
func (s *remoteCNIserver) listRunningPods() (pods map[podmodel.ID]*Pod, err error) {
	pods = make(map[podmodel.ID]*Pod)
	if err := s.dockerClient.Ping(); err != nil {
		return pods, fmt.Errorf("docker server is not available: %v", err)
	}

	// list all sandbox containers
	listOpts := docker.ListContainersOptions{
		All: true,
		Filters: map[string][]string{
			"label": {k8sLabelForSandboxContainer},
		},
	}
	containers, err := s.dockerClient.ListContainers(listOpts)
	if err != nil {
		return pods, fmt.Errorf("failed to list sandbox containers: %v", err)
	}

	// inspect every sandbox to re-construct the pod metadata
	for _, container := range containers {
		// read pod identifier from labels
		podName, hasPodName := container.Labels[k8sLabelForPodName]
		podNamespace, hasPodNamespace := container.Labels[k8sLabelForPodNamespace]
		podID := podmodel.ID{Name: podName, Namespace: podNamespace}
		if !hasPodName || !hasPodNamespace {
			s.Logger.Warnf("Sandbox container '%s' is missing pod identification\n",
				container.ID)
			continue
		}
		// inspect every sandbox container to obtain the PID, which is used in the network
		// namespace reference
		details, err := s.dockerClient.InspectContainer(container.ID)
		if err != nil {
			s.Logger.Warnf("Failed to inspect sandbox container '%s': %v\n",
				container.ID, err)
			continue
		}
		// ignore bare (without process) sandbox containers
		if details.State.Pid == 0 {
			continue
		}
		// add pod into the set of running pods
		pods[podID] = &Pod{
			ID:               podID,
			ContainerID:      container.ID,
			NetworkNamespace: fmt.Sprintf("/proc/%d/ns/net", details.State.Pid),
			// IPAddress and interface are filled by podStateResync
		}
		s.Logger.Debugf("Found running Pod: %+v", pods[podID])
	}

	return pods, nil
}

/********************************** Cleanup ***********************************/

// cleanupVswitchConnectivity cleans up base vSwitch VPP connectivity
// configuration in the host IP stack.
func (s *remoteCNIserver) cleanupVswitchConnectivity() {
	if s.config.UseTAPInterfaces {
		// everything configured in the host will disappear automatically
		return
	}

	// prepare the config transaction
	txn := s.txnFactory()

	// un-configure VETHs
	key, _ := s.interconnectVethHost()
	txn.Delete(key)
	key, _ = s.interconnectVethVpp()
	txn.Delete(key)

	// execute the config transaction
	ctx := context.Background()
	ctx = scheduler_api.WithDescription(ctx, "Remote CNI Server Cleanup")
	err := txn.Commit(ctx)
	if err != nil {
		s.Logger.Warn(err)
	}
}

/************************** Main Interface IP Address **************************/

// getStolenInterfaceConfig returns IP addresses and routes associated with the main
// interface before it was stolen from the host stack.
func (s *remoteCNIserver) getStolenInterfaceConfig(ifName string) (ipNets []*nodesync.IPWithNetwork, gw net.IP, routes []*stn_grpc.STNReply_Route, err error) {
	if ifName == "" {
		s.Logger.Debug("Getting STN info for the first stolen interface")
	} else {
		s.Logger.Debugf("Getting STN info for interface %s", ifName)
	}

	// request info about the stolen interface
	reply, err := s.getStolenInterfaceInfo(ifName)
	if err != nil {
		s.Logger.Errorf("Error by executing STN GRPC: %v", err)
		return
	}
	s.Logger.Debugf("STN GRPC reply: %v", reply)

	// parse STN IP addresses
	for _, address := range reply.IpAddresses {
		ipNet := &nodesync.IPWithNetwork{}
		ipNet.Address, ipNet.Network, err = net.ParseCIDR(address)
		if err != nil {
			s.Logger.Errorf("Failed to parse IP address returned by STN GRPC: %v", err)
			return
		}
		ipNets = append(ipNets, ipNet)
	}

	// try to find the default gateway in the list of routes
	for _, r := range reply.Routes {
		if r.DestinationSubnet == "" || strings.HasPrefix(r.DestinationSubnet, "0.0.0.0") {
			gw = net.ParseIP(r.NextHopIp)
			if err != nil {
				err = fmt.Errorf("failed to parse GW address returned by STN GRPC (%s)", r.NextHopIp)
				return
			}
			break
		}
	}
	if len(gw) == 0 && len(ipNets) > 0 {
		// no default gateway in routes, calculate fake gateway address for route pointing to VPP
		firstIP, lastIP := cidr.AddressRange(ipNets[0].Network)
		if !cidr.Inc(firstIP).Equal(ipNets[0].Address) {
			gw = cidr.Inc(firstIP)
		} else {
			gw = cidr.Dec(lastIP)
		}
	}

	// return routes without any processing
	routes = reply.Routes
	return
}

var (
	// variable used only in the context of go routines running handleDHCPNotification
	lastDHCPLease *interfaces.DHCPLease
)

// handleDHCPNotifications handles DHCP state change notifications
func (s *remoteCNIserver) handleDHCPNotification(notif idxmap.NamedMappingGenericEvent) {
	s.Logger.Info("DHCP notification received")

	// check for validity of the DHCP event
	if notif.Del {
		s.Logger.Info("Ignoring event of removed DHCP lease")
		return
	}
	if !s.useDHCP {
		s.Logger.Info("Ignoring DHCP event, dynamic IP address assignment is disabled")
		return
	}
	if notif.Value == nil {
		s.Logger.Warn("DHCP notification metadata is empty")
		return
	}
	dhcpLease, isDHCPLease := notif.Value.(*interfaces.DHCPLease)
	if !isDHCPLease {
		s.Logger.Warn("Received invalid DHCP notification")
		return
	}
	if dhcpLease.InterfaceName != s.mainPhysicalIf {
		s.Logger.Warn("DHCP notification for a non-main interface")
		return
	}
	if proto.Equal(dhcpLease, lastDHCPLease) {
		// nothing has really changed, ignore
		s.Logger.Info("Ignoring DHCP event - this lease was already processed")
		return
	}
	lastDHCPLease = dhcpLease

	// parse DHCP lease fields
	hostAddr, hostNet, defaultGw, err := s.parseDHCPLease(dhcpLease)
	if err != nil {
		return
	}

	// push event into the event loop
	s.eventLoop.PushEvent(&NodeIPv4Change{
		NodeIP:    hostAddr,
		NodeIPNet: hostNet,
		DefaultGw: defaultGw,
	})
	s.Logger.Infof("Sent NodeIPv4Change event to the event loop for DHCP lease: %+v", *dhcpLease)
}

// parseDHCPLease parses fields of a DHCP lease.
func (s *remoteCNIserver) parseDHCPLease(lease *interfaces.DHCPLease) (hostAddr net.IP, hostNet *net.IPNet, defaultGw net.IP, err error) {
	// parse IP address of the default gateway
	if lease.RouterIpAddress != "" {
		defaultGw, _, err = net.ParseCIDR(lease.RouterIpAddress)
		if err != nil {
			s.Logger.Errorf("Failed to parse DHCP route IP address: %v", err)
			return
		}
	}

	// parse host IP address and network
	if lease.HostIpAddress != "" {
		hostAddr, hostNet, err = net.ParseCIDR(lease.HostIpAddress)
		if err != nil {
			s.Logger.Errorf("Failed to parse DHCP host IP address: %v", err)
			return
		}
	}
	return
}

/**************************** Remote CNI Server API ****************************/

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
	return s.hostInterconnectVPPIfName()
}

// GetNodeIP returns the IP address of this node.
func (s *remoteCNIserver) GetNodeIP() (ip net.IP, network *net.IPNet) {
	s.Lock()
	defer s.Unlock()

	return s.nodeIP, s.nodeIPNet
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

	pod, found := s.podByID[podmodel.ID{Name: podName, Namespace: podNamespace}]
	if !found {
		return "", false
	}
	return pod.VPPIfName, true
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
			if s.nodeIPNet != nil && s.nodeIPNet.Contains(s.defaultGw) {
				return s.mainPhysicalIf, s.nodeIP
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
	return s.config.StealFirstNIC || s.config.StealInterface != "" ||
		(s.nodeConfig != nil && s.nodeConfig.StealInterface != "")
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

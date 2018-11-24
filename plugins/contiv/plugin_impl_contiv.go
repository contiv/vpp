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

//go:generate protoc -I ./model/cni --gogo_out=plugins=grpc:./model/cni ./model/cni/cni.proto
//go:generate protoc -I ./model/nodeinfo --gogo_out=plugins=grpc:./model/nodeinfo ./model/nodeinfo/nodeinfo.proto

package contiv

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
	"sync"

	"git.fd.io/govpp.git/api"
	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/fsouza/go-dockerclient"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"

	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/infra"
	grpcplugin "github.com/ligato/cn-infra/rpc/grpc"
	"github.com/ligato/cn-infra/rpc/rest"
	"github.com/ligato/cn-infra/servicelabel"
	"github.com/ligato/cn-infra/utils/safeclose"

	"github.com/ligato/vpp-agent/plugins/govppmux"
	kvscheduler_api "github.com/ligato/vpp-agent/plugins/kvscheduler/api"
	vpp_ifplugin "github.com/ligato/vpp-agent/plugins/vppv2/ifplugin"
	intf_vppcalls "github.com/ligato/vpp-agent/plugins/vppv2/ifplugin/vppcalls"
	"github.com/ligato/vpp-agent/plugins/vppv2/model/interfaces"

	stn_grpc "github.com/contiv/vpp/cmd/contiv-stn/model/stn"
	"github.com/contiv/vpp/plugins/contiv/model/cni"
	"github.com/contiv/vpp/plugins/contiv/model/nodeinfo"
	controller "github.com/contiv/vpp/plugins/controller/api"
	tmp_txn "github.com/contiv/vpp/plugins/controller/txn"
	nodeconfig "github.com/contiv/vpp/plugins/crd/handler/nodeconfig/model"
	"github.com/contiv/vpp/plugins/ksr/model/node"
)

// MgmtIPSeparator is a delimiter inserted between management IPs in nodeInfo structure
const MgmtIPSeparator = ","

// Plugin represents the instance of the Contiv network plugin, that transforms CNI requests received over
// GRPC into configuration for the vswitch VPP in order to connect/disconnect a container into/from the network.
type Plugin struct {
	Deps
	govppCh api.Channel

	nodeID          uint32
	cniServer       *remoteCNIserver
	nodeIDAllocator NodeIDAllocator
	dockerClient    *docker.Client

	ctx           context.Context
	ctxCancelFunc context.CancelFunc

	Config       *Config
	myNodeConfig *NodeConfig

	nodeIPWatcher chan *net.IPNet

	// temporary
	afterStartupResync bool
	startupResyncCond  *sync.Cond
}

// Deps groups the dependencies of the p.
type Deps struct {
	infra.PluginDeps
	ServiceLabel servicelabel.ReaderAPI
	KVScheduler  kvscheduler_api.KVScheduler
	GRPC         grpcplugin.Server
	VPPIfPlugin  vpp_ifplugin.API
	GoVPP        govppmux.API
	ETCD         *etcd.Plugin
	HTTPHandlers rest.HTTPHandlers
}

/********************************** Events ************************************/

// Init does very little. Full initialization is triggered by the first resync.
func (p *Plugin) Init() error {
	p.startupResyncCond = &sync.Cond{L: &sync.Mutex{}}

	// load config file
	p.ctx, p.ctxCancelFunc = context.WithCancel(context.Background())
	if p.Config == nil {
		if err := p.loadExternalConfig(); err != nil {
			return err
		}
	}

	// create GoVPP channel
	var err error
	p.govppCh, err = p.GoVPP.NewAPIChannel()
	if err != nil {
		return err
	}

	// connect to Docker server
	p.dockerClient, err = docker.NewClientFromEnv()
	if err != nil {
		return err
	}
	p.Log.Infof("Using docker client endpoint: %+v\n", p.dockerClient.Endpoint())

	// init node ID allocator without requesting node ID just yet
	p.nodeIDAllocator = NewIDAllocator(p.ETCD, p.ServiceLabel.GetAgentLabel(), nil)

	// register to serve pod add/del requests
	cni.RegisterRemoteCNIServer(p.GRPC.GetServer(), p)

	return nil
}

// HandlesEvent selects DBResync and KubeStateChange for specific resources to handle.
func (p *Plugin) HandlesEvent(event controller.Event) bool {
	if event.Method() == controller.Resync {
		return true
	}
	if ksChange, isKSChange := event.(*controller.KubeStateChange); isKSChange {
		switch ksChange.Resource {
		case nodeinfo.Keyword:
			// only interested in NodeInfo of other nodes
			return ksChange.Key != nodeinfo.Key(p.nodeID)
		case nodeconfig.Keyword:
			// only interested in NodeConfig for this node
			return ksChange.Key == nodeconfig.Key(p.ServiceLabel.GetAgentLabel())
		case node.NodeKeyword:
			// only interested in Node data of this node
			return ksChange.Key == node.Key(p.ServiceLabel.GetAgentLabel())
		default:
			// unhandled Kubernetes state change
			return false
		}
	}

	// unhandled event
	return false
}

// Resync is called by Controller to handle event that requires full
// re-synchronization.
// For startup resync, resyncCount is 1. Higher counter values identify
// run-time resync.
func (p *Plugin) Resync(event controller.Event, txn controller.ResyncOperations,
	kubeStateData controller.KubeStateData, resyncCount int) error {

	var err error
	if resyncCount == 1 {
		// startup resync - get node ID and start Remote CNI server

		// load configuration specific to this node
		p.myNodeConfig = p.loadNodeConfig(kubeStateData)

		// init node ID allocator
		p.nodeIDAllocator.Resync(kubeStateData)
		p.nodeID, err = p.nodeIDAllocator.GetOrAllocateNodeID()
		if err != nil {
			return controller.NewFatalError(err)
		}
		p.Log.Infof("ID of the node is %v", p.nodeID)

		// start the GRPC server handling the CNI requests
		p.cniServer, err = newRemoteCNIServer(
			&remoteCNIserverArgs{
				Logger: p.Log,
				nodeID: p.nodeID,
				txnFactory: func() controller.Transaction {
					return tmp_txn.NewTransaction(p.KVScheduler)
				},
				physicalIfsDump:             p.dumpPhysicalInterfaces,
				getStolenInterfaceInfo:      p.getStolenInterfaceInfo,
				hostLinkIPsDump:             p.getHostLinkIPs,
				dockerClient:                p.dockerClient,
				govppChan:                   p.govppCh,
				dhcpIndex:                   p.VPPIfPlugin.GetDHCPIndex(),
				agentLabel:                  p.ServiceLabel.GetAgentLabel(),
				nodeConfig:                  p.myNodeConfig,
				config:                      p.Config,
				nodeInterconnectExcludedIPs: p.excludedIPsFromNodeCIDR(),
				http:                        p.HTTPHandlers,
			})
		if err != nil {
			return fmt.Errorf("Can't create new remote CNI server due to error: %v ", err)
		}

		p.nodeIPWatcher = make(chan *net.IPNet, 1)
		go p.watchNodeIPChanges()
		p.cniServer.WatchNodeIP(p.nodeIPWatcher)
	}

	resyncErr := p.thisNodeResync(kubeStateData, txn)
	if resyncErr != nil {
		err = resyncErr
	}

	resyncErr = p.cniServer.Resync(kubeStateData, resyncCount, txn)
	if resyncErr != nil {
		err = resyncErr
	}

	if resyncCount == 1 {
		p.afterStartupResync = true
		p.startupResyncCond.Signal()
	}

	return err
}

// Update is called for KubeStateChange.
func (p *Plugin) Update(event controller.Event, txn controller.UpdateOperations) (changeDescription string, err error) {
	kubeStateChange := event.(*controller.KubeStateChange)

	updateErr := p.processThisNodeChangeEvent(kubeStateChange)
	if updateErr != nil {
		err = updateErr
	}

	changeDescription, updateErr = p.cniServer.Update(kubeStateChange, txn)
	if updateErr != nil {
		err = updateErr
	}

	return
}

// Revert does nothing here - plugin handles only BestEffort events.
func (p *Plugin) Revert(event controller.Event) error {
	return nil
}

// Add handles CNI Add request, connects a Pod container to the network.
func (p *Plugin) Add(ctx context.Context, request *cni.CNIRequest) (*cni.CNIReply, error) {
	p.startupResyncCond.L.Lock()
	for !p.afterStartupResync {
		p.startupResyncCond.Wait()
	}
	p.startupResyncCond.L.Unlock()
	return p.cniServer.Add(ctx, request)
}

// Delete handles CNI Delete request, disconnects a Pod container from the network.
func (p *Plugin) Delete(ctx context.Context, request *cni.CNIRequest) (*cni.CNIReply, error) {
	p.startupResyncCond.L.Lock()
	for !p.afterStartupResync {
		p.startupResyncCond.Wait()
	}
	p.startupResyncCond.L.Unlock()
	return p.cniServer.Delete(ctx, request)
}

// watchNodeIPChanges watches for changes of this node IP address.
func (p *Plugin) watchNodeIPChanges() {
	for {
		select {
		case newIP := <-p.nodeIPWatcher:
			if newIP != nil {
				err := p.nodeIDAllocator.UpdateIP(newIP)
				if err != nil {
					p.Log.Error(err)
				}
			}

		case <-p.ctx.Done():
		}
	}
}

// Close is called by the plugin infra upon agent cleanup.
// It cleans up the resources allocated by the plugin.
func (p *Plugin) Close() error {
	p.ctxCancelFunc()
	p.cniServer.Close()
	//p.nodeIDAllocator.releaseID()
	_, err := safeclose.CloseAll(p.govppCh)
	return err
}

/***************************** Contiv plugin API ******************************/

// GetPodByIf looks up podName and podNamespace that is associated with logical interface name.
func (p *Plugin) GetPodByIf(ifname string) (podNamespace string, podName string, exists bool) {
	return p.cniServer.GetPodByIf(ifname)
}

// GetIfName looks up logical interface name that corresponds to the interface associated with the given POD name.
func (p *Plugin) GetIfName(podNamespace string, podName string) (name string, exists bool) {
	return p.cniServer.GetIfName(podNamespace, podName)
}

// GetPodSubnet provides subnet used for allocating pod IP addresses across all nodes.
func (p *Plugin) GetPodSubnet() *net.IPNet {
	return p.cniServer.ipam.PodSubnetAllNodes()
}

// GetPodSubnetThisNode provides subnet used for allocating pod IP addresses on this node.
func (p *Plugin) GetPodSubnetThisNode() *net.IPNet {
	return p.cniServer.ipam.PodSubnetThisNode()
}

// InSTNMode returns true if Contiv operates in the STN mode (single interface for each node).
func (p *Plugin) InSTNMode() bool {
	return p.cniServer.UseSTN()
}

// NatExternalTraffic returns true if traffic with cluster-outside destination should be S-NATed
// with node IP before being sent out from the node.
func (p *Plugin) NatExternalTraffic() bool {
	if p.Config.NatExternalTraffic ||
		(p.myNodeConfig != nil && p.myNodeConfig.NatExternalTraffic) {
		return true
	}
	return false
}

// CleanupIdleNATSessions returns true if cleanup of idle NAT sessions is enabled.
func (p *Plugin) CleanupIdleNATSessions() bool {
	return p.Config.CleanupIdleNATSessions
}

// GetTCPNATSessionTimeout returns NAT session timeout (in minutes) for TCP connections, used in case that CleanupIdleNATSessions is turned on.
func (p *Plugin) GetTCPNATSessionTimeout() uint32 {
	return p.Config.TCPNATSessionTimeout
}

// GetOtherNATSessionTimeout returns NAT session timeout (in minutes) for non-TCP connections, used in case that CleanupIdleNATSessions is turned on.
func (p *Plugin) GetOtherNATSessionTimeout() uint32 {
	return p.Config.OtherNATSessionTimeout
}

// GetServiceLocalEndpointWeight returns the load-balancing weight assigned to locally deployed service endpoints.
func (p *Plugin) GetServiceLocalEndpointWeight() uint8 {
	return p.Config.ServiceLocalEndpointWeight
}

// DisableNATVirtualReassembly returns true if fragmented packets should be dropped by NAT.
func (p *Plugin) DisableNATVirtualReassembly() bool {
	return p.Config.DisableNATVirtualReassembly
}

// GetNatLoopbackIP returns the IP address of a virtual loopback, used to route traffic
// between clients and services via VPP even if the source and destination are the same
// IP addresses and would otherwise be routed locally.
func (p *Plugin) GetNatLoopbackIP() net.IP {
	// Last unicast IP from the pod subnet is used as NAT-loopback.
	podNet := p.cniServer.ipam.PodSubnetThisNode()
	_, broadcastIP := cidr.AddressRange(podNet)
	return cidr.Dec(broadcastIP)
}

// GetNodeIP returns the IP address of this node.
func (p *Plugin) GetNodeIP() (ip net.IP, network *net.IPNet) {
	return p.cniServer.GetNodeIP()
}

// GetHostIPs returns all IP addresses of this node present in the host network namespace (Linux).
func (p *Plugin) GetHostIPs() []net.IP {
	return p.cniServer.GetHostIPs()
}

// WatchNodeIP adds given channel to the list of subscribers that are notified upon change
// of nodeIP address. If the channel is not ready to receive notification, the notification is dropped.
func (p *Plugin) WatchNodeIP(subscriber chan *net.IPNet) {
	p.cniServer.WatchNodeIP(subscriber)
}

// GetMainPhysicalIfName returns name of the "main" interface - i.e. physical interface connecting
// the node with the rest of the cluster.
func (p *Plugin) GetMainPhysicalIfName() string {
	return p.cniServer.GetMainPhysicalIfName()
}

// GetOtherPhysicalIfNames returns a slice of names of all physical interfaces configured additionally
// to the main interface.
func (p *Plugin) GetOtherPhysicalIfNames() []string {
	return p.cniServer.GetOtherPhysicalIfNames()
}

// GetHostInterconnectIfName returns the name of the TAP/AF_PACKET interface
// interconnecting VPP with the host stack.
func (p *Plugin) GetHostInterconnectIfName() string {
	return p.cniServer.GetHostInterconnectIfName()
}

// GetVxlanBVIIfName returns the name of an BVI interface facing towards VXLAN tunnels to other hosts.
// Returns an empty string if VXLAN is not used (in L2 interconnect mode).
func (p *Plugin) GetVxlanBVIIfName() string {
	return p.cniServer.GetVxlanBVIIfName()
}

// GetDefaultInterface returns the name and the IP address of the interface
// used by the default route to send packets out from VPP towards the default gateway.
// If the default GW is not configured, the function returns zero values.
func (p *Plugin) GetDefaultInterface() (ifName string, ifAddress net.IP) {
	return p.cniServer.GetDefaultInterface()
}

// RegisterPodPreRemovalHook allows to register callback that will be run for each
// pod immediately before its removal.
func (p *Plugin) RegisterPodPreRemovalHook(hook PodActionHook) {
	p.cniServer.RegisterPodPreRemovalHook(hook)
}

// RegisterPodPostAddHook allows to register callback that will be run for each
// pod once it is added and before the CNI reply is sent.
func (p *Plugin) RegisterPodPostAddHook(hook PodActionHook) {
	p.cniServer.RegisterPodPostAddHook(hook)
}

// GetMainVrfID returns the ID of the main network connectivity VRF.
func (p *Plugin) GetMainVrfID() uint32 {
	return p.cniServer.GetMainVrfID()
}

// GetPodVrfID returns the ID of the POD VRF.
func (p *Plugin) GetPodVrfID() uint32 {
	return p.cniServer.GetPodVrfID()
}

/******************************* Helper methods *******************************/

// loadExternalConfig attempts to load external configuration from a YAML file.
func (p *Plugin) loadExternalConfig() error {
	externalCfg := &Config{}
	found, err := p.Cfg.LoadValue(externalCfg) // It tries to lookup `PluginName + "-config"` in the executable arguments.
	if err != nil {
		return fmt.Errorf("external Contiv plugin configuration could not load or other problem happened: %v", err)
	}
	if !found {
		return fmt.Errorf("external Contiv plugin configuration was not found")
	}

	p.Config = externalCfg
	p.Log.Infof("Contiv config: %+v", externalCfg)
	err = p.Config.ApplyIPAMConfig()
	if err != nil {
		return err
	}
	p.Config.ApplyDefaults()

	return nil
}

// loadNodeConfig loads config specific for this node (given by its agent label).
func (p *Plugin) loadNodeConfig(kubeStateData controller.KubeStateData) *NodeConfig {
	myNodeName := p.ServiceLabel.GetAgentLabel()
	// first try to get node config from CRD
	crdNodeConfigs := kubeStateData[nodeconfig.Keyword]
	for crdNodeCfgKey, crdNodeConfig := range crdNodeConfigs {
		if crdNodeCfgKey == nodeconfig.Key(myNodeName) {
			return nodeConfigFromProto(crdNodeConfig.(*nodeconfig.NodeConfig))
		}
	}
	// try to find the node-specific configuration inside the config file
	return p.Config.GetNodeConfig(myNodeName)
}

func (p *Plugin) getStolenInterfaceInfo(ifName string) (reply *stn_grpc.STNReply, err error) {
	// connect to STN GRPC server
	if p.Config.STNSocketFile == "" {
		p.Config.STNSocketFile = defaultSTNSocketFile
	}
	conn, err := grpc.Dial(
		p.Config.STNSocketFile,
		grpc.WithInsecure(),
		grpc.WithDialer(
			func(addr string, timeout time.Duration) (net.Conn, error) {
				return net.DialTimeout("unix", addr, timeout)
			}),
	)
	if err != nil {
		p.Log.Errorf("Unable to connect to STN GRPC: %v", err)
		return
	}
	defer conn.Close()
	c := stn_grpc.NewSTNClient(conn)

	// request info about the stolen interface
	return c.StolenInterfaceInfo(context.Background(), &stn_grpc.STNRequest{
		InterfaceName: ifName,
	})
}

func (p *Plugin) excludedIPsFromNodeCIDR() []net.IP {
	if p.Config == nil {
		return nil
	}
	var excludedIPs []string
	for _, oneNodeConfig := range p.Config.NodeConfig {
		if oneNodeConfig.Gateway == "" {
			continue
		}
		excludedIPs = appendIfMissing(excludedIPs, oneNodeConfig.Gateway)
	}
	var res []net.IP
	for _, ip := range excludedIPs {
		res = append(res, net.ParseIP(ip))
	}
	return res
}

// dumpPhysicalInterfaces dumps physical interfaces present on VPP.
func (p *Plugin) dumpPhysicalInterfaces() (ifaces map[uint32]string, err error) {
	ifaces = make(map[uint32]string)
	ifHandler := intf_vppcalls.NewIfVppHandler(p.govppCh, p.Log)

	// TODO: when supported dump also VMXNET3 interfaces (?)

	dump, err := ifHandler.DumpInterfacesByType(interfaces.Interface_DPDK)
	if err != nil {
		return ifaces, err
	}

	for ifIdx, iface := range dump {
		ifaces[ifIdx] = iface.Interface.Name
	}
	return ifaces, err
}

// getHostLinkIPs returns all IP addresses assigned to physical interfaces in the host
// network stack.
func (p *Plugin) getHostLinkIPs() (hostIPs []net.IP, err error) {
	links, err := netlink.LinkList()
	if err != nil {
		p.Log.Error("Unable to list host links:", err)
		return hostIPs, err
	}

	for _, l := range links {
		if !strings.HasPrefix(l.Attrs().Name, "lo") && !strings.HasPrefix(l.Attrs().Name, "docker") &&
			!strings.HasPrefix(l.Attrs().Name, "virbr") && !strings.HasPrefix(l.Attrs().Name, "vpp") {
			// not a virtual interface, list its IP addresses
			addrList, err := netlink.AddrList(l, netlink.FAMILY_V4)
			if err != nil {
				p.Log.Error("Unable to list link IPs:", err)
				return hostIPs, err
			}
			// return all IPs
			for _, addr := range addrList {
				hostIPs = append(hostIPs, addr.IP)
			}
		}
	}
	return hostIPs, nil
}

func appendIfMissing(slice []string, s string) []string {
	for _, el := range slice {
		if el == s {
			return slice
		}
	}
	return append(slice, s)
}

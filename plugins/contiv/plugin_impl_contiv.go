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
//go:generate protoc -I ./model/node --gogo_out=plugins=grpc:./model/node ./model/node/node.proto

package contiv

import (
	"context"
	"fmt"
	"net"

	"git.fd.io/govpp.git/api"
	"github.com/apparentlymart/go-cidr/cidr"

	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/datasync/resync"
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/rpc/grpc"
	"github.com/ligato/cn-infra/rpc/rest"
	"github.com/ligato/cn-infra/servicelabel"
	"github.com/ligato/cn-infra/utils/safeclose"

	"github.com/ligato/vpp-agent/plugins/govppmux"
	kvscheduler_api "github.com/ligato/vpp-agent/plugins/kvscheduler/api"
	vpp_ifplugin "github.com/ligato/vpp-agent/plugins/vppv2/ifplugin"

	"github.com/contiv/vpp/plugins/contiv/model/cni"
	"github.com/contiv/vpp/plugins/contiv/model/node"
	txn_api "github.com/contiv/vpp/plugins/controller/txn"
	nodeconfig "github.com/contiv/vpp/plugins/crd/handler/nodeconfig/model"
	k8sNode "github.com/contiv/vpp/plugins/ksr/model/node"
	k8sPod "github.com/contiv/vpp/plugins/ksr/model/pod"
)

// MgmtIPSeparator is a delimiter inserted between management IPs in nodeInfo structure
const MgmtIPSeparator = ","

// Plugin represents the instance of the Contiv network plugin, that transforms CNI requests received over
// GRPC into configuration for the vswitch VPP in order to connect/disconnect a container into/from the network.
type Plugin struct {
	Deps
	govppCh api.Channel

	cniServer       *remoteCNIserver
	nodeIDAllocator *idAllocator

	// CRD config watching
	nodeConfigResyncChan chan datasync.ResyncEvent
	nodeConfigChangeChan chan datasync.ChangeEvent
	nodeConfigWatchReg   datasync.WatchRegistration

	// kubernetes state data watching
	watchReg datasync.WatchRegistration
	resyncCh chan datasync.ResyncEvent
	changeCh chan datasync.ChangeEvent

	ctx           context.Context
	ctxCancelFunc context.CancelFunc

	Config       *Config
	myNodeConfig *NodeConfig

	nodeIPWatcher chan string

	// synchronization between resync and data change events
	resyncCounter  uint
	k8sStateData   map[string]datasync.KeyVal // key -> value, revision
	pendingChanges []datasync.ChangeEvent
}

// Deps groups the dependencies of the p.
type Deps struct {
	infra.PluginDeps
	ServiceLabel servicelabel.ReaderAPI
	KVScheduler  kvscheduler_api.KVScheduler
	GRPC         grpc.Server
	VPPIfPlugin  vpp_ifplugin.API
	GoVPP        govppmux.API
	Resync       resync.Subscriber
	ETCD         *etcd.Plugin
	Bolt         keyval.KvProtoPlugin
	Watcher      datasync.KeyValProtoWatcher
	HTTPHandlers rest.HTTPHandlers
}

// Init initializes the Contiv p. Called automatically by plugin infra upon contiv-agent startup.
func (p *Plugin) Init() error {
	// load config file
	p.ctx, p.ctxCancelFunc = context.WithCancel(context.Background())
	if p.Config == nil {
		if err := p.loadExternalConfig(); err != nil {
			return err
		}
		p.myNodeConfig = p.loadNodeConfig()
	}

	var err error
	p.govppCh, err = p.GoVPP.NewAPIChannel()
	if err != nil {
		return err
	}

	// init node ID allocator
	nodeIP := ""
	if p.myNodeConfig != nil {
		nodeIP = p.myNodeConfig.MainVPPInterface.IP
	}
	p.nodeIDAllocator = newIDAllocator(p.ETCD, p.ServiceLabel.GetAgentLabel(), nodeIP)
	nodeID, err := p.nodeIDAllocator.getID()
	if err != nil {
		return err
	}
	p.Log.Infof("ID of the node is %v", nodeID)

	p.nodeConfigResyncChan = make(chan datasync.ResyncEvent)
	p.nodeConfigChangeChan = make(chan datasync.ChangeEvent)

	p.resyncCh = make(chan datasync.ResyncEvent)
	p.changeCh = make(chan datasync.ChangeEvent)

	p.nodeConfigWatchReg, err = p.Watcher.Watch("contiv-plugin-node-config",
		p.nodeConfigChangeChan, p.nodeConfigResyncChan, nodeconfig.Key(p.ServiceLabel.GetAgentLabel()))
	if err != nil {
		return err
	}

	p.k8sStateData = make(map[string]datasync.KeyVal)
	p.watchReg, err = p.Watcher.Watch("contiv-plugin-k8s-state",
		p.changeCh, p.resyncCh, node.AllocatedIDsKeyPrefix, k8sNode.KeyPrefix(), k8sPod.KeyPrefix())
	if err != nil {
		return err
	}

	// start the GRPC server handling the CNI requests
	p.cniServer, err = newRemoteCNIServer(p.Log,
		func() txn_api.Transaction {
			return txn_api.NewTransaction(p.KVScheduler)
		},
		p.govppCh,
		p.VPPIfPlugin.GetInterfaceIndex(),
		p.VPPIfPlugin.GetDHCPIndex(),
		p.ServiceLabel.GetAgentLabel(),
		p.Config,
		p.myNodeConfig,
		nodeID,
		p.excludedIPsFromNodeCIDR(),
		p.ETCD.NewBroker(p.ServiceLabel.GetAgentPrefix()),
		p.HTTPHandlers)
	if err != nil {
		return fmt.Errorf("Can't create new remote CNI server due to error: %v ", err)
	}
	cni.RegisterRemoteCNIServer(p.GRPC.GetServer(), p.cniServer)

	p.nodeIPWatcher = make(chan string, 1)
	go p.watchEvents()
	p.cniServer.WatchNodeIP(p.nodeIPWatcher)

	// start goroutine handling changes in the configuration specific to this node
	go p.cniServer.handleNodeConfigEvents(p.ctx, p.nodeConfigResyncChan, p.nodeConfigChangeChan)

	return nil
}

// Close is called by the plugin infra upon agent cleanup. It cleans up the resources allocated by the p.
func (p *Plugin) Close() error {
	p.ctxCancelFunc()
	p.cniServer.Close()
	//p.nodeIDAllocator.releaseID()
	_, err := safeclose.CloseAll(p.govppCh, p.nodeConfigWatchReg, p.watchReg)
	return err
}

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
	return p.cniServer.ipam.PodSubnet()
}

// GetPodNetwork provides subnet used for allocating pod IP addresses on this node.
func (p *Plugin) GetPodNetwork() *net.IPNet {
	return p.cniServer.ipam.PodNetwork()
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
	podNet := p.cniServer.ipam.PodNetwork()
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
func (p *Plugin) WatchNodeIP(subscriber chan string) {
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

// loadExternalConfig attempts to load external configuration from a YAML file.
func (p *Plugin) loadExternalConfig() error {
	externalCfg := &Config{}
	found, err := p.Cfg.LoadValue(externalCfg) // It tries to lookup `PluginName + "-config"` in the executable arguments.
	if err != nil {
		return fmt.Errorf("External Contiv plugin configuration could not load or other problem happened: %v", err)
	}
	if !found {
		return fmt.Errorf("External Contiv plugin configuration was not found")
	}

	p.Config = externalCfg
	p.Log.Info("Contiv config: ", externalCfg)
	err = p.Config.ApplyIPAMConfig()
	if err != nil {
		return err
	}
	p.Config.ApplyDefaults()

	return nil
}

// loadNodeConfig loads config specific for this node (given by its agent label).
func (p *Plugin) loadNodeConfig() *NodeConfig {
	myNodeName := p.ServiceLabel.GetAgentLabel()
	// first try to get node config from CRD, reflected by contiv-crd into etcd
	// and mirrored into Bolt by us
	nodeConfig := LoadNodeConfigFromCRD(myNodeName, p.ETCD, p.Bolt, p.Log)
	if nodeConfig != nil {
		return nodeConfig
	}
	// try to find the node-specific configuration inside the config file
	return p.Config.GetNodeConfig(myNodeName)
}

func (p *Plugin) watchEvents() {
	for {
		select {
		case newIP := <-p.nodeIPWatcher:
			if newIP != "" {
				err := p.nodeIDAllocator.updateIP(newIP)
				if err != nil {
					p.Log.Error(err)
				}
			}

		case changeEv := <-p.changeCh:
			// delay processing of changes before the first resync
			if p.resyncCounter == 0 {
				p.pendingChanges = append(p.pendingChanges, changeEv)
				p.Log.WithField("keys", dataChangeEvKeys(changeEv)).Info("Delaying data-change")
				changeEv.Done(nil)
			} else {
				p.processChangeEv(changeEv)
			}

		case resyncEv := <-p.resyncCh:
			var err error
			p.resyncCounter++
			resyncErr := p.thisNodeResync(resyncEv)
			if resyncErr != nil {
				err = resyncErr
			}

			resyncErr = p.cniServer.Resync(resyncEv)
			if resyncErr != nil {
				err = resyncErr
			}

			resyncEv.Done(err)

			// apply pending changes
			for _, dataChngEv := range p.pendingChanges {
				p.Log.WithField("keys", dataChangeEvKeys(dataChngEv)).Info("Applying delayed data-changes")
				p.processChangeEv(dataChngEv)
			}
			p.pendingChanges = []datasync.ChangeEvent{}

		case <-p.ctx.Done():
		}
	}
}

func (p *Plugin) processChangeEv(changeEv datasync.ChangeEvent) {
	var err error
	for _, dataChng := range changeEv.GetChanges() {
		key := dataChng.GetKey()
		p.Log.Debug("Received CHANGE key ", key)

		if prevRev, hasPrevRev := p.k8sStateData[key]; hasPrevRev {
			if prevRev.GetRevision() >= dataChng.GetRevision() {
				p.Log.Debugf("Ignoring already processed revision for key=%s", key)
				continue
			}
		}
		p.k8sStateData[key] = dataChng

		updateErr := p.processThisNodeChangeEvent(dataChng)
		if updateErr != nil {
			err = updateErr
		}

		updateErr = p.cniServer.Update(dataChng)
		if updateErr != nil {
			err = updateErr
		}
	}
	changeEv.Done(err)
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

// dataChangeEvKeys collects all keys included in a data change event.
func dataChangeEvKeys(changeEv datasync.ChangeEvent) (keys []string) {
	for _, change := range changeEv.GetChanges() {
		keys = append(keys, change.GetKey())
	}
	return
}

func appendIfMissing(slice []string, s string) []string {
	for _, el := range slice {
		if el == s {
			return slice
		}
	}
	return append(slice, s)
}

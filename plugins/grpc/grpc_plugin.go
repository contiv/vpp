// Copyright (c) 2019 Cisco and/or its affiliates.
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

package rpc

import (
	"github.com/gogo/protobuf/proto"
	"golang.org/x/net/context"

	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/grpc/rpc"

	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/rpc/grpc"

	"github.com/ligato/vpp-agent/api/models/linux/interfaces"
	"github.com/ligato/vpp-agent/api/models/linux/l3"
	"github.com/ligato/vpp-agent/api/models/vpp/acl"
	"github.com/ligato/vpp-agent/api/models/vpp/interfaces"
	"github.com/ligato/vpp-agent/api/models/vpp/ipsec"
	"github.com/ligato/vpp-agent/api/models/vpp/l2"
	"github.com/ligato/vpp-agent/api/models/vpp/l3"
	"github.com/ligato/vpp-agent/api/models/vpp/nat"
	"github.com/ligato/vpp-agent/api/models/vpp/punt"
)

//go:generate protoc --proto_path=rpc --proto_path=$GOPATH/src --gogo_out=plugins=grpc:rpc rpc/rpc.proto

// Plugin implements GRPC access to Contiv's VPP-agent.
type Plugin struct {
	Deps

	localBroker keyval.ProtoBroker

	// Services
	changeSvc ChangeSvc
	resyncSvc ResyncSvc
}

// Deps - dependencies of Plugin
type Deps struct {
	infra.PluginDeps
	GRPCServer grpc.Server
	EventLoop  controller.EventLoop
	LocalDB    keyval.KvProtoPlugin
}

// ChangeSvc implements DataChangeService.
type ChangeSvc struct {
	log    logging.Logger
	plugin *Plugin
}

// ResyncSvc implements DataResyncService.
type ResyncSvc struct {
	log    logging.Logger
	plugin *Plugin
}

// lazyValue implements datasync.LazyValue interface.
type lazyValue struct {
	value proto.Message
}

type config map[string]proto.Message

// Init registers GRPC services.
func (p *Plugin) Init() error {
	// create broker to local DB for config persisting
	p.localBroker = p.LocalDB.NewBroker("")

	// init service handlers
	p.changeSvc.log = p.Log.NewLogger("grpcChangeSvc")
	p.changeSvc.plugin = p
	p.resyncSvc.log = p.Log.NewLogger("grpcResyncSvc")
	p.resyncSvc.plugin = p

	// Register all GRPC services if server is available.
	// Register needs to be done before 'ListenAndServe' is called in GRPC plugin
	grpcServer := p.GRPCServer.GetServer()
	if grpcServer != nil {
		rpc.RegisterDataChangeServiceServer(grpcServer, &p.changeSvc)
		rpc.RegisterDataResyncServiceServer(grpcServer, &p.resyncSvc)
	}

	return nil
}

// GetConfigSnapshot returns full configuration snapshot that is currently
// required by the GRPC client to be applied.
func (p *Plugin) GetConfigSnapshot() (controller.ExternalConfig, error) {
	extConfig := make(controller.ExternalConfig)
	iterator, err := p.localBroker.ListValues("")
	if err != nil {
		return extConfig, err
	}
	for {
		kv, stop := iterator.GetNext()
		if stop {
			break
		}
		extConfig[kv.GetKey()] = kv
	}
	iterator.Close()
	return extConfig, nil
}

func (p *Plugin) dumpLocalDB() {
	config, err := p.GetConfigSnapshot()
	if err != nil {
		p.Log.Errorf("Failed to dump local DB: %v", err)
		return
	}
	p.Log.Debugf("GRPC local DB dump: %v", config)
}

// Close does nothing.
func (p *Plugin) Close() error {
	return nil
}

// Put propagates request from GRPC client to add/modify some external configuration items.
func (svc *ChangeSvc) Put(ctx context.Context, data *rpc.DataRequest) (*rpc.PutResponse, error) {
	// prepare configuration changes
	config := buildConfig(data, false)

	// persist changes
	for key, value := range config {
		err := svc.plugin.localBroker.Put(key, value)
		if err != nil {
			svc.log.Warnf("Failed to persist changes: %v", err)
		}
	}

	// execute changes
	event := controller.NewExternalConfigChange(svc.plugin.String(), true)
	event.UpdatedKVs = convertToExternalConfig(config)
	err := svc.plugin.EventLoop.PushEvent(event)
	if err == nil {
		err = event.Wait()
	}

	return &rpc.PutResponse{}, err
}

// Del propagates request from GRPC client to remove some external configuration items.
func (svc *ChangeSvc) Del(ctx context.Context, data *rpc.DataRequest) (*rpc.DelResponse, error) {
	// prepare configuration changes
	config := buildConfig(data, true)

	// persist changes
	for key := range config {
		_, err := svc.plugin.localBroker.Delete(key)
		if err != nil {
			svc.log.Warnf("Failed to persist changes: %v", err)
		}
	}

	// execute changes
	event := controller.NewExternalConfigChange(svc.plugin.String(), true)
	event.UpdatedKVs = convertToExternalConfig(config)
	err := svc.plugin.EventLoop.PushEvent(event)
	if err == nil {
		err = event.Wait()
	}

	return &rpc.DelResponse{}, err
}

// Resync re-synchronizes configuration between the GRPC client and vpp-agent.
func (svc *ResyncSvc) Resync(ctx context.Context, data *rpc.DataRequest) (*rpc.ResyncResponse, error) {
	// prepare configuration changes
	config := buildConfig(data, false)

	// resync local DB
	err := svc.resyncDB(config)
	if err != nil {
		svc.log.Warnf("Failed to resync local DB: %v", err)
	}

	// execute changes
	event := controller.NewExternalConfigResync(svc.plugin.String(), true)
	event.ExternalConfig = convertToExternalConfig(config)
	err = svc.plugin.EventLoop.PushEvent(event)
	if err == nil {
		err = event.Wait()
	}

	return &rpc.ResyncResponse{}, err
}

func (svc *ResyncSvc) resyncDB(resyncCfg config) error {
	keys := make(map[string]struct{})

	// update database with values present in resyncCfg
	for key, value := range resyncCfg {
		keys[key] = struct{}{}
		err := svc.plugin.localBroker.Put(key, value)
		if err != nil {
			return err
		}
	}

	// read keys currently stored in DB, remove the obsolete ones
	snapshot, err := svc.plugin.GetConfigSnapshot()
	if err != nil {
		return err
	}
	for key := range snapshot {
		if _, inResyncCfg := keys[key]; !inResyncCfg {
			_, err = svc.plugin.localBroker.Delete(key)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func buildConfig(data *rpc.DataRequest, delete bool) config {
	extConfig := make(config)
	for _, item := range data.AccessLists {
		key := vpp_acl.Key(item.Name)
		extConfig[key] = item
	}
	for _, item := range data.Interfaces {
		key := vpp_interfaces.InterfaceKey(item.Name)
		extConfig[key] = item
	}
	for _, item := range data.BridgeDomains {
		key := vpp_l2.BridgeDomainKey(item.Name)
		extConfig[key] = item
	}
	for _, item := range data.FIBs {
		key := vpp_l2.FIBKey(item.BridgeDomain, item.PhysAddress)
		extConfig[key] = item
	}
	for _, item := range data.XCons {
		key := vpp_l2.XConnectKey(item.ReceiveInterface)
		extConfig[key] = item
	}
	for _, item := range data.StaticRoutes {
		key := vpp_l3.RouteKey(item.VrfId, item.DstNetwork, item.NextHopAddr)
		extConfig[key] = item
	}
	for _, item := range data.ArpEntries {
		key := vpp_l3.ArpEntryKey(item.Interface, item.IpAddress)
		extConfig[key] = item
	}
	if data.ProxyArp != nil {
		key := vpp_l3.ProxyARPKey()
		extConfig[key] = data.ProxyArp
	}
	if data.IPScanNeighbor != nil {
		key := vpp_l3.IPScanNeighborKey()
		extConfig[key] = data.IPScanNeighbor
	}
	for _, item := range data.SAs {
		key := vpp_ipsec.SAKey(item.Index)
		extConfig[key] = item
	}
	for _, item := range data.SPDs {
		key := vpp_ipsec.SPDKey(item.Index)
		extConfig[key] = item
	}
	for _, item := range data.IPRedirectPunts {
		key := vpp_punt.IPRedirectKey(item.L3Protocol, item.TxInterface)
		extConfig[key] = item
	}
	for _, item := range data.ToHostPunts {
		key := vpp_punt.ToHostKey(item.L3Protocol, item.L4Protocol, item.Port)
		extConfig[key] = item
	}
	if data.NatGlobal != nil {
		key := vpp_nat.GlobalNAT44Key()
		extConfig[key] = data.NatGlobal
	}
	for _, item := range data.DNATs {
		key := vpp_nat.DNAT44Key(item.Label)
		extConfig[key] = item
	}
	for _, item := range data.LinuxInterfaces {
		key := linux_interfaces.InterfaceKey(item.Name)
		extConfig[key] = item
	}
	for _, item := range data.LinuxArpEntries {
		key := linux_l3.ArpKey(item.Interface, item.IpAddress)
		extConfig[key] = item
	}
	for _, item := range data.LinuxRoutes {
		key := linux_l3.RouteKey(item.DstNetwork, item.OutgoingInterface)
		extConfig[key] = item
	}

	if delete {
		for key := range extConfig {
			extConfig[key] = nil
		}
	}
	return extConfig
}

func convertToExternalConfig(cfg config) controller.ExternalConfig {
	extConfig := make(controller.ExternalConfig)
	for key, value := range cfg {
		if value == nil {
			extConfig[key] = nil
		} else {
			extConfig[key] = newLazyValue(value)
		}
	}
	return extConfig
}

func newLazyValue(value proto.Message) datasync.LazyValue {
	return &lazyValue{value: value}
}

// GetValue places the value into the provided proto message.
func (lv *lazyValue) GetValue(value proto.Message) error {
	tmp, err := proto.Marshal(lv.value)
	if err != nil {
		return err
	}
	return proto.Unmarshal(tmp, value)
}

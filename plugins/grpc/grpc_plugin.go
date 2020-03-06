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
	"golang.org/x/net/context"

	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/grpc/rpc"

	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/rpc/grpc"

	"go.ligato.io/vpp-agent/v3/pkg/models"
	"go.ligato.io/vpp-agent/v3/plugins/orchestrator"
)

//go:generate protoc --proto_path=rpc --proto_path=$GOPATH/src/github.com/ligato/vpp-agent/proto --go_out=plugins=grpc,paths=source_relative:rpc rpc/rpc.proto

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
func (p *Plugin) GetConfigSnapshot() (controller.KeyValuePairs, error) {
	extConfig := make(controller.KeyValuePairs)
	iterator, err := p.localBroker.ListValues("")
	if err != nil {
		return extConfig, err
	}
	for {
		kv, stop := iterator.GetNext()
		if stop {
			break
		}
		key := kv.GetKey()
		value, err := orchestrator.UnmarshalLazyValue(key, kv)
		if err != nil {
			p.Log.Warnf("Failed to de-serialize value received from GRPC for key: %s", key)
			continue
		}
		extConfig[key] = value
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
	event.UpdatedKVs = config
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
	event.UpdatedKVs = config
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
	event.ExternalConfig = config
	err = svc.plugin.EventLoop.PushEvent(event)
	if err == nil {
		err = event.Wait()
	}

	return &rpc.ResyncResponse{}, err
}

func (svc *ResyncSvc) resyncDB(resyncCfg controller.KeyValuePairs) error {
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

func buildConfig(data *rpc.DataRequest, delete bool) controller.KeyValuePairs {
	extConfig := make(controller.KeyValuePairs)
	for _, item := range data.AccessLists {
		key := models.Key(item)
		extConfig[key] = item
	}
	for _, item := range data.Interfaces {
		key := models.Key(item)
		extConfig[key] = item
	}
	for _, item := range data.BridgeDomains {
		key := models.Key(item)
		extConfig[key] = item
	}
	for _, item := range data.FIBs {
		key := models.Key(item)
		extConfig[key] = item
	}
	for _, item := range data.XCons {
		key := models.Key(item)
		extConfig[key] = item
	}
	for _, item := range data.StaticRoutes {
		key := models.Key(item)
		extConfig[key] = item
	}
	for _, item := range data.ArpEntries {
		key := models.Key(item)
		extConfig[key] = item
	}
	if data.ProxyArp != nil {
		key := models.Key(data.ProxyArp)
		extConfig[key] = data.ProxyArp
	}
	if data.IPScanNeighbor != nil {
		key := models.Key(data.IPScanNeighbor)
		extConfig[key] = data.IPScanNeighbor
	}
	for _, item := range data.SAs {
		key := models.Key(item)
		extConfig[key] = item
	}
	for _, item := range data.SPDs {
		key := models.Key(item)
		extConfig[key] = item
	}
	for _, item := range data.IPRedirectPunts {
		key := models.Key(item)
		extConfig[key] = item
	}
	for _, item := range data.ToHostPunts {
		key := models.Key(item)
		extConfig[key] = item
	}
	if data.NatGlobal != nil {
		key := models.Key(data.NatGlobal)
		extConfig[key] = data.NatGlobal
	}
	for _, item := range data.DNATs {
		key := models.Key(item)
		extConfig[key] = item
	}
	for _, item := range data.LinuxInterfaces {
		key := models.Key(item)
		extConfig[key] = item
	}
	for _, item := range data.LinuxArpEntries {
		key := models.Key(item)
		extConfig[key] = item
	}
	for _, item := range data.LinuxRoutes {
		key := models.Key(item)
		extConfig[key] = item
	}

	if delete {
		for key := range extConfig {
			extConfig[key] = nil
		}
	}
	return extConfig
}

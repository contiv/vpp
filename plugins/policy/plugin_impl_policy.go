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

package policy

import (
	"context"
	"sync"

	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/flavors/local"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/utils/safeclose"

	"github.com/contiv/vpp/plugins/contiv"
	"github.com/contiv/vpp/plugins/ksr/model/namespace"
)

// Plugin watches configuration of K8s resources (as reflected by KSR into ETCD)
// for changes in policies, pods and namespaces and applies ACLs to VPP.
type Plugin struct {
	Deps

	resyncChan chan datasync.ResyncEvent
	changeChan chan datasync.ChangeEvent

	watchConfigReg datasync.WatchRegistration

	cancel context.CancelFunc
	wg     sync.WaitGroup

	configProcessor *ConfigProcessor
	/*
		TODO (use VPP localclient directly from processor for now):
		- policy reflector1 (standard VPP ACLs)
		- policy  reflector2 (TCP/IP VPP ACLs)
		- inject reflector(s) into the processor
	*/
}

// Deps defines dependencies of policy plugin.
type Deps struct {
	local.PluginInfraDeps
	Watcher datasync.KeyValProtoWatcher /* prefixed for KSR-published K8s state data */
	Contiv  *contiv.Plugin              /* for GetIfName() */
}

// Init initializes policy processor and starts watching ETCD for K8s configuration.
func (p *Plugin) Init() error {
	var err error
	p.Log.SetLevel(logging.DebugLevel)

	p.resyncChan = make(chan datasync.ResyncEvent)
	p.changeChan = make(chan datasync.ChangeEvent)

	p.configProcessor = &ConfigProcessor{
		ProcessorDeps{
			Log:        p.Log.NewLogger("-processor"),
			PluginName: p.PluginName,
			Contiv:     p.Contiv,
		},
	}
	p.configProcessor.Init()

	var ctx context.Context
	ctx, p.cancel = context.WithCancel(context.Background())

	go p.watchEvents(ctx)
	err = p.subscribeWatcher()
	if err != nil {
		return err
	}

	return nil
}

func (p *Plugin) subscribeWatcher() (err error) {
	p.watchConfigReg, err = p.Watcher.
		Watch("K8s resources", p.changeChan, p.resyncChan, namespace.KeyPrefix())
	return err
}

func (p *Plugin) watchEvents(ctx context.Context) {
	p.wg.Add(1)
	defer p.wg.Done()

	for {
		select {
		case resyncConfigEv := <-p.resyncChan:
			event := p.resyncParseEvent(resyncConfigEv)
			err := p.configProcessor.Resync(event)
			resyncConfigEv.Done(err)

		case dataChngEv := <-p.changeChan:
			err := p.changePropagateEvent(dataChngEv)
			dataChngEv.Done(err)

		case <-ctx.Done():
			p.Log.Debug("Stop watching events")
			return
		}
	}
}

// Close stops the processor and watching.
func (p *Plugin) Close() error {
	p.cancel()
	p.wg.Wait()
	safeclose.CloseAll(p.watchConfigReg, p.resyncChan, p.changeChan)
	p.configProcessor.Close()
	return nil
}

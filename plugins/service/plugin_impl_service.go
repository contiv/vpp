// Copyright (c) 2018 Cisco and/or its affiliates.
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

package service

import (
	"context"
	"sync"

	"github.com/ligato/cn-infra/datasync"
	kvdbsync_local "github.com/ligato/cn-infra/datasync/kvdbsync/local"
	"github.com/ligato/cn-infra/datasync/resync"
	"github.com/ligato/cn-infra/flavors/local"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/utils/safeclose"

	"github.com/ligato/vpp-agent/clientv1/linux"
	"github.com/ligato/vpp-agent/clientv1/linux/localclient"
	"github.com/ligato/vpp-agent/plugins/vpp"

	"github.com/contiv/vpp/plugins/contiv"
	"github.com/contiv/vpp/plugins/service/processor"
	"github.com/contiv/vpp/plugins/service/renderer/nat44"

	"github.com/contiv/vpp/plugins/contiv/model/node"
	epmodel "github.com/contiv/vpp/plugins/ksr/model/endpoints"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	svcmodel "github.com/contiv/vpp/plugins/ksr/model/service"
	"github.com/contiv/vpp/plugins/statscollector"
	"github.com/ligato/vpp-agent/plugins/govppmux"
)

// Plugin watches configuration of K8s resources (as reflected by KSR into ETCD)
// for changes in services, endpoints and pods and updates the NAT configuration
// in the VPP accordingly.
type Plugin struct {
	Deps

	resyncChan chan datasync.ResyncEvent
	changeChan chan datasync.ChangeEvent

	watchConfigReg datasync.WatchRegistration

	resyncLock sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup

	// delay resync until the contiv plugin has been re-synchronized.
	resyncCounter  uint
	pendingResync  datasync.ResyncEvent
	pendingChanges []datasync.ChangeEvent

	processor     *processor.ServiceProcessor
	nat44Renderer *nat44.Renderer
}

// Deps defines dependencies of the service plugin.
type Deps struct {
	local.PluginInfraDeps
	Resync  resync.Subscriber
	Watcher datasync.KeyValProtoWatcher /* prefixed for KSR-published K8s state data */
	Contiv  contiv.API                  /* to get the Node IP and all interface names */
	VPP     vpp.API                     /* interface indexes && IP addresses */
	GoVPP   govppmux.API                /* used for direct NAT binary API calls */
	Stats   statscollector.API          /* used for exporting the statistics */
}

// Init initializes the service plugin and starts watching ETCD for K8s configuration.
func (p *Plugin) Init() error {
	var err error
	p.Log.SetLevel(logging.DebugLevel)

	p.resyncChan = make(chan datasync.ResyncEvent)
	p.changeChan = make(chan datasync.ChangeEvent)

	const goVPPChanBufSize = 1 << 12
	goVppCh, err := p.GoVPP.NewAPIChannelBuffered(goVPPChanBufSize, goVPPChanBufSize)
	if err != nil {
		return err
	}

	p.processor = &processor.ServiceProcessor{
		Deps: processor.Deps{
			Log:          p.Log.NewLogger("-serviceProcessor"),
			ServiceLabel: p.ServiceLabel,
			Contiv:       p.Contiv,
		},
	}
	p.processor.Log.SetLevel(logging.DebugLevel)

	p.nat44Renderer = &nat44.Renderer{
		Deps: nat44.Deps{
			Log:       p.Log.NewLogger("-nat44Renderer"),
			VPP:       p.VPP,
			Contiv:    p.Contiv,
			GoVPPChan: goVppCh,
			NATTxnFactory: func() linuxclient.DataChangeDSL {
				return localclient.DataChangeRequest(p.PluginName)
			},
			LatestRevs: kvdbsync_local.Get().LastRev(),
			Stats:      p.Stats,
		},
	}
	p.nat44Renderer.Log.SetLevel(logging.DebugLevel)

	p.processor.Init()
	p.nat44Renderer.Init(false)

	// Register renderers.
	p.processor.RegisterRenderer(p.nat44Renderer)

	p.ctx, p.cancel = context.WithCancel(context.Background())

	go p.watchEvents()
	err = p.subscribeWatcher()
	if err != nil {
		return err
	}

	return nil
}

// AfterInit registers to the ResyncOrchestrator. The registration is done in this phase
// in order to ensure that the resync for this plugin is triggered only after
// resync of the Contiv plugin has finished.
func (p *Plugin) AfterInit() error {
	p.processor.AfterInit()
	p.nat44Renderer.AfterInit()

	if p.Resync != nil {
		reg := p.Resync.Register(string(p.PluginName))
		go p.handleResync(reg.StatusChan())
	}
	return nil
}

func (p *Plugin) subscribeWatcher() (err error) {
	p.watchConfigReg, err = p.Watcher.
		Watch("K8s services", p.changeChan, p.resyncChan,
			epmodel.KeyPrefix(), podmodel.KeyPrefix(), svcmodel.KeyPrefix(), node.AllocatedIDsKeyPrefix)
	return err
}

func (p *Plugin) watchEvents() {
	p.wg.Add(1)
	defer p.wg.Done()

	for {
		select {
		case resyncConfigEv := <-p.resyncChan:
			p.resyncLock.Lock()
			p.resyncCounter++
			p.pendingResync = resyncConfigEv
			p.pendingChanges = []datasync.ChangeEvent{}
			resyncConfigEv.Done(nil)
			p.Log.WithField("config", resyncConfigEv).Info("Delaying RESYNC config")
			p.resyncLock.Unlock()

		case dataChngEv := <-p.changeChan:
			p.resyncLock.Lock()
			if p.resyncCounter == 0 {
				p.Log.WithField("config", dataChngEv).
					Info("Ignoring data-change received before the first RESYNC")
				p.resyncLock.Unlock()
				break
			}
			if p.pendingResync != nil {
				p.pendingChanges = append(p.pendingChanges, dataChngEv)
				dataChngEv.Done(nil)
				p.Log.WithField("config", dataChngEv).Info("Delaying data-change")
			} else {
				err := p.processor.Update(dataChngEv)
				dataChngEv.Done(err)
			}
			p.resyncLock.Unlock()

		case <-p.ctx.Done():
			p.Log.Debug("Stop watching events")
			return
		}
	}
}

func (p *Plugin) handleResync(resyncChan chan resync.StatusEvent) {
	// block until NodeIP is set
	nodeIPWatcher := make(chan string, 1)
	p.Contiv.WatchNodeIP(nodeIPWatcher)
	nodeIP, nodeNet := p.Contiv.GetNodeIP()
	if nodeIP == nil || nodeNet == nil {
		<-nodeIPWatcher
	}

	for {
		select {
		case ev := <-resyncChan:
			var err error
			status := ev.ResyncStatus()
			if status == resync.Started {
				p.resyncLock.Lock()
				if p.pendingResync != nil {
					p.Log.WithField("config", p.pendingResync).Info("Applying delayed RESYNC config")
					err = p.processor.Resync(p.pendingResync)
					for i := 0; err == nil && i < len(p.pendingChanges); i++ {
						dataChngEv := p.pendingChanges[i]
						p.Log.WithField("config", dataChngEv).Info("Applying delayed data-change")
						err = p.processor.Update(dataChngEv)
					}
					p.pendingResync = nil
					p.pendingChanges = []datasync.ChangeEvent{}
				}
				p.resyncLock.Unlock()
			}
			if err != nil {
				p.Log.Error(err)
			}
			ev.Ack()
		case <-p.ctx.Done():
			return
		}
	}
}

// Close stops watching of KSR reflected data.
func (p *Plugin) Close() error {
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
	safeclose.CloseAll(p.watchConfigReg, p.resyncChan, p.changeChan)
	return nil
}

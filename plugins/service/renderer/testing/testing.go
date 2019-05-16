// Copyright (c) 2019 Bell Canada, Pantheon Technologies and/or its affiliates.
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

package testing

import (
	"context"
	"net"

	. "github.com/contiv/vpp/mock/datasync"
	. "github.com/contiv/vpp/mock/ipnet"
	. "github.com/contiv/vpp/mock/nodesync"
	. "github.com/contiv/vpp/mock/podmanager"
	. "github.com/contiv/vpp/mock/servicelabel"
	. "github.com/onsi/gomega"

	"github.com/contiv/vpp/mock/localclient"
	"github.com/contiv/vpp/plugins/contivconf"
	"github.com/contiv/vpp/plugins/contivconf/config"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ipam"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/nodesync"
	svc_processor "github.com/contiv/vpp/plugins/service/processor"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	scheduler "github.com/ligato/vpp-agent/plugins/kvscheduler/api"
)

const (
	// MasterLabel is node label of master
	MasterLabel = "master"
	// MasterID is node ID of master
	MasterID = uint32(1)
	// WorkerLabel is node label of worker
	WorkerLabel = "worker"
	// WorkerID is node ID of worker
	WorkerID = uint32(2)

	// Namespace1 is first testing namespace
	Namespace1 = "default"
	// Namespace2 is second testing namespace
	Namespace2 = "another-ns"

	// MainVrfID is id of main vrf table
	MainVrfID = 1
	// PodVrfID is id of pod vrf table
	PodVrfID = 2
)

var (
	// Pod1 is first testing pod
	Pod1 = podmodel.ID{Name: "pod1", Namespace: Namespace1}
	// Pod2 is second testing pod
	Pod2 = podmodel.ID{Name: "pod2", Namespace: Namespace1}
	// Pod3 is third testing pod
	Pod3 = podmodel.ID{Name: "pod3", Namespace: Namespace2}

	// Pod1If is name of interface leading to pod 1
	Pod1If = "master-tap1"
	// Pod2If is name of interface leading to pod 2
	Pod2If = "master-tap2"
)

// Fixture contain everything what is needed (plugins/configs/etc...) to test any kind of k8s service renderer (it
// doesn't contain the renderer plugin itself and plugins depending on it)
type Fixture struct {
	Logger       logging.Logger
	Datasync     *MockDataSync
	ServiceLabel *MockServiceLabel
	NodeSync     *MockNodeSync
	ContivConf   *contivconf.ContivConf
	IPAM         *ipam.IPAM
	PodManager   *MockPodManager
	IPNet        *MockIPNet
	SVCProcessor *svc_processor.ServiceProcessor
	Txn          *Txn
}

// NewFixture inits and composes together plugins needed for proper rendering unit testing
func NewFixture(testName string, config *config.Config, ipNet *MockIPNet, nodeIPAddr net.IP, nodeIPNet *net.IPNet,
	mgmtIP net.IP, withoutMasterIPs ...bool) *Fixture {
	fixture := &Fixture{}

	// Tracker of ongoing transaction
	fixture.Txn = &Txn{}

	// Logger
	fixture.Logger = logrus.DefaultLogger()
	fixture.Logger.SetLevel(logging.DebugLevel)
	fixture.Logger.Debug(testName)

	// Datasync
	fixture.Datasync = NewMockDataSync()

	// mock service label
	fixture.ServiceLabel = NewMockServiceLabel()
	fixture.ServiceLabel.SetAgentLabel(MasterLabel)

	// nodesync mock plugin
	fixture.NodeSync = NewMockNodeSync(MasterLabel)
	if len(withoutMasterIPs) > 0 && withoutMasterIPs[0] {
		fixture.NodeSync.UpdateNode(&nodesync.Node{
			Name: MasterLabel,
			ID:   MasterID,
		})
	} else {
		fixture.NodeSync.UpdateNode(&nodesync.Node{
			Name:            MasterLabel,
			ID:              MasterID,
			VppIPAddresses:  contivconf.IPsWithNetworks{{Address: nodeIPAddr, Network: nodeIPNet}},
			MgmtIPAddresses: []net.IP{mgmtIP},
		})
	}
	Expect(fixture.NodeSync.GetNodeID()).To(BeEquivalentTo(1))

	// ContivConf (real) plugin
	fixture.ContivConf = &contivconf.ContivConf{
		Deps: contivconf.Deps{
			PluginDeps: infra.PluginDeps{
				Log: logging.ForPlugin("contivconf"),
			},
			ServiceLabel: fixture.ServiceLabel,
			UnitTestDeps: &contivconf.UnitTestDeps{
				Config: config,
			},
		},
	}
	Expect(fixture.ContivConf.Init()).To(BeNil())
	resyncEv, _ := fixture.Datasync.ResyncEvent()
	Expect(fixture.ContivConf.Resync(resyncEv, resyncEv.KubeState, 1, nil)).To(BeNil())

	// IPAM real plugin
	fixture.IPAM = &ipam.IPAM{
		Deps: ipam.Deps{
			PluginDeps: infra.PluginDeps{
				Log: logging.ForPlugin("IPAM"),
			},
			NodeSync:   fixture.NodeSync,
			ContivConf: fixture.ContivConf,
		},
	}
	Expect(fixture.IPAM.Init()).To(BeNil())
	Expect(fixture.IPAM.Resync(resyncEv, resyncEv.KubeState, 1, nil)).To(BeNil())
	fixture.Datasync.RestartResyncCount()

	// podmanager
	fixture.PodManager = NewMockPodManager()

	// IPNet plugin
	fixture.IPNet = ipNet // totally customizable in renderer tests

	// Prepare processor.
	fixture.SVCProcessor = &svc_processor.ServiceProcessor{
		Deps: svc_processor.Deps{
			Log:          fixture.Logger,
			ServiceLabel: fixture.ServiceLabel,
			ContivConf:   fixture.ContivConf,
			IPAM:         fixture.IPAM,
			IPNet:        fixture.IPNet,
			NodeSync:     fixture.NodeSync,
			PodManager:   fixture.PodManager,
		},
	}

	Expect(fixture.SVCProcessor.Init()).To(BeNil())

	return fixture
}

// Txn is mock of ongoing transaction
type Txn struct {
	isResync bool
	vppTxn   controller.Transaction
}

// Commit is mock commit function for ongoing mock transaction
func (t *Txn) Commit() error {
	if t.vppTxn == nil {
		return nil
	}
	ctx := context.Background()
	if t.isResync {
		ctx = scheduler.WithResync(ctx, scheduler.FullResync, true)
	}
	_, err := t.vppTxn.Commit(ctx)
	t.vppTxn = nil
	return err
}

// ResyncFactory creates factory for mock transaction resync operations
func (t *Txn) ResyncFactory(txnTracker *localclient.TxnTracker) func() controller.ResyncOperations {
	return func() controller.ResyncOperations {
		if t.vppTxn != nil {
			return t.vppTxn
		}
		t.vppTxn = txnTracker.NewControllerTxn(true)
		t.isResync = true
		return t.vppTxn
	}
}

// UpdateFactory creates factory for mock transaction update operations
func (t *Txn) UpdateFactory(txnTracker *localclient.TxnTracker) func(change string) controller.UpdateOperations {
	return func(change string) controller.UpdateOperations {
		if t.vppTxn != nil {
			return t.vppTxn
		}
		t.vppTxn = txnTracker.NewControllerTxn(false)
		t.isResync = false
		return t.vppTxn
	}
}

// IPNet is helper function for parsing IP network address string into IP adddress, IP network and their combination
func IPNet(address string) (combined *net.IPNet, addrOnly net.IP, network *net.IPNet) {
	addrOnly, network, _ = net.ParseCIDR(address)
	combined = &net.IPNet{IP: addrOnly, Mask: network.Mask}
	return combined, addrOnly, network
}

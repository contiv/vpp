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

package statscollector

import (
	"fmt"
	"github.com/ligato/vpp-agent/api/models/vpp/interfaces"
	"github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/contiv/vpp/mock/ipv4net"
	"github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/servicelabel"
	"github.com/ligato/vpp-agent/plugins/vpp/model/interfaces"
	"testing"
)

const (
	testIfPodName  = "tapcli-1"
	testCntvIfName = "GigabitEthernet0/1/1"
)

type mockPrometheus struct {
	statsPath        string
	newRegistryError error
	registerError    error
}

type CollectorTestVars struct {
	plugin  *Plugin
	pmts    *mockPrometheus
	ipv4Net *ipv4net.MockIPv4Net
}

var testVars = CollectorTestVars{
	pmts: &mockPrometheus{
		statsPath:        "",
		newRegistryError: nil,
		registerError:    nil,
	},
	ipv4Net: ipv4net.NewMockIPv4Net(),
}

// TestStatsCollector tests the Statistics collector
func TestStatsCollector(t *testing.T) {
	gomega.RegisterTestingT(t)

	testVars.plugin = &Plugin{
		Deps: Deps{
			ServiceLabel: servicelabel.NewPlugin(),
			IPv4Net:      testVars.ipv4Net,
			Prometheus:   testVars.pmts,
			PluginDeps: infra.PluginDeps{
				Log: logging.ForPlugin("stats-test"),
			},
		},
	}

	// Check error handling if prometheus.NewRegistry returns error
	testVars.pmts.injectNewRegistryFuncError(fmt.Errorf("%s", "NewRegistry Error"))
	err := testVars.plugin.Init()
	gomega.Expect(err).To(gomega.MatchError("NewRegistry Error"))

	testVars.pmts.injectNewRegistryFuncError(nil)

	// Check error handling if prometheus.Register returns error
	testVars.pmts.injectRegisterFuncError(fmt.Errorf("%s", "Register Error"))
	err = testVars.plugin.Init()
	gomega.Expect(err).To(gomega.MatchError("Register Error"))

	testVars.pmts.injectRegisterFuncError(nil)

	// Check the Init() sunny path and do plugin init for the rest of the tests.
	testVars.pmts.injectNewRegistryFuncError(nil)
	err = testVars.plugin.Init()
	gomega.Expect(err).To(gomega.BeNil())

	testVars.ipv4Net.SetPodIfName(pod.ID{"test-pod", "test-namespace"}, testIfPodName)

	t.Run("testPutWithWrongArgumentType", testPutWithWrongArgumentType)
	t.Run("testPutNewPodEntry", testPutNewPodEntry)
	t.Run("testPutExistingPodEntry", testPutExistingPodEntry)
	t.Run("testPutNewContivEntry", testPutNewContivEntry)
	t.Run("testIsContivSystemInterface", testIsContivSystemInterface)
	//t.Run("testDeletePodEntry", testDeletePodEntry)

	testVars.plugin.Close()
}

func testPutWithWrongArgumentType(t *testing.T) {
	key := vpp_interfaces.StatePrefix + "stat1"

	// test with wrong argument type
	stat := &vpp_interfaces.InterfaceState_Statistics{}
	testVars.plugin.Put(key, stat)
}

func testPutNewPodEntry(t *testing.T) {

	key := interfaces.StatePrefix + testIfPodName

	// test with wrong argument type
	stat := &vpp_interfaces.InterfaceState_Statistics{
		InPackets:       1,
		InBytes:         2,
		OutPackets:      3,
		OutBytes:        4,
		DropPackets:     5,
		PuntPackets:     6,
		Ipv4Packets:     7,
		Ipv6Packets:     8,
		InNobufPackets:  9,
		InMissPackets:   10,
		InErrorPackets:  11,
		OutErrorPackets: 12,
	}

	ifState := &vpp_interfaces.InterfaceState{
		Name:       testIfPodName,
		Statistics: stat,
	}

	testVars.plugin.Put(key, ifState)
	entry, exists := testVars.plugin.ifStats[key]

	gomega.Expect(exists).To(gomega.BeTrue())
	gomega.Expect(len(testVars.plugin.ifStats)).To(gomega.Equal(1))
	checkEntry(stat, entry)
}

func testPutExistingPodEntry(t *testing.T) {

	key := interfaces.StatePrefix + testIfPodName

	// test with wrong argument type
	stat := &vpp_interfaces.InterfaceState_Statistics{
		InPackets:       21,
		InBytes:         22,
		OutPackets:      23,
		OutBytes:        24,
		DropPackets:     25,
		PuntPackets:     26,
		Ipv4Packets:     27,
		Ipv6Packets:     28,
		InNobufPackets:  29,
		InMissPackets:   30,
		InErrorPackets:  31,
		OutErrorPackets: 32,
	}

	ifState := &vpp_interfaces.InterfaceState{
		Name:       testIfPodName,
		Statistics: stat,
	}

	testVars.plugin.Put(key, ifState)

	entry, exists := testVars.plugin.ifStats[key]

	gomega.Expect(exists).To(gomega.BeTrue())
	gomega.Expect(len(testVars.plugin.ifStats)).To(gomega.Equal(1))
	checkEntry(stat, entry)
}

func testPutNewContivEntry(t *testing.T) {

	key := interfaces.StatePrefix + testCntvIfName

	// test with wrong argument type
	stat := &vpp_interfaces.InterfaceState_Statistics{
		InPackets:       1,
		InBytes:         2,
		OutPackets:      3,
		OutBytes:        4,
		DropPackets:     5,
		PuntPackets:     6,
		Ipv4Packets:     7,
		Ipv6Packets:     8,
		InNobufPackets:  9,
		InMissPackets:   10,
		InErrorPackets:  11,
		OutErrorPackets: 12,
	}

	ifState := &vpp_interfaces.InterfaceState{
		Name:       testCntvIfName,
		Statistics: stat,
	}

	testVars.plugin.Put(key, ifState)
	entry, exists := testVars.plugin.ifStats[key]

	gomega.Expect(exists).To(gomega.BeTrue())
	gomega.Expect(len(testVars.plugin.ifStats)).To(gomega.Equal(2))
	checkEntry(stat, entry)
}

/* TODO
func testDeletePodEntry(t *testing.T) {
	evt := containeridx.ChangeEvent{
		NamedMappingEvent: idxmap.NamedMappingEvent{
			Del: false,
		},
		Value: &container.Persisted{
			PodName:      "bogusPodName",
			PodNamespace: "bogusPodNamespace",
		},
	}

	gomega.Expect(len(testVars.plugin.ifStats)).To(gomega.Equal(2))

	// Test non-delete event - delete should not happen
	testVars.plugin.processPodEvent(evt)
	gomega.Expect(len(testVars.plugin.ifStats)).To(gomega.Equal(2))

	// Test Delete event where delete succeeds, but invalid Pod name
	evt.Del = true
	testVars.plugin.processPodEvent(evt)
	gomega.Expect(len(testVars.plugin.ifStats)).To(gomega.Equal(2))

	// Test Delete event where delete succeeds, but invalid Pod name
	_, evt.Value.PodName, _ = testVars.cntv.GetPodByIf(testIfPodName)
	testVars.plugin.processPodEvent(evt)
	gomega.Expect(len(testVars.plugin.ifStats)).To(gomega.Equal(2))

	// Test Delete event where delete succeeds, but invalid Pod name
	evt.Value.PodNamespace, _, _ = testVars.cntv.GetPodByIf(testIfPodName)
	testVars.plugin.processPodEvent(evt)
	gomega.Expect(len(testVars.plugin.ifStats)).To(gomega.Equal(1))
}
*/

func testIsContivSystemInterface(t *testing.T) {
	for _, ifName := range systemIfNames {
		tf := testVars.plugin.isContivSystemInterface(ifName)
		gomega.Expect(tf).To(gomega.BeTrue())
	}
	tf := testVars.plugin.isContivSystemInterface("tapcli-1")
	gomega.Expect(tf).To(gomega.BeFalse())
}

func checkEntry(stat *vpp_interfaces.InterfaceState_Statistics, entry *stats) {
	_, exists := entry.metrics[inPacketsMetric]
	gomega.Expect(exists).To(gomega.BeTrue())
	_, exists = entry.metrics[outPacketsMetric]
	gomega.Expect(exists).To(gomega.BeTrue())
	_, exists = entry.metrics[inBytesMetric]
	gomega.Expect(exists).To(gomega.BeTrue())
	_, exists = entry.metrics[outBytesMetric]
	gomega.Expect(exists).To(gomega.BeTrue())
	_, exists = entry.metrics[dropPacketsMetric]
	gomega.Expect(exists).To(gomega.BeTrue())
	_, exists = entry.metrics[puntPacketsMetric]
	gomega.Expect(exists).To(gomega.BeTrue())
	_, exists = entry.metrics[ipv4PacketsMetric]
	gomega.Expect(exists).To(gomega.BeTrue())
	_, exists = entry.metrics[ipv6PacketsMetric]
	gomega.Expect(exists).To(gomega.BeTrue())
	_, exists = entry.metrics[inNobufPacketsMetric]
	gomega.Expect(exists).To(gomega.BeTrue())
	_, exists = entry.metrics[inMissPacketsMetric]
	gomega.Expect(exists).To(gomega.BeTrue())
	_, exists = entry.metrics[inErrorPacketsMetric]
	gomega.Expect(exists).To(gomega.BeTrue())
	_, exists = entry.metrics[outErrorPacketsMetric]
	gomega.Expect(exists).To(gomega.BeTrue())

	gomega.Expect(stat.DropPackets).To(gomega.Equal(entry.data.Statistics.DropPackets))
	gomega.Expect(stat.InBytes).To(gomega.Equal(entry.data.Statistics.InBytes))
	gomega.Expect(stat.InErrorPackets).To(gomega.Equal(entry.data.Statistics.InErrorPackets))
	gomega.Expect(stat.InMissPackets).To(gomega.Equal(entry.data.Statistics.InMissPackets))
	gomega.Expect(stat.InNobufPackets).To(gomega.Equal(entry.data.Statistics.InNobufPackets))
	gomega.Expect(stat.InPackets).To(gomega.Equal(entry.data.Statistics.InPackets))
	gomega.Expect(stat.Ipv4Packets).To(gomega.Equal(entry.data.Statistics.Ipv4Packets))
	gomega.Expect(stat.Ipv6Packets).To(gomega.Equal(entry.data.Statistics.Ipv6Packets))
	gomega.Expect(stat.OutBytes).To(gomega.Equal(entry.data.Statistics.OutBytes))
	gomega.Expect(stat.OutErrorPackets).To(gomega.Equal(entry.data.Statistics.OutErrorPackets))
	gomega.Expect(stat.OutPackets).To(gomega.Equal(entry.data.Statistics.OutPackets))
	gomega.Expect(stat.PuntPackets).To(gomega.Equal(entry.data.Statistics.PuntPackets))
}

// NewRegistry creates new registry exposed at defined URL path (must begin
// with '/' character), path is used to reference registry while adding new
// metrics into registry, opts adjust the behavior of exposed registry. Must
// be called before AfterInit phase of the Prometheus plugin. An attempt to
// create  a registry with path that is already used
// by different registry returns an error.
func (mp *mockPrometheus) NewRegistry(path string, opts promhttp.HandlerOpts) error {
	mp.statsPath = path
	return mp.newRegistryError
}

// Register registers prometheus metric (e.g.: created by prometheus.NewGaugeVec,
// prometheus.NewHistogram,...)  to a specified registry
func (mp *mockPrometheus) Register(registryPath string, collector prometheus.Collector) error {
	return mp.registerError
}

// Unregister unregisters the given metric. The function returns whether a
// Collector was unregistered.
func (mp *mockPrometheus) Unregister(registryPath string, collector prometheus.Collector) bool {
	return false
}

// RegisterGauge registers custom gauge with specific valueFunc to report
// status when invoked. RegistryPath identifies the registry. The aim of this
// method is to simply common use case - adding Gauge with value func.
func (mp *mockPrometheus) RegisterGaugeFunc(registryPath string, namespace string, subsystem string,
	name string, help string, labels prometheus.Labels, valueFunc func() float64) error {
	return nil
}

func (mp *mockPrometheus) injectNewRegistryFuncError(err error) {
	mp.newRegistryError = err
}

func (mp *mockPrometheus) injectRegisterFuncError(err error) {
	mp.registerError = err
}

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

package ksr

import (
	"fmt"
	"github.com/contiv/vpp/plugins/ksr/model/ksrapi"
	"github.com/ligato/cn-infra/flavors/local"
	"github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"

	"testing"
)

const (
	newRegistryTestError = "new Registry Test Error"
	newGaugeVecTestError = "new Gauge Vector Test Error"
	testReflector        = "testReflector"
)

// mockPrometheus is a mock implementation of the main Prometheus registry
type mockPrometheus struct {
	statsPath        string
	newRegistryError error
	registerError    error
}

// mockGauge is a mock implementation of the Prometheus Gauge
type mockGauge struct {
	value float64
}

type StatsCollectorTestVars struct {
	mockPrometheus *mockPrometheus
	statsCollector *StatsCollector
}

var scTestVars StatsCollectorTestVars

func TestStatsCollector(t *testing.T) {
	gomega.RegisterTestingT(t)

	flavorLocal := &local.FlavorLocal{}
	flavorLocal.Inject()

	scTestVars.mockPrometheus = &mockPrometheus{
		newRegistryError: nil,
		registerError:    nil,
	}

	scTestVars.statsCollector = &StatsCollector{
		Log:          flavorLocal.LoggerFor("stats-collector"),
		serviceLabel: "StatsCollectorTest",
		Prometheus:   scTestVars.mockPrometheus,
	}

	// Check proper handling of registration errors
	scTestVars.mockPrometheus.injectNewRegistryFuncError(fmt.Errorf("%s", newRegistryTestError))
	err := scTestVars.statsCollector.Init()
	gomega.Expect(err).To(gomega.MatchError(newRegistryTestError))

	// Check proper handling of Gauge Vector creation errors
	scTestVars.mockPrometheus.injectNewRegistryFuncError(nil)
	scTestVars.mockPrometheus.injectRegisterFuncError(fmt.Errorf("%s", newGaugeVecTestError))
	err = scTestVars.statsCollector.Init()
	gomega.Expect(err).To(gomega.MatchError(newGaugeVecTestError))

	// Check the "sunny path" initialization
	scTestVars.mockPrometheus.injectRegisterFuncError(nil)
	err = scTestVars.statsCollector.Init()
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(len(scTestVars.statsCollector.gaugeVecs)).To(gomega.Equal(9))

	t.Run("testAddReflector", testAddReflector)
	t.Run("testUpdatePrometheusStats", testUpdatePrometheusStats)
}

func testAddReflector(t *testing.T) {
	scTestVars.statsCollector.addReflector(testReflector)

	gomega.Expect(len(scTestVars.statsCollector.metrics)).To(gomega.Equal(1))
	gomega.Expect(len(scTestVars.statsCollector.metrics[testReflector].gauges)).To(gomega.Equal(9))
}

func testUpdatePrometheusStats(t *testing.T) {
	// Test data
	stats := &ksrapi.KsrStats{
		Adds:      1,
		Deletes:   2,
		Updates:   3,
		AddErrors: 4,
		DelErrors: 5,
		UpdErrors: 6,
		ArgErrors: 7,
		Resyncs:   8,
		ResErrors: 9,
	}

	// Replaces Prometheus gauges in Stats Collector with mocks
	gauges := scTestVars.statsCollector.metrics[testReflector].gauges

	gauges[addsMetric] = &mockGauge{value: float64(0)}
	gauges[deletesMetric] = &mockGauge{value: float64(0)}
	gauges[updatesMetric] = &mockGauge{value: float64(0)}
	gauges[addErrMetric] = &mockGauge{value: float64(0)}
	gauges[deleteErrMetric] = &mockGauge{value: float64(0)}
	gauges[updateErrMetric] = &mockGauge{value: float64(0)}
	gauges[argErrMetric] = &mockGauge{value: float64(0)}
	gauges[argErrMetric] = &mockGauge{value: float64(0)}
	gauges[resyncsMetric] = &mockGauge{value: float64(0)}
	gauges[resyncErrMetric] = &mockGauge{value: float64(0)}

	scTestVars.statsCollector.updatePrometheusStats(testReflector, stats)

	// Check that correct values have been written into the gauges.
	gomega.Expect((gauges[addsMetric].(*mockGauge)).value).To(gomega.Equal(float64(stats.Adds)))
	gomega.Expect((gauges[deletesMetric].(*mockGauge)).value).To(gomega.Equal(float64(stats.Deletes)))
	gomega.Expect((gauges[updatesMetric].(*mockGauge)).value).To(gomega.Equal(float64(stats.Updates)))
	gomega.Expect((gauges[addErrMetric].(*mockGauge)).value).To(gomega.Equal(float64(stats.AddErrors)))
	gomega.Expect((gauges[deleteErrMetric].(*mockGauge)).value).To(gomega.Equal(float64(stats.DelErrors)))
	gomega.Expect((gauges[updateErrMetric].(*mockGauge)).value).To(gomega.Equal(float64(stats.UpdErrors)))
	gomega.Expect((gauges[argErrMetric].(*mockGauge)).value).To(gomega.Equal(float64(stats.ArgErrors)))
	gomega.Expect((gauges[resyncsMetric].(*mockGauge)).value).To(gomega.Equal(float64(stats.Resyncs)))
	gomega.Expect((gauges[resyncErrMetric].(*mockGauge)).value).To(gomega.Equal(float64(stats.ResErrors)))
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

// Desc returns the descriptor for the Metric. This method idempotently
// returns the same descriptor throughout the lifetime of the
// Metric. The returned descriptor is immutable by contract. A Metric
// unable to describe itself must return an invalid descriptor (created
// with NewInvalidDesc).
func (mg *mockGauge) Desc() *prometheus.Desc {
	return nil
}

// Write encodes the Metric into a "Metric" Protocol Buffer data
// transmission object.
//
// Metric implementations must observe concurrency safety as reads of
// this metric may occur at any time, and any blocking occurs at the
// expense of total performance of rendering all registered
// metrics. Ideally, Metric implementations should support concurrent
// readers.
//
// While populating dto.Metric, it is the responsibility of the
// implementation to ensure validity of the Metric protobuf (like valid
// UTF-8 strings or syntactically valid metric and label names). It is
// recommended to sort labels lexicographically. (Implementers may find
// LabelPairSorter useful for that.) Callers of Write should still make
// sure of sorting if they depend on it.
func (mg *mockGauge) Write(*dto.Metric) error {
	return nil
}

// Describe sends the super-set of all possible descriptors of metrics
// collected by this Collector to the provided channel and returns once
// the last descriptor has been sent. The sent descriptors fulfill the
// consistency and uniqueness requirements described in the Desc
// documentation. (It is valid if one and the same Collector sends
// duplicate descriptors. Those duplicates are simply ignored. However,
// two different Collectors must not send duplicate descriptors.) This
// method idempotently sends the same descriptors throughout the
// lifetime of the Collector. If a Collector encounters an error while
// executing this method, it must send an invalid descriptor (created
// with NewInvalidDesc) to signal the error to the registry.
func (mg *mockGauge) Describe(chan<- *prometheus.Desc) {

}

// Collect is called by the Prometheus registry when collecting
// metrics. The implementation sends each collected metric via the
// provided channel and returns once the last metric has been sent. The
// descriptor of each sent metric is one of those returned by
// Describe. Returned metrics that share the same descriptor must differ
// in their variable label values. This method may be called
// concurrently and must therefore be implemented in a concurrency safe
// way. Blocking occurs at the expense of total performance of rendering
// all registered metrics. Ideally, Collector implementations support
// concurrent readers.
func (mg *mockGauge) Collect(chan<- prometheus.Metric) {

}

// Set sets the Gauge to an arbitrary value.
func (mg *mockGauge) Set(value float64) {
	mg.value = value
}

// Inc increments the Gauge by 1.
func (mg *mockGauge) Inc() {

}

// Dec decrements the Gauge by 1.
func (mg *mockGauge) Dec() {

}

// Add adds the given value to the Gauge. (The value can be
// negative, resulting in a decrease of the Gauge.)
func (mg *mockGauge) Add(float64) {

}

// Sub subtracts the given value from the Gauge. (The value can be
// negative, resulting in an increase of the Gauge.)
func (mg *mockGauge) Sub(float64) {

}

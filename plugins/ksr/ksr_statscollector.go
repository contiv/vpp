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
	"github.com/contiv/vpp/plugins/ksr/model/ksrapi"
	"github.com/ligato/cn-infra/logging"
	prometheusplugin "github.com/ligato/cn-infra/rpc/prometheus"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	updateInterval = 10 // Metrics update interval, in seconds

	prometheusStatsPath = "/stats" // path where the gauges are exposed
	nodeLabel           = "node"
	reflectorType       = "reflectorType"

	addsMetric      = "adds"
	deletesMetric   = "deletes"
	updatesMetric   = "updates"
	addErrMetric    = "addErrors"
	deleteErrMetric = "deleteErrors"
	updateErrMetric = "updateErrors"
	resyncsMetric   = "resyncs"
	resyncErrMetric = "resyncErrors"
	argErrMetric    = "argErrors"
)

// StatsCollector defines the data structures for the KSR Stats Collector
type StatsCollector struct {
	Log          logging.Logger
	serviceLabel string
	metrics      map[string]*metrics
	gaugeVecs    map[string]*prometheus.GaugeVec
	Prometheus   prometheusplugin.API
}

// metrics holds all the gauges for a given gauge vectors; there is a gauge
// vector for each metric (e.g. 'add', 'delete', 'update', ...). This vector
// contains gauges for all reflectors.
type metrics struct {
	gauges map[string]prometheus.Gauge
}

// nameAndHelp defines the type for Prometheus metric metadata
type nameAndHelp struct {
	name string
	help string
}

// Init initializes the KSR Statistics Collector
func (ksc *StatsCollector) Init() error {
	ksc.gaugeVecs = make(map[string]*prometheus.GaugeVec)
	ksc.metrics = make(map[string]*metrics)

	err := ksc.Prometheus.NewRegistry(prometheusStatsPath,
		promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError, ErrorLog: ksc.Log})
	if err != nil {
		ksc.Log.Errorf("failed to create Prometheus registry for path '%s', error %s", prometheusStatsPath, err)
		return err
	}

	gaugeVecsMetadata := []nameAndHelp{
		{addsMetric, "Number of add operations to kv data store"},
		{deletesMetric, "Number of delete operations fro kv data store"},
		{updatesMetric, "Number of update operations to kv data store"},
		{addErrMetric, "Number of failed add operations"},
		{deleteErrMetric, "Number of failed delete operations"},
		{updateErrMetric, "Number of failed update operations"},
		{resyncsMetric, "Number of KSR resyncs with the kv data store"},
		{resyncErrMetric, "Number of failed KSR resyncs with the kv data store"},
		{argErrMetric, "Number of internal KSR errors - wrong argument passed to a reflector"},
	}

	for _, nh := range gaugeVecsMetadata {
		ksc.gaugeVecs[nh.name] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name:        nh.name,
			Help:        nh.help,
			ConstLabels: prometheus.Labels{nodeLabel: ksc.serviceLabel},
		}, []string{reflectorType})

		err = ksc.Prometheus.Register(prometheusStatsPath, ksc.gaugeVecs[nh.name])
		if err != nil {
			ksc.Log.Errorf("failed to register metric '%s', error %s", nh.name, err)
			return err
		}
	}

	return nil
}

// addReflector
func (ksc *StatsCollector) addReflector(objectType string) {
	entry := &metrics{
		gauges: map[string]prometheus.Gauge{},
	}
	// add gauges with corresponding labels into vectors
	var err error
	for k, vec := range ksc.gaugeVecs {
		entry.gauges[k], err = vec.GetMetricWith(prometheus.Labels{reflectorType: objectType})
		if err != nil {
			ksc.Log.Error(err)
		}
	}
	ksc.metrics[objectType] = entry
}

// start starts periodic updates of KSr starts into Prometheus.
func (ksc *StatsCollector) start(closeCh chan struct{}, rr *ReflectorRegistry) {
	go func() {
		for {
			select {
			case <-closeCh:
				ksc.Log.Info("Closing")
				return
			case <-time.After(updateInterval * time.Second):
				for _, r := range rr.getRegisteredReflectors() {
					if stats, found := rr.getKsrStats(r); found {
						ksc.updatePrometheusStats(r, stats)
					}
				}
			}
		}
	}()
}

// updatePrometheusStats updates the gauges in Prometheus
func (ksc *StatsCollector) updatePrometheusStats(objectType string, stats *ksrapi.KsrStats) {
	if adds, found := ksc.metrics[objectType].gauges[addsMetric]; found && adds != nil {
		adds.Set(float64(stats.Adds))
	}
	if deletes, found := ksc.metrics[objectType].gauges[deletesMetric]; found && deletes != nil {
		deletes.Set(float64(stats.Deletes))
	}
	if updates, found := ksc.metrics[objectType].gauges[updatesMetric]; found && updates != nil {
		updates.Set(float64(stats.Updates))
	}
	if addErrs, found := ksc.metrics[objectType].gauges[addErrMetric]; found && addErrs != nil {
		addErrs.Set(float64(stats.AddErrors))
	}
	if delErrs, found := ksc.metrics[objectType].gauges[deleteErrMetric]; found && delErrs != nil {
		delErrs.Set(float64(stats.DelErrors))
	}
	if updErrs, found := ksc.metrics[objectType].gauges[updateErrMetric]; found && updErrs != nil {
		updErrs.Set(float64(stats.UpdErrors))
	}
	if argErrs, found := ksc.metrics[objectType].gauges[argErrMetric]; found && argErrs != nil {
		argErrs.Set(float64(stats.ArgErrors))
	}
	if resyncs, found := ksc.metrics[objectType].gauges[resyncsMetric]; found && resyncs != nil {
		resyncs.Set(float64(stats.Resyncs))
	}
	if resyncErrs, found := ksc.metrics[objectType].gauges[resyncErrMetric]; found && resyncErrs != nil {
		resyncErrs.Set(float64(stats.ResErrors))
	}
}

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
	"sync"
)

type ReflectorRegistry struct {
	// reflectors is the reflector registry
	reflectors map[string]*Reflector
	// reflector registry lock
	lock sync.RWMutex
}

// dataStoreDownEvent starts all reflectors
func (rr *ReflectorRegistry) startReflectors() {
	rr.lock.RLock()
	defer rr.lock.RUnlock()

	for _, r := range rr.reflectors {
		r.Start()
	}
}

// dataStoreDownEvent signals to all registered reflectors that the data store
// is down. Reflectors should stop updates from the  respective K8s caches.
// Optionally, if data store resync with the K8s cache is in progress, it will
// be abort.
func (rr *ReflectorRegistry) dataStoreDownEvent() {
	rr.lock.RLock()
	defer rr.lock.RUnlock()

	for _, r := range rr.reflectors {
		r.stopDataStoreUpdates()
		select {
		case r.syncStopCh <- true:
			r.Log.Infof("%s: sent dataStoreResyncAbort signal", r.objType)
		default:
			r.Log.Infof("%s: syncStopCh full", r.objType)
		}
	}
}

// dataStoreUpEvent signals to all registered reflectors that the data store
// is back up. Reflectors should start the resync procedure between their
// respective data stores with their respective K8s caches.
func (rr *ReflectorRegistry) dataStoreUpEvent() {
	rr.lock.RLock()
	defer rr.lock.RUnlock()

	for _, r := range rr.reflectors {
		select {
		case <-r.syncStopCh:
			r.Log.Infof("%s: syncStopCh flushed", r.objType)
		default:
			r.Log.Infof("%s: syncStopCh not flushed", r.objType)
		}
		r.startDataStoreResync()
	}
}

// ksrHasSynced determines if all reflectors have synced their respective K8s
// caches with their respective data stores.
func (rr *ReflectorRegistry) ksrHasSynced() bool {
	for _, r := range rr.reflectors {
		if !r.HasSynced() {
			return false
		}
	}
	return true
}

// getKsrStats() gets the global statistics from all reflectors
func (rr *ReflectorRegistry) getKsrStats() *ksrapi.Stats {
	stats := ksrapi.Stats{}
	for _, r := range rr.reflectors {
		switch r.objType {
		case endpointsObjType:
			stats.EndpointsStats = r.GetStats()
		case namespaceObjType:
			stats.NamespaceStats = r.GetStats()
		case podObjType:
			stats.PodStats = r.GetStats()
		case policyObjType:
			stats.PolicyStats = r.GetStats()
		case serviceObjType:
			stats.ServiceStats = r.GetStats()
		case nodeObjType:
			stats.NodeStats = r.GetStats()
		default:
			r.Log.WithField("ksrObjectType", r.objType).
				Error("Plugin statistics sees unknown reflector object type")
		}
	}
	return &stats
}

// addReflector adds a reflector to the registry
func (rr *ReflectorRegistry) addReflector(r *Reflector) error {
	rr.lock.Lock()
	defer rr.lock.Unlock()

	if _, objExists := rr.reflectors[r.objType]; objExists {
		return fmt.Errorf("%s reflector type already exists", r.objType)
	}
	rr.reflectors[r.objType] = r
	return nil
}

// deleteReflector deletes a reflector from the registry
func (rr *ReflectorRegistry) deleteReflector(r *Reflector) error {
	rr.lock.Lock()
	defer rr.lock.Unlock()

	if _, objExists := rr.reflectors[r.objType]; !objExists {
		return fmt.Errorf("%s reflector type does not exist", r.objType)
	}
	delete(rr.reflectors, r.objType)
	return nil
}

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

package controller

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"

	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/servicelabel"

	"github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/dbresources"
	"github.com/contiv/vpp/plugins/ksr"
)

const (
	// healthCheckProbeKey is a key used to probe Etcd state
	healthCheckProbeKey = "/probe-etcd-connection"
)

var (
	// prefix under which all k8s resources are stored in DB
	ksrPrefix = servicelabel.GetDifferentAgentPrefix(ksr.MicroserviceLabel)
)

// dbWatcher watches remote database for changes. Resync and data change events
// are pushed to the Event loop as three different events:
//  * DBResync: full snapshot of the kubernetes state data and of the external
//              configuration
//  * KubeStateChange: a change of a single value from the Kubernetes state data
//  * ExternalConfigChange: a change of a single value from the external config
//
// Furthermore, the content of the remote database is mirrored into the local DB.
// When remote DB is not accessible (typically during early startup), the watcher
// will use local DB to resync from. Meanwhile, watching for changes is inactive.
// Once the connection to remote DB is (re)gained, the watcher performs resync
// against the remote database - also updating the locally mirrored data for
// future outages - and re-actives the watcher.
type dbWatcher struct {
	sync.Mutex
	*dbWatcherArgs

	remoteIsConnected bool
	resyncCount       int
	resyncReqs        chan bool // true if this is localDB-fallback resync

	ignoreChangesUntilResync bool

	remoteBroker  keyval.ProtoBroker
	remoteWatcher keyval.ProtoWatcher
	localBroker   keyval.ProtoBroker

	remoteChangeCh     chan datasync.ProtoWatchResp
	remoteWatchCloseCh chan string

	processedVals map[string]datasync.KeyVal // key (full, with prefix) -> value, revision

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

// dbWatcherArgs collects input arguments for dbWatcher.
type dbWatcherArgs struct {
	log         logging.Logger
	agentPrefix string

	eventLoop api.EventLoop

	localDB  keyval.KvProtoPlugin
	remoteDB keyval.KvProtoPlugin

	delayLocalResync        time.Duration
	remoteDBProbingInterval time.Duration
}

var (
	// ErrClosedWatcher is returned when dbWatcher is used when it is already closed.
	ErrClosedWatcher = errors.New("dbWatcher was closed")
	// ErrResyncReqQueueFull is returned when queue for resync request is full.
	ErrResyncReqQueueFull = errors.New("queue with resync requests is full")
)

// newDBWatcher is the constructor for dbWatcher.
func newDBWatcher(args *dbWatcherArgs) *dbWatcher {
	watcher := &dbWatcher{
		dbWatcherArgs:  args,
		resyncReqs:     make(chan bool, 10),
		localBroker:    args.localDB.NewBroker(""),
		remoteChangeCh: make(chan datasync.ProtoWatchResp, 1000),
		processedVals:  make(map[string]datasync.KeyVal),
	}
	watcher.ignoreChangesUntilResync = true
	watcher.ctx, watcher.cancel = context.WithCancel(context.Background())

	// start DB watching
	watcher.wg.Add(1)
	go watcher.watchDB()

	// trigger periodic remoteDB probing after the first connection has been established
	args.remoteDB.OnConnect(watcher.onFirstConnect)

	// schedule startup-resync from local DB in case remoteDB is not accessible
	watcher.wg.Add(1)
	go watcher.scheduleLocalResync(args.delayLocalResync)
	return watcher
}

// scheduleLocalResync is run in a separate go routine to trigger startup
// resync from localDB as a fallback solution if connection with the remote DB
// hasn't been initiated within a given time period.
func (w *dbWatcher) scheduleLocalResync(delay time.Duration) {
	defer w.wg.Done()

	select {
	case <-w.ctx.Done():
		return
	case <-time.After(delay):
		err := w.requestResync(true)
		if err != nil {
			w.log.Errorf("Failed to request resync against local DB: %v", err)
		}
	}
}

// onFirstConnect is triggered by remoteDB once connection with remote DB is established
// (called only for the first connection, cannot be used to detect reconnect).
func (w *dbWatcher) onFirstConnect() error {
	w.Lock()
	defer w.Unlock()

	w.remoteBroker = w.remoteDB.NewBroker("")
	w.remoteWatcher = w.remoteDB.NewWatcher("")

	// start period probing
	w.wg.Add(1)
	go w.periodicRemoteDBProbing()
	return nil
}

// periodicRemoteDBProbing runs in a separate go routine a period probing
// of the connection to remoteDB.
func (w *dbWatcher) periodicRemoteDBProbing() {
	defer w.wg.Done()
	w.probeRemoteDB()

	for {
		select {
		case <-time.After(w.remoteDBProbingInterval):
			w.probeRemoteDB()

		case <-w.ctx.Done():
			return
		}
	}
}

// probeRemoteDB checks if the connection to remote DB is functioning properly.
func (w *dbWatcher) probeRemoteDB() {
	w.Lock()
	defer w.Unlock()

	if _, _, err := w.remoteBroker.GetValue(healthCheckProbeKey, nil); err != nil {
		if w.remoteIsConnected == true {
			w.remoteIsConnected = false
			w.stopWatching()
			w.log.Warn("Lost connection to Remote DB")
		}
		return
	}

	if !w.remoteIsConnected {
		w.remoteIsConnected = true
		w.log.Info("Connection to Remote DB was (re-)established")

		// first resync, then changes
		w.ignoreChangesUntilResync = true

		// restart watching (can be broken)
		w.restartWatching()

		// request resync against remoteDB
		err := w.requestResync(false)
		if err != nil {
			w.log.Errorf("Failed to request resync against remote DB: %v", err)
		}
	}
}

// requestResync is used to request DB resync.
// The watcher loads a snapshot of the database, wraps it into the DBResync event
// and pushes it into the event loop.
func (w *dbWatcher) requestResync(local bool) error {
	select {
	case <-w.ctx.Done():
		return ErrClosedWatcher
	case w.resyncReqs <- local:
		return nil
	default:
		return ErrResyncReqQueueFull
	}
}

// watchDB watches remoteDB for changes and receives resync requests.
func (w *dbWatcher) watchDB() {
	defer w.wg.Done()

	for {
		select {
		case <-w.ctx.Done():
			return

		case local := <-w.resyncReqs:
			w.runResync(local)
			continue

		case change := <-w.remoteChangeCh:
			w.processChange(change)
			continue
		}
	}
}

// restartWatching (re)starts watching for changes in remote DB.
// The method assumes that dbWatcher is in the locked state.
func (w *dbWatcher) restartWatching() {
	w.remoteWatchCloseCh = make(chan string)
	w.remoteWatcher.Watch(w.onRemoteDBChange, w.remoteWatchCloseCh,
		servicelabel.GetDifferentAgentPrefix(ksr.MicroserviceLabel), // resources
		w.agentPrefix) // external configuration
}

// stopWatching stops watching of remote DB.
func (w *dbWatcher) stopWatching() {
	if w.remoteWatchCloseCh != nil {
		// close previous watch
		close(w.remoteWatchCloseCh)
		w.remoteWatchCloseCh = nil
		// TODO: verify that etcd plugin (default remoteDB) properly closes
		// the watch and de-allocates all resource associated with it
	}
}

// onRemoteDBChange is callback triggered when change from remote DB is received.
func (w *dbWatcher) onRemoteDBChange(change datasync.ProtoWatchResp) {
	select {
	case w.remoteChangeCh <- change:
		return
	default:
		w.log.Error("Failed to enqueue remote DB data change, requesting resync")
		if err := w.requestResync(false); err != nil {
			w.log.Error("Even queue for resync requests is full")
		}
	}
}

// runResync runs resync against local or remote DB.
func (w *dbWatcher) runResync(local bool) {
	w.Lock()
	defer w.Unlock()

	if local && (w.resyncCount > 0 || w.remoteIsConnected) {
		// no need for fallback local resync
		w.log.Info("Skipping resync against local DB")
		return
	}

	if !local && !w.remoteIsConnected {
		w.log.Info("Unable to resync against remote DB - connection is not available")
		return
	}

	w.resyncCount++
	if local {
		w.runResyncFromLocalDB()
	} else {
		w.runResyncFromRemoteDB()
	}
}

// runResyncFromLocalDB executes resync from data mirrored into the local DB.
// In reality, the method is called at most once as the startup resync.
// In case of an error, another (local) resync is NOT requested.
// The method assumes that dbWatcher is in the locked state.
func (w *dbWatcher) runResyncFromLocalDB() {
	// mirroring of external configuration into the local DB is not supported yet
	// - load only resources
	event, values, err := LoadKubeStateForResync(w.localBroker, w.log)
	if err != nil {
		w.log.Errorf("Resync from local DB has failed: %v", err)
		return
	}
	if len(values) == 0 {
		// abort local resync if local DB is empty - most likely it was cleared
		// or not yet used
		w.log.Error("Local DB is empty - aborting resync")
		return
	}
	event.Local = true

	// send the event
	err = w.eventLoop.PushEvent(event)
	if err != nil {
		w.log.Errorf("Failed to push (local) resync event: %v", err)
	}
}

// runResyncFromRemoteDB executes resync from data mirrored into the remote DB.
// The method assumes that dbWatcher is in the locked state.
func (w *dbWatcher) runResyncFromRemoteDB() {
	var err error
	defer func() {
		if err != nil {
			w.log.Errorf("Resync from remote DB has failed: %v, requesting another resync", err)
			if err := w.requestResync(false); err != nil {
				w.log.Errorf("Even queue for resync requests is broken: %v", err)
			}
		} else {
			w.ignoreChangesUntilResync = false
		}
	}()

	// load Kubernetes state from remote DB
	var (
		event  *api.DBResync
		values map[string]datasync.KeyVal
	)
	event, values, err = LoadKubeStateForResync(w.remoteBroker, w.log)
	if err != nil {
		return
	}

	// load external configuration
	var iterator keyval.ProtoKeyValIterator
	iterator, err = w.remoteBroker.ListValues(w.agentPrefix)
	if err != nil {
		return
	}
	for {
		kv, stop := iterator.GetNext()
		if stop {
			break
		}

		// record value for revision comparisons
		values[kv.GetKey()] = kv

		// add key-value pair into the event
		key := strings.TrimPrefix(kv.GetKey(), w.agentPrefix)
		event.ExternalConfig[key] = kv
	}
	iterator.Close()

	// resync local DB
	err = ResyncDatabase(w.localBroker, event.KubeState)
	if err != nil {
		return
	}

	// send resync event
	err = w.eventLoop.PushEvent(event)
	if err != nil {
		return
	}

	// now that the resync succeeded, update the map with last processed revisions
	w.processedVals = values
}

// processChange processes change received from remote DB.
func (w *dbWatcher) processChange(change datasync.ProtoWatchResp) {
	w.Lock()
	defer w.Unlock()
	key := change.GetKey()

	// ignore if dbWatcher is expecting resync
	if w.ignoreChangesUntilResync {
		w.log.Debugf("Ignoring change for key: %v (waiting for resync)", key)
		return
	}

	// check if this revision was already processed
	prevRev, hasPrevRev := w.processedVals[key]
	if hasPrevRev {
		if prevRev.GetRevision() >= change.GetRevision() {
			w.log.Debugf("Ignoring already processed revision for key=%s", key)
			return
		}
	}
	w.processedVals[key] = change

	// check if this is resource or and an external configuration
	resourceMeta, externalCfg := w.getResourceByKey(key)
	if resourceMeta == nil && !externalCfg {
		// unhandled DB resource
		return
	}

	// unamrshall resource value
	var (
		resourceNewVal, resourcePrevVal proto.Message
	)
	if resourceMeta != nil {
		// un-marshall the value
		valueType := proto.MessageType(resourceMeta.ProtoMessageName)
		if valueType == nil {
			w.log.Warnf("Failed to instantiate proto message for resource: %s", resourceMeta.Keyword)
		} else {
			if change.GetChangeType() != datasync.Delete {
				resourceNewVal = reflect.New(valueType.Elem()).Interface().(proto.Message)
			}
			resourcePrevVal = reflect.New(valueType.Elem()).Interface().(proto.Message)

			// try to deserialize the new value
			if change.GetChangeType() != datasync.Delete {
				err := change.GetValue(resourceNewVal)
				if err != nil {
					w.log.Warnf("Failed to de-serialize new value for key: %s", key)
					resourceNewVal = nil
				}
			}

			// try to deserialize the previous value
			var err error
			if hasPrevRev {
				// prioritize previous value known to dbwatcher over the one from the event
				err = prevRev.GetValue(resourcePrevVal)
			}
			if err != nil {
				w.log.Warnf("Failed to de-serialize previous value for key: %s", key)
			}
			if !hasPrevRev || err != nil {
				resourcePrevVal = nil
			}

			if resourceNewVal == nil && resourcePrevVal == nil {
				// Delete that has been already processed - after resync, the revisions
				// of deleted keys are not known, so the revision check above will not
				// cause the change to be ignored.
				w.log.Debugf("Ignoring already processed Delete for key=%s", key)
				return
			}
		}
	}

	// update local DB
	if resourceMeta != nil {
		// FIXME: with the cn-infra framework it is not possible to mirror external
		// configuration on the Contiv-level - marshalled data (i.e. bytes) are not
		// available via public interfaces.
		if change.GetChangeType() == datasync.Delete {
			w.localBroker.Delete(key)
		} else if resourceNewVal != nil {
			w.localBroker.Put(key, resourceNewVal)
		}
	}

	// finally send event about the change
	var event api.Event
	if resourceMeta != nil {
		key = strings.TrimPrefix(key, servicelabel.GetDifferentAgentPrefix(ksr.MicroserviceLabel))
		event = &api.KubeStateChange{
			Key:       key,
			Resource:  resourceMeta.Keyword,
			PrevValue: resourcePrevVal,
			NewValue:  resourceNewVal,
		}
	} else {
		key = strings.TrimPrefix(key, w.agentPrefix)
		event = &api.ExternalConfigChange{
			Key:      key,
			Revision: change,
			Value:    change,
		}
	}
	err := w.eventLoop.PushEvent(event)
	if err != nil {
		w.log.Errorf("Failed to push data change event: %v, requesting resync", err)
		if err := w.requestResync(false); err != nil {
			w.log.Errorf("Even queue for resync requests is broken: %v", err)
		}
	}
}

// getResourceByKey tries to find metadata for resource with the given key.
// Return nil if the key belongs to external configuration.
func (w *dbWatcher) getResourceByKey(key string) (resource *api.DBResource, externalConfig bool) {
	if strings.HasPrefix(key, w.agentPrefix) {
		// this is external config
		return nil, true
	}
	key = strings.TrimPrefix(key, servicelabel.GetDifferentAgentPrefix(ksr.MicroserviceLabel))
	for _, resource := range dbresources.GetDBResources() {
		if strings.HasPrefix(key, resource.KeyPrefix) {
			return resource, false
		}
	}
	return nil, false // unhandled resource
}

// close stops watching of the database.
func (w *dbWatcher) close() {
	w.cancel()
	w.wg.Wait()
	w.stopWatching()
}

// LoadKubeStateForResync loads Kubernetes state from given DB for resync.
// Loaded key-value pairs are returned both as a map and a resync event.
// Broker should not be prefixed.
func LoadKubeStateForResync(broker keyval.ProtoBroker, log logging.Logger) (event *api.DBResync, values map[string]datasync.KeyVal, err error) {
	// init output arguments
	event = api.NewDBResync()
	values = make(map[string]datasync.KeyVal)

	// load values resource by resource
	for _, resource := range dbresources.GetDBResources() {
		event.KubeState[resource.Keyword] = make(api.KeyValuePairs)
		iterator, err := broker.ListValues(ksrPrefix + resource.KeyPrefix)
		if err != nil {
			return event, values, err
		}
		for {
			kv, stop := iterator.GetNext()
			if stop {
				break
			}

			// un-marshall the value
			valueType := proto.MessageType(resource.ProtoMessageName)
			if valueType == nil {
				log.Warnf("Failed to instantiate proto message for resource: %s", resource.Keyword)
				continue
			}
			value := reflect.New(valueType.Elem()).Interface().(proto.Message)
			err := kv.GetValue(value)
			if err != nil {
				log.Warnf("Failed to de-serialize value for key: %s", kv.GetKey())
				continue
			}

			// add key-value pair into the output arguments
			if values != nil {
				values[kv.GetKey()] = kv
			}
			if event != nil {
				key := strings.TrimPrefix(kv.GetKey(), ksrPrefix)
				event.KubeState[resource.Keyword][key] = value
			}
		}
		iterator.Close()
	}
	return event, values, nil
}

// ResyncDatabase updates database content to reflect the given Kubernetes state data.
// External configuration is not supported yet.
// Broker should not be prefixed.
func ResyncDatabase(broker keyval.ProtoBroker, kubeStateData api.KubeStateData) error {
	keys := make(map[string]struct{})

	// update database with values present in the resync event
	for _, kvs := range kubeStateData {
		for key, value := range kvs {
			keys[ksrPrefix+key] = struct{}{}
			err := broker.Put(ksrPrefix+key, value)
			if err != nil {
				return err
			}
		}
	}

	// read keys currently stored in DB, remove the obsolete ones
	keyIterator, err := broker.ListKeys("")
	if err != nil {
		return err
	}
	for {
		key, _, stop := keyIterator.GetNext()
		if stop {
			break
		}
		if _, inEvent := keys[key]; !inEvent {
			_, err = broker.Delete(key)
			if err != nil {
				return err
			}
		}
	}
	keyIterator.Close()
	return nil
}

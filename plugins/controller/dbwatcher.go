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
	"sync"
	"time"
	"strings"

	"github.com/gogo/protobuf/proto"

	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/datasync"

	"github.com/contiv/vpp/plugins/controller/api"
)

const (
	// key prefix used to store VPP configuration for ligato/vpp-agent.
	vppConfigKeyPrefix = "vpp/config/v2/"

	// key prefix used to store Linux network configuration for ligato/vpp-agent.
	linuxConfigKeyPrefix = "linux/config/v2/"

	// healthCheckProbeKey is a key used to probe Etcd state
	healthCheckProbeKey = "/probe-etcd-connection"
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

	keyPrefixes    []string
	extKeyPrefixes []string

	remoteBroker  keyval.ProtoBroker
	remoteWatcher keyval.ProtoWatcher
	localBroker   keyval.ProtoBroker

	remoteChangeCh     chan datasync.ProtoWatchResp
	remoteWatchCloseCh chan string

	processedVals map[string]datasync.KeyVal // key -> value, revision

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

	resources []*api.DBResource

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
		localBroker:    args.localDB.NewBroker(args.agentPrefix),
		remoteChangeCh: make(chan datasync.ProtoWatchResp, 100),
		processedVals:  make(map[string]datasync.KeyVal),

	}
	watcher.ctx, watcher.cancel = context.WithCancel(context.Background())

	// collect key prefixes to watch
	//  -> resources:
	for _, resource := range args.resources {
		watcher.keyPrefixes = append(watcher.keyPrefixes, resource.KeyPrefix)
	}
	//  -> external configuration:
	watcher.extKeyPrefixes = append(watcher.extKeyPrefixes, args.agentPrefix + vppConfigKeyPrefix)
	watcher.extKeyPrefixes = append(watcher.extKeyPrefixes, args.agentPrefix + linuxConfigKeyPrefix)

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
			w.log.Warn("Lost connection to Remote DB")
		}
		return
	}

	if !w.remoteIsConnected {
		w.remoteIsConnected = true
		w.log.Info("Connection to Remote DB was (re-)established")

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

	select {
	case <-w.ctx.Done():
		return

	case local := <-w.resyncReqs:
		w.runResync(local)
		return

	case change := <-w.remoteChangeCh:
		w.processChange(change)
		return
	}
}

// restartWatching (re)starts watching for changes in remote DB.
// The method assumes that dbWatcher is in the locked state.
func (w *dbWatcher) restartWatching() {
	w.stopWatching()
	w.remoteWatchCloseCh = make(chan string)
	w.remoteWatcher.Watch(w.onRemoteDBChange, w.remoteWatchCloseCh,
		append(w.keyPrefixes, w.extKeyPrefixes...)...)
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
	event := &api.DBResync{
		KubeState:      make(api.KubeStateData),
		ExternalConfig: make(api.ExternalConfig),
	}

	// mirroring of external configuration into the local DB is not supported yet
	// - load only resources
	err := w.loadKubeStateForResync(w.localBroker, event, nil)
	if err != nil {
		w.log.Errorf("Resync from local DB has failed: %v", err)
		return
	}

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
		}
	}()

	event := &api.DBResync{
		KubeState:      make(api.KubeStateData),
		ExternalConfig: make(api.ExternalConfig),
	}
	processedVals := make(map[string]datasync.KeyVal)

	// TODO: handle changes newer than resync that were already processed

	// load Kubernetes state from remote DB
	err = w.loadKubeStateForResync(w.remoteBroker, event, processedVals)
	if err != nil {
		return
	}

	// load external configuration
	for _, keyPrefix := range w.extKeyPrefixes {
		var iterator keyval.ProtoKeyValIterator
		iterator, err = w.remoteBroker.ListValues(keyPrefix)
		if err != nil {
			return
		}
		for {
			kv, stop := iterator.GetNext()
			if stop {
				break
			}

			// record value for revision comparisons
			processedVals[kv.GetKey()] = kv

			// add key-value pair into the event
			event.ExternalConfig[kv.GetKey()] = kv
		}
		iterator.Close()
	}

	// resync local DB:
	//   1. read keys currently stored in local DB, remove the obsolete ones
	var keyIterator keyval.ProtoKeyIterator
	keyIterator, err = w.localBroker.ListKeys("")
	if err != nil {
		return
	}
	for {
		key, _, stop := keyIterator.GetNext()
		if stop {
			break
		}
		if _, inRemote := processedVals[key]; !inRemote {
			_, err = w.localBroker.Delete(key)
			if err != nil {
				return
			}
		}
	}
	keyIterator.Close()
	//   2. update values present in the remote DB (external configuration is not supported yet)
	for _, kvs := range event.KubeState {
		for key, value := range kvs {
			err = w.localBroker.Put(key, value)
			if err != nil {
				return
			}
		}
	}

	// send resync event
	err = w.eventLoop.PushEvent(event)
	if err != nil {
		return
	}

	// now that the resync succeeded, update the map with last processed revisions
	w.processedVals = processedVals
}

// loadKubeStateForResync is a helper method shared between runResyncFromLocalDB and
// runResyncFromRemoteDB, used to load Kubernetes state from given DB for resync.
// <event> and <values> are output parameters, both optional.
func (w *dbWatcher) loadKubeStateForResync(broker keyval.ProtoBroker, event *api.DBResync,
	values map[string]datasync.KeyVal) error {

	for _, resource := range w.resources {
		event.KubeState[resource.Keyword] = make(api.KeyValuePairs)
		iterator, err := broker.ListValues(resource.KeyPrefix)
		if err != nil {
			return err
		}
		for {
			kv, stop := iterator.GetNext()
			if stop {
				break
			}

			// un-marshall the value
			valueType := proto.MessageType(resource.ProtoMessageName)
			if valueType == nil {
				w.log.Warnf("Failed to instantiate proto message for resource: %s", resource.Keyword)
				continue
			}
			value := reflect.New(valueType.Elem()).Interface().(proto.Message)
			err := kv.GetValue(value)
			if err != nil {
				w.log.Warnf("Failed to de-serialize value for key: %s", kv.GetKey())
				continue
			}

			// add key-value pair into the output arguments
			if values != nil {
				values[kv.GetKey()] = kv
			}
			if event != nil {
				event.KubeState[resource.Keyword][kv.GetKey()] = value
			}
		}
		iterator.Close()
	}
	return nil
}

// processChange processes change received from remote DB.
func (w *dbWatcher) processChange(change datasync.ProtoWatchResp) {
	w.Lock()
	defer w.Unlock()
	key := change.GetKey()

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
	resourceMeta := w.getResourceByKey(key)
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
			var (
				err      error
				withPrev bool
			)
			if hasPrevRev {
				// prioritize previous value known to dbwatcher
				withPrev = true
				err = prevRev.GetValue(resourcePrevVal)
			} else {
				withPrev, err = change.GetPrevValue(resourcePrevVal)
			}
			if err != nil {
				w.log.Warnf("Failed to de-serialize previous value for key: %s", key)
			}
			if !withPrev || err != nil {
				resourcePrevVal = nil
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
		event = &api.KubeStateChange{
			Key:       key,
			Resource:  resourceMeta.Keyword,
			PrevValue: resourcePrevVal,
			NewValue:  resourceNewVal,
		}
	} else {
		event = &api.ExternalConfigChange{
			Change: change,
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

// getResourceByKey tries to find metadata for resource with the given nil.
// Return nil if the key belongs to external configuration.
func (w *dbWatcher) getResourceByKey(key string) *api.DBResource {
	if strings.HasPrefix(key, w.agentPrefix) {
		// this is external config
		return nil
	}
	for _, resource := range w.resources {
		if strings.HasPrefix(key, resource.KeyPrefix) {
			return resource
		}
	}
	return nil
}

// close stops watching of the database.
func (w *dbWatcher) close() {
	w.cancel()
	w.wg.Wait()
	w.stopWatching()
}

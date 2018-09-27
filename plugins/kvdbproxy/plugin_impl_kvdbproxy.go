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

package kvdbproxy

import (
	"sync"

	"github.com/gogo/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/utils/safeclose"
)

// Plugin implements proxy for a kvdbsync with ability to skip selected change events.
// The primary use case is:
//   - a plugin watches configuration in key-value datastore and processes the changes in a "standard" way
//   - a part of the configuration is processed "alternatively" and it
// 	   is persisted into key-value datastore afterwards
//   - the change events caused by persisting need to be ignored since the change is already applied
// The limitations:
// 	 - it is not possible to define multiple ignored events for the key.
type Plugin struct {
	Deps
	sync.Mutex
	ignoreList map[string]datasync.Op
	closeChan  chan interface{}
}

type kvsyncDelegate interface {
	Watch(resyncName string, changeChan chan datasync.ChangeEvent,
		resyncChan chan datasync.ResyncEvent, keyPrefixes ...string) (datasync.WatchRegistration, error)

	Put(key string, data proto.Message, opts ...datasync.PutOption) error

	Delete(key string, opts ...datasync.DelOption) (existed bool, err error)
}

// Deps group the dependencies of the Plugin
type Deps struct {
	infra.PluginDeps

	KVDB kvsyncDelegate
}

// Init initializes internal members of the plugin.
func (plugin *Plugin) Init() error {
	plugin.ignoreList = map[string]datasync.Op{}
	plugin.closeChan = make(chan interface{})
	return nil
}

// Close cleans up the resources allocated by the plugin
func (plugin *Plugin) Close() error {
	return safeclose.Close(plugin.closeChan)
}

// AddIgnoreEntry adds the entry into ignore list. The first change event matching the given key and operation
// is skipped. Once the event is skipped the entry is removed from the list.
func (plugin *Plugin) AddIgnoreEntry(key string, op datasync.Op) {
	plugin.Lock()
	defer plugin.Unlock()
	plugin.ignoreList[key] = op
}

// DelIgnoreEntry removes the entry from ignore list.
// E.g.: The method might be used if the call that was supposed to generate the change failed.
func (plugin *Plugin) DelIgnoreEntry(key string) {
	plugin.Lock()
	defer plugin.Unlock()
	delete(plugin.ignoreList, key)
}

// Watch forwards the subscription request to the injected kvdbsync plugin. The change events
// are filtered based on the plugin ignore list. The resync events are untouched.
func (plugin *Plugin) Watch(resyncName string, changeChan chan datasync.ChangeEvent,
	resyncChan chan datasync.ResyncEvent, keyPrefixes ...string) (datasync.WatchRegistration, error) {

	proxyChan := make(chan datasync.ChangeEvent)
	go func() {
	filter:
		for {
			select {
			case m := <-proxyChan:
				plugin.Lock()
				op, found := plugin.ignoreList[m.GetKey()]
				if found && op == m.GetChangeType() {
					plugin.Log.Infof("Change for %v is ignored", m.GetKey())
					delete(plugin.ignoreList, m.GetKey())
				} else if changeChan != nil {
					plugin.Log.Infof("Change for %v is about to be applied", m.GetKey())
					changeChan <- m
				}
				plugin.Unlock()
			case <-plugin.closeChan:
				break filter

			}
		}
	}()

	return plugin.KVDB.Watch(resyncName, proxyChan, resyncChan, keyPrefixes...)
}

// Put puts data into a datastore using the injected kvdbsync plugin.
func (plugin *Plugin) Put(key string, data proto.Message, opts ...datasync.PutOption) error {
	return plugin.KVDB.Put(key, data, opts...)
}

// Delete deletes data from a datastore using the injected kvdbsync plugin.
func (plugin *Plugin) Delete(key string, opts ...datasync.DelOption) (existed bool, err error) {
	return plugin.KVDB.Delete(key, opts...)
}

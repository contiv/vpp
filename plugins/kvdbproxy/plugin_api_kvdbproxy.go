package kvdbproxy

import (
	"github.com/gogo/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"
)

// Proxy forwards calls to a kvdbsync plugin. It allows to filter changeEvents that come from the plugin.
type Proxy interface {
	// AddIgnoreEntry adds the entry into ignore list. The first change event matching the given key and operation
	// is skipped. Once the event is skipped the entry is removed from the list.
	AddIgnoreEntry(key string, op datasync.Op)

	// Watch forwards the subscription request to the injected kvdbsync plugin. The change events
	// are filtered based on the plugin ignore list. The resync events are untouched.
	Watch(resyncName string, changeChan chan datasync.ChangeEvent,
		resyncChan chan datasync.ResyncEvent, keyPrefixes ...string) (datasync.WatchRegistration, error)

	// Put puts data into a datastore using the injected kvdbsync plugin.
	Put(key string, data proto.Message, opts ...datasync.PutOption) error

	// Delete deletes data from a datastore using the injected kvdbsync plugin.
	Delete(key string, opts ...datasync.DelOption) (existed bool, err error)
}

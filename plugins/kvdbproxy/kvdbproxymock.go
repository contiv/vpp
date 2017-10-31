package kvdbproxy

import (
	"github.com/golang/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"
	"strings"
)

// KvdbsyncMock mocks the behavior of kvdbproxy plugin for test purposes
type KvdbsyncMock struct {
	subs map[string]chan datasync.ChangeEvent
}

// NewKvdbsyncMock creates new instance of KvdbsyncMock
func NewKvdbsyncMock() Proxy {
	return &KvdbsyncMock{subs: map[string]chan datasync.ChangeEvent{}}
}

// Watch mocks the watch operation. It stores the changeChan and keyPrefixes for the subsequent asserts.
// Other arguments are ignored.
func (kv *KvdbsyncMock) Watch(resyncName string, changeChan chan datasync.ChangeEvent,
	resyncChan chan datasync.ResyncEvent, keyPrefixes ...string) (datasync.WatchRegistration, error) {

	for _, k := range keyPrefixes {
		kv.subs[k] = changeChan
	}

	return &regMock{}, nil
}

// Put mocks the put operation. If the key matches a prefix that is watched it generates a change event.
func (kv *KvdbsyncMock) Put(key string, data proto.Message, opts ...datasync.PutOption) error {
	for k, ch := range kv.subs {
		if strings.Contains(key, k) {
			ch <- newChangeEventMock(key, datasync.Put)
		}
	}
	return nil
}

// Delete mocks the delete operation. If the key matches a prefix that is watched it generates a change event.
func (kv *KvdbsyncMock) Delete(key string, opts ...datasync.DelOption) (existed bool, err error) {
	for k, ch := range kv.subs {
		if strings.Contains(key, k) {
			ch <- newChangeEventMock(key, datasync.Delete)
		}
	}
	return true, nil
}

// AddIgnoreEntry is a mock function that currently does nothing.
func (kv *KvdbsyncMock) AddIgnoreEntry(key string, op datasync.PutDel) {

}

type regMock struct {
}

func (r *regMock) Unregister(keyPrefix string) error {
	return nil
}

func (r *regMock) Close() error {
	return nil
}

type changeEventMock struct {
	key        string
	changeType datasync.PutDel
}

func newChangeEventMock(key string, change datasync.PutDel) *changeEventMock {
	return &changeEventMock{key: key, changeType: change}
}

func (ce *changeEventMock) Done(err error) {}

func (ce *changeEventMock) GetValue(value proto.Message) error {
	return nil
}

func (ce *changeEventMock) GetKey() string {
	return ce.key
}

func (ce *changeEventMock) GetPrevValue(value proto.Message) (prevExisted bool, err error) {
	return false, nil
}

func (ce *changeEventMock) GetRevision() int64 {
	return 0
}

func (ce *changeEventMock) GetChangeType() datasync.PutDel {
	return ce.changeType
}

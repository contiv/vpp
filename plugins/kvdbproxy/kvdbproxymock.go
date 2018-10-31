package kvdbproxy

import (
	"strings"

	"github.com/gogo/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"
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
func (kv *KvdbsyncMock) AddIgnoreEntry(key string, op datasync.Op) {

}

type regMock struct {
}

func (r *regMock) Register(resyncName string, keyPrefix string) error {
	return nil
}

func (r *regMock) Unregister(keyPrefix string) error {
	return nil
}

func (r *regMock) Close() error {
	return nil
}

type changeEventMock struct {
	wr *protoWatchRespMock
}

func newChangeEventMock(key string, change datasync.Op) *changeEventMock {
	return &changeEventMock{wr: newProtoWatchRespMock(key, change)}
}

func (ce *changeEventMock) Done(err error) {}

func (ce *changeEventMock) GetChanges() []datasync.ProtoWatchResp {
	return []datasync.ProtoWatchResp{ce.wr}
}

type protoWatchRespMock struct {
	key        string
	changeType datasync.Op
}

func newProtoWatchRespMock(key string, change datasync.Op) *protoWatchRespMock {
	return &protoWatchRespMock{key: key, changeType: change}
}

func (pw *protoWatchRespMock) GetValue(value proto.Message) error {
	return nil
}

func (pw *protoWatchRespMock) GetKey() string {
	return pw.key
}

func (pw *protoWatchRespMock) GetPrevValue(value proto.Message) (prevExisted bool, err error) {
	return false, nil
}

func (pw *protoWatchRespMock) GetRevision() int64 {
	return 0
}

func (pw *protoWatchRespMock) GetChangeType() datasync.Op {
	return pw.changeType
}

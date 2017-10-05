package kvdbproxy

import (
	"github.com/golang/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/onsi/gomega"
	"gitlab.cisco.com/ctao/vnf-agent/agent/data"
	"strings"
	"testing"
	"time"
)

func TestWatch(t *testing.T) {
	gomega.RegisterTestingT(t)

	kvdbMock := newKvdbsyncMock()

	plugin := Plugin{}
	plugin.Deps.Log = logging.ForPlugin("proxy", logrus.NewLogRegistry())
	plugin.Deps.KVDB = kvdbMock

	err := plugin.Init()
	gomega.Expect(err).To(gomega.BeNil())

	ch := make(chan datasync.ChangeEvent, 1)

	plugin.Watch("test", ch, nil, "/abc/prefix")

	// expect message to be received
	plugin.Put("/abc/prefix/something", nil)
	select {
	case change := <-ch:
		gomega.Expect(change.GetKey()).To(gomega.BeEquivalentTo("/abc/prefix/something"))
		gomega.Expect(change.GetChangeType()).To(gomega.BeEquivalentTo(data.Put))
	case <-time.After(100 * time.Millisecond):
		t.FailNow()
	}

	// expect the message to be filtered out
	plugin.AddIgnoreEntry("/abc/prefix/something", datasync.Put)
	plugin.Put("/abc/prefix/something", nil)

	select {
	case <-ch:
		t.FailNow()
	case <-time.After(100 * time.Millisecond):

	}

	// expect message to be received
	plugin.Delete("/abc/prefix/something")
	// add dummy ignore etnries
	plugin.AddIgnoreEntry("/abc/prefix/dfafdasfadfadf", datasync.Delete)
	plugin.AddIgnoreEntry("/abc/prefix/adfasfgasf", datasync.Put)
	select {
	case change := <-ch:
		gomega.Expect(change.GetKey()).To(gomega.BeEquivalentTo("/abc/prefix/something"))
		gomega.Expect(change.GetChangeType()).To(gomega.BeEquivalentTo(data.Delete))
	case <-time.After(100 * time.Millisecond):
		t.FailNow()
	}

	// expect the message to be filtered out
	plugin.AddIgnoreEntry("/abc/prefix/something", datasync.Delete)
	plugin.Delete("/abc/prefix/something")

	select {
	case <-ch:
		t.FailNow()
	case <-time.After(100 * time.Millisecond):

	}

	err = plugin.Close()
	gomega.Expect(err).To(gomega.BeNil())

	close(ch)
}

type kvdbsyncMock struct {
	subs map[string]chan datasync.ChangeEvent
}

func newKvdbsyncMock() *kvdbsyncMock {
	return &kvdbsyncMock{subs: map[string]chan datasync.ChangeEvent{}}
}

func (kv *kvdbsyncMock) Watch(resyncName string, changeChan chan datasync.ChangeEvent,
	resyncChan chan datasync.ResyncEvent, keyPrefixes ...string) (datasync.WatchRegistration, error) {

	for _, k := range keyPrefixes {
		kv.subs[k] = changeChan
	}

	return &regMock{}, nil
}

func (kv *kvdbsyncMock) Put(key string, data proto.Message, opts ...datasync.PutOption) error {
	for k, ch := range kv.subs {
		if strings.Contains(key, k) {
			ch <- newChangeEventMock(key, datasync.Put)
		}
	}
	return nil
}

func (kv *kvdbsyncMock) Delete(key string, opts ...datasync.DelOption) (existed bool, err error) {
	for k, ch := range kv.subs {
		if strings.Contains(key, k) {
			ch <- newChangeEventMock(key, datasync.Delete)
		}
	}
	return true, nil
}

type regMock struct {
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

package cache

import (
	"github.com/golang/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"

	nodeinfomodel "github.com/contiv/vpp/plugins/contiv/model/node"

	"github.com/onsi/gomega"
	"testing"
)

type dataResyncTestData struct {
	log      *logrus.Logger
	resyncEv *mockDrKeyValIterator
	cache    *ContivTelemetryCache
}

type mockDrKeyValIterator struct {
	values map[string]datasync.KeyValIterator
}

func (kvi *mockDrKeyValIterator) GetValues() map[string]datasync.KeyValIterator {
	return kvi.values
}

func (kvi *mockDrKeyValIterator) Done(err error) {

}

type mockKeyValIterator struct {
	items []datasync.KeyVal
}

func (kvi *mockKeyValIterator) GetNext() (kv datasync.KeyVal, allReceived bool) {
	if len(kvi.items) == 0 {
		return nil, true
	}
	v := kvi.items[0]
	kvi.items = kvi.items[1:]
	return v, false
}

// mockKeyVal and its methods defines a mock key-value pair used in the tests
type mockKeyVal struct {
	key   string
	rev   int64
	value proto.Message
}

func (mkv *mockKeyVal) GetKey() string {
	return mkv.key
}

func (mkv *mockKeyVal) GetRevision() int64 {
	return mkv.rev
}

func (mkv *mockKeyVal) GetValue(value proto.Message) error {
	value = mkv.value
	return nil
}

var drd dataResyncTestData

func TestDataResync(t *testing.T) {
	gomega.RegisterTestingT(t)

	// Initialize & start mock objects
	drd.log = logrus.DefaultLogger()
	drd.log.SetLevel(logging.DebugLevel)

	drd.cache = &ContivTelemetryCache{
		Deps: Deps{
			Log: drd.log,
		},
		Synced: false,
	}
	drd.cache.Init()

	drd.resyncEv = &mockDrKeyValIterator{
		values: make(map[string]datasync.KeyValIterator, 0),
	}

	drd.createTestData()

	t.Run("testResync", testResync)
}

func testResync(t *testing.T) {
	drd.cache.Resync(drd.resyncEv)
}

func (drd *dataResyncTestData) createTestData() {
	drd.resyncEv.values[nodeinfomodel.AllocatedIDsKeyPrefix] = &mockKeyValIterator{
		items: []datasync.KeyVal{
			&mockKeyVal{
				key: nodeinfomodel.AllocatedIDsKeyPrefix + "1",
				rev: 1,
				value: &nodeinfomodel.NodeInfo{
					Id:                  1,
					Name:                "k8s-worker2",
					IpAddress:           "192.168.16.1/24",
					ManagementIpAddress: "10.20.0.11",
				},
			},
			&mockKeyVal{
				key: nodeinfomodel.AllocatedIDsKeyPrefix + "2",
				rev: 1,
				value: &nodeinfomodel.NodeInfo{
					Id:                  1,
					Name:                "k8s-worker1",
					IpAddress:           "192.168.16.2/24",
					ManagementIpAddress: "10.20.0.10",
				},
			},
		},
	}
}

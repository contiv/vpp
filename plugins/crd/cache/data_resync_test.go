package cache

import (
	"github.com/golang/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"

	nodeinfomodel "github.com/contiv/vpp/plugins/contiv/model/node"

	"encoding/json"
	"github.com/onsi/gomega"
	"testing"
	"sync/atomic"
	"time"
	"fmt"
)

type dataResyncTestData struct {
	log       *logrus.Logger
	logWriter *mockLogWriter
	resyncEv  *mockDrKeyValIterator
	processor *mockProcessor
	cache     *ContivTelemetryCache
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
	if buf, err := json.Marshal(mkv.value); err == nil {
		json.Unmarshal(buf, value)
		return nil
	} else {
		return err
	}
}

// mockProcessor emulates the Processor, effectively making sure no
// data collection is started during the unit test.
type mockProcessor struct {
	collectCnt  int32
	validateCnt int32
}

func (mp *mockProcessor) CollectNodeInfo(node *Node) {
	atomic.AddInt32(&mp.collectCnt, 1)
}

func (mp *mockProcessor) ValidateNodeInfo() {
	atomic.AddInt32(&mp.validateCnt, 1)
}

// mockLogWriter collects all error logs into a buffer for analysis
// by gomega assertions.
type mockLogWriter struct {
	log []string
}

func (mlw *mockLogWriter)Write(p []byte) (n int, err error) {
	logStr := string(p)
	mlw.log = append(mlw.log, logStr)
	return len(logStr), nil
}

func (mlw *mockLogWriter) clearLog() {
	mlw.log = []string{}
}

// drd holds all the data structures required for the DataResync test
var drd dataResyncTestData

func TestDataResync(t *testing.T) {
	gomega.RegisterTestingT(t)

	// Initialize & start mock objects
	drd.logWriter = &mockLogWriter{ log: []string{} }
	drd.log = logrus.DefaultLogger()
	drd.log.SetLevel(logging.DebugLevel)
	drd.log.SetOutput(drd.logWriter)

	drd.processor = &mockProcessor{}
	drd.cache = &ContivTelemetryCache{
		Deps: Deps{
			Log: drd.log,
		},
		Synced: false,
	}
	drd.cache.Init()
	drd.cache.Processor = drd.processor

	t.Run("testResyncNodeInfoOk", testResyncNodeInfoOk)
	for i, l := range drd.logWriter.log {
		fmt.Printf("%d: %s", i, l)
	}
	t.Run("testResyncNodeInfoBadKey", testResyncNodeInfoBadKey)
	for i, l := range drd.logWriter.log {
		fmt.Printf("%d: %s", i, l)
	}
}

func testResyncNodeInfoOk(t *testing.T) {
	drd.createNewResyncKvIterator()
	drd.createNodeInfoOkTestData()

	drd.cache.Resync(drd.resyncEv)

	gomega.Expect(len(drd.cache.Cache.nMap)).To(gomega.Equal(3))
	time.Sleep(1*time.Millisecond)
	numCollects := atomic.LoadInt32(&drd.processor.collectCnt)
	gomega.Expect(numCollects).To(gomega.BeEquivalentTo(3))
}

func testResyncNodeInfoBadKey(t *testing.T) {
	drd.logWriter.clearLog()
	drd.createNewResyncKvIterator()
	drd.createNodeInfoBadKeyTestData()

	drd.cache.Resync(drd.resyncEv)

	gomega.Expect(len(drd.cache.Cache.nMap)).To(gomega.Equal(0))
}

func (d *dataResyncTestData) createNewResyncKvIterator() {
	d.resyncEv = &mockDrKeyValIterator{
		values: make(map[string]datasync.KeyValIterator, 0),
	}
}

func (d *dataResyncTestData) createNodeInfoOkTestData() {
	d.resyncEv.values[nodeinfomodel.AllocatedIDsKeyPrefix] = &mockKeyValIterator{
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
					Id:                  2,
					Name:                "k8s-worker1",
					IpAddress:           "192.168.16.2/24",
					ManagementIpAddress: "10.20.0.10",
				},
			},
			&mockKeyVal{
				key: nodeinfomodel.AllocatedIDsKeyPrefix + "3",
				rev: 1,
				value: &nodeinfomodel.NodeInfo{
					Id:                  3,
					Name:                "k8s-master",
					IpAddress:           "192.168.16.3/24",
					ManagementIpAddress: "10.20.0.2",
				},
			},
		},
	}
}

func (d *dataResyncTestData) createNodeInfoBadKeyTestData() {
	d.resyncEv.values[nodeinfomodel.AllocatedIDsKeyPrefix] = &mockKeyValIterator{
		items: []datasync.KeyVal{
			&mockKeyVal{
				key: nodeinfomodel.AllocatedIDsKeyPrefix + "ab1",
				rev: 1,
				value: &nodeinfomodel.NodeInfo{
					Id:                  1,
					Name:                "k8s-worker2",
					IpAddress:           "192.168.16.1/24",
					ManagementIpAddress: "10.20.0.11",
				},
			},
			&mockKeyVal{
				key: nodeinfomodel.AllocatedIDsKeyPrefix + "2/234",
				rev: 1,
				value: &nodeinfomodel.NodeInfo{
					Id:                  2,
					Name:                "k8s-worker1",
					IpAddress:           "192.168.16.2/24",
					ManagementIpAddress: "10.20.0.10",
				},
			},
			&mockKeyVal{
				key: nodeinfomodel.AllocatedIDsKeyPrefix + "1qer",
				rev: 1,
				value: &nodeinfomodel.NodeInfo{
					Id:                  3,
					Name:                "k8s-master",
					IpAddress:           "192.168.16.3/24",
					ManagementIpAddress: "10.20.0.2",
				},
			},
		},
	}
}

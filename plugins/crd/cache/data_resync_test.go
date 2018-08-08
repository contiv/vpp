package cache

import (
	"github.com/golang/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"

	"encoding/json"
	"fmt"
	nodeinfomodel "github.com/contiv/vpp/plugins/contiv/model/node"
	"github.com/onsi/gomega"
	"sync/atomic"
	"testing"
	"time"
)

type dataResyncTestData struct {
	log             *logrus.Logger
	logWriter       *mockLogWriter
	resyncEv        *mockDrKeyValIterator
	processor       *mockProcessor
	cache           *ContivTelemetryCache
	injectGetValErr bool
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
	buf, err := json.Marshal(mkv.value)
	if err == nil {
		if drd.injectGetValErr {
			buf[0] = 0
		}
		return json.Unmarshal(buf, value)
	}
	return err
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

func (mlw *mockLogWriter) Write(p []byte) (n int, err error) {
	logStr := string(p)
	mlw.log = append(mlw.log, logStr)
	return len(logStr), nil
}

func (mlw *mockLogWriter) clearLog() {
	mlw.log = []string{}
}

func (mlw *mockLogWriter) printLog() {
	fmt.Println("Error log:")
	fmt.Println("==========")
	for i, l := range mlw.log {
		fmt.Printf("%d: %s", i, l)
	}
}

// drd holds all the data structures required for the DataResync test
var drd dataResyncTestData

func TestDataResync(t *testing.T) {
	gomega.RegisterTestingT(t)

	// Initialize & start mock objects
	drd.logWriter = &mockLogWriter{log: []string{}}
	drd.log = logrus.DefaultLogger()
	drd.log.SetLevel(logging.ErrorLevel)
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
	t.Run("testResyncNodeInfoBadKey", testResyncNodeInfoBadKey)
	t.Run("testResyncNodeInfoBadID", testResyncNodeInfoBadID)
	t.Run("testResyncNodeInfoBadProto", testResyncNodeInfoBadProto)
	t.Run("testResyncNodeInfoAddNodeFail", testResyncNodeInfoAddNodeFail)
	t.Run("testResyncNodeInfoBadData", testResyncNodeInfoBadData)

	for i, l := range drd.logWriter.log {
		fmt.Printf("%d: %s", i, l)
	}
}

func testResyncNodeInfoOk(t *testing.T) {
	drd.createNewResyncKvIterator()
	drd.createNodeInfoOkTestData()

	drd.cache.Resync(drd.resyncEv)

	gomega.Expect(len(drd.cache.Cache.nMap)).To(gomega.Equal(3))
	time.Sleep(1 * time.Millisecond)
	numCollects := atomic.LoadInt32(&drd.processor.collectCnt)
	gomega.Expect(numCollects).To(gomega.BeEquivalentTo(3))
}

func testResyncNodeInfoBadKey(t *testing.T) {
	drd.logWriter.clearLog()
	drd.createNewResyncKvIterator()
	drd.createNodeInfoBadKeyTestData()

	drd.cache.Resync(drd.resyncEv)

	gomega.Expect(len(drd.cache.Cache.nMap)).To(gomega.Equal(0))
	gomega.Expect(len(drd.logWriter.log)).To(gomega.Equal(3))
}

func testResyncNodeInfoBadID(t *testing.T) {
	drd.logWriter.clearLog()
	drd.createNewResyncKvIterator()
	drd.createNodeInfoBadIDTestData()

	drd.cache.Resync(drd.resyncEv)

	gomega.Expect(len(drd.cache.Cache.nMap)).To(gomega.Equal(0))
	gomega.Expect(len(drd.logWriter.log)).To(gomega.Equal(1))
}

func testResyncNodeInfoBadProto(t *testing.T) {
	drd.logWriter.clearLog()
	drd.createNewResyncKvIterator()
	drd.createNodeInfoOkTestData()
	drd.injectGetValErr = true

	drd.cache.Resync(drd.resyncEv)

	drd.injectGetValErr = false

	gomega.Expect(len(drd.cache.Cache.nMap)).To(gomega.Equal(0))
	gomega.Expect(len(drd.logWriter.log)).To(gomega.Equal(3))
}

func testResyncNodeInfoBadData(t *testing.T) {
	drd.logWriter.clearLog()
	drd.createNewResyncKvIterator()
	drd.createNodeInfoBadTestData()

	drd.cache.Resync(drd.resyncEv)

	gomega.Expect(len(drd.cache.Cache.nMap)).To(gomega.Equal(0))
	gomega.Expect(len(drd.logWriter.log)).To(gomega.Equal(1))
}

func testResyncNodeInfoAddNodeFail(t *testing.T) {
	drd.logWriter.clearLog()
	drd.createNewResyncKvIterator()
	drd.createNodeInfoDuplicateNameTestData()

	drd.cache.Resync(drd.resyncEv)

	gomega.Expect(len(drd.cache.Cache.nMap)).To(gomega.Equal(1))
	gomega.Expect(len(drd.logWriter.log)).To(gomega.Equal(1))
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

func (d *dataResyncTestData) createNodeInfoBadIDTestData() {
	d.resyncEv.values[nodeinfomodel.AllocatedIDsKeyPrefix] = &mockKeyValIterator{
		items: []datasync.KeyVal{
			&mockKeyVal{
				key: nodeinfomodel.AllocatedIDsKeyPrefix + "1",
				rev: 1,
				value: &nodeinfomodel.NodeInfo{
					Id:                  2,
					Name:                "k8s-worker2",
					IpAddress:           "192.168.16.1/24",
					ManagementIpAddress: "10.20.0.11",
				},
			},
		},
	}
}

func (d *dataResyncTestData) createNodeInfoBadTestData() {
	d.resyncEv.values[nodeinfomodel.AllocatedIDsKeyPrefix] = &mockKeyValIterator{
		items: []datasync.KeyVal{
			&mockKeyVal{
				key: nodeinfomodel.AllocatedIDsKeyPrefix + "1",
				rev: 1,
				value: &nodeinfomodel.NodeInfo{
					Id: 1,
				},
			},
		},
	}
}

func (d *dataResyncTestData) createNodeInfoDuplicateNameTestData() {
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
					Name:                "k8s-worker2",
					IpAddress:           "192.168.16.2/24",
					ManagementIpAddress: "10.20.0.10",
				},
			},
		},
	}
}
